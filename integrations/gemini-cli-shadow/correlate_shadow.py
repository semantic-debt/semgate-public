#!/usr/bin/env python3
"""Coverage report for Semgate shadow v4 and Gemini CLI v0.60.0 telemetry."""
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

V4_SCHEMA = 'semgate.gemini-shadow.v4'

def load_json_stream(path: str | Path) -> list[Any]:
    text = Path(path).read_text(encoding='utf-8', errors='strict')
    decoder = json.JSONDecoder()
    records: list[Any] = []
    offset = 0
    while True:
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            return records
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(f'{path}: invalid JSON telemetry at character {exc.pos}: {exc.msg}') from exc
        records.append(value)

def walk(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)

def otel_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ('stringValue', 'intValue', 'doubleValue', 'boolValue', 'value'):
        if key in value:
            return value[key]
    return value

def attributes(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    value = record.get('attributes', {})
    if isinstance(value, list):
        return {str(item.get('key')): otel_value(item.get('value')) for item in value if isinstance(item, dict) and 'key' in item}
    return value if isinstance(value, dict) else {}

def telemetry_events(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for root in load_json_stream(path):
        for record in walk(root):
            if not isinstance(record, dict):
                continue
            attrs = attributes(record)
            body = otel_value(record.get('body'))
            name = attrs.get('event.name') or record.get('name') or body
            if not isinstance(name, str) or name not in {'gemini_cli.tool_call', 'tool_call'}:
                continue
            events.append({'function_name': attrs.get('function_name'), 'function_args': attrs.get('function_args'), 'decision': attrs.get('decision'), 'prompt_id': attrs.get('prompt_id'), 'session_id': attrs.get('session.id') or attrs.get('session_id'), 'timestamp': attrs.get('event.timestamp') or record.get('timestamp') or record.get('timeUnixNano') or record.get('observedTimeUnixNano')})
    return events

# Backward-compatible public name used by review fixtures.
events = telemetry_events

def normalized_args(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return value
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def write_private(path: str | Path, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=target.name + '.', dir=target.parent)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

def usable_identity(value: Any) -> bool:
    """An identity value is usable only as a non-blank string."""
    return isinstance(value, str) and bool(value.strip())

def reconcile(proposals: list[dict[str, Any]], evaluations: list[dict[str, Any]]) -> dict[str, int]:
    """Pair records by a validated (session_id, event_id) identity.

    Records with an absent event_id field are counted as missing. Records with a
    present but unusable event_id (null, non-string, empty, or whitespace-only),
    or a usable event_id without a usable session_id, are counted as invalid and
    never enter the pairing counters. Invalid, missing, orphan, and duplicate
    counts stay separate.
    """
    def validated_keys(records: list[dict[str, Any]], kind: str) -> tuple[Counter, dict[str, int]]:
        keys: Counter = Counter()
        stats = {f'{kind}_missing_event_id': 0, f'{kind}_invalid_event_id': 0, f'{kind}_invalid_session_id': 0}
        for record in records:
            if 'event_id' not in record:
                stats[f'{kind}_missing_event_id'] += 1
                continue
            event_id = record.get('event_id')
            if not usable_identity(event_id):
                stats[f'{kind}_invalid_event_id'] += 1
                continue
            session_id = record.get('session_id')
            if not usable_identity(session_id):
                stats[f'{kind}_invalid_session_id'] += 1
                continue
            keys[(session_id, event_id)] += 1
        return keys, stats
    proposal_ids, proposal_stats = validated_keys(proposals, 'proposals')
    evaluation_ids, evaluation_stats = validated_keys(evaluations, 'evaluations')
    return {'paired_event_ids': sum(1 for key in proposal_ids if proposal_ids[key] == 1 and evaluation_ids[key] == 1), 'proposals_missing_evaluation': sum(count for key, count in proposal_ids.items() if key not in evaluation_ids), 'orphan_evaluations': sum(count for key, count in evaluation_ids.items() if key not in proposal_ids), 'duplicate_proposal_event_ids': sum(count - 1 for count in proposal_ids.values() if count > 1), 'duplicate_evaluation_event_ids': sum(count - 1 for count in evaluation_ids.values() if count > 1), **proposal_stats, **evaluation_stats}

def evaluation_status_counts(evaluations: list[dict[str, Any]]) -> dict[str, int]:
    """Count captured shadow evaluations by their recorded status.

    This describes evaluator health (disabled, error, unscorable, fast-path,
    explicit-constraint, or model-evaluated), which is separate from capture
    health: a captured evaluation can be present yet disabled or failed.
    """
    counts: Counter = Counter()
    for record in evaluations:
        evaluation = record.get('evaluation')
        status = evaluation.get('status') if isinstance(evaluation, dict) else None
        counts[status if usable_identity(status) else 'missing_or_invalid_status'] += 1
    return dict(counts)

def build_report(shadow_records: list[Any], telemetry: list[dict[str, Any]]) -> dict[str, Any]:
    objects = [x for x in shadow_records if isinstance(x, dict)]
    schemas = Counter(str(x.get('schema') or 'legacy-unspecified') for x in objects)
    legacy = [x for x in objects if x.get('schema') != V4_SCHEMA]
    current = [x for x in objects if x.get('schema') == V4_SCHEMA]
    proposals = [x for x in current if x.get('record_type') == 'before_tool_proposal']
    evaluations = [x for x in current if x.get('record_type') == 'shadow_evaluation']
    notifications = [x for x in current if x.get('record_type') == 'permission_request_notification' and x.get('notification_type') == 'ToolPermission']
    coverage = reconcile(proposals, evaluations)
    with_args = [x for x in telemetry if x.get('function_args') is not None]
    associations = []
    for proposal_index, proposal in enumerate(proposals):
        alternatives = []
        for telemetry_index, event in enumerate(with_args):
            if event.get('function_name') != proposal.get('tool_name') or normalized_args(event.get('function_args')) != normalized_args(proposal.get('tool_input')):
                continue
            if proposal.get('session_id') and event.get('session_id') and proposal['session_id'] != event['session_id']:
                continue
            alternatives.append(telemetry_index)
        if alternatives:
            associations.append({'proposal_index': proposal_index, 'telemetry_candidate_indexes': alternatives, 'verified': False})
    if legacy:
        status = 'incompatible_legacy_records_excluded'
    elif any(coverage[key] for key in ('proposals_missing_evaluation','orphan_evaluations','duplicate_proposal_event_ids','duplicate_evaluation_event_ids','proposals_missing_event_id','evaluations_missing_event_id','proposals_invalid_event_id','evaluations_invalid_event_id','proposals_invalid_session_id','evaluations_invalid_session_id')):
        status = 'incomplete_shadow_event_pairs'
    elif not proposals and not telemetry:
        status = 'insufficient_no_proposals_or_telemetry'
    elif not proposals or not telemetry:
        status = 'insufficient_partial_collection'
    else:
        status = 'prototype_partial'
    summary = {'shadow_schema_counts': dict(schemas), 'legacy_records_excluded': len(legacy), 'shadow_proposals': len(proposals), 'shadow_evaluations': len(evaluations), **coverage, 'observed_permission_request_notifications': len(notifications), 'telemetry_tool_calls': len(telemetry), 'telemetry_calls_with_args': len(with_args), 'matched_completed_calls': 0, 'verified_completed_call_matches': 0, 'diagnostic_candidate_associations': len(associations), 'candidate_allow_all_evaluations': sum(x.get('candidate_decision') == 'allow' for x in evaluations), 'shadow_evaluation_status_counts': evaluation_status_counts(evaluations), 'candidate_allow_on_prompted_calls': None, 'counterfactual_prompt_reduction': 'not_computable_without_stable_cross_surface_identity_and_coverage', 'measurement_status': status, 'note': 'Legacy schemas are counted but excluded, including legacy content-bearing permission records. ToolPermission records are confirmation-flow attempts, not verified prompts. shadow_evaluation_status_counts describes evaluator health for captured evaluations and is separate from capture health; paired records can carry disabled, error, or unscorable evaluations.'}
    return {'summary': summary, 'joined_completed_calls': [], 'candidate_associations': associations}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--shadow', required=True)
    parser.add_argument('--telemetry', required=True)
    parser.add_argument('--out')
    args = parser.parse_args()
    report = build_report(load_json_stream(args.shadow), telemetry_events(args.telemetry))
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        write_private(args.out, text)
    else:
        print(text)
    print(json.dumps(report['summary'], indent=2), file=sys.stderr)
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
