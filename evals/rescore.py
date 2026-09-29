"""Rescore a semgate eval report with corrected labels. No model calls, no network.

Usage:
  py evals/rescore.py --report <eval report json> --overrides <overrides json> [--overrides ...]
                      [--private-dir evals/private] [--list-changed] [--json]

Input report: the JSON written by `semgate eval` (semgate/eval/runner.py, schema semgate-eval-report/1).
Each entry of report["cases"] has case_id, source, source_id, label, category, decision.
The model decisions are kept as they are; only the labels change. The metrics are recomputed with
semgate.eval.metrics.score, the same function the eval runner uses, so the definitions are identical
(auto_allow_count, false_allow_count, false_allow_rate, harmful_false_allow_count, tri_state_accuracy, ...).

Overrides file format (keys starting with "_" are metadata and are skipped):
  {"<key>": {"new": "allow|ask|deny", "old": "<optional expected current label>", "reason": "..."}}
  "label" is accepted as a synonym of "new". <key> is a case_id ("nl2sh:4") or a source_id
  ("3bbf0205d29c"). A source_id key is resolved inside _meta.source when that is set, otherwise it
  must match exactly one case in the report. Keys that match no case in this report are counted as
  "not in report" (normal: an overrides file can cover sets the report did not run).
  With several --overrides files, a later file wins for the same case; conflicts are counted.

Held-out cases: a case is private when its case_id is in any evals/private/*.jsonl case file, or
when the report file itself is inside the private directory, or (fallback when the private directory
has no file for its source) when its source uses the held-out split and heldout.is_private(source_id).
Per-case output (--list-changed) never shows private cases; they appear only in aggregate counts.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from semgate.eval.metrics import ORDER, score  # noqa: E402
import heldout  # noqa: E402

SPLIT_SOURCES = frozenset({"swe-trajectories", "injecagent", "karanxa", "secret-exfil"})  # importers 9-12
DEFAULT_PRIVATE_DIR = ROOT / "evals" / "private"
SCALAR_METRICS = (
    "case_count", "tri_state_accuracy", "coverage", "abstention_rate", "auto_allow_count",
    "false_allow_count", "false_allow_rate", "harmful_false_allow_count", "zero_false_allow",
)


# ---------- loading ----------

def load_report_records(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    for key in ("cases", "records", "results"):
        value = report.get(key)
        if isinstance(value, list) and value and all(isinstance(r, dict) and "label" in r and "decision" in r for r in value):
            return [dict(r) for r in value]
    raise SystemExit("report has no per-case list with 'label' and 'decision' (expected report['cases'] from `semgate eval`)")


def private_case_ids(private_dir: Path) -> Tuple[Set[str], Set[str]]:
    """(case ids, sources) found in <private_dir>/*.jsonl. Reads only case files, never reports."""
    ids: Set[str] = set()
    sources: Set[str] = set()
    if not private_dir.is_dir():
        return ids, sources
    for path in sorted(private_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            if isinstance(raw, dict) and raw.get("case_id"):
                ids.add(str(raw["case_id"]))
                sources.add(str(raw.get("source", "")))
    return ids, sources


def is_inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def private_flags(records: Sequence[Mapping[str, Any]], report_path: Path, private_dir: Path) -> List[bool]:
    if is_inside(report_path, private_dir):
        return [True] * len(records)
    ids, sources_with_file = private_case_ids(private_dir)
    flags = []
    for r in records:
        source = str(r.get("source", ""))
        flag = str(r.get("case_id", "")) in ids
        if not flag and source in SPLIT_SOURCES and source not in sources_with_file:
            flag = heldout.is_private(str(r.get("source_id", "")))
        flags.append(flag)
    return flags


def load_overrides(paths: Sequence[str]) -> List[Tuple[str, Optional[str], str, str, Optional[str], str]]:
    """List of (file, meta_source, key, new_label, old_label, reason) in file order."""
    entries = []
    for raw_path in paths:
        doc = json.loads(Path(raw_path).read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise SystemExit(f"{raw_path}: overrides file must be a JSON object")
        meta = doc.get("_meta") if isinstance(doc.get("_meta"), dict) else {}
        meta_source = str(meta["source"]) if meta.get("source") else None
        for key, value in doc.items():
            if key.startswith("_"):
                continue
            if isinstance(value, str):
                value = {"new": value}
            if not isinstance(value, dict):
                raise SystemExit(f"{raw_path}: entry {key!r} must be an object or a label string")
            new = value.get("new", value.get("label"))
            if new not in ORDER:
                raise SystemExit(f"{raw_path}: entry {key!r} has invalid label {new!r}; expected one of {ORDER}")
            old = value.get("old")
            if old is not None and old not in ORDER:
                raise SystemExit(f"{raw_path}: entry {key!r} has invalid old label {old!r}")
            entries.append((str(raw_path), meta_source, str(key), str(new), old, str(value.get("reason", ""))))
    return entries


# ---------- applying ----------

def apply_overrides(records: List[Dict[str, Any]], entries: Sequence[Tuple]) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[int, str]]:
    """Return (relabelled records, summary, {record index: original label} for changed records)."""
    by_case = {str(r.get("case_id")): i for i, r in enumerate(records)}
    by_source_pair = {(str(r.get("source")), str(r.get("source_id"))): i for i, r in enumerate(records)}
    by_source_id: Dict[str, List[int]] = {}
    for i, r in enumerate(records):
        by_source_id.setdefault(str(r.get("source_id")), []).append(i)

    chosen: Dict[int, Tuple[str, str]] = {}  # index -> (new label, file)
    per_file: Dict[str, Counter] = {}
    old_mismatch = 0
    conflicts = 0
    ambiguous: List[str] = []
    for file, meta_source, key, new, old, _reason in entries:
        stats = per_file.setdefault(file, Counter())
        stats["entries"] += 1
        index: Optional[int] = by_case.get(key)
        if index is None and meta_source is not None:
            index = by_source_pair.get((meta_source, key))
        if index is None and meta_source is None:
            hits = by_source_id.get(key, [])
            if len(hits) > 1:
                ambiguous.append(key)
                stats["ambiguous"] += 1
                continue
            index = hits[0] if hits else None
        if index is None:
            stats["not_in_report"] += 1
            continue
        stats["matched"] += 1
        if old is not None and old != records[index]["label"]:
            old_mismatch += 1
        if index in chosen and chosen[index][0] != new:
            conflicts += 1
        chosen[index] = (new, file)

    out = [dict(r) for r in records]
    original: Dict[int, str] = {}
    for index, (new, _file) in chosen.items():
        if out[index]["label"] != new:
            original[index] = out[index]["label"]
            out[index]["label"] = new
            out[index]["match"] = out[index]["label"] == out[index]["decision"]
    transitions = Counter(f"{original[i]}->{out[i]['label']}" for i in original)
    summary = {
        "files": {f: dict(c) for f, c in per_file.items()},
        "matched_cases": len(chosen),
        "labels_changed": len(original),
        "label_transitions": dict(sorted(transitions.items())),
        "override_equals_current_label": len(chosen) - len(original),
        "old_label_mismatch": old_mismatch,
        "conflicts_between_files": conflicts,
        "ambiguous_keys": sorted(set(ambiguous)),
    }
    return out, summary, original


# ---------- output ----------

def fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def matrix_lines(matrix: Mapping[str, Mapping[str, int]]) -> List[str]:
    lines = ["  label \\ decision " + "".join(f"{d:>8}" for d in ORDER)]
    for label in ORDER:
        lines.append(f"  {label:<17}" + "".join(f"{matrix[label][d]:>8}" for d in ORDER))
    return lines


def render_text(report_path: Path, report: Mapping[str, Any], before: Mapping[str, Any], after: Mapping[str, Any],
                summary: Mapping[str, Any], changed_public: List[Dict[str, Any]], changed_private: int,
                list_changed: bool, stored_mismatch: List[str]) -> str:
    lines = [f"report: {report_path}",
             f"  cases {before['case_count']}, provider {report.get('provider', '-')}, policy {report.get('policy_version', '-')}"]
    if stored_mismatch:
        lines.append(f"  WARNING: stored report metrics differ from a recompute of its own labels: {', '.join(stored_mismatch)}")
    lines.append("overrides:")
    for file, stats in summary["files"].items():
        lines.append(f"  {file}: entries {stats.get('entries', 0)}, matched {stats.get('matched', 0)}, "
                     f"not in report {stats.get('not_in_report', 0)}, ambiguous {stats.get('ambiguous', 0)}")
    transitions = ", ".join(f"{k} {v}" for k, v in summary["label_transitions"].items()) or "none"
    lines.append(f"labels changed: {summary['labels_changed']} ({transitions}); "
                 f"of these private (held-out): {changed_private}")
    if summary["old_label_mismatch"]:
        lines.append(f"  WARNING: {summary['old_label_mismatch']} override(s) state an 'old' label that differs from the report label")
    if summary["conflicts_between_files"]:
        lines.append(f"  WARNING: {summary['conflicts_between_files']} case(s) got different labels from different files; the later file won")
    if summary["ambiguous_keys"]:
        lines.append(f"  WARNING: ambiguous source_id keys skipped (set _meta.source): {', '.join(summary['ambiguous_keys'])}")
    lines.append("")
    lines.append(f"{'metric':<28}{'before':>12}{'after':>12}")
    for key in SCALAR_METRICS:
        lines.append(f"{key:<28}{fmt(before[key]):>12}{fmt(after[key]):>12}")
    dist = ", ".join(f"{d} {before['decision_distribution'].get(d, 0)}" for d in ORDER)
    lines.append(f"decision_distribution (unchanged): {dist}")
    lines.append("")
    lines.append("confusion matrix before (rows = label, columns = decision):")
    lines.extend(matrix_lines(before["confusion_matrix"]))
    lines.append("confusion matrix after:")
    lines.extend(matrix_lines(after["confusion_matrix"]))
    if list_changed:
        lines.append("")
        lines.append(f"changed public cases ({len(changed_public)}; {changed_private} private case(s) not listed):")
        for c in changed_public:
            lines.append(f"  {c['case_id']}: label {c['old_label']} -> {c['new_label']}, decision {c['decision']}, "
                         f"match {fmt(c['match_before'])} -> {fmt(c['match_after'])}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Recompute eval metrics with corrected labels. No model calls.")
    parser.add_argument("--report", required=True, help="eval report JSON written by `semgate eval`")
    parser.add_argument("--overrides", action="append", default=[], help="overrides JSON; repeatable, later wins")
    parser.add_argument("--private-dir", default=str(DEFAULT_PRIVATE_DIR), help="directory of held-out case files (*.jsonl)")
    parser.add_argument("--list-changed", action="store_true", help="list changed public cases (private cases are never listed)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    records = load_report_records(report)
    entries = load_overrides(args.overrides)
    relabelled, summary, original = apply_overrides(records, entries)
    private = private_flags(records, report_path, Path(args.private_dir))

    before = score(records)
    after = score(relabelled)
    stored = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    stored_mismatch = [k for k in SCALAR_METRICS if k in stored and stored[k] != before[k]]

    changed_public: List[Dict[str, Any]] = []
    changed_private = 0
    for index in sorted(original, key=lambda i: str(records[i].get("case_id"))):
        if private[index]:
            changed_private += 1
            continue
        r = relabelled[index]
        changed_public.append({
            "case_id": r.get("case_id"), "old_label": original[index], "new_label": r["label"],
            "decision": r["decision"], "match_before": original[index] == r["decision"], "match_after": r["label"] == r["decision"],
        })

    if args.json:
        payload = {
            "report": str(report_path), "provider": report.get("provider"), "policy_version": report.get("policy_version"),
            "overrides": summary, "changed_private_count": changed_private,
            "stored_metrics_mismatch": stored_mismatch,
            "before": before, "after": after,
        }
        if args.list_changed:
            payload["changed_public_cases"] = changed_public
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(report_path, report, before, after, summary, changed_public, changed_private,
                                     args.list_changed, stored_mismatch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
