"""PreToolUse hook for Claude Code and hosts that share its hook shape:
Codex CLI, Factory Droid, GitHub Copilot CLI, VS Code agent mode, Devin CLI.

    python -m semgate.claude_hook --config ~/.semgate/<host>/semgate.json [--host auto|claude|codex|droid|copilot|vscode|devin]

Reads one event on stdin, runs the same pipeline as the Antigravity hook
(rules, gates, Jev, work kinds, git facts, feedback, ledger), writes one JSON
decision on stdout in the host's format, and always exits 0 so the host reads
the JSON (exit codes are host-specific; the JSON is not). Any failure fails
closed (semgate.enforcement.fail_closed): an ask on a host that shows the ask
to a person in every mode (Claude Code), a deny with what to do on every
other host (Codex, Droid, Copilot CLI, VS Code, Devin CLI). Never an allow.

PostToolUse (`--event post`, or an event with hook_event_name PostToolUse):
records only, prints {} and exits 0. With agent_files / script_source on it
records files the agent created (hash + snapshot, F6) and scripts that
changed after the decision (F4). The join key is (session_id, tool_use_id);
hosts whose events do not carry both (Copilot CLI: no tool-call id; Devin:
prompt_id is per prompt, not per tool call) get no records, so their created
files are never treated as restorable.

PostToolUse also records the tool's output (tool_response; Copilot CLI
toolResult) in the per-session tool output store (semgate.tooloutputs). The
next PreToolUse merges it into the trajectory, so the injection scan and the
task context see the latest output even when the transcript does not hold it
yet (Claude Code on Linux, hookconf A4).

PostToolUse also looks for secrets in the output (semgate.exposures). A
secret this session has not shown before is recorded as a fingerprint
(type, masked preview, keyed fingerprint; never the value). With a policy
that has router.exposure_questions, the judge is first asked whether the
user gave that secret on purpose (the user's turns come from the
transcript). On a host whose manifest says C33 = yes (Claude Code, Droid)
the hook then prints the notice for the model as
hookSpecificOutput.additionalContext instead of {}.

Stop (`--event stop`, or hook_event_name Stop): when the session has a
secret exposure not yet shown to the user, prints {"systemMessage": <one
block listing them>} (manifest C34 = yes: Claude Code); otherwise {}. It
never blocks the stop.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

from . import enforcement, exposures, hookinput, payloadsize, storepaths, tooloutputs
from .adapters import claude_family, codex
from .antigravity_hook import record_host_response, record_post_event, remember_sent, run_core
from .chatapproval import HostChat
from .hosts.base import fit_decision

_TO_HOST = {"allow": "allow", "ask": "ask", "force_ask": "ask", "deny": "deny", "deny_unless_prior_grant": "deny"}


def _fit(host: str, decision: str, reason: str):
    """fit_decision (manifest C2), then the host's own mapping (Devin: ask
    becomes a block). The result is what render_output sends."""
    decision, reason = fit_decision(host, decision, reason)
    return claude_family.host_decision(host, decision, reason)


def run(event: Dict[str, Any], config: Dict[str, Any], host: str, meta: Dict[str, Any],
        payload_bytes: int = 0) -> Dict[str, str]:
    adapter = codex if host == "codex" else claude_family
    transcript = event.get("transcript_path") or event.get("transcriptPath")
    model = str(event.get("model") or "") or hookinput.model_from_transcript(transcript)
    payload = payloadsize.describe(payload_bytes, event.get("tool_input", event.get("toolArgs")), model)
    # Tool outputs semgate's own PostToolUse hook recorded (the transcript can
    # lack the latest one at PreToolUse: Claude Code on Linux, hookconf A4).
    session = str(event.get("session_id") or event.get("sessionId") or "")
    records, problem = tooloutputs.load_for_pre(config, session)
    merge_stats: Dict[str, Any] = {}
    result = run_core(
        config,
        payload=payload,
        build_envelope=lambda grant: adapter.envelope_from_event(event, grant, host=host, tool_outputs=records,
                                                                  merge_stats=merge_stats),
        store_problems=[problem] if problem else [],
        extra_evidence={"tool_outputs": merge_stats},
        session_id=str(event.get("session_id") or event.get("sessionId") or ""),
        step_idx=event.get("tool_use_id") or event.get("prompt_id") or event.get("timestamp"),
        user_messages=lambda: adapter.user_messages(event),
        meta=meta,
        # Only a true per-call id may join a pre record with its post event.
        record_step=event.get("tool_use_id"),
        session_started_at=lambda: adapter.transcript_started_at(event.get("transcript_path") or event.get("transcriptPath")),
        # Approval by chat reply (policy router.chat_approval; manifest C35).
        chat=HostChat(host, lambda: adapter.chat_conversation(transcript), call_id=str(event.get("tool_use_id") or "")),
    )
    return {"decision": _TO_HOST.get(str(result.get("decision")), "ask"), "reason": str(result.get("reason", ""))}


def _post(event: Dict[str, Any], config_path: str, host: str = "auto") -> int:
    """PostToolUse: record only, never block. Prints {}, or the secret
    exposure notice as post-tool context on hosts that take it (C33)."""
    out: Dict[str, Any] = {}
    try:
        host = claude_family.resolve_host(host, event)
        config = storepaths.load(config_path, host)
        session = str(event.get("session_id") or event.get("sessionId") or "")
        if hookinput.session_id_problem(session):
            session = ""          # not a usable state key: record nothing
        response = event.get("tool_response") if "tool_response" in event else event.get("toolResult")
        error = ""
        if isinstance(response, dict) and (response.get("error") or response.get("is_error") or response.get("isError")
                                           or str(response.get("resultType", "")).lower() == "failure"):
            error = str(response.get("error") or "tool reported an error")
        record_post_event(config, session, event.get("tool_use_id"), error)
        # The tool's output, for the next PreToolUse (tooloutputs). Hosts
        # without a per-call id record it with tool_use_id "" (matched by order).
        native, _canonical, args = claude_family._tool_and_args(event)
        summary = str(args.get("command") or args.get("path") or args.get("url") or args.get("pattern") or "")
        tooloutputs.record_post(config, session, event.get("tool_use_id"), native, response, summary=summary,
                                agent_id=str(event.get("agent_id") or ""), is_error=bool(error))
        # Secrets in the output: fingerprint only; tell the agent once per secret per session.
        # The user's turns (transcript) are read only when a new secret is found: the judge
        # is asked whether the user gave it on purpose (policy router.exposure_questions).
        adapter = codex if host == "codex" else claude_family
        notice = exposures.on_tool_output(config, host=host, manifest_host=host, session_id=session, tool=native,
                                          detail=summary, step=event.get("tool_use_id") or event.get("prompt_id"),
                                          output=response, user_messages=lambda: adapter.user_messages(event))
        if notice:
            out = claude_family.render_post_context(host, notice)
    except Exception as exc:
        print(f"semgate post hook failure: {type(exc).__name__}: {exc}", file=sys.stderr)
    json.dump(out, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _stop(event: Dict[str, Any], config_path: str, host: str = "auto") -> int:
    """Stop: show the session's secret exposure summary once per new
    exposure (C34 hosts). Never blocks: prints {} or {"systemMessage"}."""
    out: Dict[str, Any] = {}
    try:
        host = claude_family.resolve_host(host, event)
        session = str(event.get("session_id") or event.get("sessionId") or "")
        if session and not hookinput.session_id_problem(session) and exposures.host_supports(host, "C34"):
            text = exposures.stop_summary(storepaths.load(config_path, host), session)
            if text:
                out = {"systemMessage": text}
    except Exception as exc:
        print(f"semgate stop hook failure: {type(exc).__name__}: {exc}", file=sys.stderr)
    json.dump(out, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="semgate-claude-hook")
    parser.add_argument("--config", default=os.environ.get("SEMGATE_CONFIG", os.path.expanduser("~/.semgate/claude/semgate.json")))
    parser.add_argument("--host", default="auto", choices=("auto",) + claude_family.HOSTS + ("codex",))
    parser.add_argument("--event", default="auto", choices=("auto", "pre", "post", "stop"))
    args = parser.parse_args(argv)
    event: Any = None
    config: Any = None
    meta: Dict[str, Any] = {}
    host = args.host
    try:
        # Bounded read (hook_max_payload_bytes) and session id check: hookinput.
        event, size = hookinput.read_event(args.config)
        if args.event == "post" or (args.event == "auto" and event.get("hook_event_name") == "PostToolUse"):
            return _post(event, args.config, host)
        if args.event == "stop" or (args.event == "auto" and event.get("hook_event_name") == "Stop"):
            return _stop(event, args.config, host)
        host = claude_family.resolve_host(host, event)
        hookinput.require_session_id(event.get("session_id") or event.get("sessionId"))
        config = storepaths.load(args.config, host)
        result = run(event, config, host, meta, payload_bytes=size)
    except Exception as exc:
        if isinstance(event, dict):
            host = claude_family.resolve_host(host, event)    # failed after the event was read
        if host == "auto":
            host = "claude"
        hookinput.note_rejection(config if config is not None else args.config, exc, host)
        if args.event == "stop":
            # A Stop hook answers {} on any failure: never a decision, never a block.
            sys.stdout.write("{}\n")
            return 0
        # A hook failure must never become execution permission: an ask only
        # where the host shows it to a person in every mode, else a deny.
        failed = enforcement.fail_closed(f"semgate hook failure: {type(exc).__name__}: {exc}", host, config)
        result = {"decision": _TO_HOST.get(failed["decision"], "ask"), "reason": failed["reason"]}
        if config is None:
            # Failed before the config was loaded: record where --config says
            # (or ~/.semgate/<host>/), never in the current directory.
            config = {"ledger_file": hookinput.early_ledger_path(args.config, host)}
    # A host that cannot show an ask prompt (manifest C2 not "yes") gets a
    # deny; Devin CLI (no ask at all) gets a block. The ledger's host_response
    # records this final decision, i.e. what the host actually gets.
    result["decision"], result["reason"] = _fit(host, result["decision"], result["reason"])
    result["host"] = host      # which output format render_output uses (claude, devin, ...)
    # record_host_response fails closed on a ledger lock timeout (allow ->
    # force_ask, kept in a spill file) and returns the answer to give.
    # The session id the check above read; when it is invalid it goes in as is
    # so record_host_response stores only its length and sha256_12, never the id.
    checked = (event.get("session_id") or event.get("sessionId")) if isinstance(event, dict) else None
    conversation = (checked if hookinput.session_id_problem(checked)
                    else (event or {}).get("session_id", "") if isinstance(event, dict) else "")
    result = record_host_response({"conversationId": conversation,
                                   "stepIdx": (event or {}).get("tool_use_id") if isinstance(event, dict) else None},
                                  config, result, meta)
    result = {"decision": _TO_HOST.get(str(result.get("decision")), "ask"), "reason": str(result.get("reason", ""))}
    # Again: a lock-timeout ask from the line above must also fit the host.
    result["decision"], result["reason"] = _fit(host, result["decision"], result["reason"])
    rendered = claude_family.render_output(host, result["decision"], result["reason"])
    # The exact text the host shows the agent for a blocked call (ownmessages.py).
    if isinstance(event, dict) and isinstance(config, dict):
        remember_sent(config, event.get("session_id") or event.get("sessionId"), meta, result["decision"],
                      claude_family.rendered_reason(rendered))
    json.dump(rendered, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
