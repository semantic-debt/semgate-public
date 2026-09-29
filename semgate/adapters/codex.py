"""Codex 0.153.1 hook transcript adapter.

The rollout JSONL is an observed, version-specific format, not a stable Codex
hook API. Missing or malformed order evidence gives no chat approval.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..chatapproval import Conversation, Item
from ..envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION,
                        Trajectory, TrajectoryEntry, UserGrant, bound_user_messages, short_result)
from ..gitstate import to_epoch
from .claude_family import TranscriptContext, _OUTPUT_CAP, _tool_and_args


def _text(parts: Any, kind: str) -> str:
    if not isinstance(parts, list):
        return ""
    return "\n".join(str(p.get("text", "")) for p in parts
                     if isinstance(p, Mapping) and p.get("type") == kind and isinstance(p.get("text"), str)).strip()


def _call(payload: Mapping[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    name = str(payload.get("name") or "")
    raw = payload.get("arguments") if payload.get("type") == "function_call" else payload.get("input")
    if isinstance(raw, str) and payload.get("type") == "function_call":
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    if payload.get("type") == "custom_tool_call" and isinstance(raw, str):
        raw = {"command": raw}
    native, canonical, args = _tool_and_args({"tool_name": name, "tool_input": raw})
    if name == "exec_command":
        canonical = "bash"
        if "command" not in args and isinstance(args.get("cmd"), str):
            args["command"] = args["cmd"]
    return native, canonical, args


def _read(path: Any) -> Tuple[TranscriptContext, Optional[Conversation], str]:
    empty = TranscriptContext([], (), "")
    if not isinstance(path, str) or not path:
        return empty, None, ""
    users: List[str] = []
    items: List[Item] = []
    calls: List[TrajectoryEntry] = []
    ids: List[str] = []
    canonical: List[str] = []
    positions: Dict[str, int] = {}
    intent = ""
    started = ""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, Mapping) or not isinstance(row.get("payload"), Mapping):
                    return empty, None, ""
                payload = row["payload"]
                ts_text = row.get("timestamp")
                if not started and isinstance(ts_text, str):
                    started = ts_text
                ts = to_epoch(ts_text)
                if row.get("type") == "event_msg" and payload.get("type") == "item_completed":
                    item = payload.get("item")
                    if isinstance(item, Mapping) and item.get("type") == "UserMessage":
                        content = item.get("content")
                        text = _text(content, "text")
                        if text:
                            users.append(text)
                            items.append(Item("user", text, ts, msg_id=str(item.get("id") or "")))
                            intent = ""
                elif row.get("type") == "response_item":
                    kind = payload.get("type")
                    if kind == "message" and payload.get("role") == "assistant":
                        text = _text(payload.get("content"), "output_text")
                        if text:
                            intent = text
                            items.append(Item("agent", text, ts))
                    elif kind in ("function_call", "custom_tool_call"):
                        call_id = str(payload.get("call_id") or "")
                        if not call_id or call_id in positions:
                            return empty, None, ""
                        native, canon, args = _call(payload)
                        summary = str(args.get("command") or args.get("path") or args.get("url") or "")[:200]
                        positions[call_id] = len(calls)
                        ids.append(call_id)
                        canonical.append(canon)
                        calls.append(TrajectoryEntry(tool=native, decision="", summary=summary))
                        items.append(Item("call", native, ts, call_id=call_id))
                    elif kind in ("function_call_output", "custom_tool_call_output"):
                        n = positions.get(str(payload.get("call_id") or ""))
                        if n is not None:
                            output = str(payload.get("output") or "")
                            old = calls[n]
                            calls[n] = TrajectoryEntry(tool=old.tool, decision="", summary=old.summary,
                                                       output=output[:_OUTPUT_CAP], result=short_result(output))
    except (OSError, UnicodeError, ValueError, TypeError):
        return empty, None, ""
    context = TranscriptContext(users, tuple(calls[-20:]), intent[:AGENT_INTENT_MAX],
                                tuple(ids[-20:]), frozenset(ids))
    return context, Conversation(tuple(items), complete=True, timestamps=True, source="codex rollout 0.153.1"), started


def read_transcript_context(path: Any, current_id: str = "") -> TranscriptContext:
    ctx, _, _ = _read(path)
    if not current_id or current_id not in ctx.known_ids:
        return ctx
    kept = [(entry, call_id) for entry, call_id in zip(ctx.trace, ctx.call_ids) if call_id != current_id]
    return TranscriptContext(ctx.users, tuple(e for e, _ in kept), ctx.agent_intent,
                             tuple(i for _, i in kept), ctx.known_ids)


def chat_conversation(path: Any) -> Optional[Conversation]:
    return _read(path)[1]


def transcript_started_at(path: Any) -> str:
    return _read(path)[2]


def user_messages(event: Mapping[str, Any]) -> List[str]:
    return _read(event.get("transcript_path"))[0].users


def envelope_from_event(event: Mapping[str, Any], grant: UserGrant, *, host: str = "codex", evaluated_at: str = "",
                        tool_outputs: Optional[Sequence[Mapping[str, Any]]] = None,
                        merge_stats: Optional[Dict[str, Any]] = None) -> Envelope:
    native, tool, args = _tool_and_args(event)
    if native == "exec_command":
        tool = "bash"
        if "command" not in args and isinstance(args.get("cmd"), str):
            args["command"] = args["cmd"]
    cwd = str(event.get("cwd") or "")
    current_id = str(event.get("tool_use_id") or "")
    ctx = read_transcript_context(event.get("transcript_path"), current_id)
    trace = ctx.trace
    if tool_outputs:
        from ..tooloutputs import merge_trace
        trace, stats = merge_trace(trace, ctx.call_ids, ctx.known_ids, tool_outputs,
                                   current_id=current_id, agent_id=str(event.get("agent_id") or ""), cap=_OUTPUT_CAP)
        if merge_stats is not None:
            merge_stats.update(stats)
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool=tool, arguments=args), grant=grant,
                    environment=Environment(project_root=cwd, cwd=cwd, harness="codex-hook",
                                            session_id=str(event.get("session_id") or "")),
                    trajectory=Trajectory(recent=trace), evaluated_at=evaluated_at,
                    user_message=ctx.users[-1] if ctx.users else "",
                    user_messages=bound_user_messages(ctx.users), agent_intent=ctx.agent_intent)
