"""Pi 0.86.0 extension adapter for the active session branch."""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..chatapproval import Conversation, Item
from ..envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION,
                        Trajectory, TrajectoryEntry, UserGrant, bound_user_messages, short_result)
from ..gitstate import to_epoch
from .claude_family import _OUTPUT_CAP, _tool_and_args


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(p.get("text")) for p in content if isinstance(p, Mapping)
                         and p.get("type") == "text" and isinstance(p.get("text"), str)).strip()
    return ""


def _tool(name: Any, raw: Any) -> Tuple[str, str, Dict[str, Any]]:
    native, canonical, args = _tool_and_args({"tool_name": name, "tool_input": raw})
    if native == "bash":
        canonical = "bash"
    return native, canonical, args


def _parse(entries: Any) -> Tuple[List[str], Tuple[TrajectoryEntry, ...], Tuple[str, ...], frozenset, str, Optional[Conversation], str]:
    if not isinstance(entries, list):
        return [], (), (), frozenset(), "", None, ""
    users: List[str] = []
    calls: List[TrajectoryEntry] = []
    call_ids: List[str] = []
    positions: Dict[str, int] = {}
    items: List[Item] = []
    intent = ""
    started = ""
    for entry in entries:
        if not isinstance(entry, Mapping):
            return [], (), (), frozenset(), "", None, ""
        stamp = entry.get("timestamp")
        if not started and isinstance(stamp, str):
            started = stamp
        if entry.get("type") != "message":
            continue
        msg = entry.get("message")
        if not isinstance(msg, Mapping):
            return [], (), (), frozenset(), "", None, ""
        role = msg.get("role")
        ts = to_epoch(stamp)
        if role == "user":
            text = _text(msg.get("content"))
            if text:
                users.append(text)
                items.append(Item("user", text, ts, msg_id=str(entry.get("id") or "")))
                intent = ""
        elif role == "assistant":
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, Mapping):
                    continue
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    intent = part["text"]
                    items.append(Item("agent", intent, ts))
                elif part.get("type") == "toolCall":
                    call_id = str(part.get("id") or "")
                    if not call_id or call_id in positions:
                        return [], (), (), frozenset(), "", None, ""
                    native, _canonical, args = _tool(part.get("name"), part.get("arguments"))
                    positions[call_id] = len(calls)
                    call_ids.append(call_id)
                    summary = str(args.get("command") or args.get("path") or args.get("url") or "")[:200]
                    calls.append(TrajectoryEntry(tool=native, decision="", summary=summary))
                    items.append(Item("call", native, ts, call_id=call_id))
        elif role == "toolResult":
            n = positions.get(str(msg.get("toolCallId") or ""))
            if n is not None:
                output = _text(msg.get("content"))
                old = calls[n]
                calls[n] = TrajectoryEntry(tool=old.tool, decision="", summary=old.summary,
                                           output=output[:_OUTPUT_CAP], result=short_result(output,
                                                                                           error=bool(msg.get("isError"))))
    return (users, tuple(calls[-20:]), tuple(call_ids[-20:]), frozenset(call_ids), intent[:AGENT_INTENT_MAX],
            Conversation(tuple(items), complete=True, timestamps=True, source="pi active branch 0.86.0"), started)


def user_messages(request: Mapping[str, Any]) -> List[str]:
    return _parse(request.get("entries"))[0]


def chat_conversation(request: Mapping[str, Any]) -> Optional[Conversation]:
    return _parse(request.get("entries"))[5]


def session_started_at(request: Mapping[str, Any]) -> str:
    return _parse(request.get("entries"))[6]


def envelope_from_request(request: Mapping[str, Any], grant: UserGrant, *, evaluated_at: str = "",
                          tool_outputs: Optional[Sequence[Mapping[str, Any]]] = None,
                          merge_stats: Optional[Dict[str, Any]] = None) -> Envelope:
    _native, tool, args = _tool(request.get("tool"), request.get("args"))
    users, trace, ids, known, intent, _conv, _started = _parse(request.get("entries"))
    current_id = str(request.get("callID") or "")
    kept = [(e, i) for e, i in zip(trace, ids) if i != current_id]
    trace, ids = tuple(e for e, _ in kept), tuple(i for _, i in kept)
    if tool_outputs:
        from ..tooloutputs import merge_trace
        trace, stats = merge_trace(trace, ids, known, tool_outputs, current_id=current_id, cap=_OUTPUT_CAP)
        if merge_stats is not None:
            merge_stats.update(stats)
    cwd = str(request.get("cwd") or "")
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool=tool, arguments=args), grant=grant,
                    environment=Environment(project_root=cwd, cwd=cwd, harness="pi-extension",
                                            session_id=str(request.get("sessionID") or "")),
                    trajectory=Trajectory(recent=trace), evaluated_at=evaluated_at,
                    user_message=users[-1] if users else "", user_messages=bound_user_messages(users),
                    agent_intent=intent)
