"""OpenCode tool-call adapter (V1 `tool.execute.before`, V2 `ctx.tool.hook
("execute.before")`). Also the engine inside Roomote's sandboxes.

The plugin (integrations/opencode/semgate.js) sends one JSON request per tool
call to `semgate serve`:

    {"tool": "bash", "args": {...}, "sessionID": "...", "cwd": "...",
     "messages": [...]}          # recent session messages, optional

`messages` may be in any shape OpenCode exposes:
  V1  client.session.messages():  [{"info": {"role": ...}, "parts": [{"type": "text", "text"},
                                    {"type": "tool", "tool", "callID", "state": {"input", "output"}}]}]
  V2  ctx.session.context():      session messages after the latest compaction, in the server's order
                                  (anomalyco/opencode v2 @ bee5014, schema/src/session-message.ts):
                                  [{"id": "msg_...", "type": "user", "text", "time": {"created": ms}},
                                   {"id", "type": "assistant", "content": [{"type": "text", "text"},
                                     {"type": "tool", "id", "name", "state": {"status", "input", "content", "error"}}]},
                                   {"type": "synthetic" | "system" | "skill" | "shell" | "compaction" | ...}]
  AI SDK (older V2 builds):       [{"role": "user"|"assistant"|"tool", "content": str | [
                                    {"type": "text", "text"}, {"type": "tool-call", "toolName", "input"},
                                    {"type": "tool-result", "toolCallId", "output"}]}]
The V2 plugin also sends `api: "v2"` and, for a session without a parent,
`prompts`: [{"id", "t" (ms), "sha"}], what its session "prompt" hook saw
(chat_conversation). Everything in the request is untrusted data; the grant
comes only from the operator's config.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from ..envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, TrajectoryEntry,
                        UserGrant, bound_user_messages, short_result)
from ..harnesstools import HOST_NAMES

# OpenCode tool name -> semgate canonical tool. Harness tools (question,
# skill, todowrite, todoread) come from harnesstools.HOST_NAMES. Left as
# their own names, judged by the model and outside the default local
# auto-allow set: `execute` (V2 code mode: model-written JavaScript that can
# call every tool, the shell included), `task` (starts a subagent from a
# prompt the agent wrote; the subagent's own calls come through this hook
# too), and every name not listed here.
_TOOLS = {"bash": "bash", "shell": "bash", "edit": "edit", "patch": "edit", "multiedit": "edit", "apply_patch": "edit",
          "write": "write", "read": "read", "glob": "glob", "grep": "grep", "list": "ls", "ls": "ls",
          "webfetch": "web_fetch", "websearch": "web_search", **HOST_NAMES}
_OUTPUT_CAP = 6000


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_as_text(v.get("text") if isinstance(v, Mapping) and "text" in v else v) for v in value)
    if isinstance(value, Mapping):
        for key in ("text", "output", "value", "content"):
            if key in value:
                return _as_text(value[key])
        return json.dumps(value)[:_OUTPUT_CAP]
    return str(value)


def _summary(inp: Any) -> str:
    if isinstance(inp, Mapping):
        for k in ("command", "filePath", "file_path", "path", "url", "pattern"):
            if isinstance(inp.get(k), str):
                return inp[k][:200]
    return ""


class MessagesContext(NamedTuple):
    users: List[str]                         # the user's own turns, oldest first
    trace: Tuple[TrajectoryEntry, ...]       # tool calls with output / result / files_changed
    agent_intent: str                        # latest assistant text after the latest user turn
    call_ids: Tuple[str, ...] = ()           # callID (V1) / toolCallId (V2) of each trace entry
    known_ids: frozenset = frozenset()       # every call id in the messages


_EDIT_TOOLS = frozenset({"edit", "write", "patch", "multiedit", "apply_patch"})


def _file_of(inp: Any) -> str:
    if isinstance(inp, Mapping):
        for k in ("filePath", "file_path", "path"):
            if isinstance(inp.get(k), str) and inp[k]:
                return inp[k]
    return ""


def _v1_result(state: Mapping[str, Any], output: str) -> str:
    """V1 ToolPart state: status "completed" | "error" (+ `error` text). A bash
    call's exit code is read from state.metadata.exit when it is an integer
    (OpenCode's bash tool metadata; not verified on a live transcript)."""
    status = str(state.get("status", ""))
    meta = state.get("metadata") if isinstance(state.get("metadata"), Mapping) else {}
    exit_code = meta.get("exit") if isinstance(meta.get("exit"), int) and not isinstance(meta.get("exit"), bool) else None
    if status == "error":
        return short_result(_as_text(state.get("error")) or output, error=True)
    if exit_code is not None:
        return short_result(output, exit_code=exit_code)
    return short_result(output) if status in ("completed", "") else ""


def is_session_message(m: Any) -> bool:
    """A V2 session message (ctx.session.context()): an id and a type tag,
    no V1 `parts`, no AI SDK `role`."""
    return (isinstance(m, Mapping) and "parts" not in m and "role" not in m
            and isinstance(m.get("type"), str) and isinstance(m.get("id"), str))


def _tool_text(content: Any) -> str:
    """The text items of a V2 tool result's content (file items are left out)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(c.get("text", "")) for c in content if isinstance(c, Mapping) and c.get("type") == "text")
    return ""


def _v2_tool(c: Mapping[str, Any]) -> Tuple[TrajectoryEntry, str]:
    """One V2 assistant tool item -> (trajectory entry, call id)."""
    state = c.get("state") if isinstance(c.get("state"), Mapping) else {}
    tool = str(c.get("name", ""))
    status = str(state.get("status", ""))
    inp = state.get("input") if isinstance(state.get("input"), Mapping) else {}
    output = _tool_text(state.get("content"))
    if status == "error":
        err = state.get("error") if isinstance(state.get("error"), Mapping) else {}
        result = short_result(str(err.get("message") or "") or output, error=True)
    elif status == "completed":
        result = short_result(output)
    else:
        result = ""
    target = _file_of(inp)
    changed = (target,) if (status == "completed" and target and tool.lower() in _EDIT_TOOLS) else ()
    return (TrajectoryEntry(tool=tool, decision="", summary=_summary(inp), output=output[:_OUTPUT_CAP], result=result,
                            files_changed=changed), str(c.get("id") or ""))


def parse_messages_context(messages: Any) -> MessagesContext:
    """Users, trajectory and agent intent from any message shape. Only the
    messages the plugin sends are seen (the last MAX_MESSAGES=30 of the
    session), so the first user turn of a long session can be missing. V2
    session messages: only type "user" is a user turn (synthetic, system,
    skill, shell and compaction entries are not)."""
    users: List[str] = []
    calls: List[TrajectoryEntry] = []
    call_ids: List[str] = []
    by_id: Dict[str, int] = {}
    targets: Dict[int, str] = {}     # V2: file path argument per call index
    intent = ""
    if not isinstance(messages, list):
        return MessagesContext([], (), "")
    for m in messages:
        if not isinstance(m, Mapping):
            continue
        if isinstance(m.get("parts"), list):                       # V1 shape
            role = str((m.get("info") or {}).get("role", ""))
            texts = []
            for p in m["parts"]:
                if not isinstance(p, Mapping):
                    continue
                if p.get("type") == "text" and not p.get("synthetic"):
                    texts.append(str(p.get("text", "")))
                elif p.get("type") == "tool":
                    state = p.get("state") if isinstance(p.get("state"), Mapping) else {}
                    tool = str(p.get("tool", ""))
                    output = _as_text(state.get("output"))
                    ok = str(state.get("status", "")) == "completed"
                    target = _file_of(state.get("input"))
                    call_ids.append(str(p.get("callID") or ""))
                    calls.append(TrajectoryEntry(tool=tool, decision="", summary=_summary(state.get("input")),
                                                 output=output[:_OUTPUT_CAP], result=_v1_result(state, output),
                                                 files_changed=(target,) if (ok and target and tool.lower() in _EDIT_TOOLS) else ()))
            said = "\n".join(t for t in texts if t.strip()).strip()
            if role == "user" and said:
                users.append(said)
                intent = ""
            elif role == "assistant" and said:
                intent = said
            continue
        if is_session_message(m):                                  # V2 session message
            if m["type"] == "user":
                text = str(m.get("text") or "").strip()
                if text:
                    users.append(text)
                    intent = ""
            elif m["type"] == "assistant" and isinstance(m.get("content"), list):
                said = []
                for c in m["content"]:
                    if not isinstance(c, Mapping):
                        continue
                    if c.get("type") == "text":
                        said.append(str(c.get("text", "")))
                    elif c.get("type") == "tool":
                        entry, cid = _v2_tool(c)
                        call_ids.append(cid)
                        calls.append(entry)
                text = "\n".join(t for t in said if t.strip()).strip()
                if text:
                    intent = text
            continue
        role = str(m.get("role", ""))                              # AI SDK shape (older V2 builds)
        content = m.get("content")
        if role == "user":
            text = _as_text([c for c in content if isinstance(c, Mapping) and c.get("type") == "text"] if isinstance(content, list) else content).strip()
            if text:
                users.append(text)
                intent = ""
        elif role == "assistant" and isinstance(content, str) and content.strip():
            intent = content.strip()
        elif isinstance(content, list):
            said = _as_text([c for c in content if isinstance(c, Mapping) and c.get("type") == "text"]).strip() if role == "assistant" else ""
            if said:
                intent = said
            for c in content:
                if not isinstance(c, Mapping):
                    continue
                if c.get("type") == "tool-call":
                    by_id[str(c.get("toolCallId", ""))] = len(calls)
                    targets[len(calls)] = _file_of(c.get("input") or c.get("args"))
                    call_ids.append(str(c.get("toolCallId") or ""))
                    calls.append(TrajectoryEntry(tool=str(c.get("toolName", "")), decision="", summary=_summary(c.get("input") or c.get("args"))))
                elif c.get("type") == "tool-result":
                    n = by_id.get(str(c.get("toolCallId", "")))
                    raw = c.get("output") if "output" in c else c.get("result")
                    full = _as_text(raw)
                    out = full[:_OUTPUT_CAP]
                    # AI SDK tool results mark failures with an "error-text" /
                    # "error-json" output type or isError.
                    is_error = bool(c.get("isError")) or (isinstance(raw, Mapping) and str(raw.get("type", "")).startswith("error"))
                    result = short_result(full, error=is_error)
                    if n is not None:
                        e = calls[n]
                        target = targets.get(n, "")
                        changed = (target,) if (target and not is_error and e.tool.lower() in _EDIT_TOOLS) else ()
                        calls[n] = TrajectoryEntry(tool=e.tool, decision=e.decision, summary=e.summary, output=out, result=result,
                                                   files_changed=changed)
                    else:
                        call_ids.append(str(c.get("toolCallId") or ""))
                        calls.append(TrajectoryEntry(tool=str(c.get("toolName", "")), decision="", summary="", output=out, result=result))
    return MessagesContext(users, tuple(calls[-20:]), intent[:AGENT_INTENT_MAX], tuple(call_ids[-20:]),
                           frozenset(i for i in call_ids if i))


def messages_started_at(messages: Any) -> Any:
    """Earliest `info.time.created` (V1) or `time.created` (V2 session
    message), epoch milliseconds, of the messages the plugin sent, or ""
    when none carries one. The plugin sends only the last MAX_MESSAGES of a
    session, so this can be later than the real start; run_core also uses
    the ledger's first entry."""
    times = []
    for m in messages if isinstance(messages, list) else []:
        info = m.get("info") if isinstance(m, Mapping) and isinstance(m.get("info"), Mapping) else {}
        if not info and is_session_message(m):
            info = m                                               # V2: time.created on the message itself
        t = info.get("time") if isinstance(info.get("time"), Mapping) else {}
        created = t.get("created")
        if isinstance(created, (int, float)) and not isinstance(created, bool):
            times.append(created)
    return min(times) if times else ""


def message_shape(messages: Any) -> str:
    """"v1" when every message has the V1 shape (info + parts), "v2" when
    every message is a V2 session message (id + type), "aisdk" when every
    message has the AI SDK shape (role + content), "" otherwise (no
    messages, or a mix)."""
    if not isinstance(messages, list) or not messages:
        return ""
    if all(isinstance(m, Mapping) and isinstance(m.get("parts"), list) for m in messages):
        return "v1"
    if all(is_session_message(m) for m in messages):
        return "v2"
    if all(isinstance(m, Mapping) and "role" in m and "parts" not in m for m in messages):
        return "aisdk"
    return ""


def manifest_host(messages: Any, api: Any = None) -> str:
    """The capability manifest for this request: opencode-v2 when the plugin
    says the call came through the V2 entry point (api "v2") or the messages
    have a V2 shape, else opencode-v1 (the plugin's V1 entry point)."""
    return "opencode-v2" if api == "v2" or message_shape(messages) in ("v2", "aisdk") else "opencode-v1"


def _prompt_marks(prompts: Any) -> Dict[str, Tuple[float, str]]:
    """{message id: (epoch seconds, sha256 hex of the text)} from the V2
    plugin's `prompts`; an entry with a missing or bad field is left out."""
    from ..gitstate import to_epoch
    out: Dict[str, Tuple[float, str]] = {}
    for p in prompts if isinstance(prompts, list) else []:
        if not isinstance(p, Mapping):
            continue
        mid, sha, t = p.get("id"), p.get("sha"), p.get("t")
        if not (isinstance(mid, str) and mid and isinstance(sha, str) and len(sha) == 64):
            continue
        if not isinstance(t, (int, float)) or isinstance(t, bool):
            continue
        ts = to_epoch(t)
        if ts is not None:
            out[mid] = (ts, sha.lower())
    return out


def _v2_conversation(messages: List[Any], prompts: Any) -> Any:
    """V2: the history gives the order (the server's sequence) and the text;
    the plugin's session "prompt" hook gives the proof. A type "user" message
    is stamped with the time the hook saw it, and only when the hook saw its
    id and its text still has the hash the hook saw. Any other user message
    stays in place (it can mark the block's position) but has no time, so it
    is never counted as a reply (timestamps=True): a row written to the
    database, a text changed after it was typed, a prompt from before the
    plugin started. A steer typed before the block but delivered after it
    has a hook time before the block: not counted. Agent items: assistant
    text; call items: assistant tool items with their id (= the
    execute.before event id)."""
    from ..chatapproval import Conversation, Item
    from ..gitstate import to_epoch
    marks = _prompt_marks(prompts)
    items: List[Any] = []
    for m in messages:
        mid = str(m.get("id") or "")
        t = m.get("time") if isinstance(m.get("time"), Mapping) else {}
        created = to_epoch(t.get("created"))
        if m["type"] == "user":
            text = m.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            mark = marks.get(mid)
            ok = mark is not None and hashlib.sha256(text.encode("utf-8")).hexdigest() == mark[1]
            items.append(Item("user", text.strip(), mark[0] if ok else None, msg_id=mid))
        elif m["type"] == "assistant" and isinstance(m.get("content"), list):
            for c in m["content"]:
                if not isinstance(c, Mapping):
                    continue
                if c.get("type") == "text" and str(c.get("text", "")).strip():
                    items.append(Item("agent", str(c.get("text", "")).strip(), created, msg_id=mid))
                elif c.get("type") == "tool":
                    items.append(Item("call", str(c.get("name", "")), created, msg_id=mid, call_id=str(c.get("id") or "")))
    return Conversation(tuple(items), complete=False, timestamps=True, source="opencode v2 context + prompt hook")


def chat_conversation(messages: Any, prompts: Any = None) -> Any:
    """The messages as ordered items for approval by chat reply
    (chatapproval.Conversation).
    V1: user items follow parse_messages_context's rule (a user message's
    non-synthetic text parts), with info.id and info.time.created; agent
    items are assistant text parts; call items are tool parts with their
    callID.
    V2 session messages: only with the plugin's `prompts` (a list; absent for
    a child session, a subagent's, and when the prompt hook could not be
    registered), see _v2_conversation.
    Tool outputs are never items. None for the AI SDK shape (no ids, no
    times), for V2 without `prompts`, and for no messages. `complete` is
    False: the plugin sends only the last MAX_MESSAGES=30 messages (V2: only
    those after the latest compaction), so order comes from ids, not counts."""
    from ..chatapproval import Conversation, Item
    from ..gitstate import to_epoch
    shape = message_shape(messages)
    if shape == "v2":
        return _v2_conversation(messages, prompts) if isinstance(prompts, list) else None
    if shape != "v1":
        return None
    items: List[Any] = []
    for m in messages:
        info = m.get("info") if isinstance(m.get("info"), Mapping) else {}
        role = str(info.get("role", ""))
        t = info.get("time") if isinstance(info.get("time"), Mapping) else {}
        ts = to_epoch(t.get("created"))
        msg_id = str(info.get("id") or "")
        texts = []
        for p in m["parts"]:
            if not isinstance(p, Mapping):
                continue
            if p.get("type") == "text" and not p.get("synthetic"):
                if role == "assistant" and str(p.get("text", "")).strip():
                    items.append(Item("agent", str(p.get("text", "")).strip(), ts, msg_id=msg_id))
                texts.append(str(p.get("text", "")))
            elif p.get("type") == "tool":
                items.append(Item("call", str(p.get("tool", "")), ts, msg_id=msg_id, call_id=str(p.get("callID") or "")))
        said = "\n".join(x for x in texts if x.strip()).strip()
        if role == "user" and said:
            items.append(Item("user", said, ts, msg_id=msg_id))
    return Conversation(tuple(items), complete=False, timestamps=True, source="opencode messages")


def parse_messages(messages: Any) -> Tuple[List[str], Tuple[TrajectoryEntry, ...]]:
    """(user messages, trajectory with tool outputs) from either message shape."""
    ctx = parse_messages_context(messages)
    return ctx.users, ctx.trace


def envelope_from_request(req: Mapping[str, Any], grant: UserGrant, *, evaluated_at: str = "",
                          tool_outputs: Optional[Sequence[Mapping[str, Any]]] = None,
                          merge_stats: Optional[Dict[str, Any]] = None) -> Envelope:
    """`tool_outputs`: records serve wrote for `tool.execute.after` events of
    this session (V1 only; tooloutputs.load_for_pre), merged into the
    trajectory by call id (tooloutputs.merge_trace)."""
    native = str(req.get("tool", ""))
    tool = _TOOLS.get(native.lower(), native.lower() or "unknown")
    args = dict(req.get("args")) if isinstance(req.get("args"), Mapping) else {}
    if "path" not in args:
        for k in ("filePath", "file_path", "path"):
            if isinstance(args.get(k), str) and args[k]:
                args["path"] = args[k]
                break
    ctx = parse_messages_context(req.get("messages"))
    users, trace, call_ids = ctx.users, ctx.trace, ctx.call_ids
    if trace and tool == "bash" and trace[-1].summary.strip() == str(args.get("command", "")).strip() and not trace[-1].output:
        trace, call_ids = trace[:-1], call_ids[:-1]
    if tool_outputs:
        from ..tooloutputs import merge_trace
        trace, stats = merge_trace(trace, call_ids, ctx.known_ids, tool_outputs, current_id=str(req.get("callID") or ""),
                                   cap=_OUTPUT_CAP)
        if merge_stats is not None:
            merge_stats.update(stats)
    cwd = str(req.get("cwd") or "")
    return Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool=tool, arguments=args),
        grant=grant,
        environment=Environment(project_root=cwd, cwd=cwd, harness="opencode-plugin", session_id=str(req.get("sessionID", ""))),
        trajectory=Trajectory(recent=trace),
        evaluated_at=evaluated_at,
        user_message=users[-1] if users else "",
        user_messages=bound_user_messages(users),
        agent_intent=ctx.agent_intent,
    )


def user_messages(req: Mapping[str, Any]) -> List[str]:
    return parse_messages(req.get("messages"))[0]
