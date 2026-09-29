"""Adapter for hosts that use Claude Code's PreToolUse hook shape.

One adapter, five hosts (formats verified against each host's docs on
2026-09-22):

  host     input                                   output
  claude   tool_name/tool_input/transcript_path    hookSpecificOutput.permissionDecision
  droid    same (Factory: Execute/Edit/Create)     same
  vscode   same (run_in_terminal, create_file ...) same (VS Code also reads ~/.claude/settings.json)
  copilot  toolName/toolArgs (or the Claude form)  top-level permissionDecision
  devin    tool_name/tool_input/prompt_id          {"decision": "approve"|"block"} (no native ask)
           (and none of tool_use_id / transcript_path / permission_mode: Claude Code
           2.1.281 also sends prompt_id; see CLAUDE_ONLY_FIELDS)

The event is untrusted data: only documented fields are copied into the
envelope, and the grant never comes from the event or the transcript.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from ..envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, TrajectoryEntry,
                        UserGrant, bound_user_messages, short_result)
from ..harnesstools import HOST_NAMES

HOSTS = ("claude", "droid", "vscode", "copilot", "devin")

# host tool name (lowercased) -> semgate canonical tool
_TOOLS = {
    # shell
    "bash": "bash", "execute": "bash", "run_in_terminal": "bash", "exec": "bash", "powershell": "bash",
    "shell": "bash", "run_command": "bash", "terminal": "bash",
    # edits / writes
    "edit": "edit", "multiedit": "edit", "replace_string_in_file": "edit", "multi_replace_string_in_file": "edit",
    "insert_edit_into_file": "edit", "apply_patch": "edit", "notebookedit": "edit", "str_replace_based_edit_tool": "edit",
    "write": "write", "create": "write", "create_file": "write",
    # reads / search
    "read": "read", "view": "read", "read_file": "read", "ls": "ls", "list_dir": "ls",
    "glob": "glob", "file_search": "glob", "grep": "grep", "grep_search": "grep",
    # web
    "webfetch": "web_fetch", "fetch_webpage": "web_fetch", "fetch": "web_fetch", "websearch": "web_search",
    # harness tools: ask the user, to-do list, load a skill (harnesstools.py)
    **HOST_NAMES,
}
_PATH_KEYS = ("file_path", "filePath", "path", "notebook_path", "filename")
_OUTPUT_CAP = 6000
_HARNESS_TEXT = ("<command-", "<local-command", "<system-reminder", "<user-prompt-submit-hook", "Caveat:")


# Fields Claude Code sends and Devin CLI does not document. Claude Code
# 2.1.280 PreToolUse keys (hookconf probe, results/claude-code-2.1.280.json):
# cwd, effort, hook_event_name, permission_mode, prompt_id, session_id,
# tool_input, tool_name, tool_use_id, transcript_path (PostToolUse adds
# duration_ms, tool_response; UserPromptSubmit has transcript_path and
# permission_mode but no tool_use_id). Claude Code 2.1.281 also sends
# prompt_id (hookconf e2e 5d5714b answered it in Devin's format). Devin CLI
# documents only hook_event_name, tool_name, tool_input, session_id and a
# per-turn prompt_id (docs.devin.ai/cli/extensibility/hooks, read 2026-09-24).
# So prompt_id alone does not mean Devin.
CLAUDE_ONLY_FIELDS = ("tool_use_id", "transcript_path", "permission_mode")


def is_devin_shape(event: Mapping[str, Any]) -> bool:
    """True when the event has Devin CLI's documented shape: prompt_id and
    none of the fields only Claude Code sends."""
    return "prompt_id" in event and not any(k in event for k in CLAUDE_ONLY_FIELDS)


def detect_host(event: Mapping[str, Any]) -> str:
    if "toolName" in event or "toolArgs" in event:
        return "copilot"
    if is_devin_shape(event):
        return "devin"
    tool = str(event.get("tool_name", ""))
    if tool in ("run_in_terminal", "create_file", "replace_string_in_file", "read_file") or tool.startswith("copilot_"):
        return "vscode"
    if ".factory" in str(event.get("transcript_path", "")) or tool in ("Execute", "Create"):
        return "droid"
    return "claude"


def resolve_host(requested: str, event: Mapping[str, Any]) -> str:
    """The host to answer, from --host and the event. `auto`: detect_host.
    `claude`: Claude Code, except an event with Devin CLI's shape, because
    Devin CLI also runs the hooks in ~/.claude/settings.json and does not
    document Claude's output (hookSpecificOutput.permissionDecision): a
    Claude-format answer there could let a blocked call run. Devin's format
    turns an ask into a block, the safe direction if the shape check is
    wrong. Any other value is used as given."""
    if requested == "auto":
        return detect_host(event)
    if requested == "claude" and is_devin_shape(event):
        return "devin"
    return requested


def host_decision(host: str, decision: str, reason: str) -> Tuple[str, str]:
    """The decision the host actually gets, in semgate's allow/ask/deny, so
    the ledger's host_response records it. Devin CLI has no ask: an ask is
    sent as a block (a deny), never an approve."""
    if host == "devin" and decision == "ask":
        return "deny", ("semgate needs a human decision: " + reason)[:1000]
    return decision, reason


def _tool_and_args(event: Mapping[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    native = str(event.get("tool_name") or event.get("toolName") or "")
    raw = event.get("tool_input") if "tool_input" in event else event.get("toolArgs")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {"command": raw}
    args = dict(raw) if isinstance(raw, Mapping) else {}
    canonical = _TOOLS.get(native.lower(), native.lower() or "unknown")
    if native.lower().startswith("mcp__"):
        canonical = native          # keep MCP tool identity (server + tool)
    # canonical argument names the rules and router understand
    if canonical == "bash" and "command" not in args:
        for k in ("cmd", "commandLine", "CommandLine", "script"):
            if isinstance(args.get(k), str):
                args["command"] = args[k]
                break
    if "path" not in args:
        for k in _PATH_KEYS:
            if isinstance(args.get(k), str) and args[k]:
                args["path"] = args[k]
                break
    if canonical == "web_fetch" and "url" not in args and isinstance(args.get("urls"), list) and args["urls"]:
        args["url"] = str(args["urls"][0])
    return native, canonical, args


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, Mapping) and part.get("type") == "text":
                out.append(str(part.get("text", "")))
            elif isinstance(part, str):
                out.append(part)
        return "\n".join(out)
    return ""


class TranscriptContext(NamedTuple):
    users: List[str]                          # the user's own turns, oldest first
    trace: Tuple[TrajectoryEntry, ...]        # recent tool calls with output / result / files_changed
    agent_intent: str                         # latest assistant text after the latest user turn ("" if none)
    call_ids: Tuple[str, ...] = ()            # tool_use id of each trace entry (same order)
    known_ids: frozenset = frozenset()        # every tool_use id in the transcript (also older than the trace)


_EDIT_TOOLS = frozenset({"edit", "write"})
_EXIT_RE = re.compile(r"^\s*Exit code (-?\d+)\s*\n?")


def _result_of(canonical: str, part: Mapping[str, Any], text: str) -> str:
    """TrajectoryEntry.result from a tool_result block. Claude Code marks a
    failed call with is_error; a failed shell call's content starts with
    "Exit code N" (verified on local Claude Code transcripts 2026-09-23). A
    successful shell call carries no exit code, so it is reported as "ok"."""
    is_error = bool(part.get("is_error"))
    m = _EXIT_RE.match(text) if canonical == "bash" else None
    if m:
        return short_result(text[m.end():], exit_code=m.group(1))
    return short_result(text, error=is_error) if (text.strip() or is_error) else ""


def _is_user_turn(entry: Mapping[str, Any], text: str) -> bool:
    """The user's own text: not empty, not harness-injected text, not a
    compaction summary, not an interruption notice. (Tool results, isMeta
    and sidechain entries are left out before this check.)"""
    return bool(text and not text.startswith(_HARNESS_TEXT) and not entry.get("isCompactSummary")
                and not text.startswith("[Request interrupted"))


def chat_conversation(path: Optional[str]) -> Any:
    """The transcript as ordered items for approval by chat reply
    (chatapproval.Conversation), or None when it cannot be read. User items
    follow read_transcript_context's rule exactly (tool_result blocks, meta,
    sidechain, harness text, compaction summaries and interruption notices
    are never user items), each with the entry's `timestamp` and `uuid`.
    Agent items: assistant text blocks. Call items: assistant tool_use blocks
    with their id (the PreToolUse event's tool_use_id)."""
    from ..chatapproval import Conversation, Item
    from ..gitstate import to_epoch
    if not isinstance(path, str) or not path:
        return None
    items: List[Any] = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, Mapping) or entry.get("isMeta") or entry.get("isSidechain"):
                    continue
                msg = entry.get("message") if isinstance(entry.get("message"), Mapping) else entry
                role = str(entry.get("type") or msg.get("role") or "")
                content = msg.get("content")
                ts = to_epoch(entry.get("timestamp"))
                if role == "user":
                    texts = []
                    for part in (content if isinstance(content, list) else [content]):
                        if isinstance(part, Mapping) and part.get("type") == "text":
                            texts.append(str(part.get("text", "")))
                        elif isinstance(part, str):
                            texts.append(part)
                    text = "\n".join(t for t in texts if t).strip()
                    if _is_user_turn(entry, text):
                        items.append(Item("user", text, ts, msg_id=str(entry.get("uuid") or "")))
                elif role == "assistant" and isinstance(content, list):
                    for part in content:
                        if isinstance(part, Mapping) and part.get("type") == "text" and str(part.get("text", "")).strip():
                            items.append(Item("agent", str(part.get("text", "")).strip(), ts))
                        elif isinstance(part, Mapping) and part.get("type") == "tool_use":
                            items.append(Item("call", str(part.get("name", "")), ts, call_id=str(part.get("id") or "")))
    except OSError:
        return None
    return Conversation(tuple(items), complete=True, timestamps=True, source="claude transcript")


def read_transcript_context(path: Optional[str], current: str = "", current_id: str = "") -> TranscriptContext:
    """Users, trajectory and agent intent from a Claude-Code-style JSONL transcript.

    User messages are entries of type "user" whose content is the user's own
    text (not tool results, not harness-injected meta text, not a compaction
    summary, not an interruption notice). Tool calls come from assistant
    tool_use blocks; their results (tool_result blocks in the following user
    entry) become the trajectory outputs the injection scan reads, plus a short
    `result` and, for successful edit/write tools, `files_changed`. The agent
    intent is the latest assistant text block after the latest user turn
    (thinking blocks are not used). Never raises; empty on any problem.

    The pending call is left out: by its tool_use id (`current_id`, the
    event's tool_use_id) when given, else the last call when its command
    equals `current` and it has no output yet."""
    users: List[str] = []
    calls: List[TrajectoryEntry] = []
    call_ids: List[str] = []     # tool_use id per call
    canon: List[str] = []        # semgate canonical tool per call
    targets: List[str] = []      # path argument per call ("" when none)
    ids: Dict[str, int] = {}
    intent = ""
    empty = TranscriptContext([], (), "")
    if not isinstance(path, str) or not path:
        return empty
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(entry, Mapping) or entry.get("isMeta") or entry.get("isSidechain"):
                    continue
                msg = entry.get("message") if isinstance(entry.get("message"), Mapping) else entry
                role = str(entry.get("type") or msg.get("role") or "")
                content = msg.get("content")
                if role == "user":
                    parts = content if isinstance(content, list) else [content]
                    texts = []
                    for part in parts:
                        if isinstance(part, Mapping) and part.get("type") == "tool_result":
                            n = ids.get(str(part.get("tool_use_id", "")))
                            if n is not None:
                                full = _text_of(part.get("content"))
                                out = full[:_OUTPUT_CAP]
                                e = calls[n]
                                files: Tuple[str, ...] = ()
                                if canon[n] in _EDIT_TOOLS and not part.get("is_error"):
                                    tur = entry.get("toolUseResult") if isinstance(entry.get("toolUseResult"), Mapping) else {}
                                    fp = str(tur.get("filePath") or targets[n] or "")
                                    files = (fp,) if fp else ()
                                calls[n] = TrajectoryEntry(tool=e.tool, decision=e.decision, summary=e.summary, output=out,
                                                           result=_result_of(canon[n], part, full), files_changed=files)
                        elif isinstance(part, Mapping) and part.get("type") == "text":
                            texts.append(str(part.get("text", "")))
                        elif isinstance(part, str):
                            texts.append(part)
                    text = "\n".join(t for t in texts if t).strip()
                    if _is_user_turn(entry, text):
                        users.append(text)
                        intent = ""          # an intent stated before this turn is about an older request
                elif role == "assistant" and isinstance(content, list):
                    for part in content:
                        if isinstance(part, Mapping) and part.get("type") == "text" and str(part.get("text", "")).strip():
                            intent = str(part.get("text", "")).strip()
                        elif isinstance(part, Mapping) and part.get("type") == "tool_use":
                            inp = part.get("input") if isinstance(part.get("input"), Mapping) else {}
                            summary = str(inp.get("command") or inp.get("file_path") or inp.get("path") or inp.get("url")
                                          or inp.get("pattern") or "")[:200]
                            name = str(part.get("name", ""))
                            ids[str(part.get("id", ""))] = len(calls)
                            call_ids.append(str(part.get("id", "") or ""))
                            canon.append(_TOOLS.get(name.lower(), name.lower()))
                            # The path an edit/write targets; reported in files_changed only
                            # once its tool_result arrives without error.
                            targets.append(next((str(inp[k]) for k in _PATH_KEYS if isinstance(inp.get(k), str) and inp[k]), ""))
                            calls.append(TrajectoryEntry(tool=name, decision="", summary=summary))
    except OSError:
        return empty
    known = frozenset(i for i in call_ids if i)
    if current_id and current_id in known:
        keep = [n for n, i in enumerate(call_ids) if i != current_id]      # the pending call itself
        calls, call_ids = [calls[n] for n in keep], [call_ids[n] for n in keep]
    elif calls and current and calls[-1].summary.strip() == current.strip() and not calls[-1].output:
        calls, call_ids = calls[:-1], call_ids[:-1]   # the pending call itself
    return TranscriptContext(users, tuple(calls[-20:]), intent[:AGENT_INTENT_MAX], tuple(call_ids[-20:]), known)


def transcript_started_at(path: Optional[str]) -> str:
    """`timestamp` of the first transcript entry that has one (Claude Code
    writes an ISO-8601 UTC timestamp per line). "" on any problem."""
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            for n, line in enumerate(handle):
                if n > 50:
                    break
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, Mapping) and entry.get("timestamp"):
                    return str(entry["timestamp"])
    except OSError:
        return ""
    return ""


def read_transcript(path: Optional[str], current: str = "") -> Tuple[List[str], Tuple[TrajectoryEntry, ...]]:
    """(user messages, trajectory) from a Claude-Code-style JSONL transcript.
    See read_transcript_context. Never raises; ([], ()) on any problem."""
    ctx = read_transcript_context(path, current)
    return ctx.users, ctx.trace


def envelope_from_event(event: Mapping[str, Any], grant: UserGrant, *, host: str = "", evaluated_at: str = "",
                        tool_outputs: Optional[Sequence[Mapping[str, Any]]] = None,
                        merge_stats: Optional[Dict[str, Any]] = None) -> Envelope:
    """`tool_outputs`: records semgate's own PostToolUse hook wrote for this
    session (tooloutputs.load_for_pre), merged into the trajectory
    (tooloutputs.merge_trace). `merge_stats`, when given, receives the merge
    counts (evidence `tool_outputs`)."""
    host = host or detect_host(event)
    native, tool, args = _tool_and_args(event)
    cwd = str(event.get("cwd") or "")
    transcript = event.get("transcript_path") or event.get("transcriptPath")
    current_id = str(event.get("tool_use_id") or "")
    ctx = read_transcript_context(transcript, str(args.get("command", "")), current_id=current_id)
    users, trace = ctx.users, ctx.trace
    if tool_outputs:
        from ..tooloutputs import merge_trace
        trace, stats = merge_trace(trace, ctx.call_ids, ctx.known_ids, tool_outputs, current_id=current_id,
                                   agent_id=str(event.get("agent_id") or ""), cap=_OUTPUT_CAP)
        if merge_stats is not None:
            merge_stats.update(stats)
    user_message = users[-1] if users else ""
    return Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool=tool, arguments=args),
        grant=grant,
        environment=Environment(project_root=cwd, cwd=cwd, harness=f"{host}-hook",
                                session_id=str(event.get("session_id") or event.get("sessionId") or "")),
        trajectory=Trajectory(recent=trace),
        evaluated_at=evaluated_at,
        user_message=user_message,
        user_messages=bound_user_messages(users),
        agent_intent=ctx.agent_intent,
    )


def user_messages(event: Mapping[str, Any]) -> List[str]:
    return read_transcript(event.get("transcript_path") or event.get("transcriptPath"))[0]


def render_output(host: str, decision: str, reason: str) -> Dict[str, Any]:
    """decision in allow | ask | deny (already mapped from the core's vocabulary)."""
    reason = reason[:1000]
    if host == "copilot":
        out: Dict[str, Any] = {"permissionDecision": decision}
        if decision != "allow":
            out["permissionDecisionReason"] = reason
        return out
    if host == "devin":
        # Devin's PreToolUse has no native ask: an ask must not run unattended.
        return {"decision": "approve"} if decision == "allow" else {"decision": "block", "reason": reason if decision == "deny" else "semgate needs a human decision: " + reason}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}}


def rendered_reason(out: Mapping[str, Any]) -> str:
    """The reason text inside a render_output object ("" when none)."""
    inner = out.get("hookSpecificOutput") if isinstance(out.get("hookSpecificOutput"), Mapping) else {}
    return str(out.get("permissionDecisionReason") or out.get("reason") or inner.get("permissionDecisionReason") or "")


def render_post_context(host: str, text: str) -> Dict[str, Any]:
    """PostToolUse output that adds `text` to the model's context (docs read
    2026-09-23): Copilot CLI takes top-level additionalContext; Claude Code,
    Droid, VS Code and Devin take hookSpecificOutput.additionalContext.
    Callers send it only when the host's manifest says C33 = yes."""
    text = text[:4000]
    if host == "copilot":
        return {"additionalContext": text}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}}
