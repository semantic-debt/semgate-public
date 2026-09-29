"""Google Antigravity PreToolUse adapter.

Native hook input is untrusted event data.  The adapter copies only documented
fields into semgate's canonical envelope; it never reads a grant from the
agent's tool arguments or transcript.
"""
from __future__ import annotations
import json
import re
import urllib.parse
from typing import Any, List, Mapping, NamedTuple, Optional, Tuple
from ..envelope import (AGENT_INTENT_MAX, Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, TrajectoryEntry,
                        UserGrant, bound_user_messages, short_result)

_USER_REQUEST_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.S)
# Transcript step types that carry a tool's result in `content` (observed in
# agy 1.2.x transcripts). PLANNER_RESPONSE / USER_INPUT / SYSTEM_MESSAGE are not
# tool output and are never attached.
_OUTPUT_STEP_TYPES = frozenset({
    "VIEW_FILE", "RUN_COMMAND", "COMMAND_STATUS", "READ_URL_CONTENT", "SEARCH_WEB",
    "GREP_SEARCH", "LIST_DIRECTORY", "FIND_BY_NAME", "CODE_ACTION", "GENERIC",
})
_OUTPUT_CAP = 6000  # chars kept per tool output


def user_requests(path: Optional[str]) -> List[str]:
    """Every explicit user message of the session, oldest first, from agy's
    transcript. Only USER_INPUT steps whose source is the user count; a step the
    model or system wrote is never returned. [] on any problem."""
    out: List[str] = []
    if not isinstance(path, str) or not path:
        return out
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
                if not isinstance(entry, Mapping) or entry.get("type") != "USER_INPUT":
                    continue
                if str(entry.get("source", "USER_EXPLICIT")).upper() != "USER_EXPLICIT":
                    continue
                content = str(entry.get("content", ""))
                match = _USER_REQUEST_RE.search(content)
                text = (match.group(1) if match else content).strip()
                if text:
                    out.append(text)
    except OSError:
        return []
    return out


def transcript_started_at(path: Optional[str]) -> str:
    """`created_at` of the first transcript step that has one (agy 1.2.8
    writes ISO-8601 UTC, e.g. "2026-09-21T01:03:37Z"; seen in a local
    transcript_full.jsonl 2026-09-23). "" on any problem."""
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
                if isinstance(entry, Mapping) and entry.get("created_at"):
                    return str(entry["created_at"])
    except OSError:
        return ""
    return ""


def chat_conversation(path: Optional[str]) -> Any:
    """The transcript as ordered items for approval by chat reply
    (chatapproval.Conversation), or None when there is no readable
    transcript. User items: USER_INPUT steps whose source is USER_EXPLICIT
    (the same rule as user_requests), stamped with `created_at` (1 s
    resolution). Agent items: PLANNER_RESPONSE `content`. Call items: each
    tool call (agy's PreToolUse stepIdx is not matched to a step: not
    verified). Tool-result steps and SYSTEM steps are not items."""
    from ..chatapproval import Conversation, Item
    from ..gitstate import to_epoch
    if not isinstance(path, str) or not path:
        return None
    items: List[Item] = []
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
                if not isinstance(entry, Mapping):
                    continue
                etype = entry.get("type")
                ts = to_epoch(entry.get("created_at"))
                if etype == "USER_INPUT":
                    if str(entry.get("source", "USER_EXPLICIT")).upper() != "USER_EXPLICIT":
                        continue
                    content = str(entry.get("content", ""))
                    match = _USER_REQUEST_RE.search(content)
                    text = (match.group(1) if match else content).strip()
                    if text:
                        items.append(Item("user", text, ts, msg_id=f"step:{entry.get('step_index', '')}"))
                elif etype == "PLANNER_RESPONSE":
                    text = str(entry.get("content") or "").strip()
                    if text:
                        items.append(Item("agent", text, ts))
                    for call in entry.get("tool_calls") or []:
                        if isinstance(call, Mapping):
                            items.append(Item("call", str(call.get("name", "")), ts))
    except OSError:
        return None
    return Conversation(tuple(items), complete=True, timestamps=True, source="agy transcript")


def first_user_request(path: Optional[str]) -> str:
    """The user's first explicit message of the session ("" if none)."""
    msgs = user_requests(path)
    return msgs[0] if msgs else ""


_EDIT_TOOLS = frozenset({"write_to_file", "replace_file_content", "multi_replace_file_content"})
_STAMP_RE = re.compile(r"^(Created|Completed) At:")
_EXIT_FAIL_RE = re.compile(r"^The command failed with exit code:\s*(-?\d+)")
_CREATED_RE = re.compile(r"^Created file (\S+)")
_CHANGED_RE = re.compile(r"^The following changes were made by the (\S+)(?: tool)? to:\s*(.+)$")


def _unquote(value: Any) -> str:
    """agy tool args are often JSON-encoded strings ('"c:\\\\x\\\\a.py"')."""
    text = str(value or "").strip()
    if text.startswith('"'):
        try:
            decoded = json.loads(text)
            return decoded if isinstance(decoded, str) else text
        except ValueError:
            return text.strip('"')
    return text


def _step_result(step_type: str, content: str) -> Tuple[str, Tuple[str, ...]]:
    """(result, files_changed) of an agy tool-result step. Shapes observed in
    agy 1.2.x transcripts (2026-09-23): RUN_COMMAND "The command completed
    successfully." / "The command failed with exit code: N" then "Output:";
    CODE_ACTION "Created file file:///..." / "The following changes were made
    by the <tool> tool to: <path>" ("by the USER" is the user's own edit and is
    not reported as changed by the agent)."""
    lines = [ln.strip() for ln in str(content or "").splitlines()]
    lines = [ln for ln in lines if ln and not _STAMP_RE.match(ln)]
    if not lines:
        return "", ()
    head, rest = lines[0], [ln for ln in lines[1:] if ln != "Output:"]
    if step_type == "RUN_COMMAND":
        if head.startswith("The command completed successfully"):
            return short_result("\n".join(rest), exit_code=0), ()
        m = _EXIT_FAIL_RE.match(head)
        if m:
            return short_result("\n".join(rest), exit_code=m.group(1)), ()
        if head.startswith("Encountered error"):
            return short_result("\n".join(lines), error=True), ()
    files: Tuple[str, ...] = ()
    if step_type == "CODE_ACTION":
        created, changed = _CREATED_RE.match(head), _CHANGED_RE.match(head)
        path = created.group(1) if created else (changed.group(2).strip() if changed and changed.group(1) != "USER" else "")
        if path.startswith("file://"):
            path = urllib.parse.unquote(path[len("file://"):])
            if re.match(r"^/[A-Za-z]:", path):
                path = path[1:]           # file:///C:/x -> C:/x
        files = (path,) if path else ()
    return short_result("\n".join(lines)), files


class TranscriptContext(NamedTuple):
    user_message: str                      # latest USER_INPUT (any source; as before)
    trace: Tuple[TrajectoryEntry, ...]     # recent calls with output / result / files_changed
    user_messages: Tuple[str, ...]         # every USER_EXPLICIT turn, oldest first (bounded)
    agent_intent: str                      # latest PLANNER_RESPONSE text after the latest user turn


def _read_transcript(path: str, current_command: str) -> Tuple[str, Tuple[TrajectoryEntry, ...]]:
    """Best-effort read of agy's transcript.jsonl: the latest user request (the
    goal) and the recent tool calls (the trajectory), excluding the pending call.
    Untrusted data, never a grant. Never raises; returns ("", ()) on any problem."""
    ctx = read_transcript_context(path, current_command)
    return ctx.user_message, ctx.trace


_FILE_PATH_RE = re.compile(r"^File Path:\s*`?(file://[^`\s]+|[^`\n]+?)`?\s*$", re.M)


def _path_key(value: Any) -> str:
    """A file path or file:// URL in one comparable form: unquoted, no
    file:// prefix, forward slashes, no leading slash before a drive letter,
    lowercase (agy runs on Windows too). "" when empty."""
    text = _unquote(value).strip()
    if text.lower().startswith("file://"):
        text = urllib.parse.unquote(text[len("file://"):])
    text = text.replace("\\", "/")
    if re.match(r"^/[A-Za-z]:", text):
        text = text[1:]
    return text.rstrip("/").lower()


def _is_edit_notice(content: str) -> bool:
    """True when the step's first line (after the Created/Completed At
    stamps) is agy's edit notice: "Created file <path>" or "The following
    changes were made by the <tool or USER> to: <path>"."""
    for line in str(content or "").splitlines():
        line = line.strip()
        if not line or _STAMP_RE.match(line):
            continue
        return bool(_CREATED_RE.match(line) or _CHANGED_RE.match(line))
    return False


def _result_path(content: str, files: Tuple[str, ...]) -> str:
    """The file a tool-result step names about itself: view_file's "File
    Path: `file:///...`" line, or the file an edit result reports. "" when
    the step names none."""
    m = _FILE_PATH_RE.search(content[:2000])
    if m:
        return _path_key(m.group(1))
    return _path_key(files[0]) if files else ""


def _owner(batch: List[int], answered: set, keys: List[str], content: str, files: Tuple[str, ...]) -> Optional[int]:
    """Index of the call a tool-result step belongs to. agy 1.2.x result steps
    carry no call id (checked on 73 local transcripts 2026-09-24: steps have
    only type/source/status/created_at/step_index/content). The step is paired
    within the calls of the latest PLANNER_RESPONSE that has tool calls
    (`batch`), never with an older call: first by the file the result names
    (a view_file or edit result), else the first call of the batch that has
    no result yet (results follow their calls in call order: both multi-call
    responses in those transcripts). None when every call of the batch has
    its result."""
    open_calls = [i for i in batch if i not in answered]
    if not open_calls:
        return None
    named = _result_path(content, files)
    if named:
        for i in open_calls:
            if keys[i] and keys[i] == named:
                return i
    return open_calls[0]


def read_transcript_context(path: str, current_command: str) -> TranscriptContext:
    """See _read_transcript; also every explicit user turn (the same rule as
    user_requests), a short `result` and `files_changed` per call, and the
    agent's latest stated intent (PLANNER_RESPONSE `content`, not `thinking`).

    Tool results are paired with calls by _owner. Before 2026-09-24 each
    result went to the most recent call without output, so two parallel
    view_file calls (AGENTS.md, SKILL.md) got each other's text: the entry
    labeled AGENTS.md held SKILL.md, and pins / evidence labels read the
    wrong file."""
    user_message = ""
    recent: List[TrajectoryEntry] = []
    edit_target: List[str] = []    # TargetFile arg per call ("" when none)
    path_keys: List[str] = []      # _path_key of the file a call reads or edits ("" when none)
    batch: List[int] = []          # indexes of the latest PLANNER_RESPONSE's calls
    answered: set = set()          # indexes of calls that have their result
    users: List[str] = []
    intent = ""
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
                if not isinstance(entry, Mapping):
                    continue
                etype = entry.get("type")
                if etype == "USER_INPUT":
                    content = str(entry.get("content", ""))
                    match = _USER_REQUEST_RE.search(content)
                    user_message = (match.group(1) if match else content).strip()
                    if str(entry.get("source", "USER_EXPLICIT")).upper() == "USER_EXPLICIT" and user_message:
                        users.append(user_message)
                    intent = ""      # an intent stated before this turn is about an older request
                elif etype == "PLANNER_RESPONSE":
                    text = str(entry.get("content") or "").strip()
                    if text:
                        intent = text
                    calls = [c for c in (entry.get("tool_calls") or []) if isinstance(c, Mapping)]
                    if calls:
                        batch = []
                    for call in calls:
                        cargs = call.get("args") if isinstance(call.get("args"), Mapping) else {}
                        summary = str(cargs.get("CommandLine") or cargs.get("command")
                                      or cargs.get("FilePath") or cargs.get("AbsolutePath")  # agy 1.2.8 view_file uses AbsolutePath
                                      or cargs.get("Url") or "")[:200]
                        batch.append(len(recent))
                        recent.append(TrajectoryEntry(tool=str(call.get("name", "")), decision="", summary=summary))
                        target = _unquote(cargs.get("TargetFile")) if str(call.get("name", "")) in _EDIT_TOOLS else ""
                        edit_target.append(target)
                        path_keys.append(_path_key(target or cargs.get("AbsolutePath") or cargs.get("FilePath") or ""))
                elif entry.get("source") == "MODEL" and etype in _OUTPUT_STEP_TYPES and recent:
                    # A tool-result step (VIEW_FILE, RUN_COMMAND, READ_URL_CONTENT,
                    # ...) follows its call. Its content is attached to the call
                    # _owner picks: this is the untrusted text the injection scan
                    # reads. Truncated; never parsed as a grant.
                    content = str(entry.get("content", ""))
                    result, files = _step_result(str(etype), content)
                    i = _owner(batch, answered, path_keys, content, files)
                    if i is None:
                        # No open call in the latest batch (not seen in the 73 local
                        # agy 1.2.x transcripts). An edit notice ("Created file ...",
                        # "The following changes were made by the USER to: ...")
                        # names only a path and is skipped, as before. Any other text
                        # is kept for the injection scan as its own entry rather than
                        # given to an unrelated call.
                        if _is_edit_notice(content):
                            continue
                        recent.append(TrajectoryEntry(tool=str(etype).lower(), decision="", summary="",
                                                      output=content[:_OUTPUT_CAP], result=result, files_changed=files))
                        edit_target.append("")
                        path_keys.append("")
                        answered.add(len(recent) - 1)
                        continue
                    answered.add(i)
                    if files and edit_target[i]:
                        files = (edit_target[i],)     # the call's own TargetFile, when it has one
                    recent[i] = TrajectoryEntry(tool=recent[i].tool, decision=recent[i].decision,
                                                summary=recent[i].summary, output=content[:_OUTPUT_CAP],
                                                result=result, files_changed=files)
    except OSError:
        return TranscriptContext("", (), (), "")
    if recent and current_command and recent[-1].summary.strip().strip('"') == current_command.strip().strip('"'):
        recent = recent[:-1]  # the pending call is already in the transcript; don't echo it as history
    return TranscriptContext(user_message, tuple(recent[-20:]), bound_user_messages(users), intent[:AGENT_INTENT_MAX])

_TOOL_ALIASES = {"view_file": "read", "read_file": "read", "list_directory": "ls", "grep_search": "grep", "run_command": "bash"}

_ARG_ALIASES = {
    "CommandLine": "command", "commandLine": "command", "command": "command",
    "Cwd": "cwd", "cwd": "cwd",
    "FilePath": "path", "filePath": "path", "path": "path",
    "AbsolutePath": "path", "absolutePath": "path",
    "DirectoryPath": "directory", "directoryPath": "directory", "directory": "directory",
    "Url": "url", "URL": "url", "url": "url",
}

def grant_from_config(raw: Mapping[str, Any]) -> UserGrant:
    return UserGrant.from_dict(raw)

def envelope_from_pre_tool_use(event: Mapping[str, Any], grant: UserGrant, *, evaluated_at: str = "") -> Envelope:
    call = event.get("toolCall") if isinstance(event.get("toolCall"), Mapping) else {}
    native_tool = str(call.get("name", ""))
    tool = _TOOL_ALIASES.get(native_tool, native_tool)
    native_args = call.get("args") if isinstance(call.get("args"), Mapping) else {}
    args = dict(native_args)
    for native, canonical in _ARG_ALIASES.items():
        value = native_args.get(native)
        if value not in (None, "") and canonical not in args:
            args[canonical] = value
    workspace = event.get("workspacePaths")
    workspace_paths = [str(p) for p in workspace] if isinstance(workspace, list) else []
    root = workspace_paths[0] if workspace_paths else ""
    # Trajectory + user goal. Preferred source is agy's transcriptPath; fall back
    # to an inline recentToolCalls list if a host provides one. The user's latest
    # message comes only from the host's own transcript, never from tool args.
    recent: list = []
    raw_recent = event.get("recentToolCalls")
    if isinstance(raw_recent, list):
        for item in raw_recent[-20:]:
            if isinstance(item, Mapping):
                recent.append(TrajectoryEntry(
                    tool=str(item.get("name", item.get("tool", ""))),
                    decision=str(item.get("decision", "")),
                    summary=str(item.get("summary", ""))[:500],
                ))
    user_message = str(event.get("userMessage", "") or "")
    transcript_path = event.get("transcriptPath")
    user_turns: Tuple[str, ...] = ()
    agent_intent = ""
    if isinstance(transcript_path, str) and transcript_path:
        ctx = read_transcript_context(transcript_path, str(args.get("command", "")))
        goal, trace = ctx.user_message, ctx.trace
        if goal and not user_message:
            user_message = goal
        if trace and not recent:
            recent = list(trace)
        user_turns, agent_intent = ctx.user_messages, ctx.agent_intent
        if user_turns and user_message and user_turns[-1] != user_message:
            # The event's own userMessage (or a non-explicit latest input) is the
            # latest turn; keep user_messages[-1] == user_message.
            user_turns = bound_user_messages(list(user_turns) + [user_message])
    return Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool=tool, arguments=args),
        grant=grant,
        environment=Environment(
            project_root=root,
            cwd=str(args.get("cwd", root)),
            harness="google-antigravity",
            harness_version=str(event.get("harnessVersion", "")),
            session_id=str(event.get("conversationId", "")),
        ),
        trajectory=Trajectory(recent=tuple(recent)),
        evaluated_at=evaluated_at,
        user_message=user_message,
        user_messages=user_turns,
        agent_intent=agent_intent,
    )
