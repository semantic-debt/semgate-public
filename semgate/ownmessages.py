"""Messages semgate itself sent to the host, taken out of tool outputs before
any scan reads them.

Why. A host shows the reason of a blocked call to the agent as that call's
result. agy 1.2.x stores it as the step content of the blocked call:

    Created At: 2026-09-25T00:43:40-04:00
    Completed At: 2026-09-25T00:43:40-04:00
    Encountered error in step execution: tool call denied by pre-tool hook: <reason>

The adapters read that content as the call's output, and the injection scan
(injection.detect / render_context / render_pinned) reads every output as
untrusted text. semgate's pin question quotes the instruction line it asks
about ("... AGENTS.md, line 5: "Before committing, you must run npm run
e2e" ..."), so the scan found the marker "you must run" in semgate's own
message. Live agy session 2026-09-25 04:43-04:47 UTC: the user said yes, the
line was pinned (p=0.86), and the same `npm run e2e` was blocked again as
untrusted_instruction "in output of run_command (npm run e2e)". Each new
block quoted more words (paths, `semgate`, `AGENTS.md`), so later reads of
package.json and AGENTS.md and `semgate --help` were blocked too.

What. Every non-allow answer semgate gives the host is recorded here with the
action it answered. Before the pipeline judges the next call, each
trajectory entry that is the same action (its summary equals one of that
action's argument values: the command, path or URL) gets every exact copy of
those messages replaced with PLACEHOLDER. Only then do the gates, the
injection scan, pins, chat approval and the judge see the trajectory.

Security rules:
  - Only text semgate recorded as sent in THIS session is removed. Text that
    only looks like a semgate message ("semgate: ..." written into a README)
    is never removed: there is no prefix or pattern rule.
  - Only in the output of the call the message answered (same command, path
    or URL). A copy of a sent message inside another output (a README that
    repeats it word for word) stays and is scanned.
  - A store problem (lock timeout, unreadable file, write failure) removes
    nothing: the scan reads more text, never less.

Exact forms matched: the text as sent, and its JSON-escaped forms (for a
host that keeps a JSON string as text). A host that shortens the message is
handled by `_partial`: the longest start of a sent message, at least
MIN_PARTIAL (200) characters, that begins right after a known host wrapper
(HOST_WRAPPERS) or at the start of the output (after agy's time stamps), and
runs to the end of the output. A shorter piece is left in place: 200
characters of semgate's own wording are not something another text repeats
by chance, and a few words are.

Store: `<dir>/<session key>.jsonl`, dir = semgate.json `own_messages.dir`,
default `own_messages/` next to `ledger_file`; off with
`"own_messages": false`. `<session key>` is sha256(session id)[:32].

  record {"record_type": "own_message", "session_id", "epoch", "ts",
          "keys": [normalized argument values of the action], "text"}

Every write and read holds the file's cross-process lock (filelock). Retention
on every write: records older than MAX_AGE_S (24 h) are dropped and at most
KEEP (50) are kept per session; a text already stored for the same keys is
not written again.
"""
from __future__ import annotations

import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import filelock
from .envelope import TrajectoryEntry, utcnow_iso

PLACEHOLDER = "[this gate's own message: not scanned]"
MIN_PARTIAL = 200
KEEP = 50
MAX_AGE_S = 24 * 3600
MAX_TEXT = 4000            # characters of a message kept (semgate caps reasons at 1000 plus host prefixes)
_KEY_MAX = 2000            # characters of an argument value used as a key

# Argument names whose values name the action in a trajectory entry's
# summary (every adapter builds the summary from one of them: agy
# CommandLine / AbsolutePath / FilePath / Url; Claude command / file_path /
# path / url / pattern; Codex, Pi command / path / url; OpenCode _summary).
ARG_KEYS = ("command", "cmd", "CommandLine", "commandLine", "path", "file_path", "filePath", "AbsolutePath",
            "absolutePath", "FilePath", "TargetFile", "url", "Url", "URL", "pattern", "filepath", "notebook_path")
# Summary lengths the adapters cut to (agy, Claude, Codex, Pi: 200; agy's
# inline recentToolCalls: 500). A cut summary is compared with the value cut
# the same way.
_SUMMARY_CUTS = (200, 500)

# Text a host (or semgate's own plugin) writes right before a blocked call's
# reason R in the result the agent reads. Sources (2026-09-25):
#   agy 1.2.x          "Encountered error in step execution: tool call denied by pre-tool hook: R"
#                      (transcript step content and `error`; live transcripts)
#   Claude Code 2.1.28x "PreToolUse:Bash hook error: R" (tool_result.content, is_error; a live
#                      transcript and hookconf e2e 2026-09-24), plain R in hookconf B3
#   Codex 0.153.1      "Command blocked by PreToolUse hook: R. Command: <command>" (hookconf)
#   OpenCode V1 plugin "semgate blocked this: R" / "semgate needs a human decision before this
#                      runs: R. Tell the user ..." (assets/opencode_semgate.js enforce); V1 keeps
#                      it in state.error, V2 in state.error.message: both only reach `result`
#   Pi 0.86.0          plain R (toolResult content, isError; hookconf)
# Only used to anchor a cut copy (_partial); an exact copy of R is removed
# wherever it is in the output of the same action.
HOST_WRAPPERS = re.compile(
    r"tool call denied by pre-tool hook: "
    r"|PreToolUse:[A-Za-z0-9_.:-]{1,80} hook error: "
    r"|Command blocked by PreToolUse hook: "
    r"|semgate blocked this: "
    r"|semgate needs a human decision before this runs: ")
_STAMP_RE = re.compile(r"\A(?:[ \t]*(?:Created|Completed) At:[^\n]*\n)*[ \t]*")


# ---------------------------------------------------------------- config


def enabled(config: Mapping[str, Any]) -> bool:
    value = config.get("own_messages") if isinstance(config, Mapping) else None
    if value is False:
        return False
    if isinstance(value, Mapping) and value.get("enabled") is False:
        return False
    return True


def store_dir(config: Mapping[str, Any]) -> Path:
    value = config.get("own_messages") if isinstance(config.get("own_messages"), Mapping) else {}
    if value.get("dir"):
        return Path(os.path.expanduser(str(value["dir"])))
    from .storepaths import state_path
    return Path(state_path(config, "own_messages"))


# ---------------------------------------------------------------- keys


def norm_key(value: Any) -> str:
    """An argument value or a summary in one comparable form: a JSON-quoted
    string decoded (agy writes some arguments as '"c:\\\\x"'), whitespace
    collapsed, backslashes as slashes, case folded, no trailing slash."""
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            decoded = json.loads(text)
            text = decoded.strip() if isinstance(decoded, str) else text
        except ValueError:
            text = text.strip('"')
    return " ".join(text.split()).replace("\\", "/").casefold().rstrip("/")


def action_keys(arguments: Mapping[str, Any]) -> List[str]:
    """Keys of an action: every string value under ARG_KEYS, whole and cut
    to each summary length."""
    keys: List[str] = []
    for name in ARG_KEYS:
        value = arguments.get(name) if isinstance(arguments, Mapping) else None
        if not isinstance(value, str) or not value.strip():
            continue
        value = value[:_KEY_MAX]
        for cut in (None,) + _SUMMARY_CUTS:
            key = norm_key(value if cut is None else value[:cut])
            if key and key not in keys:
                keys.append(key)
    return keys


# ---------------------------------------------------------------- store


class OwnMessageStore:
    def __init__(self, base_dir: Any, keep: int = KEEP, max_age_s: float = MAX_AGE_S) -> None:
        self.base = Path(os.path.expanduser(str(base_dir)))
        self.keep = max(1, int(keep))
        self.max_age_s = float(max_age_s)

    def path(self, session_id: str) -> Path:
        from .agentfiles import session_key
        return self.base / f"{session_key(session_id)}.jsonl"

    def _fresh(self, record: Mapping[str, Any], now: float) -> bool:
        try:
            return now - float(record.get("epoch", 0)) <= self.max_age_s
        except (TypeError, ValueError):
            return False

    def add(self, session_id: str, keys: Sequence[str], text: str, timeout: float = 0.0,
            now: Optional[float] = None) -> bool:
        """Record `text` as sent for the action with `keys`. False when it was
        already stored. Raises filelock.LockTimeout and OSError."""
        if not session_id or not keys or not text:
            return False
        path = self.path(session_id)
        t = time.time() if now is None else float(now)
        record = {"record_type": "own_message", "session_id": session_id, "epoch": t,
                  "ts": utcnow_iso() if now is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)),
                  "keys": list(keys), "text": text[:MAX_TEXT]}
        with filelock.exclusive(path, timeout):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                raw = b""
            parsed = filelock.parse_jsonl_bytes(raw)
            kept = [r for r in parsed.records if r.get("record_type") == "own_message" and self._fresh(r, t)]
            if any(r.get("text") == record["text"] and set(r.get("keys") or ()) >= set(keys) for r in kept):
                return False
            kept = kept[-(self.keep - 1):] if self.keep > 1 else []
            line = filelock.encode_record(record)
            if len(kept) == len(parsed.records) and not parsed.malformed and not parsed.partial_tail:
                filelock.append_bytes(path, line)
            else:
                data = b"".join(filelock.encode_record(r) for r in kept) + line
                try:
                    _replace_bytes(path, data)
                except OSError as exc:      # e.g. Windows: a virus scanner holds the file; prune next time
                    print(f"semgate: own message store not pruned ({type(exc).__name__}: {exc}); appending",
                          file=sys.stderr)
                    filelock.append_bytes(path, line, repair=True)
        return True

    def read(self, session_id: str, timeout: float = 0.0, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """This session's fresh records, oldest first. Missing file -> [].
        Raises filelock.LockTimeout and OSError."""
        if not session_id:
            return []
        path = self.path(session_id)
        if not path.exists():
            return []
        result = filelock.read_jsonl_locked(path, timeout=timeout)
        t = time.time() if now is None else now
        return [r for r in result.records if r.get("record_type") == "own_message"
                and str(r.get("session_id", "")) == session_id and self._fresh(r, t)
                and isinstance(r.get("text"), str) and isinstance(r.get("keys"), list)]


def _replace_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _incident(config: Mapping[str, Any], kind: str, detail: Dict[str, Any]) -> None:
    try:
        from .ledger import Ledger
        from .storepaths import ledger_file
        Ledger(ledger_file(config)).record_incident(kind, detail)
    except Exception as exc:
        print(f"semgate: could not record {kind}: {type(exc).__name__}: {exc}", file=sys.stderr)


def _session_ok(session_id: Any) -> bool:
    from . import hookinput
    return bool(session_id) and not hookinput.session_id_problem(session_id)


def remember(config: Mapping[str, Any], session_id: Any, arguments: Mapping[str, Any], decision: Any,
             text: Any) -> bool:
    """Hook side, right when an answer goes to the host: record a non-allow
    answer's text for this action. Never raises and never changes the
    answer; a failure only means the text is still scanned next time."""
    try:
        if str(decision) == "allow" or not isinstance(text, str) or not text.strip():
            return False
        if not isinstance(config, Mapping) or not enabled(config) or not _session_ok(session_id):
            return False
        keys = action_keys(arguments or {})
        if not keys:
            return False
        return OwnMessageStore(store_dir(config)).add(str(session_id), keys, text)
    except filelock.LockTimeout as exc:
        _incident(config, "own_message_not_recorded", {"reason": "lock_timeout", "message": str(exc)[:300]})
        print(f"semgate: own message not recorded: {exc}", file=sys.stderr)
        return False
    except Exception as exc:
        try:
            _incident(config, "own_message_not_recorded", {"reason": type(exc).__name__, "message": str(exc)[:300]})
        except Exception:
            pass
        print(f"semgate: own message not recorded: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False


def load(config: Mapping[str, Any], session_id: Any) -> Tuple[List[Dict[str, Any]], str]:
    """PreToolUse side: (records, problem). A problem ("" when none) is
    recorded as an incident `own_messages_unreadable`; the caller then
    removes nothing (stricter, never softer)."""
    try:
        if not isinstance(config, Mapping) or not enabled(config) or not _session_ok(session_id):
            return [], ""
        return OwnMessageStore(store_dir(config)).read(str(session_id)), ""
    except (filelock.LockTimeout, OSError, ValueError) as exc:
        problem = f"own message store ({type(exc).__name__}: {exc})"
        _incident(config, "own_messages_unreadable", {"message": str(exc)[:300], "reason": type(exc).__name__})
        return [], problem


# ---------------------------------------------------------------- removal


def forms(text: str) -> List[str]:
    """The ways a host can hold `text` as text: as sent, and JSON-escaped
    (non-ASCII kept, and \\uXXXX), longest first, no duplicates."""
    out = [text]
    for ascii_only in (False, True):
        escaped = json.dumps(text, ensure_ascii=ascii_only)[1:-1]
        if escaped not in out:
            out.append(escaped)
    return sorted(out, key=len, reverse=True)


def _partial(output: str, text: str) -> Optional[Tuple[int, int]]:
    """(start, end) of a cut copy of `text` in `output`: it starts right after
    a HOST_WRAPPERS entry or at the start of the output (after agy's time
    stamps), is at least MIN_PARTIAL characters of the start of `text`, and
    only whitespace or "..." follows it. None otherwise."""
    if len(text) <= MIN_PARTIAL:
        return None
    head = text[:MIN_PARTIAL]
    starts = []
    m = _STAMP_RE.match(output)
    starts.append(m.end() if m else 0)
    starts.extend(w.end() for w in HOST_WRAPPERS.finditer(output))
    for start in starts:
        if not output.startswith(head, start):
            continue
        k = MIN_PARTIAL
        limit = min(len(text), len(output) - start)
        while k < limit and output[start + k] == text[k]:
            k += 1
        if output[start + k:].strip() in ("", "...", "\u2026"):
            return start, start + k
    return None


def _flat(text: str) -> str:
    """`text` as envelope.short_result writes it: each line's whitespace
    collapsed, lines joined with " | "."""
    return " | ".join(" ".join(line.split()) for line in str(text).splitlines() if line.strip())


def clean_text(output: str, texts: Sequence[str]) -> Tuple[str, int, int]:
    """(output with every copy of `texts` replaced, exact copies, cut copies)."""
    exact = partial = 0
    for text in sorted(set(t for t in texts if t), key=len, reverse=True):
        for form in forms(text):
            n = output.count(form)
            if n:
                output = output.replace(form, PLACEHOLDER)
                exact += n
    for text in sorted(set(t for t in texts if t), key=len, reverse=True):
        span = _partial(output, text)
        if span is not None:
            output = output[:span[0]] + PLACEHOLDER + output[span[1]:]
            partial += 1
    return output, exact, partial


def _clean_result(result: str, texts: Sequence[str]) -> str:
    """The entry's short result (first characters of the output, flattened)
    with a sent message cut from where its start appears to the end."""
    for text in texts:
        flat = _flat(text)
        probe = flat[:40]
        if not probe:
            continue
        idx = result.find(probe)
        if idx != -1:
            return result[:idx] + PLACEHOLDER
    return result


@dataclass
class CleanStats:
    entries: int = 0      # trajectory entries changed
    exact: int = 0        # exact copies removed from outputs
    partial: int = 0      # cut copies removed from outputs (_partial)
    results: int = 0      # short results cut

    def to_dict(self) -> Dict[str, int]:
        return ({"entries": self.entries, "exact": self.exact, "partial": self.partial, "results": self.results}
                if self.entries else {})


def clean_trace(trace: Iterable[TrajectoryEntry], records: Sequence[Mapping[str, Any]]) -> Tuple[Tuple[TrajectoryEntry, ...], CleanStats]:
    """Each entry whose summary names the same action as a record (its
    normalized summary is one of the record's keys) gets that record's text
    removed from its output and its short result (OpenCode keeps a blocked
    call's text only in state.error, which reaches `result` and not
    `output`). Other entries are unchanged."""
    entries = tuple(trace)
    stats = CleanStats()
    if not records:
        return entries, stats
    by_key: Dict[str, List[str]] = {}
    for r in records:
        for key in r.get("keys") or ():
            by_key.setdefault(str(key), []).append(str(r.get("text") or ""))
    out: List[TrajectoryEntry] = []
    for e in entries:
        texts = by_key.get(norm_key(e.summary)) if e.summary and (e.output or e.result) else None
        if not texts:
            out.append(e)
            continue
        cleaned, exact, partial = clean_text(e.output, texts) if e.output else (e.output, 0, 0)
        result = _clean_result(e.result, texts)
        if not (exact or partial) and result == e.result:
            out.append(e)
            continue
        stats.entries += 1
        stats.exact += exact
        stats.partial += partial
        stats.results += int(result != e.result)
        out.append(TrajectoryEntry(tool=e.tool, decision=e.decision, summary=e.summary, output=cleaned,
                                   result=result, files_changed=e.files_changed))
    return tuple(out), stats


def clean_envelope(envelope: Any, records: Sequence[Mapping[str, Any]]) -> Tuple[Any, CleanStats]:
    """The envelope with clean_trace applied to its trajectory (the same
    object when nothing was removed)."""
    import dataclasses
    trace, stats = clean_trace(envelope.trajectory.recent, records)
    if not stats.entries:
        return envelope, stats
    return dataclasses.replace(envelope, trajectory=dataclasses.replace(envelope.trajectory, recent=trace)), stats
