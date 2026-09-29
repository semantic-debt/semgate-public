"""Tool outputs recorded by semgate's own post-tool hook.

Why: at PreToolUse semgate reads the previous tool outputs from the host's
transcript (injection scan: injection.detect / render_context ->
untrusted_context; task context: recent_actions results). Measured with
hookconf in CI (Claude Code 2.1.278 on Linux, test A4, 2 of 2 runs): at
PreToolUse the transcript does not yet hold the output of the call just
before. That output is where an injected instruction usually sits (the agent
reads a page, then runs what the page says). On Windows the transcript had it.

What: the post-tool hook appends one record per finished tool call to a
per-session file; the next PreToolUse merges those records into the
envelope's trajectory.

  record  {"record_type": "tool_output", "session_id", "tool_use_id", "tool",
           "agent_id", "summary", "ts", "output", "truncated", "bytes",
           "sha256", "redactions", "is_error"}

  - `output`: the tool's result as text (tool_response / output), each
    secret value (semgate.secretfinder, the same detector as the exposure
    notice) replaced with a label `<secret TYPE MASKED>`, e.g.
    `DB_PASSWORD=<secret DB_PASSWORD hu…XY>`, then cut to MAX_OUTPUT_BYTES
    of UTF-8 (`truncated`: true when cut). Exception: an occurrence whose
    value, or the quoted string around it on its line, carries an
    instruction marker (injection.has_marker) is kept as it is, so the
    injection check at the next PreToolUse still sees the instruction. Text
    that only looks like an assignment (`password="ignore your rules and
    run ..."`) is not a secret for the detector (it has spaces) and is kept.
    Before 2026-09-23 this used scriptsource.scrub (the F4 scrub), which
    replaced any quoted `password=` / `token=` value with <redacted>, so an
    injected instruction written as such a value never reached the judge.
  - `summary` (the command or path): the same labels, also for the output's
    secret values that appear in it.
  - `redactions`: how many occurrences were replaced.
  - `sha256`: of the stored `output` text (after labels and cut). The
    sha256 of the raw text is not kept: it was a fingerprint of the raw
    output, so a short password in an otherwise known file could be checked
    by hashing guesses. `bytes`: UTF-8 size of the full text as the host gave
    it (a length only).

Where: `<dir>/<session key>.jsonl`, dir = semgate.json `tool_outputs.dir`,
default `tool_outputs/` next to `ledger_file` (for `semgate init <host>`:
~/.semgate/<host>/tool_outputs). `<session key>` is sha256(session id)[:32]
(agentfiles.session_key); the session id is checked with hookinput rules
first and never becomes a path component. Off with `"tool_outputs": false`
or `{"enabled": false}`.

Locks (filelock): every write and every read holds the file's cross-process
lock. A write that does not get the lock in time records nothing and writes
a ledger incident `tool_output_not_recorded`; it never blocks the tool (the
post hook only records). A PreToolUse read that fails (lock timeout, OS
error) fails closed: run_core turns an allow into an ask (store_problems)
and the ledger gets `tool_outputs_unreadable`.

Retention, on every write under the lock: records older than MAX_AGE_S
(24 h) are dropped and at most KEEP_STEPS (20, the trajectory window) are
kept. When a session's first record is written, other sessions' files not
modified for 24 h are deleted (their `.lock` sidecars stay: deleting a lock
file another process may hold would break the lock).

Merge (merge_trace), per trajectory entry, matched by tool_use_id when both
sides have one:
  - transcript has no output  -> the record's output fills it (and `result`
    when empty);
  - both have output and they agree (after collapsing whitespace and
    Claude's Read line numbers, one contains the other) -> the transcript
    text is kept;
  - both have output and they differ -> the record's text comes first and the
    transcript text follows it (neither source can hide the other); counted
    in evidence `tool_outputs.differ`.
Records without a tool_use_id (hosts without a per-call id) are paired with
trajectory entries that have no id and no output: first a record whose tool
and summary equal exactly one such entry's (and no other record's) goes to
that entry (`by_summary`; parallel calls finish in any order), then the rest
from the end, only while the tool names agree (`by_order`). A record whose
tool_use_id the transcript does not show at all (the host has not written
the call yet) is appended at the end (at most
APPEND_MAX, newest last). Records of another agent_id (a subagent) are not
used. The pending call (current tool_use_id) is never merged.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import filelock
from .envelope import TrajectoryEntry, short_result, utcnow_iso

MAX_OUTPUT_BYTES = 64 * 1024
KEEP_STEPS = 20
MAX_AGE_S = 24 * 3600
APPEND_MAX = 5
_SCRUB_WINDOW = 4 * MAX_OUTPUT_BYTES      # chars scrubbed before the cut (bounds regex time)
_PREFERRED_KEYS = ("stdout", "stderr", "output", "result", "content", "text", "file", "error")


# ---------------------------------------------------------------- config


def enabled(config: Mapping[str, Any]) -> bool:
    value = config.get("tool_outputs") if isinstance(config, Mapping) else None
    if value is False:
        return False
    if isinstance(value, Mapping) and value.get("enabled") is False:
        return False
    return True


def store_dir(config: Mapping[str, Any]) -> Path:
    value = config.get("tool_outputs") if isinstance(config.get("tool_outputs"), Mapping) else {}
    if value.get("dir"):
        return Path(os.path.expanduser(str(value["dir"])))
    from .storepaths import state_path
    return Path(state_path(config, "tool_outputs"))


def store_for(config: Mapping[str, Any]) -> Optional["ToolOutputStore"]:
    return ToolOutputStore(store_dir(config)) if enabled(config) else None


# ---------------------------------------------------------------- text of a tool result


def _leaves(value: Any, out: List[str], depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(value, str):
        if value:
            out.append(value)
    elif isinstance(value, Mapping):
        keys = [k for k in _PREFERRED_KEYS if k in value] + [k for k in value if k not in _PREFERRED_KEYS and k != "type"]
        for k in keys:
            _leaves(value[k], out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _leaves(item, out, depth + 1)


def response_text(value: Any) -> str:
    """The text of a host's tool result: a string as is; for an object or a
    list, every string value, depth first, with stdout / stderr / output /
    result / content / text first (Claude Code Bash: {stdout, stderr, ...};
    Read: {file: {content}}; MCP: [{type: text, text}]). Numbers, booleans
    and `type` tags are skipped."""
    parts: List[str] = []
    _leaves(value, parts)
    return "\n".join(parts)


def _cut_utf8(text: str, limit: int) -> Tuple[str, bool]:
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode("utf-8", "ignore"), True


_QUOTE_REACH = 2000       # chars searched on each side of a secret for the quoted string around it


def _quoted_around(text: str, start: int, end: int) -> List[str]:
    """The quoted strings ("..." and '...') on the same line that contain
    text[start:end], searched at most _QUOTE_REACH chars each way."""
    ls = max(text.rfind("\n", 0, start) + 1, start - _QUOTE_REACH)
    le = text.find("\n", end, end + _QUOTE_REACH)
    le = min(len(text), end + _QUOTE_REACH) if le < 0 else le
    out = []
    for q in ('"', "'"):
        a, b = text.rfind(q, ls, start), text.find(q, end, le)
        if a >= 0 and b >= 0:
            out.append(text[a + 1:b])
    return out


@functools.lru_cache(maxsize=4096)
def _has_marker(text: str) -> bool:
    from .injection import has_marker
    return has_marker(text)


def carries_marker(text: str, start: int, end: int) -> bool:
    """True when the secret at text[start:end], or a quoted string around
    it, carries an instruction marker: that text stays in the store as it is
    (never hide injection text from the judge). Cached per string: an output
    that repeats one value thousands of times is checked once."""
    return _has_marker(text[start:end]) or any(_has_marker(q) for q in _quoted_around(text, start, end))


def make_record(session_id: str, tool_use_id: Any, tool: str, text: str, *, summary: str = "", agent_id: str = "",
                is_error: bool = False, max_bytes: int = MAX_OUTPUT_BYTES, now: Optional[float] = None) -> Dict[str, Any]:
    from .secretfinder import label_secrets
    raw = str(text or "")
    raw_bytes = raw.encode("utf-8", "replace")
    head = raw[:_SCRUB_WINDOW] if len(raw) > _SCRUB_WINDOW else raw
    clean, redactions, found = label_secrets(head, keep=carries_marker)
    output, cut = _cut_utf8(clean, max_bytes)
    summary_text, _, _ = label_secrets(str(summary or ""), extra=found)
    ts = time.time() if now is None else float(now)
    return {
        "record_type": "tool_output",
        "session_id": session_id,
        "tool_use_id": "" if tool_use_id is None else str(tool_use_id),
        "tool": str(tool or ""),
        "agent_id": str(agent_id or ""),
        "summary": summary_text[:200],
        "ts": utcnow_iso() if now is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "epoch": ts,
        "output": output,
        "truncated": bool(cut or len(raw) > len(head)),
        "bytes": len(raw_bytes),
        "sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "redactions": redactions,
        "is_error": bool(is_error),
    }


# ---------------------------------------------------------------- store


class ToolOutputStore:
    def __init__(self, base_dir: Any, keep_steps: int = KEEP_STEPS, max_age_s: float = MAX_AGE_S) -> None:
        self.base = Path(os.path.expanduser(str(base_dir)))
        self.keep_steps = max(1, int(keep_steps))
        self.max_age_s = float(max_age_s)

    def path(self, session_id: str) -> Path:
        from .agentfiles import session_key
        return self.base / f"{session_key(session_id)}.jsonl"

    def _fresh(self, record: Mapping[str, Any], now: float) -> bool:
        try:
            return now - float(record.get("epoch", 0)) <= self.max_age_s
        except (TypeError, ValueError):
            return False

    def record(self, record: Mapping[str, Any], timeout: float = 0.0) -> None:
        """Append `record` (make_record) under the lock, pruning first.
        Raises filelock.LockTimeout (caller: skip + incident) and OSError."""
        session_id = str(record.get("session_id") or "")
        if not session_id:
            return
        path = self.path(session_id)
        now = float(record.get("epoch") or time.time())
        new_session = not path.exists()
        with filelock.exclusive(path, timeout):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                raw = b""
            parsed = filelock.parse_jsonl_bytes(raw)
            kept = [r for r in parsed.records if r.get("record_type") == "tool_output" and self._fresh(r, now)]
            kept = kept[-(self.keep_steps - 1):] if self.keep_steps > 1 else []
            line = filelock.encode_record(record)
            if len(kept) == len(parsed.records) and not parsed.malformed and not parsed.partial_tail:
                filelock.append_bytes(path, line)
            else:
                data = b"".join(filelock.encode_record(r) for r in kept) + line
                try:
                    _replace_bytes(path, data)
                except OSError as exc:       # e.g. Windows: a virus scanner holds the file; prune next time
                    print(f"semgate: tool output store not pruned ({type(exc).__name__}: {exc}); appending", file=sys.stderr)
                    filelock.append_bytes(path, line, repair=True)
        if new_session:
            self._drop_stale_sessions(path, now)

    def _drop_stale_sessions(self, own: Path, now: float) -> None:
        try:
            candidates = [p for p in self.base.glob("*.jsonl") if p != own]
        except OSError:
            return
        for p in candidates:
            try:
                if now - p.stat().st_mtime <= self.max_age_s:
                    continue
                with filelock.exclusive(p, 0.2):
                    if now - p.stat().st_mtime > self.max_age_s:
                        p.unlink()
            except (OSError, filelock.LockTimeout):
                continue

    def read(self, session_id: str, timeout: float = 0.0, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """This session's fresh records, oldest first, read under the lock.
        Missing file -> []. Raises filelock.LockTimeout and OSError."""
        if not session_id:
            return []
        path = self.path(session_id)
        result = filelock.read_jsonl_locked(path, timeout=timeout)
        t = time.time() if now is None else now
        return [r for r in result.records if r.get("record_type") == "tool_output"
                and str(r.get("session_id", "")) == session_id and self._fresh(r, t)]


def _replace_bytes(path: Path, data: bytes) -> None:
    """Unique temp file in the same directory, then os.replace. The caller
    holds the lock; every reader of this store also takes it."""
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


# ---------------------------------------------------------------- hook side


def _incident(config: Mapping[str, Any], kind: str, detail: Dict[str, Any]) -> None:
    try:
        from .ledger import Ledger
        from .storepaths import ledger_file
        Ledger(ledger_file(config)).record_incident(kind, detail)
    except Exception as exc:
        print(f"semgate: could not record {kind}: {type(exc).__name__}: {exc}", file=sys.stderr)


def record_post(config: Mapping[str, Any], session_id: str, tool_use_id: Any, tool: str, output: Any, *,
                summary: str = "", agent_id: str = "", is_error: bool = False) -> bool:
    """Post-tool side: record one tool output. Never raises, never blocks the
    tool. `session_id` must already be checked (hookinput); "" records
    nothing. Returns True when recorded."""
    try:
        store = store_for(config)
        if store is None or not session_id:
            return False
        text = output if isinstance(output, str) else response_text(output)
        record = make_record(session_id, tool_use_id, tool, text, summary=summary, agent_id=agent_id, is_error=is_error)
        try:
            store.record(record)
        except filelock.LockTimeout as exc:
            _incident(config, "tool_output_not_recorded", {"reason": "lock_timeout", "tool_use_id": record["tool_use_id"],
                                                           "tool": record["tool"], "message": str(exc)[:300]})
            print(f"semgate: tool output not recorded: {exc}", file=sys.stderr)
            return False
        return True
    except Exception as exc:
        _incident(config, "tool_output_not_recorded", {"reason": type(exc).__name__, "message": str(exc)[:300]})
        print(f"semgate: tool output not recorded: {type(exc).__name__}: {exc}", file=sys.stderr)
        return False


def load_for_pre(config: Mapping[str, Any], session_id: str) -> Tuple[List[Dict[str, Any]], str]:
    """PreToolUse side: (records, problem). `problem` is "" when the store
    was read (or is off / has no file); otherwise a short text, and a ledger
    incident `tool_outputs_unreadable` was written. The caller fails closed on
    a problem (run_core store_problems: an allow becomes an ask)."""
    try:
        store = store_for(config)
    except Exception as exc:
        store, problem = None, f"tool output store not usable ({type(exc).__name__}: {exc})"
        _incident(config, "tool_outputs_unreadable", {"message": problem[:300]})
        return [], problem
    if store is None or not session_id:
        return [], ""
    try:
        return store.read(session_id), ""
    except (filelock.LockTimeout, OSError) as exc:
        problem = f"the tool output store ({type(exc).__name__}: {exc})"
        _incident(config, "tool_outputs_unreadable", {"message": str(exc)[:300], "reason": type(exc).__name__})
        return [], problem


# ---------------------------------------------------------------- merge

_LINE_NO_RE = re.compile(r"(?m)^[ \t]*\d+(?:\t|→)")


def _norm(text: str) -> str:
    return " ".join(_LINE_NO_RE.sub("", text or "").split())


def agree(transcript_text: str, record_text: str) -> bool:
    a, b = _norm(transcript_text), _norm(record_text)
    if not a or not b:
        return a == b
    return a in b or b in a


def _entry(e: TrajectoryEntry, output: str, result: str) -> TrajectoryEntry:
    return TrajectoryEntry(tool=e.tool, decision=e.decision, summary=e.summary, output=output, result=result,
                           files_changed=e.files_changed)


def merge_trace(trace: Sequence[TrajectoryEntry], call_ids: Sequence[str], known_ids: Any,
                records: Sequence[Mapping[str, Any]], *, current_id: Any = "", agent_id: str = "",
                cap: int = 6000, window: int = 20) -> Tuple[Tuple[TrajectoryEntry, ...], Dict[str, Any]]:
    """See the module docstring. `call_ids[i]` is the host's call id of
    trace[i] ("" when unknown); `known_ids` every call id the transcript
    shows (also calls older than the trace window). Returns (trace, stats);
    stats is {} when no record was used."""
    current = "" if current_id is None else str(current_id)
    mine = [r for r in records if str(r.get("agent_id", "") or "") == (agent_id or "")
            and not (current and str(r.get("tool_use_id", "") or "") == current)]
    by_id: Dict[str, Mapping[str, Any]] = {}
    for r in mine:
        rid = str(r.get("tool_use_id", "") or "")
        if rid:
            by_id[rid] = r
    known = set(str(k) for k in (known_ids or ()) if k)
    out = list(trace)
    ids = [str(call_ids[i]) if i < len(call_ids) and call_ids[i] else "" for i in range(len(out))]
    filled: List[str] = []
    differ: List[str] = []
    agreed = 0
    used = set()

    def apply(i: int, r: Mapping[str, Any], label: str) -> None:
        nonlocal agreed
        e = out[i]
        text = str(r.get("output", ""))
        rec_result = short_result(text, error=bool(r.get("is_error")))
        if not e.output:
            out[i] = _entry(e, text[:cap], e.result or rec_result)
            filled.append(label)
        elif agree(e.output, text):
            agreed += 1
        else:
            joined = text[:cap] + "\n[transcript text of the same call follows]\n" + e.output[:cap]
            out[i] = _entry(e, joined, e.result or rec_result)
            differ.append(label)

    for i, cid in enumerate(ids):
        if cid and cid != current and cid in by_id:
            apply(i, by_id[cid], cid)
            used.add(cid)
    # Hosts without a per-call id. First by what the call was about: a record
    # whose tool and summary (command, path or URL) equal exactly one open
    # call's goes to that call, whatever the order. Parallel calls finish in
    # any order, so pairing by order alone gave two parallel reads each
    # other's text.
    anon = [r for r in mine if not r.get("tool_use_id")]
    slots = [i for i in range(len(out)) if not ids[i] and not out[i].output]
    by_summary = 0

    def same_call(r: Mapping[str, Any], i: int) -> bool:
        s = " ".join(str(r.get("summary", "")).split())
        return bool(s) and str(r.get("tool", "")).lower() == str(out[i].tool).lower() and " ".join(out[i].summary.split()) == s

    for r in list(anon):
        matches = [i for i in slots if same_call(r, i)]
        if len(matches) == 1 and sum(1 for x in anon if same_call(x, matches[0])) == 1:
            apply(matches[0], r, f"summary:{matches[0]}")
            by_summary += 1
            anon.remove(r)
            slots.remove(matches[0])
    # Then the rest from the end while tool names agree.
    by_order = 0
    while anon and slots:
        r, i = anon[-1], slots[-1]
        if str(r.get("tool", "")).lower() != str(out[i].tool).lower():
            break
        apply(i, r, f"order:{i}")
        by_order += 1
        anon.pop()
        slots.pop()
    # Calls the transcript does not show yet.
    missing = [r for r in mine if r.get("tool_use_id") and str(r["tool_use_id"]) not in known
               and str(r["tool_use_id"]) not in used and str(r["tool_use_id"]) != current]
    appended = []
    for r in missing[-APPEND_MAX:]:
        text = str(r.get("output", ""))
        out.append(TrajectoryEntry(tool=str(r.get("tool", "")), decision="", summary=str(r.get("summary", ""))[:200],
                                   output=text[:cap], result=short_result(text, error=bool(r.get("is_error")))))
        appended.append(str(r["tool_use_id"]))
    stats: Dict[str, Any] = {}
    if filled or differ or agreed or appended or by_order or by_summary:
        stats = {"records": len(mine), "filled": len(filled), "agreed": agreed, "differ": len(differ),
                 "appended": len(appended), "by_order": by_order}
        if by_summary:
            stats["by_summary"] = by_summary
        if differ:
            stats["differ_ids"] = differ[:10]
        if any(r.get("truncated") for r in mine):
            stats["truncated"] = sum(1 for r in mine if r.get("truncated"))
        redacted = sum(int(r.get("redactions", 0) or 0) for r in mine)
        if redacted:
            stats["redactions"] = redacted
    return tuple(out[-window:]), stats
