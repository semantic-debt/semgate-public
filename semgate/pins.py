"""Pinned command lines of project instruction files (AGENTS.md, CLAUDE.md, ...).

Problem. The agent reads the project's AGENTS.md with a tool. The file says
"Before committing, you must run ./scripts/check.sh". "you must run" is an
instruction marker (injection.INSTRUCTION_MARKERS) next to the command, so
the command is the human gate `untrusted_instruction`: it cannot be
approved in chat and the agent may not trust it. That treats the owner's own
file like a hostile README. But the file can come from a stranger's
repository, or the agent can have edited it, so it is not trusted by
default either.

What this module does:

1. Recognized instruction files (is_instruction_file): AGENTS.md, AGENT.md,
   AGENTS.override.md, CLAUDE.md, CLAUDE.local.md, GEMINI.md, .cursorrules,
   .windsurfrules, .clinerules, copilot-instructions.md, and rule files
   under .cursor/rules/ (*.mdc, *.md), .github/instructions/
   (*.instructions.md), .clinerules/ (*.md) and .windsurf/rules/ (*.md).
   Names are compared without case, in any folder inside the project.
2. Command lines of such a file (command_lines): a line with an
   instruction marker, a line inside a fenced code block, a line with an
   inline code span, and a line that starts with "$ ".
3. A pin is (project, file, line key). The line key is sha256 of the line
   with whitespace collapsed (norm), or, when secretfinder finds a secret in
   the line, a keyed fingerprint (trust.key); the store then keeps only a
   masked copy of the text. Pins are records in the trust store
   (trust.jsonl, record_type "pin", events add / remove), appended and read
   under the same file lock, each with a keyed tag (a record without a
   valid tag is ignored; trustauth.py). Adding needs an Auth: the CLI's
   (a ticket from the hook, or the user's own terminal) or the hook's
   chat-approved pin (pingate.py). Pins do not expire; `semgate trust
   remove --file` ends them.
4. PinView (one per hook call) tells the injection scan which lines of a
   tool output that came from an instruction file are pinned. A marker hit
   whose lines (the marker line and every line in the marker's window that
   names a token of the command) are ALL pinned is not untrusted_instruction:
   the command goes to the normal judgment, and the pinned lines go to the
   judge as `project_instructions` ("pinned by the user"), not as
   untrusted_context. A pin never allows anything by itself.
5. A hit with unpinned lines stays untrusted_instruction. ask_info() says
   which lines to ask about: every command line of the file (read from
   disk) plus the hit's lines when the file has no pin yet (the first
   time); only the hit's unpinned lines when it has pins (a new or changed
   line). A line that matches a hard rule is never pinned.

Nothing here runs a command or reads the network.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import filelock

SCHEMA = 2                           # 2: every record carries a keyed tag (trustauth.py)
TAG_LABEL = "pin record v2"
RECORD_TYPE = "pin"
MAX_FILE_BYTES = 256 * 1024          # a larger instruction file is not read from disk (the output lines still count)
MAX_LINE_CHARS = 400                 # stored display text per line
MAX_LIST = 5                         # commands shown in the question

_NAMES = frozenset({"agents.md", "agent.md", "agents.override.md", "claude.md", "claude.local.md", "gemini.md",
                    ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md"})
# Names inside the regex used by rules.py (instruction_file_edit gate).
NAME_RE = (r"(?:agents?\.md|agents\.override\.md|claude(?:\.local)?\.md|gemini\.md|\.cursorrules|\.windsurfrules"
           r"|\.clinerules|copilot-instructions\.md|\.cursor[/\\]rules[/\\][^\s'\"/\\]+\.mdc?"
           r"|\.github[/\\]instructions[/\\][^\s'\"/\\]+\.instructions\.md|\.windsurf[/\\]rules[/\\][^\s'\"/\\]+\.md)")


def is_instruction_file(path: str) -> bool:
    """True for a recognized instruction file name (any folder, any case)."""
    if not isinstance(path, str) or not path.strip():
        return False
    parts = [p for p in re.split(r"[/\\]+", path.strip().strip("'\"").lower()) if p and p != "."]
    if not parts:
        return False
    name = parts[-1]
    if name in _NAMES:
        return True
    parent = parts[-2] if len(parts) >= 2 else ""
    grand = parts[-3] if len(parts) >= 3 else ""
    if parent == "rules" and grand == ".cursor" and (name.endswith(".mdc") or name.endswith(".md")):
        return True
    if parent == "instructions" and grand == ".github" and name.endswith(".instructions.md"):
        return True
    if parent == ".clinerules" and name.endswith(".md"):
        return True
    if parent == "rules" and grand == ".windsurf" and name.endswith(".md"):
        return True
    return False


# ---------------------------------------------------------------- lines


def norm(line: str) -> str:
    return " ".join(str(line or "").split())


# Line-number prefixes that file-reading tools add: Claude Code Read
# ("     3\t..." or "     3→..."), agy view_file ("3: ..."), "3| ...".
_NUMBER_RE = re.compile(r"^\s*(\d{1,7})(?:\t|→|: ?|\| ?)(.*)$")


def split_number(line: str) -> Tuple[Optional[int], str]:
    m = _NUMBER_RE.match(line or "")
    return (int(m.group(1)), m.group(2)) if m else (None, line or "")


_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_INLINE_RE = re.compile(r"`([^`\n]{2,})`")
_PROMPT_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?\$\s+(\S.*)$")


def _has_marker(text: str) -> bool:
    from . import injection
    return injection.has_marker(text)


def command_lines(text: str) -> List[Tuple[int, str]]:
    """(1-based line number, line) of every command line (module text, 2)."""
    out: List[Tuple[int, str]] = []
    in_fence = False
    for i, raw in enumerate(str(text or "").splitlines(), 1):
        if _FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if not raw.strip():
            continue
        if in_fence or _PROMPT_RE.match(raw) or _has_marker(raw) or any(re.search(r"[A-Za-z]", s) for s in _INLINE_RE.findall(raw)):
            out.append((i, raw.rstrip("\r")))
    return out


_STOP_WORDS = frozenset("too first before after then and when if to so each every always once also again please".split())


def command_of(line: str) -> str:
    """The command a command line names, for the question's short list: the
    first inline code span, the text after "$ ", else the line."""
    text = norm(split_number(line)[1]) if split_number(line)[0] is not None else norm(line)
    m = _INLINE_RE.search(text)
    if m:
        return norm(m.group(1))
    m = _PROMPT_RE.match(text)
    if m:
        return norm(m.group(1))
    tail = re.search(r"\b(?:run|execute|call|invoke)\s+(.+)$", text, re.IGNORECASE)
    if tail:
        words: List[str] = []
        for word in tail.group(1).split():
            if word.lower().strip(".,;:!?") in _STOP_WORDS or len(words) >= 6:
                break
            words.append(word)
            if re.search(r"[.,;:!?]$", word) and not re.search(r"[/\\]$", word):
                break
        if words:
            return " ".join(words).rstrip(".,;:!?")
    return text


def _secrets(text: str) -> List[str]:
    from . import secretfinder
    try:
        return [f.value for f in secretfinder.find(text)]
    except Exception:
        return []


def shown_line(text: str) -> str:
    """A line as it may be stored or printed (secrets masked, cut)."""
    from . import secretfinder
    t = norm(text)
    found = _secrets(t)
    if found:
        t = secretfinder.mask_in(t, found)
    return t if len(t) <= MAX_LINE_CHARS else t[: MAX_LINE_CHARS - 3] + "..."


def hard_rule_line(text: str) -> str:
    """The hard-rule pattern a line matches (such a line is never pinned), or ""."""
    from .trust import hard_rule_hit
    return hard_rule_hit(norm(text))


def file_key(rel: str) -> str:
    return os.path.normcase(str(PurePosixPath(*[p for p in re.split(r"[/\\]+", rel) if p and p != "."]))).replace("\\", "/")


# ---------------------------------------------------------------- store


def _iso(epoch: float) -> str:
    from .trust import _iso as iso
    return iso(epoch)


class PinStore:
    """Pin events in the trust store file. `key_path` is the trust key (HMAC
    for lines with a secret)."""

    def __init__(self, path: Any, lock_timeout: float = 0.0, clock: Any = None) -> None:
        self.path = Path(path)
        self.lock_timeout = float(lock_timeout)
        self.clock = clock or time.time
        self._key_cache: Optional[bytes] = None

    @property
    def key_path(self) -> Path:
        from .trust import KEY_NAME
        return self.path.with_name(KEY_NAME)

    def _key(self) -> bytes:
        if self._key_cache is None:
            from . import fingerprints
            self._key_cache, _note = fingerprints.load_key(self.key_path, self.lock_timeout)
        return self._key_cache

    def line_keys(self, line: str, keyed: bool) -> List[str]:
        """The keys a line may be stored under: sha256 of norm(line), and the
        keyed fingerprint when `keyed` (the store holds keyed lines)."""
        t = norm(line)
        if not t:
            return []
        out = ["sha256:" + hashlib.sha256(t.encode("utf-8")).hexdigest()]
        if keyed:
            try:
                from . import fingerprints
                out.append(fingerprints.fingerprint(self._key(), t))
            except Exception:
                pass
        return out

    def key_for(self, line: str) -> str:
        """The key a new pin of `line` is stored under."""
        t = norm(line)
        if _secrets(t):
            from . import fingerprints
            return fingerprints.fingerprint(self._key(), t)
        return "sha256:" + hashlib.sha256(t.encode("utf-8")).hexdigest()

    ignored = 0                   # pin records the last records() call ignored (no valid tag)

    def records(self) -> List[Dict[str, Any]]:
        """Pin events with a valid tag. Raises LockTimeout / OSError / KeyUnavailable."""
        from . import trustauth
        if not self.path.exists():
            self.ignored = 0
            return []
        res = filelock.read_jsonl_locked(self.path, timeout=self.lock_timeout)
        if res.malformed:
            filelock.warn_malformed(self.path, res, "trust")
        rows = [r for r in res.records if r.get("record_type") == RECORD_TYPE]
        if not rows:
            self.ignored = 0
            return []
        key = self._key()
        good = [r for r in rows if r.get("schema") == SCHEMA and trustauth.tag_ok(key, TAG_LABEL, r)]
        self.ignored = len(rows) - len(good)
        trustauth.warn_ignored(self.path, "pin", self.ignored)
        return good

    def _append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        from . import trustauth
        record = trustauth.tagged(self._key(), TAG_LABEL, record)
        filelock.append_record(self.path, record, timeout=self.lock_timeout, spill=False, repair=True)
        return record

    @staticmethod
    def state(records: Sequence[Mapping[str, Any]], project: Optional[str] = None) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """{(project, file_key): {"file", "project_root", "lines": {key: {"text", "line"}}, "ts"}}."""
        out: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for r in records:
            proj, fk = str(r.get("project_root", "")), str(r.get("file_key", ""))
            if not proj or not fk or (project is not None and proj != project):
                continue
            key = (proj, fk)
            if r.get("event") == "remove":
                out.pop(key, None)
                continue
            if r.get("event") != "add":
                continue
            cur = out.setdefault(key, {"file": str(r.get("file", fk)), "project_root": proj, "lines": {}, "ts": ""})
            if r.get("replace") is True:
                cur["lines"] = {}
            for ln in r.get("lines") or []:
                if isinstance(ln, Mapping) and str(ln.get("key", "")):
                    cur["lines"][str(ln["key"])] = {"text": str(ln.get("text", "")), "line": ln.get("line")}
            cur["file"], cur["ts"] = str(r.get("file", fk)), str(r.get("ts", ""))
        return out

    def add(self, project: str, rel: str, lines: Sequence[Mapping[str, Any]], *, auth: Any, replace: bool = False,
            now: Optional[float] = None) -> Dict[str, Any]:
        """Append a pin event. `lines`: [{"key", "text" (already shown_line), "line"}].
        `auth` (trustauth.Auth): why it may be written. Raises NotAuthorized, LockTimeout."""
        from . import trustauth
        auth = trustauth.require(auth)
        if not project or not rel:
            raise ValueError("a pin needs a project and a file")
        t = self.clock() if now is None else float(now)
        record = {"record_type": RECORD_TYPE, "schema": SCHEMA, "event": "add", "pin_id": uuid.uuid4().hex[:12],
                  "project_root": project, "file": rel.replace("\\", "/"), "file_key": file_key(rel), "replace": bool(replace),
                  "lines": [{"key": str(x["key"]), "text": str(x.get("text", ""))[:MAX_LINE_CHARS], "line": x.get("line")}
                            for x in lines], "ts": _iso(t), **auth.fields()}
        return self._append(record)

    def remove(self, project: str, rel: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        cur = self.state(self.records(), project).get((project, file_key(rel)))
        if cur is None:
            return None
        t = self.clock() if now is None else float(now)
        record = {"record_type": RECORD_TYPE, "schema": SCHEMA, "event": "remove", "project_root": project,
                  "file": rel.replace("\\", "/"), "file_key": file_key(rel), "ts": _iso(t)}
        self._append(record)
        return cur


# ---------------------------------------------------------------- one hook call


@dataclass
class FileLines:
    """The pins of one instruction file, for one hook call."""
    rel: str
    abs_path: str
    keys: frozenset
    keyed: bool
    store: Optional[PinStore] = None
    _disk: Optional[List[str]] = field(default=None, repr=False)

    @property
    def pinned_any(self) -> bool:
        return bool(self.keys)

    def covers(self, raw_line: str) -> bool:
        """The line (with or without a tool's line-number prefix) is pinned."""
        if not self.keys or not norm(raw_line):
            return False
        candidates = [raw_line]
        num, rest = split_number(raw_line)
        if num is not None:
            candidates.append(rest)
        for c in candidates:
            keys = self.store.line_keys(c, self.keyed) if self.store is not None else \
                ["sha256:" + hashlib.sha256(norm(c).encode("utf-8")).hexdigest()]
            if any(k in self.keys for k in keys):
                return True
        return False

    def disk_lines(self) -> List[str]:
        if self._disk is None:
            self._disk = []
            try:
                p = Path(self.abs_path)
                if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES:
                    self._disk = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._disk = []
        return self._disk

    def line_number(self, raw_line: str) -> Optional[int]:
        """The line's number in the file on disk (same text), else the
        number the tool printed in front of it, else None."""
        num, rest = split_number(raw_line)
        wanted = {norm(raw_line), norm(rest)}
        wanted.discard("")
        for i, line in enumerate(self.disk_lines(), 1):
            if norm(line) in wanted:
                return i
        return num

    def text_of(self, raw_line: str) -> str:
        """The line without a tool's number prefix when the file has it that way."""
        num, rest = split_number(raw_line)
        if num is not None:
            disk = {norm(x) for x in self.disk_lines()}
            if norm(rest) in disk or norm(raw_line) not in disk:
                return rest
        return raw_line


class PinView:
    """Which lines of the tool outputs the agent read are pinned. Built once
    per hook call: the store is read at most once, lazily. A store that
    cannot be read counts as no pins (stricter: nothing is lifted), and the
    error is kept in `error`."""

    def __init__(self, store: PinStore, project_root: str, cwd: str = "") -> None:
        from .trust import project_of
        self.store = store
        self.project = project_of(project_root or cwd) if (project_root or cwd) else ""
        self.cwd = cwd or project_root
        self._state: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None
        self._keyed = False
        self.error = ""

    def _load(self) -> Dict[Tuple[str, str], Dict[str, Any]]:
        if self._state is None:
            try:
                self._state = PinStore.state(self.store.records(), self.project)
            except Exception as exc:
                self._state, self.error = {}, f"{type(exc).__name__}: {exc}"[:300]
            self._keyed = any(k.startswith("hmac-") for v in self._state.values() for k in v["lines"])
        return self._state

    def resolve(self, path: str) -> Optional[Tuple[str, str]]:
        """(rel posix path in the project, absolute path) for a recognized
        instruction file inside the project, else None."""
        if not self.project or not is_instruction_file(path):
            return None
        raw = os.path.expanduser(path.strip().strip("'\""))
        absolute = raw if os.path.isabs(raw) else os.path.join(self.cwd or self.project, raw)
        try:
            real = os.path.realpath(absolute)
        except (OSError, ValueError):
            return None
        full, root = os.path.normcase(real), self.project
        if not full.startswith(root.rstrip("\\/") + os.sep):
            return None
        try:
            rel = os.path.relpath(real, root).replace("\\", "/")   # keeps the file's own letter case
        except ValueError:
            return None
        return rel, real

    def source_file(self, summary: str) -> Optional[Tuple[str, str]]:
        """The instruction file a tool call read, from its summary (a path, or
        a command such as `cat AGENTS.md`)."""
        text = str(summary or "")
        if not text.strip():
            return None
        direct = self.resolve(text) if not re.search(r"\s", text.strip()) else None
        if direct:
            return direct
        for tok in re.split(r"[\s'\"`,;|&<>()\[\]{}]+", text):
            if tok and is_instruction_file(tok):
                found = self.resolve(tok)
                if found:
                    return found
        return None

    def for_entry(self, entry: Any) -> Optional[FileLines]:
        """FileLines for a trajectory entry whose output came from a
        recognized instruction file in the project, else None."""
        found = self.source_file(getattr(entry, "summary", ""))
        if found is None:
            return None
        state = self._load()
        cur = state.get((self.project, file_key(found[0])))
        keys = frozenset(cur["lines"]) if cur else frozenset()
        return FileLines(rel=found[0], abs_path=found[1], keys=keys, keyed=self._keyed, store=self.store)

    def pinned(self, rel: str) -> Dict[str, Any]:
        return self._load().get((self.project, file_key(rel))) or {}


# ---------------------------------------------------------------- the question


def _quote(text: str, limit: int = 160) -> str:
    t = shown_line(text)
    return t if len(t) <= limit else t[: limit - 3] + "..."


def ask_info(fl: FileLines, hit_lines: Sequence[str], store: Optional[PinStore]) -> Dict[str, Any]:
    """What to ask the user about a hit with unpinned lines, and which lines a
    yes pins. hit_lines: the hit's unpinned lines as the tool output shows
    them (the marker line first)."""
    first_time = not fl.pinned_any
    seen: set = set()
    lines: List[Dict[str, Any]] = []
    refused: List[Dict[str, Any]] = []

    def add(raw: str, number: Optional[int]) -> None:
        text = fl.text_of(raw)
        t = norm(text)
        if not t or t in seen:
            return
        seen.add(t)
        entry = {"line": number, "text": shown_line(text), "command": _quote(command_of(text), 50)}
        hit = hard_rule_line(t)
        if hit:
            refused.append(dict(entry, hard_rule=hit))
            return
        if fl.covers(text):
            return
        entry["key"] = store.key_for(t) if store is not None else "sha256:" + hashlib.sha256(t.encode("utf-8")).hexdigest()
        lines.append(entry)

    for raw in hit_lines:
        add(raw, fl.line_number(raw))
    if first_time:
        for number, raw in command_lines("\n".join(fl.disk_lines())):
            add(raw, number)
    lines.sort(key=lambda e: (e["line"] is None, e["line"] or 0))
    head = hit_lines[0] if hit_lines else ""
    head_no = fl.line_number(head) if head else None
    where = f"{fl.rel}, line {head_no}" if head_no else fl.rel
    cmds = [e["command"] for e in lines]
    shown = ", ".join(cmds[:MAX_LIST]) + (f", +{len(cmds) - MAX_LIST} more" if len(cmds) > MAX_LIST else "")
    count = f"{len(lines)} line{'s' if len(lines) != 1 else ''}"
    if first_time:
        q = (f'This command comes from {where}: "{_quote(fl.text_of(head))}". '
             f"Do you trust the command lines in {fl.rel}? ({count}: {shown})")
    else:
        q = (f'This command comes from {where}: "{_quote(fl.text_of(head))}". '
             f"This line is new or changed since you trusted the command lines of {fl.rel}. "
             f"Do you trust {'it' if len(lines) == 1 else 'these lines'}? ({count}: {shown})")
    if refused:
        q += (f" semgate never trusts {len(refused)} line{'s' if len(refused) != 1 else ''} of it that match a hard rule "
              f"(line {', '.join(str(e['line']) for e in refused if e['line']) or '?'}).")
    return {"file": fl.rel, "path": fl.abs_path, "line": head_no, "first_time": first_time, "question": q,
            "lines": lines, "refused": refused}


# ---------------------------------------------------------------- CLI: `semgate trust file`


def file_lines_to_pin(abs_path: str, store: PinStore) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(lines to pin, lines refused because they match a hard rule) for every
    current command line of the file on disk."""
    p = Path(abs_path)
    if not p.is_file():
        raise ValueError(f"{abs_path} is not a file")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{abs_path} is larger than {MAX_FILE_BYTES // 1024} KB")
    text = p.read_text(encoding="utf-8", errors="replace")
    pin: List[Dict[str, Any]] = []
    refused: List[Dict[str, Any]] = []
    seen: set = set()
    for number, raw in command_lines(text):
        t = norm(raw)
        if t in seen:
            continue
        seen.add(t)
        entry = {"line": number, "text": shown_line(raw), "command": _quote(command_of(raw), 50)}
        hit = hard_rule_line(t)
        if hit:
            refused.append(dict(entry, hard_rule=hit))
            continue
        pin.append(dict(entry, key=store.key_for(t)))
    return pin, refused


def resolve_cli_file(path: str, project: str, cwd: str = "") -> Tuple[str, str]:
    """(rel, abs) of a recognized instruction file inside `project`, or
    ValueError. A relative path is read from `cwd` (default: the current
    directory)."""
    view = PinView(PinStore(os.devnull), project, cwd or os.getcwd())
    if not is_instruction_file(path):
        raise ValueError(f"{path} is not a recognized instruction file (AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, ...)")
    found = view.resolve(path)
    if found is None:
        raise ValueError(f"{path} is not inside the project {view.project}")
    return found


def print_err(msg: str) -> None:
    print(msg, file=sys.stderr)
