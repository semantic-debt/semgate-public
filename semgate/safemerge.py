"""Safe edits of a host's config file (used by `semgate init` / `uninstall`).

Rules, for every host:

1. Refuse (MergeRefused: clear message, exit 2, file untouched) when the file
   is not valid JSON (or JSONC, where the host allows comments), or when a key
   semgate must touch has an unexpected type (for example `hooks` is a list).
2. Edit text, not a re-serialized copy: only semgate's own entries are
   inserted or replaced; every other byte (comments, key order, spacing, the
   user's deny/ask rules) stays as it was. The edited text is parsed again and
   must equal the intended document; for a JSONC file that check failing
   means refuse and print the snippet to paste by hand. For a strict JSON
   file (no comments) the fallback is the previous behaviour: write the whole
   document re-serialized.
3. Never loosen: the new document with semgate's entries removed must equal
   the old document with semgate's entries removed. Anything else is refused.
4. Backup before write (`<name>.semgate-bak-<timestamp>` next to the file),
   then write atomically (temp file in the same folder + os.replace).
5. SEMGATE_WRITE_ROOT (set by the test suite): refuse to write any path that
   is not inside that folder.

Standard library only. The JSONC reader accepts // and /* */ comments and
trailing commas; it refuses duplicate keys.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


class MergeRefused(Exception):
    """The file was not changed. The message says why and what to do."""

    def __init__(self, message: str, snippet: str = ""):
        super().__init__(message)
        self.snippet = snippet


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- parsing


@dataclass
class Node:
    kind: str                         # object | array | string | number | literal
    start: int
    end: int                          # exclusive
    value: Any = None
    keys: List[str] = field(default_factory=list)          # object: member keys, in order
    key_starts: List[int] = field(default_factory=list)    # object: offset of each key's opening quote
    children: List["Node"] = field(default_factory=list)   # object: member values; array: items
    commas: List[Optional[int]] = field(default_factory=list)  # offset of the comma after each child, or None

    def member(self, key: str) -> Optional["Node"]:
        for k, child in zip(self.keys, self.children):
            if k == key:
                return child
        return None


_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


class _Parser:
    def __init__(self, text: str, jsonc: bool):
        self.t = text
        self.i = 0
        self.jsonc = jsonc
        self.has_comments = False
        self.has_trailing_commas = False

    def err(self, msg: str) -> ParseError:
        line = self.t.count("\n", 0, self.i) + 1
        return ParseError(f"{msg} at line {line}")

    def ws(self) -> None:
        t, n = self.t, len(self.t)
        while self.i < n:
            c = t[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif c == "/" and self.jsonc and t.startswith("//", self.i):
                self.has_comments = True
                j = t.find("\n", self.i)
                self.i = n if j < 0 else j
            elif c == "/" and self.jsonc and t.startswith("/*", self.i):
                self.has_comments = True
                j = t.find("*/", self.i + 2)
                if j < 0:
                    raise self.err("unterminated comment")
                self.i = j + 2
            else:
                return

    def value(self) -> Node:
        self.ws()
        if self.i >= len(self.t):
            raise self.err("unexpected end of file")
        c = self.t[self.i]
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c == '"':
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.t.startswith(word, self.i):
                s = self.i
                self.i += len(word)
                return Node("literal", s, self.i, val)
        m = _NUMBER.match(self.t, self.i)
        if m and m.end() > self.i:
            self.i = m.end()
            return Node("number", m.start(), m.end(), json.loads(m.group(0)))
        raise self.err(f"unexpected character {c!r}")

    def string(self) -> Node:
        s = self.i
        j = s + 1
        t, n = self.t, len(self.t)
        while j < n:
            if t[j] == "\\":
                j += 2
                continue
            if t[j] == '"':
                break
            j += 1
        if j >= n:
            raise self.err("unterminated string")
        self.i = j + 1
        try:
            val = json.loads(t[s:self.i])
        except ValueError as exc:
            raise self.err(f"bad string ({exc})")
        return Node("string", s, self.i, val)

    def obj(self) -> Node:
        node = Node("object", self.i, self.i, {})
        self.i += 1
        while True:
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == "}":
                if node.commas and node.commas[-1] is not None:
                    if not self.jsonc:
                        raise self.err("trailing comma")
                    self.has_trailing_commas = True
                self.i += 1
                node.end = self.i
                return node
            if node.commas and node.commas[-1] is None:
                raise self.err("expected ',' or '}'")
            if self.i >= len(self.t) or self.t[self.i] != '"':
                raise self.err("expected a key")
            key = self.string()
            if key.value in node.value:
                raise self.err(f"duplicate key {key.value!r}")
            self.ws()
            if self.i >= len(self.t) or self.t[self.i] != ":":
                raise self.err("expected ':'")
            self.i += 1
            child = self.value()
            node.keys.append(key.value)
            node.key_starts.append(key.start)
            node.children.append(child)
            node.value[key.value] = child.value
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                node.commas.append(self.i)
                self.i += 1
            else:
                node.commas.append(None)

    def arr(self) -> Node:
        node = Node("array", self.i, self.i, [])
        self.i += 1
        while True:
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == "]":
                if node.commas and node.commas[-1] is not None:
                    if not self.jsonc:
                        raise self.err("trailing comma")
                    self.has_trailing_commas = True
                self.i += 1
                node.end = self.i
                return node
            if node.commas and node.commas[-1] is None:
                raise self.err("expected ',' or ']'")
            child = self.value()
            node.children.append(child)
            node.value.append(child.value)
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                node.commas.append(self.i)
                self.i += 1
            else:
                node.commas.append(None)


@dataclass
class Parsed:
    text: str             # without a leading BOM
    root: Node
    has_comments: bool
    has_trailing_commas: bool
    bom: str = ""

    @property
    def value(self) -> Any:
        return self.root.value


def parse(text: str, jsonc: bool = False) -> Parsed:
    """Parse JSON (or JSONC) keeping the offsets of every value. A file that
    is empty or only whitespace (and comments) is an empty object."""
    bom = ""
    if text.startswith("﻿"):
        bom, text = "﻿", text[1:]
    p = _Parser(text, jsonc)
    p.ws()
    if p.i >= len(text):
        root = Node("object", len(text), len(text), {})
        return Parsed(text, root, p.has_comments, False, bom)
    root = p.value()
    p.ws()
    if p.i != len(text):
        raise p.err("unexpected text after the JSON value")
    return Parsed(text, root, p.has_comments, p.has_trailing_commas, bom)


def load_jsonc(path: Path) -> Any:
    """Read a JSON/JSONC file (read-only helper for `semgate doctor`)."""
    return parse(Path(path).read_text(encoding="utf-8"), jsonc=True).value


# ---------------------------------------------------------------- editing


class Editor:
    """Collects non-overlapping text edits against one parsed file."""

    def __init__(self, parsed: Parsed):
        self.p = parsed
        self.t = parsed.text
        self.edits: List[Tuple[int, int, str]] = []
        self.nl = "\r\n" if "\r\n" in self.t else "\n"
        self.step = self._detect_step()

    # -- helpers
    def _detect_step(self) -> str:
        for line in self.t.splitlines():
            stripped = line.lstrip(" \t")
            if stripped and len(stripped) < len(line) and stripped[0] in "\"{[}]":
                lead = line[: len(line) - len(stripped)]
                return "\t" if lead.startswith("\t") else " " * min(len(lead), 8)
        return "  "

    def _line_start(self, pos: int) -> int:
        return self.t.rfind("\n", 0, pos) + 1

    def _indent_before(self, pos: int) -> Optional[str]:
        """The whitespace between the line start and pos, or None when other
        text precedes pos on its line."""
        s = self._line_start(pos)
        lead = self.t[s:pos]
        return lead if lead.strip(" \t") == "" else None

    def _line_indent(self, pos: int) -> str:
        s = self._line_start(pos)
        j = s
        while j < len(self.t) and self.t[j] in " \t":
            j += 1
        return self.t[s:j]

    def _eol_after(self, pos: int) -> Optional[int]:
        """If only spaces and an optional // comment follow pos on its line,
        the offset of the end of that line (before the newline); else None."""
        j = pos
        while j < len(self.t) and self.t[j] in " \t":
            j += 1
        if j >= len(self.t) or self.t[j] in "\r\n":
            return j if j < len(self.t) and self.t[j] != "\r" else j
        if self.t.startswith("//", j):
            k = self.t.find("\n", j)
            k = len(self.t) if k < 0 else k
            return k - 1 if k > 0 and self.t[k - 1] == "\r" else k
        return None

    def dump(self, value: Any, base: str) -> str:
        out = json.dumps(value, indent=self.step if self.step != "\t" else "\t")
        return out.replace("\n", self.nl + base)

    def add(self, start: int, end: int, text: str) -> None:
        self.edits.append((start, end, text))

    # -- operations
    def replace_value(self, node: Node, value: Any) -> None:
        self.add(node.start, node.end, self.dump(value, self._line_indent(node.start)))

    def set_member(self, obj: Node, key: str, value: Any) -> None:
        self.set_members(obj, [(key, value)])

    def set_members(self, obj: Node, items: Sequence[Tuple[str, Any]]) -> None:
        """Replace obj[key] when present; insert the missing keys together,
        in order, after the last member."""
        missing: List[Tuple[str, Any]] = []
        for key, value in items:
            existing = obj.member(key)
            if existing is not None:
                self.replace_value(existing, value)
            else:
                missing.append((key, value))
        if not missing:
            return
        if obj.children:
            last_i = len(obj.children) - 1
            indent = self._indent_before(obj.key_starts[last_i])
            if indent is None:
                indent = self._line_indent(obj.start) + self.step
            members = ("," + self.nl + indent).join(json.dumps(k) + ": " + self.dump(v, indent) for k, v in missing)
            comma = obj.commas[last_i]
            if comma is not None:      # trailing comma style (JSONC): keep it
                at = self._eol_after(comma + 1)
                at = comma + 1 if at is None else at
                self.add(at, at, self.nl + indent + members + ",")
                return
            vend = obj.children[last_i].end
            eol = self._eol_after(vend)
            if eol is not None and eol != vend:
                self.add(vend, vend, ",")
                self.add(eol, eol, self.nl + indent + members)
            else:
                self.add(vend, vend, "," + self.nl + indent + members)
            return
        outer = self._line_indent(obj.start)
        inner = outer + self.step
        members = ("," + self.nl + inner).join(json.dumps(k) + ": " + self.dump(v, inner) for k, v in missing)
        close = obj.end - 1
        if self.t[obj.start + 1:close].strip() == "":
            self.add(obj.start + 1, close, self.nl + inner + members + self.nl + outer)
        else:                           # only comments inside: keep them
            self.add(close, close, self.nl + inner + members + self.nl + outer)

    def remove_members(self, obj: Node, keys: Sequence[str]) -> None:
        """Remove the named members (absent keys are ignored)."""
        idx = [i for i, k in enumerate(obj.keys) if k in set(keys)]
        self._remove_children(obj, idx, obj.key_starts)

    def rewrite_array(self, arr: Node, remove: Sequence[int], append: Sequence[Any]) -> None:
        """Remove the items at `remove` and append `append` at the end."""
        remove_set = set(remove)
        n = len(arr.children)
        kept = [i for i in range(n) if i not in remove_set]
        inner = None
        for i in range(n):
            ind = self._indent_before(arr.children[i].start)
            if ind is not None:
                inner = ind
                break
        if inner is None:
            inner = self._line_indent(arr.start) + self.step
        if not kept:
            body = self.t[arr.start + 1:arr.end - 1]
            if not _has_comment(body):
                self.replace_value(arr, list(append))
                return
        trailing_style = n > 0 and arr.commas[n - 1] is not None
        if not append:
            self._remove_children(arr, sorted(remove_set), [c.start for c in arr.children])
            return
        for i in sorted(remove_set):
            self._remove_item(arr.children[i].start, arr.children[i].end, arr.commas[i])
        items = [self.dump(v, inner) for v in append]
        joined = ("," + self.nl + inner).join(items)
        if kept:
            k = kept[-1]
            if arr.commas[k] is not None:
                c = arr.commas[k]
                at = self._eol_after(c + 1) if trailing_style else None
                at = c + 1 if at is None else at
                self.add(at, at, self.nl + inner + joined + ("," if trailing_style else ""))
            else:
                vend = arr.children[k].end
                eol = self._eol_after(vend)
                if eol is not None and eol != vend:
                    self.add(vend, vend, ",")
                    self.add(eol, eol, self.nl + inner + joined)
                else:
                    self.add(vend, vend, "," + self.nl + inner + joined)
        else:
            close = arr.end - 1
            self.add(close, close, self.nl + inner + joined + self.nl + self._line_indent(arr.start))

    def _remove_children(self, node: Node, idx: Sequence[int], starts: Sequence[int]) -> None:
        """Remove children `idx` of an object or array. When the last kept
        child is followed only by removed children, its comma is removed too
        (unless the file uses trailing commas)."""
        if not idx:
            return
        n = len(node.children)
        gone = set(idx)
        kept = [i for i in range(n) if i not in gone]
        if not kept and not _has_comment(self.t[node.start + 1:node.end - 1]):
            self.add(node.start + 1, node.end - 1, "")
            return
        for i in sorted(gone):
            self._remove_item(starts[i], node.children[i].end, node.commas[i])
        trailing_style = node.commas[n - 1] is not None
        if kept and kept[-1] < n - 1 and node.commas[kept[-1]] is not None and not trailing_style:
            c = node.commas[kept[-1]]
            self.add(c, c + 1, "")

    def _remove_item(self, start: int, end: int, comma: Optional[int]) -> None:
        s = start
        e = comma + 1 if comma is not None else end
        lead = self._indent_before(s)
        eol = self._eol_after(e)
        if lead is not None and eol is not None and eol == _skip_spaces(self.t, e):
            # the item (and its comma) fills whole lines: drop those lines
            s = self._line_start(s)
            e = eol
            if e < len(self.t) and self.t[e] == "\r":
                e += 1
            if e < len(self.t) and self.t[e] == "\n":
                e += 1
        else:
            e = _skip_spaces(self.t, e)
        self.add(s, e, "")

    def result(self) -> str:
        edits = sorted(self.edits, key=lambda x: (x[0], x[1]))
        for (s1, e1, _), (s2, e2, _) in zip(edits, edits[1:]):
            if s2 < e1:
                raise MergeRefused("internal error: overlapping edits")
        out = self.t
        for s, e, text in reversed(edits):
            out = out[:s] + text + out[e:]
        return self.p.bom + out


def _skip_spaces(t: str, j: int) -> int:
    while j < len(t) and t[j] in " \t":
        j += 1
    return j


def _has_comment(text: str) -> bool:
    """True when `text` (a slice of JSONC) contains a comment outside strings."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "/" and i + 1 < n and text[i + 1] in "/*":
            return True
        i += 1
    return False


# ---------------------------------------------------------------- writing


def write_root() -> Optional[Path]:
    root = os.environ.get("SEMGATE_WRITE_ROOT", "")
    return Path(root).resolve() if root else None


def check_write_allowed(path: Path) -> None:
    root = write_root()
    if root is None:
        return
    target = Path(path).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise MergeRefused(f"refusing to write {target}: outside SEMGATE_WRITE_ROOT ({root})")


def backup_path(path: Path) -> Path:
    stamp = f"{_dt.datetime.now():%Y%m%d-%H%M%S}"
    candidate = path.with_name(path.name + f".semgate-bak-{stamp}")
    n = 1
    while candidate.exists():
        candidate = path.with_name(path.name + f".semgate-bak-{stamp}-{n}")
        n += 1
    return candidate


def safe_write(path: Path, text: str, backup: bool = True, announce: Optional[Callable[[str, Path], None]] = None) -> Optional[Path]:
    """Backup (when the file exists and backup=True), then atomic write.
    Returns the backup path or None."""
    path = Path(path)
    check_write_allowed(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    saved: Optional[Path] = None
    if backup and path.is_file():
        saved = backup_path(path)
        check_write_allowed(saved)
        shutil.copy2(path, saved)
        if announce is not None:
            announce("backup", saved)
    tmp = path.with_name(f".{path.name}.semgate-tmp-{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        if path.exists():
            try:
                shutil.copymode(path, tmp)
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    return saved


# ---------------------------------------------------------------- the merge


@dataclass
class MergePlan:
    """How one host's config file is edited.

    validate(doc)           raise MergeRefused on an unexpected shape
    merged(doc)             the intended new document (pure)
    strip(doc)              the document without semgate's entries (pure)
    edit(editor, parsed)    record the text edits that turn old into merged
    """
    validate: Callable[[Any], None]
    merged: Callable[[Any], Any]
    strip: Callable[[Any], Any]
    edit: Callable[[Editor, Parsed], None]
    jsonc: bool = False              # the host accepts comments in this file


@dataclass
class MergeResult:
    old_text: Optional[str]
    new_text: str
    new_doc: Any
    method: str                      # "edit" | "rewrite" | "new"
    note: str = ""


def merge_file(path: Path, plan: MergePlan) -> MergeResult:
    """Compute the new text for `path`. Raises MergeRefused; writes nothing."""
    path = Path(path)
    old_text: Optional[str] = None
    if path.is_file():
        try:
            old_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MergeRefused(f"{path} cannot be read as UTF-8 text ({exc}); fix or move it first")
    if old_text is None:
        doc: Any = {}
        plan.validate(doc)
        new_doc = plan.merged(doc)
        _never_looser(plan, doc, new_doc, path)
        return MergeResult(None, json.dumps(new_doc, indent=2) + "\n", new_doc, "new")
    try:
        parsed = parse(old_text, jsonc=plan.jsonc)
    except ParseError as exc:
        kind = "JSON/JSONC" if plan.jsonc else "JSON"
        raise MergeRefused(f"{path} is not valid {kind} ({exc}); fix or move it first")
    doc = parsed.value
    plan.validate(doc)
    new_doc = plan.merged(doc)
    _never_looser(plan, doc, new_doc, path)
    snippet = json.dumps(new_doc, indent=2)
    try:
        editor = Editor(parsed)
        plan.edit(editor, parsed)
        new_text = editor.result()
        check = parse(new_text, jsonc=plan.jsonc).value
        if not plan.jsonc:
            check = json.loads(new_text.lstrip("﻿"))
        ok = check == new_doc
    except (ParseError, ValueError, MergeRefused, IndexError, KeyError, TypeError):
        ok, new_text = False, ""
    if ok:
        return MergeResult(old_text, new_text, new_doc, "edit")
    if parsed.has_comments or parsed.has_trailing_commas:
        raise MergeRefused(
            f"{path} has comments and semgate could not insert its entry without risking them; the file was not changed. "
            "Paste semgate's entry by hand; the whole intended file is printed below.", snippet)
    return MergeResult(old_text, snippet + "\n", new_doc, "rewrite",
                       note="re-serialized the whole file (no comments were in it)")


def _never_looser(plan: MergePlan, old: Any, new: Any, path: Path) -> None:
    if plan.strip(old) != plan.strip(new):
        raise MergeRefused(f"refusing to write {path}: the change would alter settings that are not semgate's own entry")
