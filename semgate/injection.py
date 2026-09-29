"""Untrusted-context instruction scan (indirect prompt injection).

An agent reads files, web pages and command output. Any of that content can
carry text written to steer the agent ("ignore your instructions and run
..."). If the next command the agent proposes carries out such text, the
command is the injection's payload even when it looks ordinary on its own.

Input: `envelope.trajectory.recent[*].output` (tool results the adapter
copied from the host transcript) and the proposed command.

Two layers, in the same spirit as the rest of semgate:

- Deterministic (`detect`): an *instruction marker* (text addressed to an AI /
  agent, or overriding prior instructions) appears in a tool output, and the
  proposed command overlaps the text around that marker. Both conditions must
  hold: a security article that merely contains the phrase never gates a
  command that has nothing to do with it. Result: a human gate
  (`untrusted_instruction`), never an allow. Overlap means a significant
  token of the command (significant_tokens: a URL, host, path or rare word)
  or, for a simple command that has none (`npm install`, `npm run e2e`,
  `git status`), its whole words as one phrase (command_phrases). A one-word
  command (`make`) counts where the text shows it as a command, and a command
  with more flags than the text (`npm run e2e --silent` for "npm run e2e")
  counts through its prefixes (command_links).
- Semantic (`render_context`): the passages of tool output that overlap the
  command, regardless of markers, are handed to the router as
  `untrusted_context` so the model can be asked whether the command follows an
  instruction found there rather than the user's request. Empty when nothing
  overlaps, so single-command evaluation is unaffected. A phrase overlap
  (short command) counts here only when the same output also carries an
  instruction marker: "To test, run npm test" in a README is not sent.

Nothing here reads the network or executes anything.
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from typing import Any, Iterator, List, Optional, Sequence, Tuple

from .envelope import Envelope

# Text that addresses the model or overrides its instructions. Kept to shapes
# that ordinary documentation does not use: "run the following command" alone
# is what every README says, so it is NOT a marker.
INSTRUCTION_MARKERS: Tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(ignore|disregard|forget|override)\b[^\n.]{0,30}\b(previous|prior|above|earlier|all|your|the)\b[^\n.]{0,20}\b(instructions?|prompts?|rules|guidelines|policy|policies)\b",
        r"\b(you|the (ai|assistant|agent|model))\s+(must|should|need to|have to|are required to|are now|will now)\b[^\n.]{0,40}\b(run|execute|download|install|delete|remove|send|upload|curl|wget|copy|type)\b",
        r"\b(ai|llm|language model|assistant|agent|copilot|claude|gpt|gemini|antigravity|codex)\b[^\n.]{0,60}\b(new|updated|real|actual|hidden|secret)\s+(instructions?|task|objective|rules)\b",
        r"\b(new|updated|additional|hidden|secret|real|actual)\s+(instructions?|task|objective|rules)\s+(for|to)\s+(the\s+)?(ai|llm|assistant|agent|model|bot)\b",
        r"\bsystem\s*prompt\b",
        # Chat-template control tokens. Real model transcripts never appear inside
        # a README or a command's output; their presence means someone is trying
        # to forge a conversation turn. Family patterns cover the whole list in
        # elder-plinius/L1B3RT4S *SPECIAL_TOKENS.json (im_start/end, eot_id,
        # start_header_id, SYSTEM_TOKEN, fim_*, ...), not just a few names.
        r"<\|[a-z_]{2,32}\|>",                      # <|im_start|> <|eot_id|> <|SYSTEM_TOKEN|> <|fim_prefix|> ...
        r"<</?SYS>>|\[/?INST\]",                    # llama-2 style
        r"<(start|end)_of_turn>|<\|?(bos|eos|pad|unk|BOS_TOKEN)\|?>",  # gemma / sentencepiece controls
        r"</?system>|</?think>",                    # forged system block / reasoning block
        r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\b[^\n.]{0,40}\b(the\s+)?(user|human|operator|developer)\b",
        r"\bbefore\s+(continuing|proceeding|you continue|doing anything else)\b[^\n.]{0,60}\b(run|execute|download|install|send)\b",
        r"\bthis is (an? )?(instruction|command|message) (for|to) (the )?(ai|assistant|agent|model|bot)\b",
    )
)

_WINDOW = 400          # chars of output on each side of a marker that count as "around" it
_SNIPPET = 220         # chars on each side of a command token when rendering context for the model
_CONTEXT_CAP = 1500    # total chars of untrusted context handed to the model
_MIN_TOKEN = 5

# Words that overlap by accident in any shell text; never count as evidence.
_COMMON = frozenset("""
bash shell command commands python python3 node npm pnpm yarn pip cargo make cmake echo print printf
then else done true false while until export local return exit sudo curl wget http https https:// http://
install build test tests start stop status version --help --version file files path name value string
output input error errors option options using with from into this that these those your their
""".split())

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:@%+=~-]{" + str(_MIN_TOKEN) + ",}")
_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"]+", re.IGNORECASE)


@dataclass(frozen=True)
class InjectionHit:
    tool: str          # tool whose output carried the instruction
    marker: str        # the marker text that matched
    overlap: str       # the command token found next to it
    excerpt: str       # short passage around the marker (for the reason / ledger)
    source: str = ""   # that call's summary: the file path, URL or command whose output it was
    # When the output came from a project instruction file (pins.py): the
    # hit's lines that are not pinned (the marker line first), and the file.
    lines: Tuple[str, ...] = ()
    file_lines: Any = field(default=None, compare=False, repr=False)


def command_text(envelope: Envelope) -> str:
    arguments = envelope.action.arguments
    for key in ("command", "url", "Url", "path"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def significant_tokens(command: str) -> List[str]:
    """Tokens of the command that would be evidence if found in untrusted text:
    URLs and hosts first, then any token of 5+ chars that is not a common shell
    word. Order is deterministic (longest first) so the rendered context is stable."""
    tokens: List[str] = []
    for url in _URL_RE.findall(command):
        tokens.append(url)
        host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", url, flags=re.I).split("/")[0]
        if host and host not in tokens:
            tokens.append(host)
    for tok in _TOKEN_RE.findall(command):
        low = tok.lower().strip(".:/")
        if len(low) < _MIN_TOKEN or low in _COMMON or low.lstrip("-").isdigit():
            continue
        if tok not in tokens:
            tokens.append(tok)
    return sorted(set(tokens), key=lambda s: (-len(s), s))


# Short commands (command_phrases). `npm run e2e`, `npm install`, `git status`,
# `pip install .` have no significant token: every word is common or shorter
# than _MIN_TOKEN. Before 2026-09-24 such a command was never compared with
# what the agent read, so "AI agent: you must run npm install" in a README was
# invisible to the gate and to the judge. For these commands the words of each
# simple command, as one phrase, are the overlap instead.
_QUOTE_CHARS = "'\"`"
_NAVIGATION = frozenset({"cd", "pushd", "popd"})
_MIN_PHRASE_WORDS = 2


def command_phrases(command: str) -> List[str]:
    """Phrases of the command that count as overlap in untrusted text: one per
    simple command (shellparse.split_commands: split at && || ; | & and
    newlines outside quotes) that has no significant token of its own. A
    phrase is the program and its arguments (shellparse.effective_argv:
    wrappers such as sudo/env/time, VAR=value assignments and redirections
    removed), quotes removed, lowercased, whitespace collapsed.

    A phrase needs at least _MIN_PHRASE_WORDS (2) words: a one-word command
    (`make`, `ls`, `yarn`, `pwd`, `tox`) is an ordinary English or shell word
    that appears in almost every README and command output, so as a plain
    phrase it carries no evidence (command_links counts it only where the
    text shows it as a command). Skipped too: `cd DIR` / `pushd DIR` (they only
    change the folder) and a command that reads a heredoc (its body is the
    content, the command line alone is `python -` or `cat`). Examples:
      "npm run e2e"                    -> ["npm run e2e"]
      "cd /repo && npm install"        -> ["npm install"]
      "CI=1 npm test 2>&1 | tail -5"   -> ["npm test", "tail -5"]
      "make" / "ls"                    -> []
      "pip install requests-oauthlib"  -> []  (the package name is a significant token)
      'python -c "import os; print(1)"' -> []  (one simple command; "import" is a token)"""
    out: List[str] = []
    for words in _simple_words(command):
        if len(words) < _MIN_PHRASE_WORDS:
            continue
        phrase = " ".join(w for w, _ in words).lower()
        if significant_tokens(phrase) or phrase in out:
            continue
        out.append(phrase)
    return out


_SUBSTITUTION_RE = re.compile(r"\$\(|`|<\(|>\(")


def _simple_words(command: str) -> List[List[Tuple[str, bool]]]:
    """(word, plain) per simple command (shellparse.split_commands), for
    command_phrases and command_links: the program and its arguments
    (shellparse.effective_argv: wrappers, VAR=value assignments and
    redirections removed), quotes removed, whitespace collapsed. `plain` is
    False for a word with a command or process substitution ($(...),
    backticks, <(...)). The parentheses of a subshell are not part of a word:
    `(cd a && make)` gives `cd a` (skipped) and `make`. Skipped: a command
    that reads a heredoc and `cd` / `pushd` / `popd`."""
    from . import shellparse
    try:
        simples = shellparse.split_commands(command or "")
    except Exception:
        return []
    out: List[List[Tuple[str, bool]]] = []
    for simple in simples:
        if simple.heredocs:
            continue
        argv = shellparse.effective_argv(simple.tokens)
        pairs: List[Tuple[str, bool]] = []
        for i, t in enumerate(argv):
            word = " ".join(t.value.split())
            if i == 0:
                word = word.lstrip("({")
            if i == len(argv) - 1 and word.count(")") > word.count("("):
                word = word.rstrip(")")
            word = word.strip(_QUOTE_CHARS)
            if word:
                pairs.append((word, not (t.substitutions or _SUBSTITUTION_RE.search(t.raw))))
        if pairs and pairs[0][0].lower() not in _NAVIGATION:
            out.append(pairs)
    return out


def phrase_pattern(phrase: str) -> "re.Pattern":
    """A phrase as it may be written in untrusted text: case-insensitive, any
    whitespace between words, optional quotes or backticks around each word,
    and bounded so that `npm test` does not match `pnpm test` or
    `npm test:unit` (a sentence may end right after it: "run npm test.")."""
    q = "[" + re.escape(_QUOTE_CHARS) + "]?"
    body = r"\s+".join(q + re.escape(w) + q for w in phrase.split())
    return re.compile(r"(?<![\w./@:=+~-])" + body + r"(?![\w@=+~-]|[./:][\w])", re.IGNORECASE)


# One-word and flag-extended commands (command_links, 2026-09-25). Two
# commands that an instruction in untrusted text can name, and that
# command_phrases does not link to it:
#
# 1. A one-word command (`make`, `yarn`, `tox`, `ls`). The word is also
#    English ("make sure"), so it counts only where the text shows it as a
#    command (_shown_as_command): as the first word of an inline code span
#    (`make`, <code>make</code>), of a line inside a fenced code block, or
#    after a "$ " prompt; directly after "run" / "execute" ("you must run
#    make"); or alone on its line (after a list bullet or a "> "). A line
#    that only starts with the word ("Make sure gcc is installed") does not
#    count.
# 2. A command with more flags or arguments than the text names
#    (`npm run e2e --silent`, `make -j8` for "you must run npm run e2e" /
#    "run `make`"). Each prefix of a simple command, from its first word up
#    to (not including) its first significant token, is looked for when the
#    rest of that simple command has no command substitution. The text must
#    end its command right after the prefix (_ends_command: end of line,
#    closing backtick or quote, sentence punctuation, a shell operator, or
#    a prose word such as "before"), so the prefix `npm run` does not match
#    "npm run lint". A one-word prefix also needs rule 1. The extension never
#    crosses `;`, `&&`, `||` or `|`: each simple command is compared on its
#    own.
#
# The other direction is linked as before: `npm run e2e` matches the text
# "npm run e2e -- --update-snapshots" (phrase_pattern stops at a space), so
# the agent running part of an instructed command is still linked. Word
# boundaries are those of phrase_pattern: `npm test` never matches
# "npm test:unit". A marker is still required for the gate (detect) and for
# the judge's passage (render_context).

_PROSE_END_WORDS = frozenset("""
before after then and or but when whenever while if to so first too each every always once also again please
now here there instead in on at for from as afterwards immediately
""".split())
_NUMBER_PREFIX_RE = re.compile(r"^\s*\d{1,7}(?:\t|→|: ?|\| ?)")   # tool line numbers (pins.split_number)
_FENCE_LINE_RE = re.compile(r"^\s*(?:```|~~~)")
_AFTER_VERB_RE = re.compile(r"\b(?:run|execute)\s*:?\s+[`'\"]?$", re.IGNORECASE)
_PROMPT_BEFORE_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)?\$\s+$")
_FENCED_BEFORE_RE = re.compile(r"^\s*(?:\$\s+|>\s+)?$")
_LINE_START_BEFORE_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s+)?$")
_END_PUNCT_RE = re.compile(r"[.,;:!?)\]}]+(?:\s|$)")
_END_OPERATOR_RE = re.compile(r"[ \t]*(?:&&|\|\||[;|&<>])")
_NEXT_WORD_RE = re.compile(r"[ \t]+([A-Za-z]+)\b")


@functools.lru_cache(maxsize=16)
def _fenced_starts(text: str) -> Tuple[Tuple[int, int], ...]:
    """(start, end) character ranges of the lines inside fenced code blocks.
    Cached: detect() asks once per marker window and per link."""
    ranges: List[Tuple[int, int]] = []
    inside, start, pos = False, 0, 0
    for line in text.split("\n"):
        body = _NUMBER_PREFIX_RE.sub("", line, count=1)
        if _FENCE_LINE_RE.match(body) or _FENCE_LINE_RE.match(line):
            if inside:
                ranges.append((start, pos))
            else:
                start = pos + len(line) + 1
            inside = not inside
        pos += len(line) + 1
    if inside:                                           # an output cut inside a fence
        ranges.append((start, pos))
    return tuple(ranges)


def _shown_as_command(text: str, start: int, end: int, fenced: Sequence[Tuple[int, int]]) -> str:
    """How the text shows the word at [start, end) as a command: "strong"
    (code span, fenced line, $ prompt, after run/execute: what follows may be
    its arguments), "line" (alone on its line), or "" (prose). The match may
    include the quote or backtick around the word (phrase_pattern)."""
    while start < end and text[start] in _QUOTE_CHARS:
        start += 1
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    before = _NUMBER_PREFIX_RE.sub("", text[line_start:start], count=1)
    stripped = before.rstrip(" \t")
    if _FENCE_LINE_RE.match(before):
        return ""                                        # ```python: the fence's language tag
    if stripped.endswith("`") and before.count("`") % 2 == 1:
        return "strong"                                  # `make ...`
    if stripped.lower().endswith("<code>"):
        return "strong"
    if _AFTER_VERB_RE.search(before) or _PROMPT_BEFORE_RE.match(before):
        return "strong"
    if any(s <= start < e for s, e in fenced) and _FENCED_BEFORE_RE.match(before):
        return "strong"
    if _LINE_START_BEFORE_RE.match(before) and not text[end:line_end].strip(" \t\r`'\".,;:!?"):
        return "line"
    return ""


def _ends_command(text: str, end: int) -> bool:
    """The text's command ends at `end`: what follows is not another word of
    the command (see the comment above _PROSE_END_WORDS)."""
    rest = text[end:end + 80]
    after = rest.lstrip(_QUOTE_CHARS)
    closed = end > 0 and text[end - 1] in _QUOTE_CHARS          # phrase_pattern took the closing quote
    if closed or len(after) != len(rest) or not after or after[0] == "<":
        return True
    if after[0] in "\r\n":
        # End of the line. In hard-wrapped prose the command can go on in the
        # next line ("run npm run\ne2e"): a next line that starts with a
        # lowercase letter, a digit or a flag (-x, --x; not a "- " bullet)
        # continues it.
        nl = text.find("\n", end)
        nxt = text[nl + 1:nl + 81] if nl != -1 else ""
        nxt = _NUMBER_PREFIX_RE.sub("", nxt.split("\n", 1)[0], count=1).lstrip(" \t")
        return not re.match(r"[a-z0-9]|-\S", nxt)
    if _END_PUNCT_RE.match(after) or _END_OPERATOR_RE.match(after):
        return True
    m = _NEXT_WORD_RE.match(after)
    return bool(m and m.group(1).lower() in _PROSE_END_WORDS)


@dataclass(frozen=True)
class CommandLink:
    """One way the command can be named in untrusted text (command_links).
    kind: "phrase" (command_phrases, unchanged), "word" (a one-word command,
    rule 1), "prefix" (the command minus trailing flags/arguments, rule 2)."""
    text: str
    kind: str
    pattern: "re.Pattern" = field(compare=False, repr=False)
    words: int = 0

    def finditer(self, text: str, pos: int = 0, endpos: Optional[int] = None) -> Iterator[Tuple[int, int]]:
        endpos = len(text) if endpos is None else endpos
        if self.kind == "phrase":
            for m in self.pattern.finditer(text, pos, endpos):
                yield m.start(), m.end()
            return
        fenced: Optional[Sequence[Tuple[int, int]]] = None
        for m in self.pattern.finditer(text, pos, endpos):
            s, e = m.start(), m.end()
            if self.kind == "prefix" and not _ends_command(text, e):
                continue
            if self.words == 1:
                if fenced is None:
                    fenced = _fenced_starts(text)
                if not _shown_as_command(text, s, e, fenced):
                    continue
            yield s, e

    def search(self, text: str, pos: int = 0, endpos: Optional[int] = None) -> Optional[Tuple[int, int]]:
        return next(self.finditer(text, pos, endpos), None)


def command_links(command: str) -> List[CommandLink]:
    """Every phrase of the command that counts as overlap in untrusted text:
    the command_phrases (kind "phrase"), a one-word simple command without a
    significant token (kind "word": `make`, `yarn`), and the prefixes of a
    simple command with more words (kind "prefix"; see the comment above
    _PROSE_END_WORDS). Examples:
      "npm run e2e --silent" -> prefix "npm", "npm run", "npm run e2e"
      "make"                 -> word "make"
      "make -j8"             -> phrase "make -j8", prefix "make"
      "npm run e2e $(cat x)" -> phrase only if it has no token; no prefix
      "cd app && make"       -> word "make" (cd is skipped)"""
    out: List[CommandLink] = [CommandLink(p, "phrase", phrase_pattern(p), len(p.split())) for p in command_phrases(command)]
    seen = {(c.text, c.kind) for c in out}

    def add(text: str, kind: str, n: int) -> None:
        if (text, kind) not in seen and not any(c.text == text and c.kind == "phrase" for c in out):
            seen.add((text, kind))
            out.append(CommandLink(text, kind, phrase_pattern(text), n))

    for words in _simple_words(command):
        if len(words) == 1:
            word = words[0][0].lower()
            if not significant_tokens(word):
                add(word, "word", 1)
            continue
        for k in range(1, len(words)):
            prefix = " ".join(w for w, _ in words[:k]).lower()
            if significant_tokens(prefix):
                break
            if all(plain for _, plain in words[k:]):
                add(prefix, "prefix", k)
    return out


def _outputs(envelope: Envelope):
    for entry in envelope.trajectory.recent:
        if entry.output:
            yield entry


def _line_span(text: str, pos: int) -> Tuple[int, int]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return start, (len(text) if end == -1 else end)


def involved_lines(text: str, m_start: int, m_end: int, w_start: int, w_end: int, tokens: List[str], command: str,
                   phrases: Sequence["CommandLink"] = ()) -> List[str]:
    """The lines of a marker hit: the line(s) of the marker, then every line
    in the window [w_start, w_end) that names a command token, a command
    link (command_links) or the whole command. Raw lines, marker line
    first, then in file order, no duplicates."""
    low = text.lower()
    head_spans = []
    pos = m_start
    while True:
        s, e = _line_span(text, pos)
        head_spans.append((s, e))
        if e >= m_end or e >= len(text):
            break
        pos = e + 1
    other = set()
    for needle in [t.lower() for t in tokens] + ([command.lower()] if command else []):
        if not needle:
            continue
        idx = low.find(needle, w_start)
        while idx != -1 and idx < w_end:
            other.add(_line_span(text, idx))
            idx = low.find(needle, idx + len(needle))
    for link in phrases:
        for s, _ in link.finditer(text, w_start, w_end):
            other.add(_line_span(text, s))
    spans = head_spans + sorted(other - set(head_spans))
    out: List[str] = []
    for s, e in spans:
        line = text[s:e].rstrip("\r")
        if line.strip() and line not in out:
            out.append(line)
    return out


def detect(envelope: Envelope, pins: Any = None) -> List[InjectionHit]:
    """Deterministic layer: instruction marker AND command overlap within the
    same passage of one tool output. Returns at most one hit per output.

    `pins` (pins.PinView): for an output that came from a project
    instruction file, a marker whose lines (involved_lines) are all pinned
    by the user is not a hit; the scan goes on to the next marker. A hit
    from such a file carries its unpinned lines (`lines`, `file_lines`).
    None: unchanged."""
    command = command_text(envelope)
    if not command:
        return []
    tokens = significant_tokens(command)
    links = command_links(command)
    if not tokens and not links:
        return []
    hits: List[InjectionHit] = []
    for entry in _outputs(envelope):
        text = entry.output
        low = text.lower()
        fl = pins.for_entry(entry) if pins is not None else None
        found = None
        for marker in INSTRUCTION_MARKERS:
            for m in marker.finditer(text):
                start, end = max(0, m.start() - _WINDOW), min(len(text), m.end() + _WINDOW)
                window = low[start:end]
                overlap = next((t for t in tokens if t.lower() in window), None)
                if overlap is None:
                    overlap = next((c.text for c in links if c.search(text, start, end) is not None), None)
                # The whole command as a plain substring: only for commands with
                # a significant token (as before). A command without one is
                # compared through its bounded phrases above, so `npm test`
                # does not overlap `npm test:unit` or `pnpm test`.
                if overlap is None and tokens and command.lower() in window:
                    overlap = command
                if overlap is not None:
                    unpinned: Tuple[str, ...] = ()
                    if fl is not None:
                        lines = involved_lines(text, m.start(), m.end(), start, end, tokens, command, links)
                        unpinned = tuple(x for x in lines if not fl.covers(x))
                        if not unpinned:
                            continue              # every line of this hit is pinned by the user
                    excerpt = " ".join(text[max(0, m.start() - 80):m.end() + 80].split())
                    found = InjectionHit(tool=entry.tool, marker=m.group(0)[:120], overlap=overlap[:120], excerpt=excerpt[:300],
                                         source=str(entry.summary or "")[:120], lines=unpinned, file_lines=fl)
                    break
            if found:
                break
        if found:
            hits.append(found)
    return hits


def pinned_lines_of(entry: Any, pins: Any) -> Tuple[Any, List[int]]:
    """(FileLines or None, indexes of the output's lines that are pinned)."""
    fl = pins.for_entry(entry) if pins is not None else None
    if fl is None or not fl.pinned_any:
        return fl, []
    return fl, [i for i, line in enumerate(str(entry.output or "").split("\n")) if fl.covers(line.rstrip("\r"))]


def without_pinned(text: str, indexes: List[int]) -> str:
    """The output with its pinned lines blanked (the line count stays)."""
    if not indexes:
        return text
    drop = set(indexes)
    return "\n".join("" if i in drop else line for i, line in enumerate(text.split("\n")))


def render_pinned(envelope: Envelope, pins: Any, cap: int = 800) -> str:
    """`project_instructions` for the judge: the pinned lines of instruction
    files the agent read that name a token of the command, or that carry a
    marker in an output that names the command. Empty when none."""
    if pins is None:
        return ""
    command = command_text(envelope)
    tokens = [t.lower() for t in significant_tokens(command)] if command else []
    links = command_links(command) if command else []
    if not tokens and not links:
        return ""
    parts: List[str] = []
    seen = set()
    for entry in _outputs(envelope):
        fl, idx = pinned_lines_of(entry, pins)
        if fl is None or not idx:
            continue
        output = str(entry.output)
        lines = output.split("\n")
        # Lines a command link names, found in the whole output (a one-word
        # command counts by its place in the file: a fenced block, a prompt).
        linked = {output.count("\n", 0, s) for c in links for s, _ in c.finditer(output)}
        overlaps = any(t in output.lower() for t in tokens) or bool(linked)
        for i in idx:
            raw = lines[i].rstrip("\r")
            low = raw.lower()
            names = any(t in low for t in tokens) or i in linked
            if not (names or (overlaps and has_marker(raw))):
                continue
            text = " ".join(fl.text_of(raw).split())
            key = (fl.rel, text)
            if key in seen:
                continue
            seen.add(key)
            number = fl.line_number(raw)
            parts.append(f"{fl.rel}" + (f" line {number}" if number else "") + f": {text}")
    out = "\n".join(parts)
    return out if len(out) <= cap else out[: max(0, cap - 3)] + "..."


def has_marker(text: str) -> bool:
    """True when `text` carries any instruction marker (see INSTRUCTION_MARKERS)."""
    return any(marker.search(text or "") for marker in INSTRUCTION_MARKERS)


# Warning noise filter (task context only). In SWE trajectories most of the
# untrusted_context budget went to pytest/Python deprecation warnings that
# overlap the command only through the project path, e.g. a passage
#   /workspace/pkg__pkg__1.0/pkg/io.py:12: DeprecationWarning: foo is deprecated
# for the command `cd /workspace/pkg__pkg__1.0 && python -m pytest tests/...`.
# Such a passage is dropped when ALL of these hold:
#   1. it contains a warning marker (_WARNING_RE),
#   2. it contains no instruction marker (never drop a possible injection),
#   3. every occurrence of every command token in it sits inside a word that is
#      a local file path (_is_path_word) or a warning class name (...Warning).
# A URL, a host, user@host, or any plain word overlapping the command keeps
# the passage. Nothing else is filtered.
_WARNING_RE = re.compile(r"(?:Pytest|Pending)?DeprecationWarning\b|\bis deprecated\b")
_WARNING_WORD_RE = re.compile(r"^\w*Warning$")
_WORD_STRIP = "'\"()[]{}<>,;`"
_LINE_SUFFIX_RE = re.compile(r"(?::\d+)*:?$")
_HOST_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_CODE_EXT_RE = re.compile(r"\.(py|pyi|pyx|js|mjs|cjs|ts|tsx|jsx|rs|go|java|kt|c|h|cc|cpp|hpp|rb|php|sh|cfg|ini|toml|txt|json|ya?ml|md|rst|lock)$", re.I)


def _is_path_word(word: str) -> bool:
    """A local file path as it appears in a traceback or warning line
    (/abs/dir/file.py:12:, tests/test_x.py::test_a, ./a/b, setup.py:3:).
    Never a URL, a host path (first segment ends in a letters-only label, e.g.
    evil.example/x), user@host, a word with other colons, or a bare file name
    written as prose."""
    w = word.strip(_WORD_STRIP)
    if not w or "://" in w or "@" in w:
        return False
    w = re.sub(r"::[^:]*$", "", w)                  # pytest node id: path::test_name
    located = bool(re.search(r":\d+:?$", w))        # traceback / warning style path:12:
    w = _LINE_SUFFIX_RE.sub("", w)
    drive = re.match(r"^[A-Za-z]:[\\/]", w)
    rest = w[2:] if drive else w
    if not rest or ":" in rest:
        return False
    if not re.fullmatch(r"[\w.+~\\/-]+", rest):
        return False
    if "/" in rest or "\\" in rest:
        first = "" if rest.startswith(("/", "\\", "~", ".")) else re.split(r"[\\/]", rest, maxsplit=1)[0]
        # "evil.example/x" is a host path, not a file path (letters-only last
        # label); "pkg__pkg__2.0/x" and "./x" are local.
        return not _HOST_RE.match(first)
    # A bare file name counts only in traceback form (setup.py:12:), not as prose.
    return located and bool(_CODE_EXT_RE.search(rest))


def is_warning_noise(passage: str, tokens: List[str]) -> bool:
    """See the rule above _WARNING_RE. `passage` is raw tool output text."""
    if not _WARNING_RE.search(passage) or has_marker(passage):
        return False
    words = [(m.start(), m.end(), m.group(0)) for m in re.finditer(r"\S+", passage)]
    low = passage.lower()
    for tok in tokens:
        t = tok.lower()
        idx = low.find(t)
        while idx != -1:
            word = next((w for s, e, w in words if s <= idx < e), "")
            if not (_is_path_word(word) or _WARNING_WORD_RE.match(word.strip(_WORD_STRIP).rstrip(":"))):
                return False
            idx = low.find(t, idx + len(t))
    return True


def render_context(envelope: Envelope, window: int = _SNIPPET, cap: int = _CONTEXT_CAP, drop_noise: bool = False,
                   pins: Any = None) -> str:
    """Semantic layer input: passages of tool output that mention something the
    command also mentions, labelled by the tool that produced them. Empty when
    no output overlaps the command. Capped so the provider prompt stays small.

    Overlap is the trigger: an output that never mentions the command
    contributes nothing, so reading a hostile file and then running an
    unrelated command asks the model nothing. Once an output does overlap, the
    passages around any instruction marker in that same output are included
    too, so an order at the top of a file and the command's URL at the bottom
    are both visible to the model (the deterministic gate needs them within
    _WINDOW of each other; this path does not).

    `window` (chars each side) and `cap` (total chars) default to the module
    constants; a router policy can override them via the thresholds
    injection_window_chars / injection_context_cap_chars.

    `drop_noise` (router task_context only): skip passages that are warning
    boilerplate overlapping the command only through file paths
    (is_warning_noise). Off by default, so the output is unchanged.

    `pins` (pins.PinView): lines of an instruction file that the user
    pinned are left out (they go to the judge as project_instructions,
    render_pinned). None: unchanged."""
    command = command_text(envelope)
    if not command:
        return ""
    tokens = significant_tokens(command)
    links = command_links(command)
    # The noise filter compares the exact phrases as plain text (as before
    # command_links); a one-word or prefix link counts through its own
    # matches (link_starts below), not as a substring: "python" is in every
    # traceback path.
    phrases = command_phrases(command)
    if not tokens and not links:
        return ""
    window = int(window) if window else _SNIPPET
    cap = int(cap) if cap else _CONTEXT_CAP
    parts: List[str] = []
    total = 0
    for entry in _outputs(envelope):
        text = entry.output
        if pins is not None:
            text = without_pinned(text, pinned_lines_of(entry, pins)[1])
        low = text.lower()
        spans: List[Tuple[int, int]] = []
        link_starts: List[int] = []
        for tok in tokens:
            idx = low.find(tok.lower())
            while idx != -1 and len(spans) < 4:
                spans.append((max(0, idx - window), min(len(text), idx + len(tok) + window)))
                idx = low.find(tok.lower(), idx + len(tok))
        if links and has_marker(text):
            # A command phrase (short command, command_links) is weak
            # evidence alone: "run npm test" is in every README and is not an
            # instruction to the agent. It brings the output to the judge only
            # when the same output also carries an instruction marker.
            found = 0
            for link in links:
                for s, e in link.finditer(text):
                    if link.kind != "phrase":
                        link_starts.append(s)
                    if found >= 4:
                        continue
                    spans.append((max(0, s - window), min(len(text), e + window)))
                    found += 1
        if not spans:
            continue
        marker_spans = 0
        for marker in INSTRUCTION_MARKERS:
            for m in marker.finditer(text):
                spans.append((max(0, m.start() - window), min(len(text), m.end() + window)))
                marker_spans += 1
                if marker_spans >= 4:
                    break
            if marker_spans >= 4:
                break
        spans.sort()
        merged: List[List[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        label = (entry.summary or entry.tool).strip()[:80]
        for s, e in merged:
            if drop_noise and is_warning_noise(text[s:e], tokens + phrases) and not any(s <= x < e for x in link_starts):
                continue
            # Whitespace collapse is a measured defense, not cosmetics. On 120
            # L1B3RT4S jailbreak prompts (2026-09-22, Jev 1.13) the same full
            # text raw vs flattened moved P(injected) median 0.91 -> 0.94 and
            # cases below 0.70 from 19 -> 1: the prompts steer through layout
            # (fake system blocks, dividers, one-token-per-line) more than words.
            passage = " ".join(text[s:e].split())
            piece = f"[from {entry.tool}: {label}] ...{passage}..."
            if total + len(piece) > cap:
                piece = piece[: max(0, cap - total)]
            if piece:
                parts.append(piece)
                total += len(piece)
            if total >= cap:
                return "\n".join(parts)
    return "\n".join(parts)
