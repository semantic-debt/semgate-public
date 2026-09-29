"""A small shell lexer for two jobs: quote awareness and script extraction.

Written for semgate (Apache-2.0); no code or patterns from other projects.

1. gate_view(command)   the command with *data* removed: comments, the quoted
   text given to commands that only print or search (echo, printf, grep, rg,
   git commit -m, ...), and the bodies of data heredocs (cat > f <<EOF). A
   `grep -rn "rm -rf" docs` then no longer looks like a delete. Redirect
   targets, command substitutions and anything unknown are kept.

2. extract_scripts(command)   code hidden inside strings that WILL run:
   bash/sh -c '...', eval "...", powershell -Command "...", cmd /c "...",
   python -c / node -e / perl -e / ruby -e / php -r, ssh host '...',
   docker/kubectl exec ... -- ..., $(...), `...`, <(...), and heredoc bodies
   fed to a shell or interpreter (bash <<EOF, python - <<EOF, psql <<EOF).
   Shell code is extracted recursively (depth-limited), and shell strings
   inside inline python/node (os.system("..."), subprocess ...) are pulled
   out too. The extracted text is checked by the same rules as the command.

Safety contract (enforced in rules.py): hard denies see the full command
plus the extracted scripts (extraction can only add denies); human gates see
gate_view plus the extracted scripts (masking can only remove data, and a
command that loses its gate still goes to the model, never straight to
allow). Anything the lexer cannot make sense of is left unmasked.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAX_DEPTH = 3
MAX_LEN = 200_000

# Commands whose arguments are text to print, search for, or store. Quoted
# arguments of these are data, not something the shell will run.
DATA_COMMANDS = {"echo", "printf", "print", "write-host", "write-output", "grep", "egrep", "fgrep", "rg", "ag", "ack",
                 "findstr", "select-string", "sls", "jq", "yq", "wc", "sort", "uniq", "head", "tail", "less", "more"}
# echo-like commands: every non-redirect argument is data, quoted or not
PRINT_COMMANDS = {"echo", "printf", "print", "write-host", "write-output"}
# git subcommands + flags whose next argument is a message / search text
GIT_MESSAGE_FLAGS = {"commit": {"-m", "--message"}, "tag": {"-m", "--message"}, "log": {"--grep", "-S", "-G"},
                     "grep": {"-e"}, "stash": {"-m", "--message"}}
GH_TEXT_FLAGS = {"--body", "-b", "--title", "-t", "--notes", "-n", "--message", "-m"}
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "timeout", "stdbuf", "command", "builtin", "exec",
            "xargs", "watch", "strace", "chronic", "caffeinate", "unbuffer", "setsid"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
POWERSHELLS = {"powershell", "pwsh", "powershell.exe", "pwsh.exe"}
INTERPRETER_CODE_FLAGS = {"python": {"-c"}, "python3": {"-c"}, "python2": {"-c"}, "py": {"-c"}, "pypy": {"-c"},
                          "node": {"-e", "--eval", "-p", "--print"}, "deno": {"eval"}, "bun": {"-e", "--eval"},
                          "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "lua": {"-e"}, "osascript": {"-e"}}
HEREDOC_CODE_COMMANDS = SHELLS | {"python", "python3", "py", "node", "perl", "ruby", "php", "psql", "mysql", "sqlite3",
                                  "mongosh", "mongo", "redis-cli", "powershell", "pwsh", "deno", "bun", "sh", "ssh", "kubectl", "docker"}
_OPERATORS = ("&&", "||", ";;", "|&", ";", "|", "&", "\n")
_REDIRECT_RE = re.compile(r"^(\d*|&)(>>?|<<?<?|>&|<&|>\|)(-?)$")


@dataclass
class Token:
    raw: str                       # as written (quotes included)
    value: str                     # quotes removed, escapes resolved
    quoted: bool = False           # any part was quoted
    substitutions: List[str] = field(default_factory=list)   # $(...), `...`, <(...) bodies found inside
    redirect: bool = False         # a redirect operator (>, >>, <, 2>&1 ...)


@dataclass
class Simple:
    """One simple command: tokens up to the next ; && || | & or newline."""
    tokens: List[Token]
    heredocs: List[Tuple[str, str]] = field(default_factory=list)   # (delimiter, body)
    start: int = 0
    end: int = 0


def _read_balanced(s: str, i: int, open_ch: str, close_ch: str) -> int:
    """Index just after the matching close for s[i] == open_ch (quote-aware)."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "'" :
            k = s.find("'", j + 1)
            j = len(s) if k < 0 else k + 1
            continue
        if c == '"':
            j = _skip_double(s, j)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(s)


def _skip_double(s: str, i: int) -> int:
    j = i + 1
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        if c == "$" and s.startswith("$(", j):
            j = _read_balanced(s, j + 1, "(", ")")
            continue
        if c == "`":
            k = s.find("`", j + 1)
            j = len(s) if k < 0 else k + 1
            continue
        j += 1
    return len(s)


def _substitutions(text: str) -> List[str]:
    """Bodies of $(...), `...` and <(...)/>(...) anywhere outside single quotes."""
    out: List[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            k = text.find("'", i + 1)
            i = len(text) if k < 0 else k + 1
            continue
        if text.startswith("$(", i) and not text.startswith("$((", i):
            end = _read_balanced(text, i + 1, "(", ")")
            out.append(text[i + 2:end - 1])
            i = end
            continue
        if c in "<>" and text.startswith("(", i + 1):
            end = _read_balanced(text, i + 1, "(", ")")
            out.append(text[i + 2:end - 1])
            i = end
            continue
        if c == "`":
            k = text.find("`", i + 1)
            if k > 0:
                out.append(text[i + 1:k])
                i = k + 1
                continue
        i += 1
    return out


def split_commands(command: str) -> List[Simple]:
    """Lex into simple commands. Heredoc bodies are attached to the command
    that opened them and removed from the token stream."""
    s = command[:MAX_LEN]
    cmds: List[Simple] = []
    tokens: List[Token] = []
    pending_heredocs: List[Tuple[str, bool]] = []   # (delimiter, strip_tabs)
    cur_heredocs: List[Tuple[str, str]] = []
    start = 0
    i = 0
    buf_raw, buf_val, quoted = "", "", False

    def flush_word():
        nonlocal buf_raw, buf_val, quoted
        if buf_raw:
            tok = Token(raw=buf_raw, value=buf_val, quoted=quoted, substitutions=_substitutions(buf_raw),
                        redirect=bool(_REDIRECT_RE.match(buf_raw)) and not quoted)
            tokens.append(tok)
        buf_raw, buf_val, quoted = "", "", False

    def end_command(pos):
        nonlocal tokens, start, cur_heredocs
        flush_word()
        if tokens or cur_heredocs:
            cmds.append(Simple(tokens=tokens, heredocs=cur_heredocs, start=start, end=pos))
        tokens, cur_heredocs = [], []
        start = pos

    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            if s[i + 1] == "\n":
                i += 2
                continue
            buf_raw += s[i:i + 2]
            buf_val += s[i + 1]
            i += 2
            continue
        if c == "'":
            k = s.find("'", i + 1)
            k = len(s) if k < 0 else k
            buf_raw += s[i:k + 1]
            buf_val += s[i + 1:k]
            quoted = True
            i = k + 1
            continue
        if c == '"':
            k = _skip_double(s, i)
            buf_raw += s[i:k]
            buf_val += re.sub(r'\\(["\\$`])', r"\1", s[i + 1:k - 1])
            quoted = True
            i = k
            continue
        if c == "$" and s.startswith("$(", i):
            k = _read_balanced(s, i + 1, "(", ")")
            buf_raw += s[i:k]
            buf_val += s[i:k]
            i = k
            continue
        if c == "`":
            k = s.find("`", i + 1)
            k = len(s) - 1 if k < 0 else k
            buf_raw += s[i:k + 1]
            buf_val += s[i:k + 1]
            i = k + 1
            continue
        if c in "<>" and s.startswith("(", i + 1) and not buf_raw:
            k = _read_balanced(s, i + 1, "(", ")")
            buf_raw += s[i:k]
            buf_val += s[i:k]
            i = k
            continue
        if c == "#" and not buf_raw:
            # comment to end of line
            k = s.find("\n", i)
            i = len(s) if k < 0 else k
            continue
        if c == "<" and s.startswith("<<", i) and not s.startswith("<<<", i):
            flush_word()
            m = re.match(r"<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2", s[i:])
            if m:
                pending_heredocs.append((m.group(3), m.group(1) == "-"))
                tokens.append(Token(raw=m.group(0), value=m.group(0), redirect=True))
                i += m.end()
                continue
        if c == "\n":
            if pending_heredocs:
                # heredoc bodies start on the next line
                end_pos = i + 1
                for delim, strip in pending_heredocs:
                    lines, j = [], end_pos
                    while j <= len(s):
                        k = s.find("\n", j)
                        line = s[j:] if k < 0 else s[j:k]
                        check = line.lstrip("\t") if strip else line
                        if check.rstrip("\r") == delim:
                            end_pos = len(s) if k < 0 else k + 1
                            break
                        lines.append(line)
                        if k < 0:
                            end_pos = len(s)
                            break
                        j = k + 1
                    cur_heredocs.append((delim, "\n".join(lines)))
                pending_heredocs = []
                end_command(end_pos)
                i = end_pos
                continue
            end_command(i + 1)
            i += 1
            continue
        if c in " \t\r":
            flush_word()
            i += 1
            continue
        op = next((o for o in _OPERATORS if s.startswith(o, i)), None)
        if op and op != "\n":
            if op == "&" and (s.startswith("&>", i) or (buf_raw.endswith((">", "<")))):
                buf_raw += c
                buf_val += c
                i += 1
                continue
            end_command(i + len(op))
            i += len(op)
            continue
        if c in "<>":
            # a redirect glued to a word start (>file, 2>&1) becomes its own token
            if buf_raw and not buf_raw.isdigit() and buf_raw not in ("&",):
                flush_word()
            j = i
            while j < len(s) and s[j] in "<>&|-" and j - i < 3:
                j += 1
            while j < len(s) and s[j].isdigit() and s[j - 1] == "&":
                j += 1
            buf_raw += s[i:j]
            buf_val += s[i:j]
            tok_text = buf_raw
            buf_raw, buf_val = "", ""
            tokens.append(Token(raw=tok_text, value=tok_text, redirect=True))
            i = j
            continue
        buf_raw += c
        buf_val += c
        i += 1
    if pending_heredocs:
        # unterminated heredoc: the rest of the text is its body
        cur_heredocs.extend((d, "") for d, _ in pending_heredocs)
    end_command(len(s))
    return cmds


def _base(word: str) -> str:
    w = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return w


def effective_argv(tokens: List[Token]) -> List[Token]:
    """Tokens from the real program on, skipping wrappers (sudo, env X=1, time,
    timeout 5, nice -n 10 ...), variable assignments and redirects."""
    toks = [t for t in tokens if not t.redirect]
    # drop redirect targets (the word right after a redirect operator)
    clean: List[Token] = []
    skip = False
    for t in tokens:
        if skip:
            skip = False
            continue
        if t.redirect:
            if not re.search(r"[&]\d$", t.raw) and not t.raw.startswith("<<"):
                skip = True
            continue
        clean.append(t)
    toks = clean
    i = 0
    while i < len(toks):
        v = toks[i].value
        b = _base(v)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", v) and not toks[i].quoted:
            i += 1
            continue
        if b in WRAPPERS:
            i += 1
            # skip the wrapper's own options and numeric args (timeout 5, nice -n 10, sudo -u x)
            while i < len(toks) and (toks[i].value.startswith("-") or re.match(r"^\d+[smhd]?$", toks[i].value)
                                     or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i].value)):
                if toks[i].value in ("-u", "-g", "-n", "-s", "-c", "--user") and i + 1 < len(toks):
                    i += 1
                i += 1
            continue
        break
    return toks[i:]


def redirect_targets(tokens: List[Token]) -> List[int]:
    idx = []
    for n, t in enumerate(tokens):
        if t.redirect and not t.raw.startswith("<<") and not re.search(r"&\d$", t.raw) and n + 1 < len(tokens):
            idx.append(n + 1)
    return idx


def _data_token_indexes(simple: Simple) -> List[int]:
    """Indexes (into simple.tokens) of arguments that are data, not code."""
    toks = simple.tokens
    argv = effective_argv(toks)
    if not argv:
        return []
    prog = _base(argv[0].value)
    targets = set(redirect_targets(toks))
    pos = {id(t): n for n, t in enumerate(toks)}
    masked: List[int] = []

    def mask(tok: Token):
        n = pos[id(tok)]
        if n not in targets and not tok.substitutions:
            masked.append(n)

    if prog in PRINT_COMMANDS:
        for t in argv[1:]:
            mask(t)
    elif prog in DATA_COMMANDS:
        for t in argv[1:]:
            if t.quoted:
                mask(t)
    elif prog == "git" and len(argv) > 1:
        sub = argv[1].value
        flags = GIT_MESSAGE_FLAGS.get(sub, set())
        for n, t in enumerate(argv[2:], start=2):
            if t.value in flags and n + 1 < len(argv):
                mask(argv[n + 1])
            elif any(t.value.startswith(f + "=") for f in flags if f.startswith("--")):
                mask(t)
            elif sub == "grep" and t.quoted:
                mask(t)
    elif prog == "gh":
        for n, t in enumerate(argv[1:], start=1):
            if t.value in GH_TEXT_FLAGS and n + 1 < len(argv):
                mask(argv[n + 1])
    return masked


def gate_view(command: str) -> str:
    """The command with data removed (see module doc). Falls back to the
    original text if anything goes wrong."""
    try:
        simples = split_commands(command)
        parts: List[str] = []
        for simple in simples:
            masked = set(_data_token_indexes(simple))
            words = ["'_'" if n in masked else t.raw for n, t in enumerate(simple.tokens)]
            argv = effective_argv(simple.tokens)
            prog = _base(argv[0].value) if argv else ""
            if simple.heredocs and prog not in HEREDOC_CODE_COMMANDS:
                pass   # data heredoc (cat > f <<EOF): body left out
            elif simple.heredocs:
                words += [body for _, body in simple.heredocs]
            parts.append(" ".join(words))
        return "\n".join(parts)
    except Exception:
        return command


_PY_SHELL_STRINGS = re.compile(
    r"(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|"
    r"exec(?:Sync)?|spawnSync|system|shell_exec|passthru|popen|`)\s*\(\s*(?:[rbuf]?)(['\"])(.*?)(?<!\\)\1", re.S)


def _code_after_flag(argv: List[Token], flags) -> Optional[str]:
    for n, t in enumerate(argv[1:], start=1):
        v = t.value
        if v in flags and n + 1 < len(argv):
            return argv[n + 1].value
        for f in flags:
            if f.startswith("-") and len(f) == 2 and v.startswith(f) and len(v) > 2 and not v.startswith("--"):
                return v[2:]
    return None


def _scripts_in(simple: Simple) -> List[Tuple[str, str]]:
    """(kind, code) pairs directly contained in one simple command.
    kind is 'shell' (re-lexed recursively) or 'code' (checked as text)."""
    out: List[Tuple[str, str]] = []
    for t in simple.tokens:
        for sub in t.substitutions:
            out.append(("shell", sub))
    argv = effective_argv(simple.tokens)
    if not argv:
        return out
    prog = _base(argv[0].value)
    rest = [t.value for t in argv[1:]]          # unquoted values, for matching flags
    raw = [t.raw for t in argv[1:]]             # as written, for re-lexing (keeps quoting)

    def rejoin(a: int, b: Optional[int] = None) -> str:
        """Code made of argv[1:][a:b]: one word -> its unquoted value; several
        words -> joined as written so their quoting survives re-lexing."""
        sl = argv[1:][a:b]
        return sl[0].value if len(sl) == 1 else " ".join(t.raw for t in sl)
    if prog in SHELLS or prog == "busybox":
        code = _code_after_flag(argv, {"-c"})
        if code is not None:
            out.append(("shell", code))
    elif prog in POWERSHELLS:
        for n, v in enumerate(rest):
            if v.lower() in ("-command", "-c", "-com", "/c", "-cmd"):
                out.append(("shell", rejoin(n + 1)))
                break
    elif prog in ("cmd", "cmd.exe"):
        for n, v in enumerate(rest):
            if v.lower() in ("/c", "/k", "/r"):
                out.append(("shell", rejoin(n + 1)))
                break
    elif prog in ("eval", "invoke-expression", "iex"):
        out.append(("shell", rejoin(0)))
    elif prog in ("ssh",):
        # ssh [opts] host command...   (options with a value: -i -p -l -o -F -J -L -R -D)
        n, host_seen = 0, False
        while n < len(rest):
            v = rest[n]
            if not host_seen and v.startswith("-"):
                n += 2 if v in ("-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-E", "-S", "-W", "-b", "-c", "-e", "-m", "-O", "-Q", "-w") else 1
                continue
            if not host_seen:
                host_seen = True
                n += 1
                continue
            out.append(("shell", rejoin(n)))
            break
    elif prog in ("docker", "podman", "kubectl", "oc", "nerdctl") and "exec" in rest:
        if "--" in rest:
            out.append(("shell", rejoin(rest.index("--") + 1)))
        else:
            # docker exec [opts] container cmd...
            k = rest.index("exec") + 1
            while k < len(rest) and rest[k].startswith("-"):
                k += 2 if rest[k] in ("-u", "--user", "-w", "--workdir", "-e", "--env", "-c", "--container", "-n", "--namespace") else 1
            if k + 1 < len(rest):
                out.append(("shell", rejoin(k + 1)))
    elif prog == "find" and ("-exec" in rest or "-execdir" in rest or "-ok" in rest):
        for flag in ("-exec", "-execdir", "-ok"):
            if flag in rest:
                k = rest.index(flag) + 1
                body = []
                while k < len(rest) and rest[k] not in (";", "\\;", "+"):
                    body.append(raw[k])
                    k += 1
                out.append(("shell", " ".join(body)))
    else:
        flags = INTERPRETER_CODE_FLAGS.get(prog) or INTERPRETER_CODE_FLAGS.get(re.sub(r"[\d.]+$", "", prog))
        if flags:
            code = _code_after_flag(argv, flags)
            if code is not None:
                out.append(("code", code))
    if simple.heredocs and prog in HEREDOC_CODE_COMMANDS:
        for _, body in simple.heredocs:
            out.append(("shell" if prog in SHELLS or prog in ("ssh",) else "code", body))
    return out


def extract_scripts(command: str, depth: int = 0) -> List[str]:
    """All code that the command will run from inside strings, heredocs and
    substitutions, recursively. Never raises."""
    if depth >= MAX_DEPTH or not command or len(command) > MAX_LEN:
        return []
    found: List[str] = []
    try:
        for simple in split_commands(command):
            for kind, code in _scripts_in(simple):
                code = code.strip()
                if not code or code in found:
                    continue
                found.append(code)
                if kind == "shell":
                    found += [c for c in extract_scripts(code, depth + 1) if c not in found]
                else:
                    for m in _PY_SHELL_STRINGS.finditer(code):
                        inner = m.group(2).strip()
                        if inner and inner not in found:
                            found.append(inner)
                            found += [c for c in extract_scripts(inner, depth + 1) if c not in found]
    except Exception:
        return found
    return found
