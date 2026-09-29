"""Find secrets in text (tool outputs), and label them in semgate's own files.

find(): detection. Used by semgate.exposures to notice when a tool output
shows a secret to the agent. Its patterns are a superset of
scriptsource._SECRET_PATTERNS (the F4 script-source scrub, unchanged;
tests/test_secret_exposure.py checks that every value the scrub removes is
also found here).

label_secrets(): replaces every occurrence of each found value with
`<secret TYPE MASKED>` (label()). Used by semgate.tooloutputs for the tool
output store and by semgate.exposures for the user's turns it sends to the
judge. It never changes what the agent or the host sees.

Detectors, in priority order (a later match that overlaps an earlier one is
dropped, so one value is reported once, with its most specific type):

  PEM private key      -----BEGIN ... PRIVATE KEY----- with >= 40 body chars
  Anthropic API key    sk-ant-...
  OpenAI-style API key sk-... / sk-proj-... (20+ chars, letters and digits)
  GitHub token         ghp_ gho_ ghu_ ghs_ ghr_ github_pat_
  Slack token          xoxb- xoxp- xoxa- xoxr- xoxs- xoxe- xoxo-
  AWS access key ID    AKIA / ASIA + 16 (the AWS docs example ...EXAMPLE is skipped)
  JWT                  eyJ<header>.eyJ<payload>.<signature>
  password in URL      scheme://user:PASSWORD@host
  secret NAME          NAME=value (no spaces), NAME = "value", "name": "value",
                       where NAME looks secret (KEY with a qualifier, SECRET,
                       TOKEN, PASSWORD, PASSWD, PASS, PWD, CREDENTIAL(S),
                       API_KEY, PRIVATE, DSN, ...), and the value looks like a
                       secret (>= 8 chars, no spaces, not a path, URL, number,
                       placeholder or variable reference, at least two
                       character classes).
  quoted secret NAME   NAME = 'value', NAME: "value" (quoted values only),
                       where NAME looks secret as above or its last part is
                       AUTH (`basic_auth`), and the value has >= 12 chars and
                       looks like a secret by quoted_value(): one character
                       class is enough (`'abcdefghijklmnop'`), but a
                       one-class value is skipped when it is all capitals
                       (`AUTOINCREMENT`), an identifier
                       (`refresh_token`, `x-api-key`, `my.setting`), holds a
                       secret word (`authorization`, `secretkey`), a
                       placeholder (`xxx`, `test`, `your_..._here`), a
                       domain, or has fewer than 5 distinct characters.

Only the first MAX_SCAN characters of a text are scanned (bounded time).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

MAX_SCAN = 512 * 1024


@dataclass(frozen=True)
class Found:
    type: str          # e.g. "AWS access key ID", "secret DB_PASSWORD"
    value: str         # the raw secret: never written anywhere by semgate
    start: int         # span of the value in the scanned text
    end: int


def mask(value: str) -> str:
    """First 4 + last 4 characters for 16+ chars (`AKIA…WXYZ`); 2 + 2 for
    10-15; 1 + 1 for 6-9; only `…` below 6."""
    n = len(value)
    k = 4 if n >= 16 else 2 if n >= 10 else 1 if n >= 6 else 0
    return f"{value[:k]}…{value[-k:]}" if k else "…"


# ---------------------------------------------------------------- token patterns

_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----")
_PEM_BODY_CHARS = re.compile(r"[A-Za-z0-9+/=\s:,\-\\]*")
_TOKENS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("Anthropic API key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI-style API key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)
_URL_PASSWORD = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/?#@\"'<>]{1,256}:([^\s/?#@\"'<>]{1,256})@[A-Za-z0-9\[]")

# ---------------------------------------------------------------- NAME = value

_QUOTED = re.compile(
    r"""(?<![\w.])["']?(?P<name>[A-Za-z_][\w.-]{0,80})["']?[ \t]{0,3}(?:=>|:=|=|:)[ \t]{0,3}"""
    r"""(?P<q>["'])(?P<val>[^"'\r\n]{1,1024})(?P=q)""")
_UNQUOTED = re.compile(r"""(?<![\w.])(?P<name>[A-Za-z_][\w.]{0,80})=(?P<val>[^\s"'`;&|<>(){}\[\],]{1,1024})""")

_SECRET_PARTS = frozenset({"SECRET", "SECRETS", "TOKEN", "TOKENS", "PASSWORD", "PASSWORDS", "PASSWD", "PASS", "PWD",
                           "CREDENTIAL", "CREDENTIALS", "CREDS", "APIKEY", "APIKEYS", "DSN", "PASSPHRASE"})
_SUBSTRINGS = ("PASSWORD", "PASSWD", "SECRET", "APIKEY", "CREDENTIAL")
# A KEY / PRIVATE part counts only next to another part that is not one of these.
_KEY_NOT_SECRET = frozenset({"PUBLIC", "PUBLISHABLE", "PRIMARY", "FOREIGN", "SORT", "PARTITION", "CACHE", "IDEMPOTENCY",
                             "ROUTING", "OBJECT", "SHORTCUT", "HOT", "MAP", "LOOKUP", "DEDUPE", "UNIQUE", "INDEX",
                             "TRANSLATION", "I18N", "SIGNING_PUBLIC", "HASH", "GROUP", "PARTITIONING", "COMPOSITE",
                             "SESSION_STORAGE", "STORAGE", "LOCAL_STORAGE", "REDIS", "ENV", "CONFIG", "DICT", "JSON"})
_TOKEN_NOT_SECRET = frozenset({"PAGE", "NEXT", "PREV", "PREVIOUS", "CONTINUATION", "CURSOR", "SYNC", "RESUME",
                               "CANCELLATION", "IDEMPOTENCY", "CHANGE", "MAX", "MIN", "NUM", "TOTAL", "INPUT", "OUTPUT",
                               "COMPLETION", "PROMPT", "CACHE", "REASONING"})
# A last part that names metadata about a secret, not the secret.
_SAFE_LAST = frozenset({"PATH", "FILE", "FILES", "DIR", "ID", "IDS", "NAME", "NAMES", "ARN", "TYPE", "LENGTH", "LEN",
                        "SIZE", "TTL", "EXPIRY", "EXPIRES", "EXPIRATION", "HEADER", "PREFIX", "ENDPOINT", "REGION",
                        "FORMAT", "ALGORITHM", "ALG", "VERSION", "COUNT", "ENABLED", "MODE", "FIELD", "KIND",
                        "LOCATION", "POLICY", "ROTATION", "SOURCE", "PROVIDER", "METHOD", "SCOPE", "SCOPES",
                        "USAGE", "HINT", "LABEL", "TIMEOUT", "LIMIT", "URL", "URI", "HOST", "PORT", "USER",
                        "USERNAME", "PROMPT", "REQUIRED", "MIN", "MAX", "RESET", "CHANGED", "UPDATED", "CREATED",
                        "AT", "PROMPTED", "STRENGTH", "POLICY", "RULES", "HASH", "HASHER", "HASHERS", "VALIDATORS",
                        "BACKEND", "BACKENDS", "CLASS", "COLUMN", "INPUT", "FIELDS", "FILENAME", "ENV", "VAR"})
_NOT_SECRET_NAMES = frozenset({"PATH", "HOME", "PWD", "OLDPWD", "USER", "SHELL", "TERM", "LANG", "HOSTNAME", "LOGNAME",
                               "KEY", "KEYS", "PRIVATE", "ID", "NAME"})
_PLACEHOLDER_BITS = ("xxxx", "****", "redacted", "placeholder", "your_", "your-", "yourkey", "yourtoken", "example",
                     "changeme", "change_me", "dummy", "replace_me", "replaceme", "<", ">", "…", "...", "${", "$(",
                     "{{", "%s", "%(", "_here", "-here", "insert", "todo", "fixme", "secret_value", "not_set",
                     "notset", "sample")
_PLACEHOLDER_WORDS = frozenset({"password", "passwd", "secret", "token", "apikey", "api_key", "undefined", "changeit",
                                "required", "optional", "string", "none", "null", "true", "false"})
_CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_WIN_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_ATTR_PATH = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_ONE_CASE_WORD = re.compile(r"^(?:[a-z_]+|[A-Z_]+)$")


def _parts(name: str) -> List[str]:
    out: List[str] = []
    for chunk in re.split(r"[_.\-]+", name):
        if chunk:
            out += [p.upper() for p in _CAMEL.findall(chunk)] or [chunk.upper()]
    return out


def secret_name(name: str) -> bool:
    """True when a variable / key name names a secret value."""
    upper = name.upper().replace("-", "_").replace(".", "_")
    if upper in _NOT_SECRET_NAMES:
        return False
    parts = _parts(name)
    if not parts or parts[-1] in _SAFE_LAST:
        return False
    if upper.endswith("DATABASE_URL") or upper.endswith("DB_URL"):
        return True                  # only reached for a non-URL value (URLs go to the URL detector)
    others = set(parts)
    for i, p in enumerate(parts):
        rest = others - {p}
        if p in ("KEY", "KEYS"):
            if len(parts) >= 2 and not (rest & _KEY_NOT_SECRET):
                return True
        elif p == "PRIVATE":
            if len(parts) >= 2 and not (rest & _KEY_NOT_SECRET):
                return True
        elif p in ("TOKEN", "TOKENS"):
            if not (rest & _TOKEN_NOT_SECRET):
                return True
        elif p in _SECRET_PARTS:
            return True
        elif p.startswith("SECRETAR"):
            continue                 # SECRETARY
        elif any(s in p for s in _SUBSTRINGS) or (p.endswith("TOKEN") and len(p) > 5 and not p.startswith("TOKEN")):
            return True
    return False


def _classes(value: str) -> int:
    return (any(c.islower() for c in value) + any(c.isupper() for c in value) + any(c.isdigit() for c in value)
            + any(not c.isalnum() and c not in "_-." for c in value))


def secret_value(value: str, name: str = "", quoted: bool = False) -> bool:
    """True when `value` (assigned to a secret-looking name) looks like a real
    secret, not a path, URL, number, placeholder or reference."""
    v = value.strip()
    if len(v) < 8 or any(c.isspace() for c in v):
        return False
    low = v.lower()
    if low in _PLACEHOLDER_WORDS or any(b in low for b in _PLACEHOLDER_BITS):
        return False
    if v[0] in "$%@&*#" or len(set(v)) <= 2:
        return False
    if "://" in v:                                   # URL: the URL detector decides
        return False
    if v.startswith(("/", "./", "../", "~/", "~\\", ".\\", "..\\")) or _WIN_PATH.match(v):
        return False
    if re.fullmatch(r"[\d.,:+\-]+", v):              # numbers, versions, times
        return False
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):   # an e-mail address
        return False
    if not quoted and _ATTR_PATH.match(v):           # settings.API_KEY, os.environ
        return False
    if "EXAMPLE" in v:                               # AWS docs example keys
        return False
    if _classes(v) >= 2:
        return not re.fullmatch(r"[A-Z][A-Z0-9_]*", v)   # another variable's NAME
    return len(v) >= 20 and not _ONE_CASE_WORD.match(v)


QUOTED_MIN = 12
_WIDE_PLACEHOLDER_WORDS = frozenset({"test", "testing", "xxx", "xxxxxx"})
_SECRET_WORDS = ("token", "secret", "password", "passwd", "credential", "auth", "apikey", "api_key", "key", "bearer")
_DOMAIN = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


def quoted_name(name: str) -> bool:
    """secret_name(), plus names whose last part is AUTH (`auth`,
    `basic_auth`, `HTTP_AUTH`): only used for quoted values."""
    if secret_name(name):
        return True
    upper = name.upper().replace("-", "_").replace(".", "_")
    parts = _parts(name)
    return bool(parts) and parts[-1] == "AUTH" and upper not in _NOT_SECRET_NAMES


def quoted_value(value: str) -> bool:
    """True when a quoted value of >= QUOTED_MIN chars, assigned to a secret
    name, looks like a secret. Same exclusions as secret_value() (spaces,
    placeholders, `$VAR`, URLs, paths, numbers, e-mail addresses, AWS
    example keys, another variable's NAME); in addition one character class
    is enough, unless the value is all capitals, an identifier (has `_`, `-`
    or `.`), holds a secret word, is a domain, or has fewer than 5 distinct
    characters."""
    v = value.strip()
    if len(v) < QUOTED_MIN:
        return False
    if secret_value(v, quoted=True):
        return True
    low = v.lower()
    if any(c.isspace() for c in v) or low in _PLACEHOLDER_WORDS or low in _WIDE_PLACEHOLDER_WORDS             or any(b in low for b in _PLACEHOLDER_BITS) or "xxx" in low:
        return False
    if v[0] in "$%@&*#" or len(set(low)) < 5 or "://" in v or "EXAMPLE" in v:
        return False
    if v.startswith(("/", "./", "../", "~/", "~\\", ".\\", "..\\")) or _WIN_PATH.match(v):
        return False
    if _classes(v) != 1 or not v.isalnum():      # two classes were secret_value()'s call; identifiers stop here
        return False
    if v.isdigit() or v.isupper() or _DOMAIN.match(low) or low.startswith("test") or any(w in low for w in _SECRET_WORDS):
        return False                                 # isupper: SQL keywords and enum constants (`AUTOINCREMENT`)
    return True


PEM_MAX_BLOCKS = 100
PEM_MAX_BODY = 16384


def _pem(text: str) -> List[Found]:
    """Forward-only scan: each header looks at most PEM_MAX_BODY characters
    ahead, up to the next `-----`; at most PEM_MAX_BLOCKS headers (linear
    time even for text full of headers)."""
    out: List[Found] = []
    pos = 0
    for _ in range(PEM_MAX_BLOCKS):
        m = _PEM_BEGIN.search(text, pos)
        if m is None:
            break
        limit = min(len(text), m.end() + PEM_MAX_BODY)
        end_marker = f"-----END {m.group(1)}PRIVATE KEY-----"
        dash = text.find("-----", m.end(), limit)
        stop = dash if dash >= 0 and text.startswith(end_marker, dash) else -1
        if dash >= 0:
            body_end = dash
        else:                        # output cut before the END line: the body up to the first non-PEM character
            body_end = _PEM_BODY_CHARS.match(text, m.end(), limit).end()
        pos = max(m.end(), body_end)
        body = text[m.end():body_end]
        clean = re.sub(r"\s+", "", body.replace("\\n", "").replace("\\r", ""))
        # drop header lines of encrypted PEM (Proc-Type: 4,ENCRYPTED / DEK-Info: ...)
        clean = re.sub(r"Proc-Type:[^A-Za-z0-9+/]*\d,[A-Z]+|DEK-Info:[A-Z0-9-]+,[0-9A-F]+", "", clean)
        if len(clean) < 40:
            continue
        span_end = stop + len(end_marker) if stop >= 0 else body_end
        out.append(Found("PEM private key", clean, m.start(), span_end))
    return out


def find(text: str) -> List[Found]:
    """Secrets in `text` (first MAX_SCAN chars), in order of position, each
    distinct value once."""
    if not text:
        return []
    t = text[:MAX_SCAN]
    found: List[Found] = []
    # Accepted spans never overlap, so sorted starts and their ends find an
    # overlap with two neighbours (binary search); a list scan was quadratic
    # (10,000 hits in one output: 50 million comparisons, seconds).
    starts: List[int] = []
    ends: List[int] = []

    def add(kind: str, value: str, s: int, e: int) -> None:
        if not value:
            return
        i = bisect.bisect_left(starts, s)
        if (i > 0 and ends[i - 1] > s) or (i < len(starts) and starts[i] < e):
            return
        starts.insert(i, s)
        ends.insert(i, e)
        found.append(Found(kind, value, s, e))

    if "PRIVATE KEY-----" in t:
        for f in _pem(t):
            add(f.type, f.value, f.start, f.end)
    for kind, pattern in _TOKENS:
        for m in pattern.finditer(t):
            v = m.group(0)
            if kind == "OpenAI-style API key":
                tail = v[3:]
                if v.startswith("sk-ant-") or not (any(c.isdigit() for c in tail) and any(c.isalpha() for c in tail)):
                    continue
            if kind == "AWS access key ID" and v.endswith("EXAMPLE"):
                continue
            add(kind, v, m.start(), m.end())
    for m in _URL_PASSWORD.finditer(t):
        pw = m.group(1)
        low = pw.lower()
        if len(pw) < 4 or pw[0] in "${<%*" or low in _PLACEHOLDER_WORDS or low in ("pass", "pwd", "****") \
                or any(b in low for b in ("xxxx", "****", "<", "${", "your", "redacted", "placeholder")):
            continue
        add("password in URL", pw, m.start(1), m.end(1))
    for pattern, quoted in ((_QUOTED, True), (_UNQUOTED, False)):
        for m in pattern.finditer(t):
            name, val = m.group("name"), m.group("val")
            if not quoted:
                val = val.rstrip(".:")
            if quoted:
                hit = quoted_name(name) and (quoted_value(val) or (secret_name(name) and secret_value(val, name, True)))
            else:
                hit = secret_name(name) and secret_value(val, name, False)
            if hit:
                add(f"secret {name[:40]}", val, m.start("val"), m.start("val") + len(val))
    found.sort(key=lambda f: f.start)
    seen = set()
    unique: List[Found] = []
    for f in found:
        if f.value not in seen:
            seen.add(f.value)
            unique.append(f)
    return unique


def mask_in(text: str, values: List[str]) -> str:
    """`text` with each of `values` (and every secret find() sees in it)
    replaced by its mask. For short labels such as a command summary."""
    out = text
    for v in sorted(set(values) | {f.value for f in find(text)}, key=len, reverse=True):
        if v:
            out = out.replace(v, mask(v))
    return out


def first(text: str) -> Optional[Found]:
    hits = find(text)
    return hits[0] if hits else None


# ---------------------------------------------------------------- labels (semgate's own files)

LABEL_PASSES = 3                 # passes of find(): a repeated multi-line PEM block is found in a later pass
LITERAL_HITS_MAX = 200           # distinct values whose other literal occurrences are also replaced


def label(f: Found) -> str:
    """`<secret TYPE MASKED>`, e.g. `<secret DB_PASSWORD hu…XY>`,
    `<secret GitHub token ghp_…Zz9Y>` (the "secret " prefix of a NAME type
    is not repeated)."""
    kind = f.type[len("secret "):] if f.type.startswith("secret ") else f.type
    return f"<secret {kind} {mask(f.value)}>"


def label_secrets(text: str, extra: Sequence[Found] = (),
                  keep: Optional[Callable[[str, int, int], bool]] = None) -> Tuple[str, int, List[Found]]:
    """(`text` with every occurrence of every secret value replaced by
    label(f), number of replacements, the secrets found in `text`).

    `extra`: secrets found elsewhere (the tool output, for its command
    line); their values are replaced where they occur in `text` too.
    `keep(text, start, end)` True leaves that occurrence as it is
    (tooloutputs: an occurrence inside text that carries an instruction
    marker). find() scans the first MAX_SCAN chars; the other occurrences of
    a found value are replaced in the whole text."""
    out, count = text or "", 0
    found_all: List[Found] = []
    for n in range(LABEL_PASSES):
        hits = find(out)
        found_all += hits
        spans: List[Tuple[int, int, str]] = []
        for i, f in enumerate(list(hits) + (list(extra) if n == 0 else [])):
            lab = label(f)
            occ = [(f.start, f.end)] if i < len(hits) else []
            if f.value and (i >= len(hits) or i < LITERAL_HITS_MAX):
                j = out.find(f.value)
                while j >= 0:
                    occ.append((j, j + len(f.value)))
                    j = out.find(f.value, j + len(f.value))
            for s, e in occ:
                if keep is None or not keep(out, s, e):
                    spans.append((s, e, lab))
        spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        kept: List[Tuple[int, int, str]] = []
        for s, e, lab in spans:
            if not kept or s >= kept[-1][1]:
                kept.append((s, e, lab))
        if not kept:
            break
        parts: List[str] = []
        pos = 0
        for s, e, lab in kept:
            parts += [out[pos:s], lab]
            pos = e
        parts.append(out[pos:])
        out = "".join(parts)
        count += len(kept)
    unique: Dict[str, Found] = {}
    for f in found_all:
        unique.setdefault(f.value, f)
    return out, count, list(unique.values())
