"""Reading and checking one hook event (claude_hook, antigravity_hook, serve).

Owner decision (2026-09-23): no small payload cap. The size of every payload
is recorded as evidence (semgate.payloadsize). The only hard limit is a memory
guard: stdin is read up to `hook_max_payload_bytes` (semgate.json, default
64 MiB). Above it the payload is not parsed, the decision is ask and the
ledger gets an incident. The rest of an over-limit payload is read and
thrown away so the host is not blocked writing it.

The session id keys state files (deny streak, agent files), so it must be a
short plain token: at most 256 characters of [A-Za-z0-9._:-], not only dots.
An invalid id is rejected the same way (ask + ledger incident). An empty id is
allowed (hosts without one; state keyed by it is then off).

Every failure raises InputRejected; the callers already turn any exception
into ask (never allow).

Where an early failure is recorded (before the hook loaded its config):
`early_ledger_path`. It is the `ledger_file` of the --config file when that
file can be read, resolved as the hooks resolve it (semgate.storepaths: a
relative path against the config's folder, not set: `~/.semgate/<host>/`);
else `~/.semgate/<host>/ledger.jsonl`. Never a path relative to the current
directory, which for a hook is the agent's project.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple, Union

DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MIN_MAX_PAYLOAD_BYTES = 1024
SESSION_ID_MAX = 256
_SESSION_RE = re.compile(r"[A-Za-z0-9._:-]+")
_CHUNK = 1 << 20


class InputRejected(ValueError):
    def __init__(self, message: str, kind: str, detail: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.kind = kind
        self.detail = dict(detail or {})


def _mib(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MiB"


def max_payload_bytes(config: Union[str, Mapping[str, Any], None]) -> int:
    """`hook_max_payload_bytes` from semgate.json (a path or a loaded dict).
    Missing, unreadable or invalid (not an int >= 1024): the default."""
    try:
        if isinstance(config, str):
            with open(os.path.expanduser(config), encoding="utf-8") as handle:
                config = json.load(handle)
        value = config.get("hook_max_payload_bytes") if isinstance(config, Mapping) else None
    except (OSError, ValueError):
        return DEFAULT_MAX_PAYLOAD_BYTES
    if isinstance(value, bool) or not isinstance(value, int) or value < MIN_MAX_PAYLOAD_BYTES:
        return DEFAULT_MAX_PAYLOAD_BYTES
    return value


@dataclass
class RawInput:
    data: Optional[bytes]     # None when over the limit
    size: int                 # bytes seen (all of them, also when over the limit)
    limit: int

    @property
    def over_limit(self) -> bool:
        return self.data is None


def read_limited(stream: Any = None, limit: int = DEFAULT_MAX_PAYLOAD_BYTES) -> RawInput:
    """Read a binary stream to EOF keeping at most `limit` bytes."""
    if stream is None:
        stream = getattr(sys.stdin, "buffer", sys.stdin)   # tests may replace stdin with a text stream
    buf = bytearray()
    size = 0
    over = False
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        size += len(chunk)
        if not over:
            if size > limit:
                over = True
                buf = bytearray()      # free it; the rest is only counted
            else:
                buf += chunk
    return RawInput(None if over else bytes(buf), size, limit)


def parse_event(raw: RawInput) -> Dict[str, Any]:
    if raw.over_limit:
        raise InputRejected(
            f"hook payload is {_mib(raw.size)}, above hook_max_payload_bytes ({_mib(raw.limit)}); not parsed",
            "payload_over_limit", {"bytes": raw.size, "limit": raw.limit})
    try:
        event = json.loads(raw.data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InputRejected(f"hook input is not valid JSON ({exc})", "payload_not_json", {"bytes": raw.size})
    if not isinstance(event, dict):
        raise InputRejected("hook input must be a JSON object", "payload_not_object", {"bytes": raw.size})
    return event


def read_event(config_path: str, stream: Any = None) -> Tuple[Dict[str, Any], int]:
    """(event, raw payload bytes). Raises InputRejected."""
    raw = read_limited(stream, max_payload_bytes(config_path))
    return parse_event(raw), raw.size


def session_id_problem(value: Any) -> str:
    """"" when `value` is an acceptable session id (or empty), else why not."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        return f"session id is a {type(value).__name__}, not a string"
    if len(value) > SESSION_ID_MAX:
        return f"session id is {len(value)} characters (limit {SESSION_ID_MAX})"
    if not _SESSION_RE.fullmatch(value):
        return "session id has characters outside [A-Za-z0-9._:-]"
    if set(value) == {"."}:
        return "session id is only dots"
    return ""


def session_id_digest(value: Any) -> Dict[str, Any]:
    """{"length", "sha256_12"} of a session id (repr() for a non-string): what
    records keep of an invalid id instead of the id itself."""
    text = value if isinstance(value, str) else repr(value)
    return {"length": len(text), "sha256_12": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]}


def require_session_id(value: Any) -> None:
    problem = session_id_problem(value)
    if problem:
        raise InputRejected(problem + "; not used as a state key", "invalid_session_id", session_id_digest(value))


def host_state_ledger(host: str) -> str:
    """`~/.semgate/<host>/ledger.jsonl` (the user-level state dir of `semgate
    init <host>`), for records when the config cannot be read."""
    from .storepaths import host_ledger
    return host_ledger(host)


def early_ledger_path(config: Union[str, Mapping[str, Any], None], host: str) -> str:
    """The ledger for a record written on an early-failure path (before or
    without the loaded config). `config` is the --config path or a loaded
    dict (already resolved by storepaths.load). A readable config file: its
    `ledger_file` resolved as the hooks resolve it (storepaths.load), so the
    record lands next to the hook's other records. A config that cannot be
    read (missing, not JSON, not an object) or has no ledger_file:
    host_state_ledger(host). Never a path relative to the current directory."""
    from . import storepaths
    if isinstance(config, str):
        try:
            return str(storepaths.load(config, host)["ledger_file"])
        except (OSError, ValueError):
            return host_state_ledger(host)
    if not isinstance(config, Mapping):
        return host_state_ledger(host)
    value = config.get("ledger_file")
    return os.path.expanduser(value) if isinstance(value, str) and value.strip() else host_state_ledger(host)


def note_rejection(config: Union[str, Mapping[str, Any], None], exc: BaseException, host: str = "unknown") -> None:
    """Ledger incident `hook_input_rejected` (best effort, never raises), in
    early_ledger_path(config, host)."""
    if not isinstance(exc, InputRejected):
        return
    try:
        from .ledger import Ledger
        Ledger(early_ledger_path(config, host)).record_incident(
            "hook_input_rejected", {"reason": exc.kind, "message": str(exc)[:300], **exc.detail})
    except Exception as err:
        print(f"semgate: could not record hook_input_rejected: {type(err).__name__}: {err}", file=sys.stderr)


# ---------------------------------------------------------------- serve (JSON lines)


@dataclass
class OversizeLine:
    size: int
    limit: int
    head: str = ""            # the first 100 characters (to recover the request id)

    @property
    def request_id(self) -> Any:
        """The numeric id when the line starts with {"id": N (the plugin's
        JSON.stringify order), else None."""
        m = re.match(r'\s*\{\s*"id"\s*:\s*(\d{1,15})\s*,', self.head)
        return int(m.group(1)) if m else None


def bounded_lines(stream: Any, limit: int) -> Iterator[Union[str, OversizeLine]]:
    """Lines of a text stream, each at most `limit` characters. A longer line
    is read to its end and thrown away; an OversizeLine stands for it."""
    while True:
        line = stream.readline(limit + 1)
        if not line:
            return
        if len(line) <= limit or line.endswith("\n"):
            yield line
            continue
        size, head = len(line), line[:100]
        del line
        while True:
            more = stream.readline(_CHUNK)
            if not more:
                break
            size += len(more)
            if more.endswith("\n"):
                break
        yield OversizeLine(size, limit, head)


# ---------------------------------------------------------------- model id


def model_from_transcript(path: Any, tail_bytes: int = 256 * 1024) -> str:
    """The model id of the latest assistant entry in a Claude-Code-style JSONL
    transcript (message.model), from its last `tail_bytes`. "" on any problem."""
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            end = handle.tell()
            handle.seek(max(0, end - tail_bytes))
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return ""
    for line in reversed(text.splitlines()):
        if '"model"' not in line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        msg = entry.get("message") if isinstance(entry, Mapping) else None
        model = msg.get("model") if isinstance(msg, Mapping) else None
        if isinstance(model, str) and model and not model.startswith("<"):
            return model
    return ""


def model_from_messages(messages: Any) -> str:
    """OpenCode: the latest assistant message's info.modelID (V1 shape)."""
    if not isinstance(messages, list):
        return ""
    for m in reversed(messages):
        info = m.get("info") if isinstance(m, Mapping) else None
        if isinstance(info, Mapping) and info.get("role") == "assistant" and isinstance(info.get("modelID"), str):
            return info["modelID"]
    return ""
