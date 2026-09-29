"""Cross-process locks and safe reads/writes for semgate's shared store files.

Why: every hook call is its own process. Several run at once (parallel tool
calls, subagents, several sessions, `semgate serve`). A `threading.Lock`
orders threads of one process only. On Windows the C runtime does an
O_APPEND write as "seek to the end, then write", so two processes can write
at the same offset and one record overwrites the other (formal/REPORT.md, S1:
5-18 % of records lost in the stress tests).

How:
  - The lock is an OS lock on a sidecar file `<name>.lock` next to the store
    (Windows `msvcrt.locking` on byte 0; POSIX `fcntl.flock(LOCK_EX)`). The
    sidecar holds no data and is never modified, so opening it is cheap (on
    Windows, opening a just-modified file with read access costs ~9 ms, most
    likely a virus scan; measured in formal/results/after). Locks of two
    handles conflict even inside one process.
  - The OS drops the lock when the holder exits or crashes. The sidecar's
    existence means nothing: a crashed hook never blocks later hooks, and
    there is no stale lock to clean up.
  - Threads of one process first take a per-path threading lock, so they do
    not busy-poll each other.
  - Waiting is bounded (DEFAULT_TIMEOUT_S, env SEMGATE_LOCK_TIMEOUT_S). When
    the lock is not free in time, `LockTimeout` is raised. Callers fail
    closed: the decision can only become an ask, never an allow.
  - The same sidecar orders files that are replaced with os.replace (small
    state files such as deny_streak.json).

Appends: one record = one `os.write` of the whole line through an
O_WRONLY|O_APPEND handle, under the lock (the C runtime's "seek to the end,
then write" is safe when only the lock holder writes). With `repair=True`
(the feedback store) the last byte is checked first: if a writer crashed in
the middle of a line, a newline is written first, so the next record is never
glued onto a torn line. The hot stores skip that check (it needs a read
handle); there a crash in the middle of one write can make the next record
unreadable, which every reader skips (and the session-drift reader turns
into an ask).

Reads: `read_jsonl` returns only complete, well-formed lines. A malformed
line is skipped and counted (never parsed "tolerantly": a partial line must
never count as a record). A last line without its newline is a write in
progress, or a crashed write; it is ignored and not counted as malformed.
"""
from __future__ import annotations

import json
import os
import random
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Tuple, Union

DEFAULT_TIMEOUT_S = 5.0
PathLike = Union[str, "os.PathLike[str]"]

_thread_locks: Dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


class LockTimeout(TimeoutError):
    """The cross-process lock on a store file was not free in time."""


def timeout_s() -> float:
    try:
        value = float(os.environ.get("SEMGATE_LOCK_TIMEOUT_S", "") or DEFAULT_TIMEOUT_S)
    except ValueError:
        return DEFAULT_TIMEOUT_S
    return value if value > 0 else DEFAULT_TIMEOUT_S


def _key(path: PathLike) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _thread_lock(path: PathLike) -> threading.Lock:
    key = _key(path)
    with _thread_locks_guard:
        lock = _thread_locks.get(key)
        if lock is None:
            lock = _thread_locks[key] = threading.Lock()
        return lock


if os.name == "nt":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

    _OPEN_FLAGS = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    _APPEND_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    _OPEN_FLAGS = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    _APPEND_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)


def lock_path(path: PathLike) -> Path:
    """The sidecar that carries the lock of `path`: `<name>.lock` (a path that
    already ends in .lock is its own sidecar)."""
    p = Path(path)
    return p if p.name.endswith(".lock") else p.with_name(p.name + ".lock")


@contextmanager
def exclusive(path: PathLike, timeout: float = 0.0) -> Iterator[int]:
    """Hold the cross-process lock of `path` (on its sidecar lock_path(path),
    created if missing, parents too). Raises LockTimeout after `timeout`
    seconds (default timeout_s()). Yields the sidecar's descriptor (no data)."""
    limit = timeout if timeout and timeout > 0 else timeout_s()
    deadline = time.monotonic() + limit
    lp = lock_path(path)
    tlock = _thread_lock(lp)
    if not tlock.acquire(timeout=limit):
        raise LockTimeout(f"lock on {os.fspath(path)} not free within {limit:g} s (another thread)")
    try:
        lp.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(os.fspath(lp), _OPEN_FLAGS, 0o600)
        try:
            delay = 0.0005
            while not _try_lock(fd):
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"lock on {os.fspath(path)} not free within {limit:g} s (another process)")
                time.sleep(delay * (0.5 + random.random()))
                delay = min(delay * 2, 0.005)
            try:
                yield fd
            finally:
                _unlock(fd)
        finally:
            os.close(fd)
    finally:
        tlock.release()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def encode_record(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, default=str) + "\n").encode("utf-8")


def append_bytes(path: PathLike, data: bytes, repair: bool = False) -> None:
    """Append `data` (one or more complete lines) to `path`. The caller holds
    the lock (exclusive(path)). With `repair`, a missing final newline left by
    a crashed writer is written first."""
    p = Path(path)
    if repair:
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            size = 0
        if size > 0:
            with open(p, "rb") as handle:
                handle.seek(size - 1)
                if handle.read(1) not in (b"\n", b""):
                    data = b"\n" + data
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(os.fspath(p), _APPEND_FLAGS, 0o600)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)


def spill_path(path: PathLike) -> Path:
    """A file no other process writes: `<name>.lock-timeout.<pid>.<rand>.jsonl`
    next to the store. Semgate's readers do not read it; it keeps the record
    for the operator when the store's lock was not free."""
    p = Path(path)
    return p.with_name(f"{p.name}.lock-timeout.{os.getpid()}.{random.getrandbits(32):08x}.jsonl")


def spill_files(path: PathLike) -> List[Path]:
    p = Path(path)
    try:
        return sorted(p.parent.glob(f"{p.name}.lock-timeout.*.jsonl"))
    except OSError:
        return []


def spill_record(path: PathLike, record: Mapping[str, Any], why: str = "") -> None:
    """Keep `record` (with `"lock_timeout": true`) in a spill file only this
    process writes. Prints where it went, or why it could not be kept."""
    spill = spill_path(path)
    try:
        spill.parent.mkdir(parents=True, exist_ok=True)
        with open(spill, "ab") as handle:
            handle.write(encode_record(dict(record, lock_timeout=True)))
        where = f"record kept in {spill}"
    except OSError as err:
        where = f"could not keep the record either: {err}"
    print(f"semgate: {why + '; ' if why else ''}{where}", file=sys.stderr)


def append_record(path: PathLike, record: Mapping[str, Any], timeout: float = 0.0, spill: bool = True,
                  repair: bool = False) -> None:
    """Append one JSON record as one line, under the cross-process lock.

    On LockTimeout the record is kept in a spill file (spill_record; unless
    `spill` is False, when the caller keeps its own final record) and
    LockTimeout is raised so that the caller fails closed."""
    data = encode_record(record)
    try:
        with exclusive(path, timeout):
            append_bytes(path, data, repair)
    except LockTimeout as exc:
        if spill:
            spill_record(path, record, str(exc))
        raise


class ReadResult:
    """Well-formed records of a JSONL file, plus what was skipped.
    `malformed` holds the byte offset of each skipped line."""

    __slots__ = ("records", "malformed", "partial_tail")

    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self.malformed: List[int] = []
        self.partial_tail = False


def parse_jsonl_bytes(raw: bytes, keep: Any = None) -> ReadResult:
    """Split on b"\\n" (a trailing b"\\r" is stripped). A line counts only
    when it is complete (ends with a newline) and is one JSON object.
    `keep(line_bytes) -> bool`, when given, is a cheap pre-filter (e.g. a
    substring test); lines it rejects are neither parsed nor checked."""
    out = ReadResult()
    pos = 0
    n = len(raw)
    while pos < n:
        end = raw.find(b"\n", pos)
        if end < 0:
            if raw[pos:].strip():
                out.partial_tail = True
            break
        line = raw[pos:end].strip()
        start = pos
        pos = end + 1
        if not line or (keep is not None and not keep(line)):
            continue
        try:
            obj = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            out.malformed.append(start)
            continue
        if isinstance(obj, dict):
            out.records.append(obj)
        else:
            out.malformed.append(start)
    return out


def read_jsonl(path: PathLike, keep: Any = None) -> ReadResult:
    """Read without a lock. Every append is one write call under the lock,
    so a reader sees whole lines; the only line that can be cut is the last
    one while it is being written, and that one is ignored (partial_tail).
    Missing file -> empty result. OSError propagates."""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return ReadResult()
    return parse_jsonl_bytes(raw, keep)


def read_bytes_locked(path: PathLike, timeout: float = 0.0) -> bytes:
    """The whole file, read under the lock (no write in progress). Raises
    LockTimeout. Missing file -> b"", no file is created."""
    if not Path(path).exists():
        return b""
    with exclusive(path, timeout):
        try:
            return Path(path).read_bytes()
        except FileNotFoundError:
            return b""


def read_jsonl_locked(path: PathLike, keep: Any = None, timeout: float = 0.0) -> ReadResult:
    """read_jsonl under the lock. Raises LockTimeout."""
    return parse_jsonl_bytes(read_bytes_locked(path, timeout), keep)


def json_needle(text: str) -> bytes:
    """`text` as it appears inside a json.dumps string (ASCII escapes)."""
    return json.dumps(text)[1:-1].encode("ascii")


_warned: Dict[str, set] = {}


def warn_malformed(path: PathLike, result: ReadResult, store: str) -> None:
    """One `store_warning` record per malformed line (keyed by its byte
    offset), appended to the same file, plus one stderr line per process.
    Best effort: a lock timeout here only skips the warning."""
    if not result.malformed:
        return
    key = _key(path)
    seen = _warned.setdefault(key, set())
    already = {int(r.get("offset", -1)) for r in result.records
               if r.get("record_type") == "store_warning" and r.get("kind") == "malformed_line"}
    new = [off for off in result.malformed if off not in already and off not in seen]
    if not new:
        return
    seen.update(new)
    print(f"semgate: {store} {os.fspath(path)} has {len(result.malformed)} malformed line(s); skipped", file=sys.stderr)
    from .envelope import utcnow_iso
    data = b"".join(encode_record({"record_type": "store_warning", "kind": "malformed_line", "store": store,
                                   "offset": off, "ts": utcnow_iso()}) for off in new)
    try:
        with exclusive(path, min(1.0, timeout_s())):
            append_bytes(path, data)
    except (LockTimeout, OSError):
        pass


def write_json_atomic(path: PathLike, value: Any) -> None:
    """Write a small JSON file: unique temp file in the same directory, then
    os.replace. The caller holds the sidecar lock (see sidecar())."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(json.dumps(value, sort_keys=True).encode("utf-8"))
            handle.flush()
        os.replace(tmp, p)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def sidecar(path: PathLike) -> Path:
    """Same as lock_path (kept for callers that name the sidecar)."""
    return lock_path(path)
