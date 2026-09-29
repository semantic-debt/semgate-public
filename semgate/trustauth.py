"""Who may write the trust store (`semgate trust add`, `semgate trust file`).

Problem. The hook gate trust_request (trustgate.py) reads the command TEXT.
The agent can run the CLI in a form the text rules do not see: `S=semgate`
in one tool call and `$S trust add "x"` in the next, an alias, a wrapper
script it wrote, `python -m semgate.cli trust add`. Text matching cannot
catch every form. So the CLI itself checks who runs it. `semgate trust add`
and `semgate trust file` write only when one of these holds:

a. Approval ticket (the agent path). When trustgate allows the agent's
   request, the hook writes a ticket to `trust-tickets.jsonl` next to the
   trust store: the kind (add / file), the exact command (as a keyed
   fingerprint; the file: its path in the project and the keys of the lines
   the judge saw), the days, the project, the session, the agent host
   process, and an expiry TICKET_TTL_S (120 s) later. The CLI consumes a
   matching live ticket (one use, under the file lock). A ticket for another
   command, other days, another project, other file lines, an expired or a
   used ticket does not match. A ticket made under one agent host process is
   refused when the CLI runs under ANOTHER agent host process that semgate
   knows (another session).

b. A person in their own terminal (the human path). No ticket, and ALL of:
   - no agent sign in the process: none of ENV_MARKERS is set (Claude Code
     sets CLAUDECODE and AI_AGENT for its tools), no parent process is an
     agent CLI by name (AGENT_NAMES: claude, codex*, agy, opencode*, ...),
     and no parent process is an agent host that semgate's hook recorded
     (agent-hosts.json: every hook call records the process that runs the
     agent, by pid and start time, so a reused pid does not match), and
     the chain does not end at a shell or launcher whose parent has exited
     (Windows keeps the parent pid of an orphan: Start-Process after which
     the agent's shell exits, or Git Bash's exec of `env -u CLAUDECODE ...`,
     which starts a new process and ends the old one, cutting the agent
     host out of the chain);
   - the person types a random word that the CLI prints (read from stdin).
   A TTY check is not used: Git Bash (mintty) gives native programs a pipe,
   not a console, and Codex runs tool commands in a PTY.

Every other write of a trust or pin record needs an `Auth` (TrustStore.add,
PinStore.add): "ticket" or "terminal" from the CLI, "chat" from the hook's
chat-approved pins (pingate.py), "eval" / "test". The record keeps `via`.

Integrity tag. Every trust, pin, ticket and registry record carries `tag`:
HMAC-SHA256 (fingerprints.fingerprint) with the trust key (`trust.key` next
to the store) over the record without the tag, with a label per record type.
Readers ignore a record without a valid tag and print how many they ignored
(`semgate trust list` shows the count). A refused CLI run appends a tagged
`trust_refused` record, so `semgate trust list` shows the attempt.

What this guarantees and what it does not (threat model: the agent may be
steered, and it runs with the user's own OS permissions):
  - The CLI forms above (`$S`, alias, wrapper script, `python -m`) fail
    without a ticket when the agent's process tree or environment shows the
    agent. The agent CAN evade that on purpose: start the CLI detached from
    its own process tree (a scheduled task, WMI Win32_Process.Create,
    `setsid`/`nohup` after its shell exits, a tmux server), remove the
    environment markers, and drive the typed word with a script that reads
    the CLI's output and writes its input. Each step is visible in the
    command text that the hook judges.
  - The tag stops records written without semgate's code or without the key
    (an `echo >> trust.jsonl` through a path the text rules missed, a copied
    store, a record from another install). It does NOT stop code that reads
    `trust.key` (the same OS user can read it; reading it is the
    credentials_secrets gate) or that imports semgate and calls its writer:
    the library is not a boundary. The hook's text rules (rules.py: writes
    under a .semgate folder are hard-denied; `semgate.trust*` / `pins`
    imports are the trust_request gate) are the check for that code.
  - Deleting `trust.key` or the registry makes semgate ignore every trust
    (the key is recreated, old tags no longer match) or forget the recorded
    hosts until the next hook call: fail closed for trusts, a gap for the
    host check.
"""
from __future__ import annotations

import hmac
import json
import os
import random
import re
import subprocess
import sys
from . import proc
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import filelock

TICKETS_NAME = "trust-tickets.jsonl"
HOSTS_NAME = "agent-hosts.json"
TICKET_TTL_S = 120.0
CLOCK_SKEW_S = 5.0
TICKET_KEEP_S = 3600.0           # tickets older than this are dropped when the file is rewritten
TICKETS_MAX_BYTES = 256 * 1024
HOST_REFRESH_S = 300.0           # a known host is written again only after this many seconds
HOST_KEEP_S = 7 * 86400.0
HOSTS_MAX = 64

# Environment variables that an agent host sets for the commands its tools
# run. Only names seen in a tool's environment are listed (Claude Code
# 2.1: CLAUDECODE=1, AI_AGENT=claude-code_<version>_agent; Pi 0.87:
# AI_AGENT=pi and PI_CODING_AGENT=true, docs/environment-variables.md of the
# Pi package; Pi runs as node, so its process name is not an agent name). A
# person's own terminal does not have them. The agent can remove them; they
# are one sign.
ENV_MARKERS = ("CLAUDECODE", "AI_AGENT", "PI_CODING_AGENT")
# Executable names of agent CLIs (lower case, without .exe). A parent
# process with one of these names is an agent. Only the human path uses it;
# a false match makes the CLI refuse and say why.
AGENT_NAMES = frozenset({"claude", "agy", "opencode", "opencode2", "cursor-agent", "droid", "amp", "gemini-cli"})
AGENT_PREFIXES = ("codex",)      # codex.exe, codex-windows-sandbox-*, codex-command-runner
# Processes that only start another program (the hook's parent chain is
# walked past them to find the agent host).
_WRAPPER_RE = re.compile(r"^(bash|sh|dash|zsh|fish|ksh|tcsh|csh|cmd|powershell|pwsh|conhost|env|timeout|nohup|"
                         r"python[\d.]*w?|py|pyw|pypy[\d.]*|uv|uvx|pipx|semgate|winpty|winpty-agent|sudo|doas|"
                         r"script|stdbuf|nice|ionice|chcp)$")
# Terminals, session roots and system processes: never recorded as an
# agent host (a person's own terminal runs under them too).
_NOT_HOSTS = frozenset({"explorer", "windowsterminal", "openconsole", "mintty", "conemu", "conemu64", "conemuc",
                        "conemuc64", "sshd", "ssh", "tmux", "tmux: server", "screen", "systemd", "init", "launchd",
                        "login", "su", "gnome-terminal-server", "konsole", "xterm", "alacritty", "wezterm-gui",
                        "kitty", "terminal", "iterm2", "hyper", "tabby", "warp", "services", "svchost", "wininit",
                        "winlogon", "wsl", "wslhost", "wslrelay", "sihost", "userinit", "runtimebroker"})

_TICKET_LABEL = "trust ticket v1"
_HOSTS_LABEL = "agent hosts v1"
_REFUSED_LABEL = "trust refused v1"


class NotAuthorized(Exception):
    """The CLI may not write this trust: no ticket and not a person's terminal."""


@dataclass(frozen=True)
class Auth:
    """Why a trust or pin record may be written. `via`: ticket | terminal |
    chat | eval | test. Kept in the record (`via`, `auth`)."""
    via: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def fields(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"via": self.via}
        if self.detail:
            out["auth"] = {str(k): v for k, v in self.detail.items()}
        return out


def require(auth: Any) -> "Auth":
    if not isinstance(auth, Auth) or not auth.via:
        raise NotAuthorized("a trust or pin record needs an Auth (a ticket from the hook, or the user's own terminal)")
    return auth


# ---------------------------------------------------------------- tags


def _canonical(record: Mapping[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "tag"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def make_tag(key: bytes, label: str, record: Mapping[str, Any]) -> str:
    from . import fingerprints
    return fingerprints.fingerprint(key, f"semgate {label}\x00" + _canonical(record))


def tag_ok(key: bytes, label: str, record: Mapping[str, Any]) -> bool:
    value = record.get("tag")
    return isinstance(value, str) and hmac.compare_digest(value, make_tag(key, label, record))


def tagged(key: bytes, label: str, record: Mapping[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in record.items() if k != "tag"}
    out["tag"] = make_tag(key, label, out)
    return out


_warned: Dict[Tuple[str, str], int] = {}


def warn_ignored(path: Any, what: str, count: int) -> None:
    """One stderr line per process and store when records were ignored."""
    if count <= 0:
        return
    key = (os.path.normcase(os.path.abspath(os.fspath(path))), what)
    if _warned.get(key) == count:
        return
    _warned[key] = count
    print(f"semgate: {os.fspath(path)}: ignored {count} {what} record(s) without a valid semgate tag (written by hand, "
          f"by an older semgate, or with another trust.key). Add them again with `semgate trust add` / `semgate trust "
          f"file` if you want them.", file=sys.stderr)


def key_for_store(store_path: Any, lock_timeout: float = 0.0) -> bytes:
    """The trust key next to the store (`trust.key`). Raises fingerprints.KeyUnavailable."""
    from . import fingerprints
    from .trust import KEY_NAME
    key, _note = fingerprints.load_key(Path(store_path).with_name(KEY_NAME), lock_timeout)
    return key


# ---------------------------------------------------------------- processes


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    name: str                 # executable name, lower case, without .exe
    start: str = ""           # creation time, opaque ("" unknown)

    @property
    def key(self) -> str:
        return f"{self.pid}:{self.start}"


def _norm_name(name: str) -> str:
    base = re.split(r"[/\\]", str(name or "").strip())[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _win_table() -> Optional[Dict[int, Tuple[int, str]]]:
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    k32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == wintypes.HANDLE(-1).value:
        return None
    out: Dict[int, Tuple[int, str]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), _norm_name(entry.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out or None


def _win_start(pid: int) -> str:
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = k32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not k32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return ""
        return str((int(times[0].dwHighDateTime) << 32) | int(times[0].dwLowDateTime))
    finally:
        k32.CloseHandle(handle)


def _linux_proc(pid: int) -> Optional[Proc]:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    left, right = raw.find("("), raw.rfind(")")
    if left < 0 or right < left:
        return None
    rest = raw[right + 2:].split()
    try:
        return Proc(pid=pid, ppid=int(rest[1]), name=_norm_name(raw[left + 1:right]), start=rest[19])
    except (IndexError, ValueError):
        return None


def _ps_table() -> Optional[Dict[int, Proc]]:
    try:
        text = proc.run(["ps", "-A", "-o", "pid=,ppid=,lstart=,comm="], capture_output=True, text=True,
                              timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    out: Dict[int, Proc] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        out[pid] = Proc(pid=pid, ppid=ppid, name=_norm_name(" ".join(parts[7:])), start=" ".join(parts[2:7]))
    return out or None


class Chain(list):
    """ancestry(): a list of Proc, plus `parent_gone`: the last one's parent
    process has exited (or its pid was reused), rather than the chain ending
    at a root process."""
    parent_gone = False


def _start_cmp(a: str, b: str) -> Optional[int]:
    """-1/0/1 for two start values of the same kind, None when not comparable."""
    if a.isdigit() and b.isdigit():
        x, y = int(a), int(b)
        return (x > y) - (x < y)
    return None


def ancestry(pid: Optional[int] = None, limit: int = 64) -> Optional[Chain]:
    """[this process, its parent, ...] up to the first parent that is gone
    (or whose pid was reused: it started after its child). None when the
    parent processes cannot be read on this system."""
    pid = os.getpid() if pid is None else int(pid)
    chain = Chain()
    try:
        if sys.platform == "win32":
            table = _win_table()
            if table is None or pid not in table:
                return None
            cur: Optional[Proc] = Proc(pid=pid, ppid=table[pid][0], name=table[pid][1], start=_win_start(pid))
            while cur is not None and len(chain) < limit:
                chain.append(cur)
                parent = table.get(cur.ppid)
                if cur.ppid in (0, cur.pid) or any(p.pid == cur.ppid for p in chain):
                    break
                if parent is None:
                    chain.parent_gone = True
                    break
                nxt = Proc(pid=cur.ppid, ppid=parent[0], name=parent[1], start=_win_start(cur.ppid))
                if _start_cmp(nxt.start, cur.start) == 1:
                    chain.parent_gone = True                 # the pid was reused: the real parent is gone
                    break
                cur = nxt
            return chain
        if os.path.isdir("/proc/self"):
            cur = _linux_proc(pid)
            if cur is None:
                return None
            while cur is not None and len(chain) < limit:
                chain.append(cur)
                if cur.ppid in (0, cur.pid) or any(p.pid == cur.ppid for p in chain):
                    break
                nxt = _linux_proc(cur.ppid)
                if nxt is None or _start_cmp(nxt.start, cur.start) == 1:
                    chain.parent_gone = True
                    break
                cur = nxt
            return chain
        table = _ps_table()
        if table is None or pid not in table:
            return None
        cur = table[pid]
        while cur is not None and len(chain) < limit:
            chain.append(cur)
            if cur.ppid in (0, cur.pid) or any(p.pid == cur.ppid for p in chain):
                break
            nxt = table.get(cur.ppid)
            if nxt is None:
                chain.parent_gone = True
            cur = nxt
        return chain
    except Exception:
        return None


def is_agent_name(name: str) -> bool:
    n = _norm_name(name)
    return n in AGENT_NAMES or n.startswith(AGENT_PREFIXES)


def host_process(chain: Optional[Sequence[Proc]]) -> Optional[Proc]:
    """The agent host above a hook process: the nearest parent that is not a
    shell or launcher (chain[0] is the hook itself). None when that parent is
    a terminal or a system process, or the chain is unknown."""
    for proc in (chain or [])[1:]:
        if _WRAPPER_RE.match(proc.name):
            continue
        if proc.name in _NOT_HOSTS:
            return None
        return proc
    return None


# ---------------------------------------------------------------- the hook's record of agent hosts


def hosts_path(store_path: Any) -> Path:
    return Path(store_path).with_name(HOSTS_NAME)


def read_hosts(store_path: Any, key: Optional[bytes] = None) -> Tuple[Dict[str, Dict[str, Any]], str]:
    """({host key: entry}, problem). problem is "" or says why the file is
    not semgate's (bad tag, not JSON)."""
    path = hosts_path(store_path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}, ""
    except OSError as exc:
        return {}, f"unreadable ({type(exc).__name__})"
    try:
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("hosts"), dict):
            raise ValueError("no hosts")
        if key is None:
            key = key_for_store(store_path)
        if not tag_ok(key, _HOSTS_LABEL, doc):
            return {}, "its tag does not match (it was changed outside semgate)"
        return {str(k): dict(v) for k, v in doc["hosts"].items() if isinstance(v, dict)}, ""
    except Exception as exc:
        return {}, f"not semgate's format ({type(exc).__name__})"


_noted: Dict[str, str] = {}
_hook_chain: Dict[int, Optional[Chain]] = {}


def _own_chain() -> Optional[Chain]:
    """ancestry() of this process, read once per process (the hook side:
    `semgate serve` answers many calls; its parents do not change)."""
    pid = os.getpid()
    if pid not in _hook_chain:
        _hook_chain[pid] = ancestry(pid)
    return _hook_chain[pid]


def note_agent_host(store_path: Any, host: str = "", session_id: str = "", now: Optional[float] = None,
                    chain: Optional[Sequence[Proc]] = None) -> str:
    """The hook, on every call: record the process that runs the agent (the
    nearest parent that is not a shell or launcher), so `semgate trust add`
    run by that agent's tools is not taken for a person's terminal. Returns
    the host key ("" when none was found). Never raises."""
    try:
        t = time.time() if now is None else float(now)
        proc = host_process(_own_chain() if chain is None else chain)
        if proc is None or not proc.start:
            return ""
        ck = os.path.normcase(os.path.abspath(os.fspath(hosts_path(store_path))))
        key = key_for_store(store_path)
        known, _problem = read_hosts(store_path, key)          # read on every call: a changed file is written again
        cur = known.get(proc.key)
        if cur is not None and t - float(cur.get("last_seen", 0) or 0) < HOST_REFRESH_S:
            _noted[ck] = proc.key
            return proc.key
        path = hosts_path(store_path)
        with filelock.exclusive(path, 2.0):
            known, problem = read_hosts(store_path, key)
            if problem:
                print(f"semgate: {path}: {problem}; starting it again", file=sys.stderr)
            entry = dict(known.get(proc.key) or {"pid": proc.pid, "start": proc.start, "name": proc.name,
                                                 "first_seen": t, "sessions": []})
            entry.update(last_seen=t, host=host or entry.get("host", ""))
            sessions = [s for s in entry.get("sessions") or [] if s != session_id]
            entry["sessions"] = (sessions + ([session_id] if session_id else []))[-5:]
            known[proc.key] = entry
            keep = sorted((kv for kv in known.items() if t - float(kv[1].get("last_seen", 0) or 0) < HOST_KEEP_S),
                          key=lambda kv: float(kv[1].get("last_seen", 0) or 0))[-HOSTS_MAX:]
            filelock.write_json_atomic(path, tagged(key, _HOSTS_LABEL, {"schema": 1, "hosts": dict(keep)}))
        _noted[ck] = proc.key
        return proc.key
    except Exception as exc:
        print(f"semgate: could not record the agent host: {type(exc).__name__}: {exc}", file=sys.stderr)
        return ""


def current_host_key(store_path: Any) -> str:
    """The key note_agent_host recorded in this process, else computed now."""
    ck = os.path.normcase(os.path.abspath(os.fspath(hosts_path(store_path))))
    if ck in _noted:
        return _noted[ck]
    proc = host_process(_own_chain())
    return proc.key if proc is not None and proc.start else ""


# ---------------------------------------------------------------- the human path


def agent_signs(store_paths: Sequence[Any], env: Optional[Mapping[str, str]] = None,
                chain: Optional[Sequence[Proc]] = None, *, read_chain: bool = True) -> List[str]:
    """Why this process looks like an agent's tool call, not a person's own
    terminal ([] when no sign was found). `store_paths`: the stores whose
    agent-host record is read (the store written and the default store)."""
    env = os.environ if env is None else env
    out: List[str] = []
    for name in ENV_MARKERS:
        if str(env.get(name, "")).strip():
            out.append(f"the environment variable {name} is set (an agent's tools set it)")
    if chain is None and read_chain:
        chain = ancestry()
    if chain is None:
        out.append("semgate cannot read the parent processes on this system, so it cannot tell a terminal from an agent")
        return out
    known: Dict[str, Dict[str, Any]] = {}
    seen_paths = set()
    for sp in store_paths:
        ck = os.path.normcase(os.path.abspath(os.fspath(hosts_path(sp))))
        if ck in seen_paths:
            continue
        seen_paths.add(ck)
        try:
            found, problem = read_hosts(sp)
        except Exception as exc:
            found, problem = {}, f"{type(exc).__name__}"
        if problem:
            out.append(f"semgate's record of agent sessions {hosts_path(sp)} is not usable: {problem} (semgate's hook "
                       f"writes it again at the next tool call of an agent; you can also delete the file)")
        known.update(found)
    procs = list(chain)
    if getattr(chain, "parent_gone", False) and procs and _WRAPPER_RE.match(procs[-1].name):
        # Windows keeps the parent pid of an orphan: a shell or launcher whose
        # parent has exited was started by a program that did not wait for
        # it (Start-Process, a background job of an agent's shell), or by
        # Git Bash's exec of a program such as `env` (MSYS starts a new
        # process and ends the old one), which hides the agent above it. A
        # terminal the user opened starts from a terminal or explorer.
        out.append(f"it was started by {procs[-1].name} (pid {procs[-1].pid}), whose parent process has exited "
                   f"(a detached start, or a start through env / bash -c in Git Bash; in your own terminal, run "
                   f"semgate trust directly)")
    for proc in procs[1:]:
        entry = known.get(proc.key) if proc.start else None
        if entry is not None:
            host = entry.get("host") or "an agent"
            out.append(f"it runs under {proc.name} (pid {proc.pid}), the process of a {host} session that semgate's hook "
                       f"saw")
        elif is_agent_name(proc.name):
            out.append(f"it runs under {proc.name} (pid {proc.pid}), an agent CLI")
    return out


_SYLLABLES = [c + v for c in "bdfgklmnprstvz" for v in "aeiou"]


def confirm_word(rng: Optional[random.Random] = None) -> str:
    r = rng or random.SystemRandom()
    return "".join(r.choice(_SYLLABLES) for _ in range(3))


def ask_person(lines: Sequence[str], *, read: Optional[Callable[[], str]] = None,
               write: Optional[Callable[[str], None]] = None, word: Optional[str] = None) -> bool:
    """Print what will be trusted and a random word; True when the next input
    line is that word. End of input or another answer: False."""
    word = word or confirm_word()
    out = write or (lambda s: (sys.stdout.write(s), sys.stdout.flush()))
    for line in lines:
        out(line + "\n")
    out(f"Type {word} and press Enter to confirm (anything else cancels): ")
    try:
        answer = (read or sys.stdin.readline)()
    except (EOFError, OSError, ValueError, RuntimeError):
        answer = ""
    if not answer:
        out("\n")
    return str(answer or "").strip().lower() == word


# ---------------------------------------------------------------- tickets


def tickets_path(store_path: Any) -> Path:
    return Path(store_path).with_name(TICKETS_NAME)


def _target_fp(key: bytes, kind: str, target: str) -> str:
    from . import fingerprints
    return fingerprints.fingerprint(key, f"semgate ticket target\x00{kind}\x00{target}")


def _shown(target: str) -> str:
    from . import secretfinder
    try:
        found = [f.value for f in secretfinder.find(target)]
    except Exception:
        found = []
    text = secretfinder.mask_in(target, found) if found else target
    return text[:200]


def file_target(rel: str) -> str:
    from .pins import file_key
    return file_key(rel)


def _read_tickets(path: Path, key: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Tagged ticket events of the file (the caller holds the lock), and the
    number of events ignored for a bad tag."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return [], 0
    res = filelock.parse_jsonl_bytes(raw)
    good, bad = [], 0
    for r in res.records:
        if r.get("record_type") != "trust_ticket":
            continue
        if tag_ok(key, _TICKET_LABEL, r):
            good.append(r)
        else:
            bad += 1
    return good, bad


def issue_ticket(store_path: Any, *, kind: str, target: str, days: int, project: str, lines: Sequence[str] = (),
                 session_id: str = "", judgment_id: str = "", host: str = "", host_key: str = "",
                 now: Optional[float] = None, lock_timeout: float = 2.0) -> Dict[str, Any]:
    """The hook, after trustgate allowed the agent's request: a one-time
    ticket for exactly this request. Raises (LockTimeout, OSError,
    KeyUnavailable): the caller then does not allow the request."""
    t = time.time() if now is None else float(now)
    key = key_for_store(store_path)
    path = tickets_path(store_path)
    rec = {"record_type": "trust_ticket", "schema": 1, "event": "issue", "ticket_id": uuid.uuid4().hex[:16],
           "kind": kind, "target_fp": _target_fp(key, kind, target), "target_shown": _shown(target),
           "days": int(days), "project_root": project, "lines": sorted(str(x) for x in lines),
           "session_id": session_id, "judgment_id": judgment_id, "host": host, "host_key": host_key,
           "t": t, "expires": t + TICKET_TTL_S}
    rec = tagged(key, _TICKET_LABEL, rec)
    with filelock.exclusive(path, lock_timeout):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size > TICKETS_MAX_BYTES:
            events, _bad = _read_tickets(path, key)
            keep = [r for r in events if t - float(r.get("t", 0) or 0) < TICKET_KEEP_S]
            tmp = path.with_name(f"{path.name}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
            tmp.write_bytes(b"".join(filelock.encode_record(r) for r in keep))
            os.replace(tmp, path)
        filelock.append_bytes(path, filelock.encode_record(rec), repair=True)
    return rec


@dataclass
class TicketCheck:
    ticket: Optional[Dict[str, Any]] = None
    why: str = ""


def consume_ticket(store_path: Any, *, kind: str, target: str, days: int, project: str, lines: Sequence[str] = (),
                   chain_hosts: Iterable[str] = (), now: Optional[float] = None,
                   lock_timeout: float = 5.0) -> TicketCheck:
    """Use the live ticket for exactly this request (one time). `chain_hosts`:
    the recorded agent hosts among this process's parents; a ticket made
    under another recorded host is not used. Raises LockTimeout."""
    t = time.time() if now is None else float(now)
    path = tickets_path(store_path)
    if not path.exists():
        return TicketCheck(why="no approval ticket from semgate's hook")
    key = key_for_store(store_path)
    fp = _target_fp(key, kind, target)
    wanted_lines = sorted(str(x) for x in lines)
    hosts = set(chain_hosts)
    with filelock.exclusive(path, lock_timeout):
        events, _bad = _read_tickets(path, key)
        used = {str(r.get("ticket_id")) for r in events if r.get("event") == "use"}
        issued = [r for r in events if r.get("event") == "issue"]
        why = "no approval ticket from semgate's hook for this request"
        found = None
        for r in sorted(issued, key=lambda r: float(r.get("t", 0) or 0), reverse=True):
            if r.get("kind") != kind or r.get("target_fp") != fp or str(r.get("project_root")) != project:
                continue
            if kind == "add" and int(r.get("days", -1)) != int(days):
                why = f"the approved request was for {r.get('days')} days"
                continue
            if kind == "file" and list(r.get("lines") or []) != wanted_lines:
                why = "the file's command lines changed since semgate approved the request"
                continue
            if str(r.get("ticket_id")) in used:
                why = "the approval ticket for this request was already used"
                continue
            if not (float(r.get("t", 0)) - CLOCK_SKEW_S <= t < float(r.get("expires", 0))):
                why = f"the approval ticket expired ({int(t - float(r.get('t', 0) or 0))} s old, limit {int(TICKET_TTL_S)} s)"
                continue
            if hosts and r.get("host_key") and r.get("host_key") not in hosts:
                why = "the approval ticket belongs to another agent session"
                continue
            found = r
            break
        if found is None:
            return TicketCheck(why=why)
        use = tagged(key, _TICKET_LABEL, {"record_type": "trust_ticket", "schema": 1, "event": "use",
                                          "ticket_id": found["ticket_id"], "t": t, "pid": os.getpid()})
        filelock.append_bytes(path, filelock.encode_record(use), repair=True)
    return TicketCheck(ticket=found)


# ---------------------------------------------------------------- the CLI's check


def chain_hosts(store_paths: Sequence[Any], chain: Optional[Sequence[Proc]]) -> List[str]:
    known: Dict[str, Any] = {}
    for sp in store_paths:
        try:
            known.update(read_hosts(sp)[0])
        except Exception:
            continue
    return [p.key for p in (chain or [])[1:] if p.start and p.key in known]


def authorize(store_path: Any, *, kind: str, target: str, days: int, project: str, lines: Sequence[str] = (),
              summary: Sequence[str] = (), env: Optional[Mapping[str, str]] = None,
              chain: Optional[Sequence[Proc]] = None, read: Optional[Callable[[], str]] = None,
              write: Optional[Callable[[str], None]] = None, now: Optional[float] = None) -> Auth:
    """The CLI's check before `semgate trust add | file` writes: a ticket
    from the hook, else a person in their own terminal. Raises NotAuthorized
    (the message says why and what to do) or LockTimeout."""
    from .trust import default_store
    stores = [Path(store_path), default_store()]
    if chain is None:
        chain = ancestry()
    got = consume_ticket(store_path, kind=kind, target=target, days=days, project=project, lines=lines,
                         chain_hosts=chain_hosts(stores, chain), now=now)
    if got.ticket is not None:
        tk = got.ticket
        return Auth("ticket", {"ticket_id": tk.get("ticket_id", ""), "session_id": tk.get("session_id", ""),
                               "judgment_id": tk.get("judgment_id", ""), "host": tk.get("host", "")})
    signs = agent_signs(stores, env=env, chain=chain, read_chain=False)
    if signs:
        raise NotAuthorized(f"{got.why}, and this is not a terminal the user opened: " + "; ".join(signs))
    if not ask_person(summary, read=read, write=write):
        raise NotAuthorized("not confirmed")
    return Auth("terminal", {"confirmed": "typed word"})


def record_refused(store_path: Any, *, kind: str, target: str, project: str, why: str,
                   now: Optional[float] = None) -> None:
    """A tagged `trust_refused` record in the trust store (shown by `semgate
    trust list`). Best effort."""
    from .trust import _iso
    try:
        t = time.time() if now is None else float(now)
        key = key_for_store(store_path)
        rec = tagged(key, _REFUSED_LABEL, {"record_type": "trust_refused", "schema": 1, "kind": kind,
                                           "target": _shown(target), "project_root": project, "why": why[:400],
                                           "ts": _iso(t), "pid": os.getpid()})
        filelock.append_record(store_path, rec, timeout=1.0, spill=False, repair=True)
    except Exception as exc:
        print(f"semgate: the refused attempt was not recorded: {type(exc).__name__}", file=sys.stderr)


def refused_records(records: Sequence[Mapping[str, Any]], key: bytes) -> List[Dict[str, Any]]:
    return [dict(r) for r in records if r.get("record_type") == "trust_refused" and tag_ok(key, _REFUSED_LABEL, r)]
