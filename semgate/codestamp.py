"""Which semgate code is running, and which plugin copy is installed.

Two uses:

1. Hot reload of `semgate serve --stdio` (serve.py). OpenCode's service and
   Pi keep one serve process for days. CodeWatcher takes a fingerprint of
   this semgate package when serve starts: sha256 over the relative path and
   bytes of every WATCHED file under the package folder (*.py, *.json, *.js,
   *.ts, *.md; __pycache__ skipped). About 105 files and 1.5 MB in a checkout:
   hashing takes about 12 ms, once. After that, check() only lists the folder
   and stats the files (about 1 ms on Windows) and hashes again only when a
   size, an mtime or the file set changed. A changed file set must stay the
   same for `settle` seconds before it counts (pip writes files one by one;
   serve must not restart into a half-installed package). Same bytes after a
   reinstall (new mtimes only): no change.

   Policy files are not needed in the fingerprint: run_core loads the policy
   file on every request. A wheel install has the policies inside the
   package folder, so they are watched there anyway; that costs at most one
   extra restart.

2. Stamps for the plugin files that `semgate init` renders into host folders
   (OpenCode plugin, Pi extension). The first line of every rendered copy is

       // semgate-asset: opencode_semgate.js sha256=<64 hex> version=0.4.0

   sha256 is of the SOURCE asset in this package (line ends normalized to
   \\n, so a CRLF checkout gives the same value), not of the rendered copy:
   two installs with different interpreter paths carry the same stamp. The
   copy also sends the same stamp text with every request (client.stamp), so
   serve can record that the plugin loaded in the host is older than the
   installed asset (a file refresh does not reach a plugin the host has
   already loaded).
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__

PACKAGE_DIR = Path(__file__).resolve().parent
WATCHED_SUFFIXES = (".py", ".json", ".js", ".ts", ".md")

# host -> the asset `semgate init <host>` renders
ASSETS: Dict[str, str] = {"opencode": "opencode_semgate.js", "pi": "pi_semgate.ts"}
STAMP_PREFIX = "// semgate-asset: "
ASSET_PLACEHOLDER = "__SEMGATE_ASSET__"
_STAMP = re.compile(r"(?P<asset>[A-Za-z0-9_.\-]+) sha256=(?P<sha256>[0-9a-f]{64}) version=(?P<version>[^\s\"']+)")
# A copy written before stamps existed still says what it is: it starts
# `semgate.serve` (this text is in every plugin and extension semgate wrote).
LEGACY_MARKER = "semgate.serve"


# ---------------------------------------------------------------- asset stamps


def asset_source(name: str) -> str:
    import importlib.resources as resources
    return (resources.files("semgate.assets") / name).read_text(encoding="utf-8")


def asset_sha256(name: str, text: Optional[str] = None) -> str:
    body = asset_source(name) if text is None else text
    return hashlib.sha256(body.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def stamp(name: str) -> str:
    """"opencode_semgate.js sha256=<hex> version=<__version__>" for the asset
    in this package."""
    return f"{name} sha256={asset_sha256(name)} version={__version__}"


def stamp_line(name: str) -> str:
    return STAMP_PREFIX + stamp(name)


def parse_stamp(text: object) -> Optional[Dict[str, str]]:
    """{"asset", "sha256", "version"} from a stamp string (a plugin's
    client.stamp), or None."""
    if not isinstance(text, str):
        return None
    m = _STAMP.search(text[:400])
    return {k: m.group(k) for k in ("asset", "sha256", "version")} if m else None


def read_stamp(text: str) -> Optional[Dict[str, str]]:
    """The stamp in the first lines of a rendered copy, or None (a copy from
    before stamps, or not semgate's)."""
    for line in text.splitlines()[:5]:
        if line.startswith(STAMP_PREFIX):
            return parse_stamp(line[len(STAMP_PREFIX):])
    return None


def is_semgate_copy(text: str) -> bool:
    """True when `text` is a plugin/extension semgate wrote: it has the stamp,
    or (written before stamps) it starts semgate.serve."""
    return read_stamp(text) is not None or LEGACY_MARKER in text


def copy_status(text: str, name: str) -> Tuple[str, str]:
    """("current" | "outdated" | "unstamped" | "foreign", detail) for a copy of
    asset `name`."""
    found = read_stamp(text)
    want = asset_sha256(name)
    if found is None:
        if LEGACY_MARKER in text:
            return "unstamped", f"no stamp: written before semgate stamped its plugins; current sha {want[:12]}"
        return "foreign", "not written by semgate"
    if found["asset"] != name:
        return "foreign", f"stamp names {found['asset']}, expected {name}"
    if found["sha256"] == want:
        return "current", f"sha {want[:12]} version {found['version']}"
    return "outdated", f"installed sha {found['sha256'][:12]} (version {found['version']}) vs current {want[:12]} (version {__version__})"


# ---------------------------------------------------------------- code fingerprint


Signature = Tuple[Tuple[str, int, int], ...]     # (relative path, size, mtime_ns), sorted


class CodeWatcher:
    """Detects that the semgate code under `root` changed since start.

    check() is cheap (list + stat) and rate limited by `interval`; it returns
    a reason text once a change is real (content hash differs) and stable for
    `settle` seconds, else None. It never raises."""

    def __init__(self, root: Path = PACKAGE_DIR, interval: float = 1.0, settle: float = 2.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.root = Path(root)
        self.interval, self.settle, self.clock = float(interval), float(settle), clock
        self.version = __version__
        self._sig: Optional[Signature] = self._scan()
        self.fingerprint = self._hash(self._sig) if self._sig is not None else ""
        self._pending: Optional[Tuple[Signature, float]] = None
        self._last = self.clock()
        self.changed_to = ""

    def _scan(self) -> Optional[Signature]:
        out: List[Tuple[str, int, int]] = []

        def walk(folder: str, rel: str) -> None:
            with os.scandir(folder) as entries:
                for e in entries:
                    if e.is_dir(follow_symlinks=False):
                        if e.name != "__pycache__" and not e.name.startswith("."):
                            walk(e.path, rel + e.name + "/")
                    elif e.name.endswith(WATCHED_SUFFIXES):
                        st = e.stat()
                        out.append((rel + e.name, st.st_size, st.st_mtime_ns))
        try:
            walk(str(self.root), "")
        except OSError:
            return None             # the folder is being replaced (pip): try again later
        return tuple(sorted(out))

    def _hash(self, sig: Signature) -> str:
        h = hashlib.sha256()
        for rel, _, _ in sig:
            h.update(rel.encode("utf-8") + b"\0")
            try:
                with open(self.root / rel, "rb") as handle:
                    h.update(handle.read())
            except OSError:
                h.update(b"\0missing\0")
            h.update(b"\0")
        return h.hexdigest()

    def check(self, force: bool = False) -> Optional[str]:
        try:
            return self._check(force)
        except Exception:           # a watcher problem must never break serve
            return None

    def _check(self, force: bool) -> Optional[str]:
        now = self.clock()
        if self.changed_to:
            return self._reason()
        if not force and now - self._last < self.interval:
            return None
        self._last = now
        sig = self._scan()
        if sig is None or sig == self._sig:
            self._pending = None
            return None
        if self._pending is None or self._pending[0] != sig:
            self._pending = (sig, now)          # first seen now: wait until it stays the same
            if self.settle > 0:
                return None
        if now - self._pending[1] < self.settle:
            return None
        new = self._hash(sig)
        self._pending = None
        if new == self.fingerprint:
            self._sig = sig                     # new mtimes, same bytes
            return None
        self.changed_to = new
        return self._reason()

    def _reason(self) -> str:
        new_version = installed_version(self.root) or "?"
        return (f"semgate code changed under {self.root} (version {self.version} -> {new_version}, "
                f"code {self.fingerprint[:12]} -> {self.changed_to[:12]})")


_VERSION_LINE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


def installed_version(root: Path = PACKAGE_DIR) -> str:
    """__version__ as written in <root>/__init__.py now (the running process
    keeps the one it imported), or ""."""
    try:
        m = _VERSION_LINE.search((Path(root) / "__init__.py").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return ""
    return m.group(1) if m else ""
