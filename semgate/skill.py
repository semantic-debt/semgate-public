"""The `semgate` agent skill: what an agent must do with semgate's answers.

`semgate init <host>` writes semgate/assets/semgate_skill.md as the host's
user-level skill; `semgate uninstall <host>` removes it. Every host below
reads a `<folder>/semgate/SKILL.md` with YAML front matter `name` (equal to
the folder name) and `description`. Checked 2026-09-24 (docs/skill.md has
the quotes):

  claude       ~/.claude/skills/semgate/SKILL.md          Claude Code 2.1.281 binary ("Personal
                                                           (~/.claude/skills/<name>/SKILL.md)") and
                                                           code.claude.com/docs/en/skills
  antigravity  ~/.gemini/config/skills/semgate/SKILL.md   docs bundled in agy 1.2.10 ("Global
                                                           Discovery: ~/.gemini/config/", "skills/
                                                           <skill_name>/") and antigravity.google/docs/skills
  codex        ~/.agents/skills/semgate/SKILL.md          codex-cli 0.153.1 source (host_roots.rs:
                                                           $HOME/.agents/skills; $CODEX_HOME/skills is
                                                           the deprecated one) and the Codex skills docs
  opencode     ~/.agents/skills/semgate/SKILL.md          opencode.ai/docs/skills (also
                                                           ~/.config/opencode/skills, ~/.claude/skills)
  pi           ~/.agents/skills/semgate/SKILL.md          pi docs/skills.md ("Pi also supports the Agent
                                                           Skills locations ~/.agents/skills/"); not installed here
  droid        ~/.agents/skills/semgate/SKILL.md          docs.factory.ai/cli/configuration/skills ("also
                                                           reads from ~/.agents/skills/"); droid 0.164.0 binary
  copilot      ~/.agents/skills/semgate/SKILL.md          docs.github.com Copilot CLI add-skills ("create a
                                                           ~/.copilot/skills or ~/.agents/skills directory");
                                                           docs only, not installed here

~/.agents/skills is read by codex, opencode, pi, droid and copilot, not by
Claude Code or agy: one file serves the five. Uninstalling one of them keeps
it while another of the five still has a semgate hook installed (hosts
.hook_configs), and says which; the last one removes it. OpenCode also reads
~/.claude/skills, so with claude and opencode both installed it finds the
same text twice (same name, same content).
No host needs a section in a global instructions file: every host above
has user-level skills.

The file is semgate's own: it carries MARKER. An existing file without the
marker is never overwritten or removed (refused with a message). Writes go
through safemerge.safe_write (backup, atomic, SEMGATE_WRITE_ROOT).
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import sysconfig
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

NAME = "semgate"
MARKER = "<!-- written by `semgate init`; `semgate uninstall` removes it -->"
SHARED = ("codex", "opencode", "pi", "droid", "copilot")
LOCATIONS: Dict[str, str] = {
    "claude": "~/.claude/skills/semgate/SKILL.md",
    "antigravity": "~/.gemini/config/skills/semgate/SKILL.md",
    "codex": "~/.agents/skills/semgate/SKILL.md",
    "opencode": "~/.agents/skills/semgate/SKILL.md",
    "pi": "~/.agents/skills/semgate/SKILL.md",
    "droid": "~/.agents/skills/semgate/SKILL.md",
    "copilot": "~/.agents/skills/semgate/SKILL.md",
}


def text(cmd: Optional[str] = None) -> str:
    """The skill. With `cmd` (see command()) other than plain "semgate", every
    `semgate trust ...` it tells the agent to run starts with `cmd`, and one
    line says so."""
    import importlib.resources as resources
    body = (resources.files("semgate.assets") / "semgate_skill.md").read_text(encoding="utf-8")
    if not cmd or cmd == "semgate":
        return body
    body = body.replace("`semgate trust ", f"`{cmd} trust ")
    return body.replace(_ANCHOR, _ANCHOR + f"\nIn this install the semgate command is `{cmd}`. Type it exactly like that: "
                                           "your shell may not find a bare `semgate` (it is often not on PATH).\n", 1)


_ANCHOR = 'Its messages start with "semgate". Read the whole message before you act.\n'
# Characters that need quotes in bash, PowerShell or cmd, or that
# trust.parse_add does not take in a bare word.
_NEEDS_QUOTES = re.compile(r"""[\s"'$`;&|<>(){}\[\],*?%!#^@]""")   # "~" is literal inside a word (C:/PROGRA~1)


def command() -> str:
    """How an agent's shell runs this install's semgate, for the skill.

    A bare `semgate` works only when the agent's shell has the scripts folder
    on PATH. A venv install (C:/.../.venv/Scripts, /.../venv/bin) is on PATH
    only while the venv is active, and the agent's shell does not activate it.
    So: the absolute path of the `semgate` console script of this interpreter
    (its own folder, then the default and the user scheme's scripts folder),
    else `<python> -m semgate`. Written with forward slashes and without
    quotes, so bash, PowerShell and cmd run the same text and trust.parse_add
    reads it (it takes a folder before `semgate` or `python`). A path that
    would need quotes (a space) is replaced by its Windows short path; if it
    still needs quotes, plain `semgate` (then it must be on PATH; `semgate
    doctor` says whether it is).

    A bare `semgate` found on PATH is kept, unless it is there only because
    the running venv is active in this shell. rules.check_grant_scope reads
    an absolute path in a command as a path the agent touches, except
    exactly this install's own command as the program word (own_programs),
    so the absolute form is not blocked by the grant's path scope.
    """
    exe = Path(os.path.abspath(sys.executable))
    found = shutil.which("semgate")
    if found and not _only_via_active_venv(Path(found), exe):
        return "semgate"
    scripts = _own_scripts(exe)
    if scripts:
        return _bare(scripts[0]) or "semgate"
    python = _bare(exe)
    return f"{python} -m semgate" if python else "semgate"


def _own_scripts(exe: Path) -> List[Path]:
    """The `semgate` console scripts of THIS install that exist: the one in
    the interpreter's own folder, then the default and the user scheme's
    scripts folder when this semgate package is installed there."""
    name = "semgate.exe" if os.name == "nt" else "semgate"
    site = Path(__file__).resolve().parent.parent          # where this semgate package is installed
    folders = [exe.parent]
    for scheme in (None, _user_scheme()):
        try:
            paths = sysconfig.get_paths(scheme) if scheme else sysconfig.get_paths()
            libs = {Path(paths[k]).resolve() for k in ("purelib", "platlib") if paths.get(k)}
        except Exception:
            continue
        if site in libs:                                   # a script of THIS install, not an older one
            folders.append(Path(paths["scripts"]))
    return [folder / name for folder in folders if (folder / name).is_file()]


def program_key(word: str) -> str:
    """How own_programs() compares a program word: backslashes as slashes,
    and case-folded on Windows (its file names ignore case). Nothing else is
    normalized: no `..`, no `.`, no doubled slash, no link is resolved."""
    word = word.replace("\\", "/")
    return word.casefold() if os.name == "nt" else word


def own_programs() -> Tuple[frozenset, frozenset]:
    """(scripts, pythons): program_key() forms of the exact program paths
    that run THIS install's semgate, as command() writes them into the skill
    and as they are on disk (long and 8.3 short form on Windows).

    scripts: the `semgate` console scripts of this install (_own_scripts).
    pythons: this interpreter (sys.executable, not resolved), for the
    `<python> -m semgate` form.

    rules.check_grant_scope lets exactly these words through as the program
    of a simple command. The command's word is compared as text and never
    resolved, so another venv's semgate, a copy, or a link at another path
    to this one is a different word and stays a path the agent touches."""
    exe = Path(os.path.abspath(sys.executable))

    def forms(path: Path) -> set:
        out = {program_key(str(path))}
        bare = _bare(path)
        if bare:
            out.add(program_key(bare))
        return out

    scripts: set = set()
    for script in _own_scripts(exe):
        scripts |= forms(script)
    pythons = forms(exe) if exe.is_file() else set()
    return frozenset(scripts), frozenset(pythons)


def _only_via_active_venv(found: Path, exe: Path) -> bool:
    """True when `found` is in the running venv's own scripts folder: it is
    on this shell's PATH because the venv is activated here, and the agent's
    shell does not activate it."""
    if sys.prefix == sys.base_prefix:
        return False
    try:
        return found.resolve().parent == exe.parent.resolve()
    except OSError:
        return True


def _user_scheme() -> Optional[str]:
    try:
        return sysconfig.get_preferred_scheme("user")
    except Exception:
        return None


def _bare(path: Path) -> Optional[str]:
    text = str(path)
    if os.name == "nt" and _NEEDS_QUOTES.search(text):
        text = _short_path(text) or text
    text = text.replace("\\", "/")
    return None if _NEEDS_QUOTES.search(text) else text


def _short_path(path: str) -> str:
    """Windows 8.3 short path ("C:/PROGRA~1/..."), or "" when there is none."""
    try:
        import ctypes
        from ctypes import wintypes
        fn = ctypes.windll.kernel32.GetShortPathNameW
        fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        fn.restype = wintypes.DWORD
        buf = ctypes.create_unicode_buffer(1024)
        n = fn(path, buf, 1024)
        return buf.value if 0 < n < 1024 else ""
    except Exception:
        return ""


def path_for(host: str) -> Optional[Path]:
    where = LOCATIONS.get(host)
    return Path(os.path.expanduser(where)) if where else None


def install(host: str, dry_run: bool = False,
            announce: Optional[Callable[[str, Path], None]] = None) -> Tuple[str, Optional[Path]]:
    """(state, path): state is "write", "would write", "unchanged",
    "refused: ..." or "no skill location for <host>"."""
    from .safemerge import MergeRefused, safe_write
    path = path_for(host)
    if path is None:
        return f"no verified skill location for {host}", None
    body = text(command())
    if path.is_file():
        old = path.read_text(encoding="utf-8", errors="replace")
        if old == body:
            return "unchanged", path
        if MARKER not in old:
            return "refused: the file exists and was not written by semgate", path
    if dry_run:
        return "would write", path
    try:
        safe_write(path, body, backup=path.is_file(), announce=announce)
    except MergeRefused as exc:
        return f"refused: {exc}", path
    return "write", path


def still_hooked(hosts: List[str]) -> List[str]:
    """The hosts of `hosts` that still have a semgate hook at user level."""
    from .hosts import ADAPTERS
    from .hosts.base import HostEnv
    env = HostEnv.current(run_binaries=False)
    out: List[str] = []
    for name in hosts:
        adapter = ADAPTERS.get(name)
        try:
            if adapter is not None and adapter.hook_configs(env):
                out.append(name)
        except Exception:
            out.append(name)              # unreadable: assume it is still used (keep the file)
    return out


def uninstall(host: str, dry_run: bool = False,
              announce: Optional[Callable[[str, Path], None]] = None) -> Tuple[str, Optional[Path]]:
    from .safemerge import check_write_allowed
    path = path_for(host)
    if path is None or not path.is_file():
        return "nothing to remove", path
    if MARKER not in path.read_text(encoding="utf-8", errors="replace"):
        return "kept: not written by semgate", path
    if host in SHARED:
        others = still_hooked([h for h in SHARED if h != host])
        if others:
            return f"kept: {', '.join(others)} still use it", path
    if dry_run:
        return "would remove", path
    check_write_allowed(path)             # semgate's own generated file: no backup
    path.unlink()
    try:
        path.parent.rmdir()               # the semgate/ folder, when empty
    except OSError:
        pass
    return "removed", path
