"""Links a command creates: where each link is created and what it points to.

Used by the code signal S6_link_placement (codesignals.py) and the human gate
`persistence_link` (rules.py). Pure string work on the parsed command; the
only filesystem access is the optional `is_dir` callback the caller passes
(scriptsource.LocalWorkspace.is_dir live, SyntheticWorkspace.is_dir in evals).

Commands understood:

- `ln` / `gln` (GNU rules: options may come anywhere before `--`; `-s`, `-f`,
  `-n`/`-h`, `-T`, `-r`, `-t DIR` / `--target-directory=DIR`, clusters such
  as `-sfn` or `-stDIR`, unique long-option prefixes, `busybox ln`).
  The four forms of GNU ln:
    ln [-T] TARGET LINK_NAME     (two paths; LINK_NAME is not a folder, or -T)
    ln TARGET                    (one path: the link goes in the current folder)
    ln TARGET... DIRECTORY       (the last path is an existing folder, or there
                                  are more than two paths)
    ln -t DIRECTORY TARGET...
  In the folder forms the link is DIRECTORY/<last part of TARGET>. BSD/macOS
  ln stops reading options at the first path; that difference is not modeled
  (on BSD, `ln /x -s /` would treat "-s" as a path).
- `cp -s` / `cp -l` (`--symbolic-link`, `--link`): the same placement rules.
- `link A B` (hard link at B).
- PowerShell `New-Item` / `ni` with `-ItemType SymbolicLink|HardLink|Junction`
  (`-Path`, `-Name`, `-Value`/`-Target`, parameter prefixes, `-Param:value`).
- cmd `mklink [/D|/H|/J] LINK TARGET`.

Commands inside `bash -c '...'`, `pwsh -c "..."`, `cmd /c ...`, `$(...)` and
`find -exec ... \\;` are read too (shellparse.extract_scripts). A path with a
variable other than the home variable, a glob, or an xargs/find placeholder
`{}` is unknown and never guessed.

Links made by code (form "code"): Python code is parsed with `ast` (calls to
os.symlink, os.link, Path(...).symlink_to / hardlink_to / link_to, also
through `from os import symlink as s`, `import os as o`, `from pathlib import
Path as P`, `Path.symlink_to(p, t)`); Node code is matched by pattern
(fs.symlink / symlinkSync / fs.promises.symlink / link / linkSync, target
first, then the new link). Only literal paths are known: string literals,
f-strings without values, os.path.join / Path(a, b) / a / b of literals,
os.path.expanduser('~/...'), Path.home(), os.environ['HOME']. A variable or
any other expression is unknown (None). Python does not expand "~" by itself:
os.symlink(x, '~/.bashrc') creates ./~/.bashrc. Sources: `python -c`, `py`,
`python3.12`, `pypy`, `node -e/--eval/-p`, `bun -e`, heredocs to them, also
after `cd` and inside `bash -c` (code_blocks), and script files F4 read
(script_links; .py, .js, .mjs, .cjs, and .sh through find_links).

The persistence check (persistence_hits, link_hits) also takes the folders
of the live PATH (path_dirs_from: judge's `path_env`, which the hooks fill
from os.environ) and the project folder (the same-repo rule, same_repo).

Paths are normalized to forward slashes. The home folder is kept as "~" (from
`~`, `$HOME`, `${HOME}`, `$env:USERPROFILE`, `%USERPROFILE%`); /root,
/home/<user>, /Users/<user>, C:/Users/<user> and this machine's home count as
a home folder when classifying (also /c/Users/<user> in Git Bash and
/mnt/c/Users/<user> in WSL).
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from . import shellparse

IsDir = Callable[[str, bool], Optional[bool]]   # (normalized path, follow symlinks) -> True/False/None (unknown)

_QUICK = re.compile(r"(?i)(?<![\w.-])(?:g?ln|link|cp|mklink|new-item|ni|busybox)(?![\w.-])")
_HOME_VAR = re.compile(r"^(?:\$HOME|\$\{HOME\}|\$env:USERPROFILE|\$env:HOME|%USERPROFILE%)(?=[/\\]|$)", re.I)
_UNKNOWN = re.compile(r"[`*?\[]|\$|\{\}|%[A-Za-z_]+%")
_DRIVE = re.compile(r"^([A-Za-z]):(?:[/\\]|$)")


# Code that may create a link: Python os.symlink / os.link / Path.symlink_to /
# hardlink_to / link_to; Node fs.symlink / symlinkSync / link / linkSync.
_CODE_QUICK = re.compile(r"(?i)symlink|hardlink_to|link_to|(?<![\w$])link(?:sync)?\s*\(")


def might_link(command: str) -> bool:
    """Cheap pre-filter: can this command create a link at all?"""
    return bool(command) and bool(_QUICK.search(command) or _CODE_QUICK.search(command))


# ---------- paths ----------


def norm(path: str, cwd: str = "") -> Optional[str]:
    """`path` resolved against `cwd`, with forward slashes, `.` and `..`
    removed. Home stays "~". Drive letters are lower case ("c:/x"). None when
    the path is unknown (empty, a variable, a glob, a placeholder, a relative
    path with no cwd, or `..` above the home folder)."""
    p = (path or "").strip()
    if not p:
        return None
    m = _HOME_VAR.match(p)
    if m:
        p = "~" + p[m.end():]
    if _UNKNOWN.search(p):
        return None
    p = p.replace("\\", "/")
    if p == "~" or p.startswith("~/"):
        root, rest = "~", p[1:]
    elif re.match(r"^~[A-Za-z0-9_.-]+(/|$)", p):
        user, _, rest = p[1:].partition("/")
        root, rest = "/", "home/" + user + "/" + rest
    elif p.startswith("/"):
        root, rest = "/", p
    elif _DRIVE.match(p):
        root, rest = p[0].lower() + ":", p[2:]
    elif re.match(r"^[A-Za-z]:", p):
        return None                                   # drive-relative (C:foo)
    else:
        base = norm(cwd) if cwd else None
        if base is None:
            return None
        return norm(base + "/" + p)
    segs: List[str] = []
    for part in rest.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if segs:
                segs.pop()
            elif root == "~":
                return None
            continue
        segs.append(part)
    if root == "~":
        return "~" + ("/" + "/".join(segs) if segs else "")
    if root == "/":
        return "/" + "/".join(segs)
    return root + "/" + "/".join(segs)


def _join(folder: str, name: str) -> str:
    return (folder if folder.endswith("/") else folder + "/") + name


def parent(path: str) -> str:
    if path in ("/", "~") or re.match(r"^[a-z]:/$", path):
        return path
    head = path.rsplit("/", 1)[0]
    if not head:
        return "/"
    if re.match(r"^[a-z]:$", head):
        return head + "/"
    return head


def last_part(raw: str) -> str:
    """The name ln gives a link it puts inside a folder: the last part of the
    TARGET as written (trailing slashes removed). "" for "/" or unknown."""
    p = (raw or "").replace("\\", "/").rstrip("/")
    return p.rsplit("/", 1)[-1] if p else ""


def home_rel(path: str) -> Optional[str]:
    """The part of `path` below a home folder ("" for the home folder itself),
    or None when the path is not in a home folder."""
    if path == "~":
        return ""
    if path.startswith("~/"):
        return path[2:]
    low = path.lower()
    real = norm(os.path.expanduser("~"))
    if real and real not in ("~", "/") and (low == real.lower() or low.startswith(real.lower().rstrip("/") + "/")):
        return path[len(real):].lstrip("/")
    for rx in (r"^/root(?:/|$)", r"^/home/[^/]+(?:/|$)", r"^/users/[^/]+(?:/|$)", r"^[a-z]:/users/[^/]+(?:/|$)",
               r"^(?:/mnt)?/[a-z]/users/[^/]+(?:/|$)"):     # Git Bash /c/Users/x, WSL /mnt/c/Users/x
        m = re.match(rx, low)
        if m:
            return path[m.end():]
    return None


def display(path: str) -> str:
    return path if len(path) <= 90 else "..." + path[-87:]


# ---------- persistence locations ----------


@dataclass(frozen=True)
class Place:
    kind: str       # root | shell_startup | ssh | autostart | service | path_dir | git | editor | agent_config
                    # | python_startup | system_config
    where: str      # the entry that matched, as a path
    reason: str     # plain words: why a file there runs later


_R_SHELL = "shell startup file: its code runs in every new shell"
_R_SSH = "ssh folder: authorized_keys lets someone log in; config and rc run commands on connect"
_R_AUTOSTART = "autostart folder: programs here start at every login"
_R_SERVICE = "service or scheduled-job folder: units and jobs here start programs on their own"
_R_PATH = "folder on PATH: a file here runs whenever a command of that name is typed"
_R_GIT = "git hooks or git settings: git runs programs from here on commit, checkout and other commands"
_R_EDITOR = "editor startup or settings: the editor runs this code or these tasks when it starts or opens a folder"
_R_AGENT = "coding-agent settings: hooks, permissions, instructions and skills here apply to later agent sessions"
_R_PY = "Python startup file: Python runs it on every start"
_R_ETC = "system configuration folder: services, cron, login shells and the program loader read files here"
_R_ROOT = ("an entry directly in the root folder: machine-wide and outside every project "
           "(on most Linux systems /bin, /lib and /sbin are links there)")

# Below a home folder (path relative to home, lower case).
HOME_ENTRIES: Tuple[Tuple[str, str, str], ...] = tuple(
    [(n, "shell_startup", _R_SHELL) for n in (
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv", ".zprofile",
        ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc", ".xprofile", ".xinitrc", ".xsessionrc",
        ".config/fish", "documents/powershell", "documents/windowspowershell")]
    + [(".ssh", "ssh", _R_SSH)]
    + [(n, "autostart", _R_AUTOSTART) for n in (
        ".config/autostart", "library/launchagents",
        "appdata/roaming/microsoft/windows/start menu/programs/startup")]
    + [(n, "service", _R_SERVICE) for n in (".config/systemd", ".local/share/systemd")]
    + [(n, "path_dir", _R_PATH) for n in ("bin", ".local/bin")]
    + [(n, "git", _R_GIT) for n in (".gitconfig", ".config/git")]
    + [(n, "editor", _R_EDITOR) for n in (
        ".vimrc", ".vim", ".config/nvim", ".emacs", ".emacs.d", ".config/code/user",
        "appdata/roaming/code/user", "library/application support/code/user")]
    + [(n, "agent_config", _R_AGENT) for n in (
        ".claude", ".claude.json", ".codex", ".gemini", ".cursor", ".config/opencode", ".copilot", ".grok",
        ".semgate")]
)

# Absolute folders (lower case; "*:" is any drive letter).
ABS_ENTRIES: Tuple[Tuple[str, str, str], ...] = tuple(
    [("/etc", "system_config", _R_ETC)]
    + [(n, "service", _R_SERVICE) for n in ("/var/spool/cron", "/lib/systemd", "/usr/lib/systemd",
                                            "/library/launchagents", "/library/launchdaemons",
                                            "/library/startupitems")]
    + [("*:/programdata/microsoft/windows/start menu/programs/startup", "autostart", _R_AUTOSTART)]
    + [(n, "path_dir", _R_PATH) for n in ("/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin",
                                          "/sbin", "/opt/homebrew/bin", "*:/windows")]
)

# Anywhere in a path, including inside the project (lower-case segment runs).
ANYWHERE_ENTRIES: Tuple[Tuple[Tuple[str, ...], str, str], ...] = (
    ((".git", "hooks"), "git", _R_GIT),
    ((".git", "config"), "git", _R_GIT),
    ((".claude", "settings.json"), "agent_config", _R_AGENT),
    ((".claude", "settings.local.json"), "agent_config", _R_AGENT),
    ((".claude", "hooks"), "agent_config", _R_AGENT),
    ((".codex", "config.toml"), "agent_config", _R_AGENT),
    ((".codex", "hooks.json"), "agent_config", _R_AGENT),
    ((".cursor", "hooks.json"), "agent_config", _R_AGENT),
    ((".cursor", "hooks"), "agent_config", _R_AGENT),
    ((".cursor", "mcp.json"), "agent_config", _R_AGENT),
    ((".cursor", "rules"), "agent_config", _R_AGENT),
    ((".gemini", "settings.json"), "agent_config", _R_AGENT),
    ((".mcp.json",), "agent_config", _R_AGENT),
    ((".vscode", "tasks.json"), "editor", _R_EDITOR),
    ((".vscode", "settings.json"), "editor", _R_EDITOR),
)
_ANYWHERE_FOLDERS = frozenset({".git", ".claude", ".codex", ".cursor", ".gemini", ".vscode"})


def _abs_key(low: str) -> str:
    return re.sub(r"^[a-z]:/", "*:/", low)


def _under(path: str, entry: str) -> bool:
    return path == entry or path.startswith(entry.rstrip("/") + "/")


_R_PATH_LIVE = ("folder on the PATH of the agent process: a file here runs whenever a command of that name "
                "is typed")


# ---------- the live PATH ----------


def _fold_case(path: str) -> bool:
    """Compare this path without case: Windows paths (a drive letter, Git Bash
    /c/..., WSL /mnt/c/...) and every path when semgate runs on Windows."""
    return os.name == "nt" or bool(re.match(r"^(?:[a-z]:|(?:/mnt)?/[a-z])(?:/|$)", path.lower()))


def path_key(path: str) -> str:
    """A normalized path in one comparable form: home paths as "~/...",
    lower case for Windows paths."""
    rel = home_rel(path)
    key = path if rel is None else ("~/" + rel if rel else "~")
    return key.lower() if _fold_case(path) else key


def _rel_below(key: str, base: str) -> Optional[str]:
    """The part of `key` below `base` ("" when equal), None when outside. Both
    are path_key forms."""
    if key == base:
        return ""
    head = base.rstrip("/") + "/"
    return key[len(head):] if key.startswith(head) else None


_ABS_PATH = re.compile(r"^(?:[/~\\]|[A-Za-z]:[/\\])")


def path_dirs_from(path_env: Optional[str], project_root: str = "") -> Tuple[str, ...]:
    """The folders of a PATH value, as path_key forms, for the persistence
    check. Windows PATH uses ";", POSIX ":" (the value decides: a ";" or a
    leading drive letter means Windows). Left out: empty, relative and "."
    entries, entries with an unexpanded variable, and entries strictly inside
    the project folder (.venv/bin, node_modules/.bin: the project's own
    tools). None or "" gives () (the fixed list only)."""
    if not path_env:
        return ()
    value = str(path_env)
    sep = ";" if (";" in value or _DRIVE.match(value.strip().strip('"'))) else ":"
    root = norm(project_root) if project_root else None
    root_key = path_key(root) if root else None
    out: List[str] = []
    for raw in value.split(sep):
        entry = raw.strip().strip('"')
        if not entry or entry in (".", "./") or not _ABS_PATH.match(entry):
            continue
        n = norm(entry)
        if not n:
            continue
        key = path_key(n)
        if root_key and _rel_below(key, root_key):
            continue                                   # strictly inside the project
        if key not in out:
            out.append(key)
    return tuple(out)


def live_path_dirs(project_root: str = "") -> Tuple[str, ...]:
    """path_dirs_from the PATH of this process. Hooks run as children of the
    agent CLI, so this is the PATH the agent's commands use. Only hook entry
    points call this; evals pass a fixed PATH (or none)."""
    return path_dirs_from(os.environ.get("PATH", ""), project_root)


def _path_dir_hit(path: str, path_dirs: Sequence[str]) -> Optional[str]:
    """The PATH folder `path` is directly in (or is), or None. PATH lookup is
    not recursive: only direct entries count."""
    if not path_dirs:
        return None
    key = path_key(path)
    up = path_key(parent(path))
    for d in path_dirs:
        if key == d or up == d:
            return d
    return None


def _anywhere_place(low: str) -> Optional[Place]:
    """Entries that count by name wherever they are (git hooks and settings,
    editor tasks, agent settings, Python startup files). `low`: lower case."""
    segs = low.split("/")
    for run, kind, reason in ANYWHERE_ENTRIES:
        n = len(run)
        if any(tuple(segs[i:i + n]) == run for i in range(len(segs) - n + 1)):
            return Place(kind, "/".join(run), reason)
    name = segs[-1]
    if name in ("sitecustomize.py", "usercustomize.py") or (
            name.endswith(".pth") and ("site-packages" in segs or "dist-packages" in segs)):
        return Place("python_startup", name, _R_PY)
    return None


def place_of(path: Optional[str], path_dirs: Sequence[str] = ()) -> Optional[Place]:
    """The persistence location a created path is in, or None. `path_dirs`
    (path_dirs_from): folders on the live PATH, checked after the fixed list."""
    if not path:
        return None
    low = path.lower()
    if re.match(r"^/[^/]+$", low) or re.match(r"^[a-z]:/[^/]+$", low):
        return Place("root", parent(path), _R_ROOT)
    rel = home_rel(path)
    if rel is not None:
        r = rel.lower()
        for entry, kind, reason in HOME_ENTRIES:
            if _under(r, entry):
                return Place(kind, "~/" + entry, reason)
    key = _abs_key(low)
    for entry, kind, reason in ABS_ENTRIES:
        if _under(key, entry):
            return Place(kind, entry, reason)
    place = _anywhere_place(low)
    if place is not None:
        return place
    d = _path_dir_hit(path, path_dirs)
    if d is not None:
        return Place("path_dir", d, _R_PATH_LIVE)
    return None


def _fixed_path_dir_parent(path: str) -> Optional[str]:
    """The fixed-list PATH folder `path` is directly in, or None."""
    up = parent(path)
    rel = home_rel(up)
    if rel is not None:
        for entry, kind, _ in HOME_ENTRIES:
            if kind == "path_dir" and rel.lower().rstrip("/") == entry:
                return "~/" + entry
    key = _abs_key(up.lower()).rstrip("/")
    for entry, kind, _ in ABS_ENTRIES:
        if kind == "path_dir" and key == entry:
            return entry
    return None


def _holds_listed(root: str) -> bool:
    """True when the folder is /, a drive root, a home folder, the folder of
    home folders, or holds an entry of the fixed list below it (~/.config holds
    ~/.config/nvim, /usr holds /usr/bin). Such a folder is never treated as
    one repo for the same-repo rule."""
    low = root.lower().rstrip("/") or "/"
    if low in ("/", "/home", "/users", "~") or re.match(r"^[a-z]:$", low) or re.match(r"^[a-z]:/users$", low):
        return True
    rel = home_rel(root)
    if rel is not None:
        r = rel.lower().rstrip("/")
        if r == "" or any(entry.startswith(r + "/") for entry, _, _ in HOME_ENTRIES):
            return True
    key = _abs_key(low)
    return any(entry.startswith(key + "/") for entry, _, _ in ABS_ENTRIES)


def same_repo(path: Optional[str], target: Optional[str], project_root: str) -> bool:
    """The same-repo rule: the link, its target and the project are all inside
    one project folder, and neither the link nor the target is in .git. The
    project folder must not be /, a home folder, or a folder that holds a
    listed location. Then only entries that count by name (git hooks and
    settings, .vscode/tasks.json, .claude/settings*.json, .mcp.json, *.pth,
    ...) and a new entry directly in a PATH folder are checked, even when the
    project itself lives in a listed place (a repo at ~/.config/nvim)."""
    if not (path and target and project_root):
        return False
    root = norm(project_root)
    if not root or _holds_listed(root) or _fully_sensitive(root):
        return False
    base = path_key(root)
    for p in (path, target):
        rel = _rel_below(path_key(p), base)
        if rel is None or ".git" in rel.lower().split("/"):
            return False
    return True


# Folders where every file matters (not only some names): a repo inside one
# never gets the same-repo rule, so every link there is checked in full
# (a repo at ~/.ssh: `ln -s id.pub authorized_keys` asks). Mixed folders such
# as ~/.config/nvim keep the rule.
_FULLY_SENSITIVE = frozenset({"ssh", "autostart", "service", "system_config"})


def _fully_sensitive(root: str) -> bool:
    rel = home_rel(root)
    if rel is not None:
        r = rel.lower()
        return any(_under(r, e) for e, kind, _ in HOME_ENTRIES if kind in _FULLY_SENSITIVE)
    key = _abs_key(root.lower())
    return any(_under(key, _abs_key(e)) for e, kind, _ in ABS_ENTRIES if kind in _FULLY_SENSITIVE)


def _named_place(path: str, path_dirs: Sequence[str]) -> Optional[Place]:
    """place_of for a link inside one repo (same_repo): only entries that count
    by name, and a new entry directly in a PATH folder (fixed list or live)."""
    place = _anywhere_place(path.lower())
    if place is not None:
        return place
    d = _fixed_path_dir_parent(path)
    if d is not None:
        return Place("path_dir", d, _R_PATH)
    d = _path_dir_hit(path, path_dirs)
    if d is not None:
        return Place("path_dir", d, _R_PATH_LIVE)
    return None


def _named_target_place(target: str) -> Optional[Place]:
    """target_place for a link inside one repo: only entries that count by
    name, or a folder named like one that holds them (.claude, .vscode, ...)."""
    low = target.lower()
    place = _anywhere_place(low)
    if place is not None:
        return place
    last = low.rsplit("/", 1)[-1]
    if last in _ANYWHERE_FOLDERS:
        for run, kind, reason in ANYWHERE_ENTRIES:
            if run[0] == last:
                return Place(kind, "/".join(run), reason)
    return None


def target_place(target: Optional[str]) -> Optional[Place]:
    """A link target that is a persistence location, is inside one, or is a
    folder that contains one: a later write through the link changes that
    location while the command shows only the link's name. Folders on PATH are
    left out (a link to a program is how programs are used), and so is an
    ordinary entry in /."""
    if not target:
        return None
    low = target.lower()
    if low == "/" or re.match(r"^[a-z]:/$", low):
        return Place("root", target, "the root folder: every system file is reachable through this link")
    if low in ("/home", "/users") or re.match(r"^[a-z]:/users$", low):
        return Place("shell_startup", target, "the folder of all home folders, with their shell startup files")
    place = place_of(target)
    if place is not None and place.kind not in ("root", "path_dir"):
        return place
    if place is not None and place.kind == "root":
        # /etc, /Library/... are entries directly in / and listed folders too.
        key = _abs_key(low).rstrip("/")
        for entry, kind, reason in ABS_ENTRIES:
            if kind != "path_dir" and _under(key, entry):
                return Place(kind, entry, reason)
    rel = home_rel(target)
    if rel is not None:
        r = rel.lower().rstrip("/")
        for entry, kind, reason in HOME_ENTRIES:
            if kind != "path_dir" and (r == "" or entry.startswith(r + "/")):
                return Place(kind, "~/" + entry, reason)
    key = _abs_key(low).rstrip("/")
    for entry, kind, reason in ABS_ENTRIES:
        if kind != "path_dir" and entry.startswith(key + "/"):
            return Place(kind, entry, reason)
    if low.rsplit("/", 1)[-1] in _ANYWHERE_FOLDERS:
        for run, kind, reason in ANYWHERE_ENTRIES:
            if run[0] == low.rsplit("/", 1)[-1]:
                return Place(kind, "/".join(run), reason)
    return None


# ---------- commands ----------


@dataclass(frozen=True)
class NewLink:
    path: Optional[str]           # where the link is created (normalized; None unknown)
    target_raw: str               # what it points to, as written
    target: Optional[str]         # the target resolved (symbolic: against the link's folder; hard and -r: cwd)


@dataclass(frozen=True)
class LinkCommand:
    program: str                  # ln | cp | link | new-item | mklink; code: os.symlink, Path.symlink_to, fs.symlinkSync ...
    kind: str                     # symbolic | hard | junction
    form: str                     # named | inside | many | single | target_dir | unknown | code
    links: Tuple[NewLink, ...]
    folder: Optional[str] = None  # the folder the links go in (inside, many, single, target_dir)
    folder_raw: str = ""          # that folder as written
    why: str = ""                 # inside: root | home | current | parent | slash | disk
    maybe: Tuple[str, ...] = ()   # other paths the command may create (not checked on disk, or xargs input)
    sources_raw: Tuple[str, ...] = ()
    origin: str = ""              # code: "python" | "node" (inline code), or "script:<rel>" (a script file F4 read)

    def possible_paths(self) -> List[str]:
        out = [x.path for x in self.links if x.path]
        return out + [p for p in self.maybe if p not in out]

    def targets(self) -> List[str]:
        return [x.target for x in self.links if x.target]


_LN_LONG = {
    "--symbolic": "s", "--force": "", "--no-dereference": "n", "--no-target-directory": "T", "--relative": "r",
    "--verbose": "", "--interactive": "", "--logical": "", "--physical": "", "--directory": "", "--backup": "",
    "--target-directory": "t", "--suffix": "S", "--help": "?", "--version": "?",
}
_CP_LONG = {
    "--symbolic-link": "s", "--link": "l", "--target-directory": "t", "--no-target-directory": "T",
    "--suffix": "S", "--no-dereference": "", "--dereference": "", "--recursive": "", "--force": "",
    "--interactive": "", "--archive": "", "--backup": "", "--preserve": "", "--no-preserve": "", "--parents": "",
    "--reflink": "", "--remove-destination": "", "--sparse": "", "--strip-trailing-slashes": "", "--update": "",
    "--verbose": "", "--one-file-system": "", "--no-clobber": "", "--attributes-only": "", "--copy-contents": "",
    "--help": "?", "--version": "?",
}
_VALUE_LONG = {"--target-directory", "--suffix"}


def _long(arg: str, table: dict) -> Tuple[str, str, bool]:
    """(canonical name, value, has '=') for a long option; unique prefixes
    count, as in GNU getopt. ("", "", False) when unknown or ambiguous."""
    name, eq, val = arg.partition("=")
    if name in table:
        return name, val, bool(eq)
    hits = [k for k in table if k.startswith(name)]
    return (hits[0], val, bool(eq)) if len(hits) == 1 else ("", "", False)


@dataclass
class _Opts:
    symbolic: bool = False
    hard_via_cp: bool = False
    nodir: bool = False
    no_target_dir: bool = False
    relative: bool = False
    target_dir: Optional[str] = None
    info_only: bool = False
    operands: List[str] = field(default_factory=list)


def _parse_opts(args: Sequence[str], table: dict, short_value: str, short_flags: dict) -> _Opts:
    o = _Opts()
    i, ended = 0, False
    while i < len(args):
        a = args[i]
        if ended or a == "-" or not a.startswith("-"):
            o.operands.append(a)
            i += 1
            continue
        if a == "--":
            ended = True
            i += 1
            continue
        if a.startswith("--"):
            name, val, has_eq = _long(a, table)
            code = table.get(name, "")
            if name in _VALUE_LONG and not has_eq:
                val = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            if code == "t":
                o.target_dir = val
            elif code:
                _flag(o, code)
            i += 1
            continue
        j = 1
        while j < len(a):
            ch = a[j]
            if ch in short_value:
                val = a[j + 1:]
                if not val:
                    val = args[i + 1] if i + 1 < len(args) else ""
                    i += 1
                if ch == "t":
                    o.target_dir = val
                break
            _flag(o, short_flags.get(ch, ""))
            j += 1
        i += 1
    return o


def _flag(o: _Opts, code: str) -> None:
    if code == "s":
        o.symbolic = True
    elif code == "l":
        o.hard_via_cp = True
    elif code == "n":
        o.nodir = True
    elif code == "T":
        o.no_target_dir = True
    elif code == "r":
        o.relative = True
    elif code == "?":
        o.info_only = True


_LN_SHORT = {"s": "s", "n": "n", "h": "n", "T": "T", "r": "r"}
_CP_SHORT = {"s": "s", "l": "l", "T": "T"}


def _known_dir(raw: str, full: Optional[str], nodir: bool, is_dir: Optional[IsDir]) -> str:
    """Why `raw` is known to be an existing folder ("" when not known)."""
    r = raw.strip()
    if full == "/" or (full and re.match(r"^[a-z]:/$", full)):
        return "root"
    if r in ("~", "~/") or full == "~":
        return "home"
    if r in (".", "./"):
        return "current"
    if r in ("..", "../"):
        return "parent"
    if r.endswith("/") or r.endswith("\\"):
        return "slash"
    if full and is_dir is not None:
        try:
            if is_dir(full, not nodir):
                return "disk"
        except Exception:
            return ""
    return ""


def _target(raw: str, link_path: Optional[str], cwd: str, symbolic_relative_to_link: bool) -> Optional[str]:
    if symbolic_relative_to_link and link_path and not (raw.startswith(("/", "~", "\\")) or _DRIVE.match(raw)
                                                        or _HOME_VAR.match(raw)):
        return norm(raw, parent(link_path))
    return norm(raw, cwd)


def _placement(program: str, kind: str, o: _Opts, cwd: str, is_dir: Optional[IsDir], appended: bool) -> Optional[LinkCommand]:
    ops = o.operands
    sym_rel = kind == "symbolic" and not o.relative

    def one(src: str, path: Optional[str]) -> NewLink:
        return NewLink(path, src, _target(src, path, cwd, sym_rel))

    def inside(folder: Optional[str], srcs: Sequence[str]) -> Tuple[NewLink, ...]:
        out = []
        for s in srcs:
            name = last_part(s)
            ok = folder and name and not _UNKNOWN.search(name)
            out.append(one(s, _join(folder, name) if ok else None))
        return tuple(out)

    srcs = tuple(ops)
    if o.target_dir is not None:
        folder = norm(o.target_dir, cwd)
        if not ops and not appended:
            return None
        # With xargs, more targets come from the input: their links go in the
        # same folder under names not known here.
        maybe = (_join(folder, "<input>"),) if (appended and folder) else ()
        return LinkCommand(program, kind, "target_dir" if not appended else "unknown", inside(folder, ops),
                           folder, o.target_dir, maybe=maybe, sources_raw=srcs)
    if appended:
        # xargs adds paths after the ones written: any written path may be the
        # link or its target.
        maybe = tuple(p for p in (norm(x, cwd) for x in ops) if p)
        links = tuple(NewLink(None, x, norm(x, cwd)) for x in ops)
        return LinkCommand(program, kind, "unknown", links, maybe=maybe, sources_raw=srcs)
    if not ops:
        return None
    if o.no_target_dir:
        if len(ops) != 2:
            return None
        return LinkCommand(program, kind, "named", (one(ops[0], norm(ops[1], cwd)),), sources_raw=srcs[:1])
    if len(ops) == 1:
        folder = norm(cwd) if cwd else None
        return LinkCommand(program, kind, "single", inside(folder, ops), folder, cwd or ".", sources_raw=srcs)
    last = ops[-1]
    folder = norm(last, cwd)
    if len(ops) > 2:
        return LinkCommand(program, kind, "many", inside(folder, ops[:-1]), folder, last, sources_raw=srcs[:-1])
    why = _known_dir(last, folder, o.nodir, is_dir)
    if why:
        return LinkCommand(program, kind, "inside", inside(folder, ops[:1]), folder, last, why, sources_raw=srcs[:1])
    other = inside(folder, ops[:1])[0].path
    return LinkCommand(program, kind, "named", (one(ops[0], folder),), folder=None, folder_raw=last,
                       maybe=(other,) if other else (), sources_raw=srcs[:1])


def _raw(tok: shellparse.Token) -> str:
    """A PowerShell / cmd word as written: backslashes are path separators
    there, not escapes. Surrounding quotes removed."""
    r = tok.raw
    if len(r) >= 2 and r[0] == r[-1] and r[0] in "'\"":
        return r[1:-1]
    return r


_NI_PARAMS = ("path", "name", "itemtype", "type", "value", "target", "force", "credential", "whatif", "confirm",
              "literalpath")


def _new_item(words: Sequence[str], cwd: str) -> Optional[LinkCommand]:
    vals = {}
    positional: List[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w.startswith("-") and len(w) > 1 and not re.match(r"^-\d", w):
            name, _, inline = w[1:].partition(":")
            low = name.lower()
            hits = [p for p in _NI_PARAMS if p == low] or [p for p in _NI_PARAMS if p.startswith(low)]
            key = hits[0] if len(hits) == 1 or (hits and hits[0] == low) else ""
            key = {"type": "itemtype", "target": "value", "literalpath": "path"}.get(key, key)
            if key in ("force", "whatif", "confirm") or not key:
                i += 1
                continue
            if inline:
                vals[key] = inline
            elif i + 1 < len(words):
                vals[key] = words[i + 1]
                i += 1
            i += 1
            continue
        positional.append(w)
        i += 1
    itype = vals.get("itemtype", "").strip("'\"").lower()
    kind = {"symboliclink": "symbolic", "hardlink": "hard", "junction": "junction"}.get(itype)
    if not kind:
        return None
    path_raw = vals.get("path") or (positional[0] if positional else "")
    if not path_raw and not vals.get("name"):
        return None
    folder = norm(path_raw or ".", cwd)
    link = _join(folder, vals["name"]) if (vals.get("name") and folder) else folder if not vals.get("name") else None
    target_raw = vals.get("value", "")
    target = norm(target_raw, parent(link) if (link and kind == "symbolic") else cwd) if target_raw else None
    return LinkCommand("new-item", kind, "named", (NewLink(link, target_raw, target),), sources_raw=(target_raw,))


def _mklink(words: Sequence[str], cwd: str) -> Optional[LinkCommand]:
    kind = "symbolic"
    ops: List[str] = []
    for w in words:
        lw = w.lower()
        if lw == "/d":
            kind = "symbolic"
        elif lw == "/h":
            kind = "hard"
        elif lw == "/j":
            kind = "junction"
        else:
            ops.append(w)
    if len(ops) != 2:
        return None
    link = norm(ops[0], cwd)
    target = norm(ops[1], parent(link) if (link and kind == "symbolic") else cwd)
    return LinkCommand("mklink", kind, "named", (NewLink(link, ops[1], target),), sources_raw=(ops[1],))


def _one_command(tokens: List[shellparse.Token], cwd: str, is_dir: Optional[IsDir]) -> Optional[LinkCommand]:
    eff = shellparse.effective_argv(tokens)
    if not eff:
        return None
    start = len(tokens) - len(eff)
    before = [t.value for t in tokens[:start] if not t.redirect]
    appended = False
    if any(shellparse._base(v) == "xargs" for v in before):
        # xargs appends its input after the written paths, unless it replaces a
        # placeholder (-I / -i / --replace).
        appended = not any(v.startswith(("-I", "-i", "--replace")) for v in before)
    argv = [t.value for t in eff]
    prog = shellparse._base(argv[0])
    if prog in ("busybox", "busybox.exe") and len(argv) > 1:
        argv, eff = argv[1:], eff[1:]
        prog = shellparse._base(argv[0])
    if prog in ("ln", "gln", "ln.exe"):
        o = _parse_opts(argv[1:], _LN_LONG, "tS", _LN_SHORT)
        if o.info_only:
            return None
        return _placement("ln", "symbolic" if o.symbolic else "hard", o, cwd, is_dir, appended)
    if prog in ("cp", "gcp", "cp.exe"):
        o = _parse_opts(argv[1:], _CP_LONG, "tS", _CP_SHORT)
        if o.info_only or not (o.symbolic or o.hard_via_cp):
            return None
        return _placement("cp", "symbolic" if o.symbolic else "hard", o, cwd, is_dir, appended)
    if prog in ("link", "link.exe") and len(argv) == 3 and not appended:
        return LinkCommand("link", "hard", "named", (NewLink(norm(argv[2], cwd), argv[1], norm(argv[1], cwd)),),
                           sources_raw=(argv[1],))
    if prog in ("new-item", "ni"):
        return _new_item([_raw(t) for t in eff[1:]], cwd)
    if prog in ("mklink", "mklink.exe"):
        return _mklink([_raw(t) for t in eff[1:]], cwd)
    return None


def _cd_target(argv: Sequence[str]) -> Optional[str]:
    if argv and shellparse._base(argv[0]) in ("cd", "pushd", "set-location", "sl", "chdir"):
        if "-" in argv[1:]:
            return ""                                  # cd - : the previous folder, unknown here
        return next((a for a in argv[1:] if not a.startswith("-")), "~")
    return None


def find_links(command: str, cwd: str = "", is_dir: Optional[IsDir] = None) -> List[LinkCommand]:
    """Every link the command creates, in order. Never raises for ordinary
    input; an unparsable command gives []."""
    if not might_link(command):
        return []
    out: List[LinkCommand] = []
    try:
        top = shellparse.split_commands(command)
    except Exception:
        top = []
    here = cwd
    for simple in top:
        argv = [t.value for t in shellparse.effective_argv(simple.tokens)]
        cd = _cd_target(argv)
        if cd is not None:
            nxt = norm(cd, here)
            here = nxt or ""
            continue
        lc = _one_command(simple.tokens, here, is_dir)
        if lc is not None:
            out.append(lc)
    try:
        inner = shellparse.extract_scripts(command)
    except Exception:
        inner = []
    for code in inner:
        if not might_link(code):
            continue
        try:
            simples = shellparse.split_commands(code)
        except Exception:
            continue
        inner_here = cwd
        for simple in simples:
            argv = [t.value for t in shellparse.effective_argv(simple.tokens)]
            cd = _cd_target(argv)
            if cd is not None:
                inner_here = norm(cd, inner_here) or ""
                continue
            lc = _one_command(simple.tokens, inner_here, is_dir)
            if lc is not None and lc not in out:
                out.append(lc)
    # Links made by inline code (python -c, node -e, python - <<EOF), also
    # inside bash -c and after cd.
    if _CODE_QUICK.search(command):
        for lang, code, here in code_blocks(command, cwd):
            for lc in code_links(code, lang, here, origin=lang):
                if lc not in out:
                    out.append(lc)
    return out


# ---------- links made from code ----------


_PY_NAMES = {"python", "py", "pypy"}
_NODE_NAMES = {"node", "nodejs", "bun"}
_CODE_FLAGS = {"python": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}}
_SCRIPT_EXT = {".py": "python", ".js": "node", ".mjs": "node", ".cjs": "node"}


def _interpreter(word: str) -> str:
    """"python" or "node" for an interpreter program name, else ""."""
    b = shellparse._base(word)
    if b.endswith(".exe"):
        b = b[:-4]
    short = re.sub(r"[\d.]+$", "", b)
    if b in _PY_NAMES or short in _PY_NAMES:
        return "python"
    if b in _NODE_NAMES or short in _NODE_NAMES:
        return "node"
    return ""


def code_blocks(command: str, cwd: str = "", depth: int = 0) -> List[Tuple[str, str, str]]:
    """(language, code, folder it runs in) for inline Python and Node code the
    command runs: `python -c CODE`, `node -e CODE`, `python - <<EOF`, also
    after `cd` and inside `bash -c`, `pwsh -c`, `cmd /c`, `$(...)`. Never
    raises."""
    out: List[Tuple[str, str, str]] = []
    if depth > shellparse.MAX_DEPTH or not command or len(command) > shellparse.MAX_LEN:
        return out
    try:
        simples = shellparse.split_commands(command)
    except Exception:
        return out
    here = cwd
    for simple in simples:
        try:
            argv_t = shellparse.effective_argv(simple.tokens)
        except Exception:
            continue
        argv = [t.value for t in argv_t]
        cd = _cd_target(argv)
        if cd is not None:
            here = norm(cd, here) or ""
            continue
        lang = _interpreter(argv[0]) if argv else ""
        if lang:
            code = shellparse._code_after_flag(argv_t, _CODE_FLAGS[lang])
            if code is not None:
                out.append((lang, code, here))
            elif simple.heredocs and not any(a.lower().endswith(tuple(_SCRIPT_EXT)) for a in argv[1:]):
                out += [(lang, body, here) for _, body in simple.heredocs]
        try:
            inner = shellparse._scripts_in(simple)
        except Exception:
            inner = []
        for kind, code in inner:
            if kind == "shell" and code.strip():
                out += [b for b in code_blocks(code, here, depth + 1) if b not in out]
    return out


def code_links(code: str, lang: str, cwd: str = "", origin: str = "") -> List[LinkCommand]:
    """Links the code creates with literal paths. Python: parsed with ast;
    Node: a pattern match on fs calls with string literals. A path that is not
    a literal (a variable, an f-string with a value, a call not listed) is
    unknown (None). A syntax error gives []. Never raises."""
    if not code or not _CODE_QUICK.search(code):
        return []
    try:
        if lang == "python":
            return _python_links(code, cwd, origin or lang)
        if lang == "node":
            return _node_links(code, cwd, origin or lang)
    except (RecursionError, MemoryError, ValueError):
        return []
    return []


def script_links(script: "object") -> List[LinkCommand]:
    """Links a script file F4 read creates (scriptsource.ScriptFile): Python
    and Node code by the file's extension, shell scripts with find_links. The
    folder the script runs in is `run_cwd` (the command's folder); without it
    only absolute and home paths are known."""
    path = str(getattr(script, "path", "") or "")
    content = str(getattr(script, "content", "") or "")
    cwd = str(getattr(script, "run_cwd", "") or "")
    rel = str(getattr(script, "rel", "") or path)
    if getattr(script, "kind", "") == "shell":
        return find_links(content, cwd, None)
    ext = os.path.splitext(path.replace("\\", "/"))[1].lower()
    lang = _SCRIPT_EXT.get(ext, "")
    return code_links(content, lang, cwd, origin="script:" + rel) if lang else []


# Python: values of path expressions. A value is (text, home): `home` is True
# when a leading "~" means the home folder (os.path.expanduser, Path.home(),
# os.environ["HOME"]). Python does not expand "~" or "$HOME" by itself.

_HOME_KEYS = {"HOME", "USERPROFILE"}
_PY_CANON = (("posixpath.", "os.path."), ("ntpath.", "os.path."), ("pathlib.PosixPath", "pathlib.Path"),
             ("pathlib.WindowsPath", "pathlib.Path"))


def _canon(q: str) -> str:
    for a, b in _PY_CANON:
        if q == a.rstrip(".") and b.endswith("."):
            return b.rstrip(".")
        if q.startswith(a):
            return b + q[len(a):]
    return q


def _py_aliases(tree: ast.AST) -> dict:
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    names[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    names[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    names[a.asname or a.name] = node.module + "." + a.name
    return names


def _qual(node: ast.AST, names: dict) -> Optional[str]:
    """The dotted name a call target refers to after imports ("os.symlink",
    "pathlib.Path.home"), or None."""
    if isinstance(node, ast.Name):
        return _canon(names.get(node.id, node.id))
    if isinstance(node, ast.Attribute):
        base = _qual(node.value, names)
        return _canon(base + "." + node.attr) if base else None
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return _canon(node.args[0].value.split(".")[0])
    return None


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8")
            except UnicodeDecodeError:
                return None
        if isinstance(v, str):
            return v
    return None


def _is_abs_text(text: str, home: bool) -> bool:
    return text.startswith(("/", "\\")) or bool(_DRIVE.match(text)) or (home and text.startswith("~"))


def _pjoin(parts: Sequence[Tuple[str, bool]]) -> Tuple[str, bool]:
    """os.path.join / Path(a, b) / a / b: a later absolute part replaces
    everything before it."""
    text, home = parts[0]
    for t, h in parts[1:]:
        if _is_abs_text(t, h) or not text:
            text, home = t, h
        else:
            text = text.rstrip("/\\") + "/" + t
    return text, home


def _pv(node: Optional[ast.AST], names: dict, depth: int = 0) -> Optional[Tuple[str, bool]]:
    if node is None or depth > 30:
        return None
    s = _const_str(node)
    if s is not None:
        return s, False
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            c = _const_str(v)
            if c is None:
                return None                             # an f-string with a value: unknown
            parts.append(c)
        return "".join(parts), False
    if isinstance(node, ast.BinOp):
        left, right = _pv(node.left, names, depth + 1), _pv(node.right, names, depth + 1)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left[0] + right[0], left[1]
        if isinstance(node.op, ast.Div):
            return _pjoin([left, right])
        return None
    if isinstance(node, ast.Subscript):
        if _qual(node.value, names) == "os.environ" and _const_str(node.slice) in _HOME_KEYS:
            return "~", True
        return None
    if not isinstance(node, ast.Call):
        return None
    f, args = node.func, node.args
    q = _qual(f, names)
    if q in ("os.path.expanduser", "os.path.expandvars") and len(args) == 1:
        v = _pv(args[0], names, depth + 1)
        if v is None:
            return None
        text = v[0]
        if q == "os.path.expandvars":
            m = _HOME_VAR.match(text)
            text = "~" + text[m.end():] if m else text
        return text, v[1] or text == "~" or text.startswith(("~/", "~\\"))
    if q in ("os.getenv", "os.environ.get") and args and _const_str(args[0]) in _HOME_KEYS:
        return "~", True
    if q == "pathlib.Path.home" and not args:
        return "~", True
    if q in ("pathlib.Path.cwd", "os.getcwd") and not args:
        return ".", False
    if q in ("os.path.join", "pathlib.Path", "pathlib.PurePath"):
        if not args:
            return (".", False) if q != "os.path.join" else None
        parts = [_pv(a, names, depth + 1) for a in args]
        return None if any(p is None for p in parts) else _pjoin(parts)   # type: ignore[arg-type]
    if q in ("str", "os.fspath", "os.path.abspath", "os.path.normpath") and len(args) == 1:
        return _pv(args[0], names, depth + 1)
    if isinstance(f, ast.Attribute):
        if f.attr == "expanduser" and not args:
            v = _pv(f.value, names, depth + 1)
            return (v[0], v[1] or v[0] == "~" or v[0].startswith(("~/", "~\\"))) if v else None
        if f.attr in ("absolute", "resolve") and not args:
            return _pv(f.value, names, depth + 1)
        if f.attr == "joinpath":
            parts = [_pv(f.value, names, depth + 1)] + [_pv(a, names, depth + 1) for a in args]
            return None if any(p is None for p in parts) else _pjoin(parts)   # type: ignore[arg-type]
    return None


def _as_path_text(v: Optional[Tuple[str, bool]]) -> Optional[str]:
    """The value as text for norm(): a "~" or "$HOME" Python does not expand
    is a folder of that name in the current folder."""
    if v is None:
        return None
    text, home = v
    if not home and (text.startswith("~") or _HOME_VAR.match(text)):
        return "./" + text
    return text


def _code_link(program: str, kind: str, link_text: Optional[str], target_text: Optional[str], cwd: str,
               origin: str) -> Optional[LinkCommand]:
    if link_text is None and target_text is None:
        return None
    path = norm(link_text, cwd) if link_text is not None else None
    target = (_target(target_text, path, cwd, kind == "symbolic") if target_text is not None else None)
    raw = target_text if target_text is not None else ""
    return LinkCommand(program, kind, "code", (NewLink(path, raw, target),), sources_raw=(raw,), origin=origin)


def _python_links(code: str, cwd: str, origin: str) -> List[LinkCommand]:
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return []
    names = _py_aliases(tree)
    found: List[Tuple[int, int, LinkCommand]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        q = _qual(f, names)
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        lc = None
        if q in ("os.symlink", "os.link"):
            src = node.args[0] if node.args else kw.get("src")
            dst = node.args[1] if len(node.args) > 1 else kw.get("dst")
            lc = _code_link(q, "symbolic" if q == "os.symlink" else "hard",
                            _as_path_text(_pv(dst, names)), _as_path_text(_pv(src, names)), cwd, origin)
        elif isinstance(f, ast.Attribute) and f.attr in ("symlink_to", "hardlink_to", "link_to"):
            if q in ("pathlib.Path." + f.attr, "pathlib.PurePath." + f.attr):   # Path.symlink_to(p, target)
                self_node = node.args[0] if node.args else None
                rest = node.args[1:]
            else:
                self_node, rest = f.value, node.args
            other = rest[0] if rest else kw.get("target")
            me, it = _as_path_text(_pv(self_node, names)), _as_path_text(_pv(other, names))
            if f.attr == "link_to":                    # Path(a).link_to(b): b becomes a hard link to a
                lc = _code_link("Path.link_to", "hard", it, me, cwd, origin)
            else:
                lc = _code_link("Path." + f.attr, "symbolic" if f.attr == "symlink_to" else "hard", me, it, cwd,
                                origin)
        if lc is not None:
            found.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), lc))
    return [lc for _, _, lc in sorted(found, key=lambda x: (x[0], x[1]))]


# Node: fs.symlink / symlinkSync / fs.promises.symlink (target, path[, type])
# and fs.link / linkSync (existingPath, newPath), string literal arguments.
_NODE_CALL = re.compile(r"(?<![\w$])(symlinkSync|symlink|linkSync|link)\s*\(")
_NODE_FS_RECV = re.compile(r"(?:(?<![\w$])(?:fs|fsp|fse|fsPromises|fs_extra|fsExtra|promises)"
                           r"|require\(\s*['\"](?:node:)?fs(?:/promises)?['\"]\s*\))\s*\.\s*$")
_JS_STR = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\$]|\\.|\$(?!\{))*`""", re.S)
_JS_RECV = re.compile(r"[\w$)\]]\s*\.\s*$")
_JS_FS_LIKE = re.compile(r"(?i)(?:fs\w*|promises|require\([^()]*\))\s*\.\s*$")


def _js_skip_string(code: str, i: int) -> int:
    """The index after the string or template literal starting at i (a
    template's ${...} parts are skipped by brace count)."""
    q = code[i]
    i += 1
    depth = 0
    while i < len(code):
        ch = code[i]
        if ch == "\\":
            i += 2
            continue
        if q == "`" and ch == "$" and code[i + 1:i + 2] == "{":
            depth += 1
            i += 2
            continue
        if q == "`" and depth and ch == "}":
            depth -= 1
        elif ch == q and not depth:
            return i + 1
        elif ch == "\n" and q != "`":
            return i
        i += 1
    return i


def _js_args(code: str, start: int) -> List[str]:
    """The top-level arguments of a call whose "(" is just before `start`, as
    written. Stops at the closing ")" (or after 2000 characters)."""
    args: List[str] = []
    depth, cur, i = 0, start, start
    end = min(len(code), start + 2000)
    while i < end:
        ch = code[i]
        if ch in "'\"`":
            i = _js_skip_string(code, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(code[cur:i].strip())
                return [] if args == [""] else args
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(code[cur:i].strip())
            cur = i + 1
        i += 1
    return []


def _js_literal(arg: str) -> Optional[str]:
    """The value of a JS string literal (a template without ${}), else None."""
    if not _JS_STR.fullmatch(arg.strip()):
        return None
    body = arg.strip()[1:-1]
    return re.sub(r"\\(.)", lambda x: {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(x.group(1), x.group(1)), body)


def _node_links(code: str, cwd: str, origin: str) -> List[LinkCommand]:
    out: List[LinkCommand] = []
    for m in _NODE_CALL.finditer(code):
        fn = m.group(1)
        before = code[max(0, m.start() - 60):m.start()]
        if fn == "link" and not _NODE_FS_RECV.search(before):
            continue                                   # a `link(` that is not fs.link
        if fn == "symlink" and _JS_RECV.search(before) and not _JS_FS_LIKE.search(before):
            continue                                   # obj.symlink( where obj does not look like fs
        args = _js_args(code, m.end())
        if len(args) < 2:
            continue
        a, b = _js_literal(args[0]), _js_literal(args[1])
        kind = "symbolic" if fn.startswith("symlink") else "hard"
        if kind == "symbolic" and len(args) > 2 and _js_literal(args[2]) == "junction":
            kind = "junction"
        lc = _code_link(("fs." + fn), kind, _as_path_text((b, False)) if b is not None else None,
                        _as_path_text((a, False)) if a is not None else None, cwd, origin)
        if lc is not None and lc not in out:
            out.append(lc)
    return out


# ---------- the persistence check (used by the human gate) ----------


@dataclass(frozen=True)
class PersistenceHit:
    link: str               # the link path (or "?" when unknown)
    target: str             # the target as written
    place: Place
    side: str               # "link" (created there) | "target" (points there)

    def text(self) -> str:
        if self.side == "link":
            return f"creates the link {display(self.link)} -> {self.target}: {self.place.reason}"
        return (f"link {display(self.link)} points to {self.target} ({self.place.where}): {self.place.reason}; "
                "later writes through the link change it")


def link_hits(commands: Iterable[LinkCommand], project_root: str = "",
              path_dirs: Sequence[str] = ()) -> List[PersistenceHit]:
    """The persistence check over links already found. `project_root`: the
    same-repo rule (same_repo). `path_dirs` (path_dirs_from): the live PATH."""
    hits: List[PersistenceHit] = []
    for lc in commands:
        # No written target (`xargs ln -s -t DIR`): the links still land in DIR.
        for link in lc.links or (NewLink(None, "<input>", None),):
            candidates = [link.path] if link.path else []
            candidates += [p for p in lc.maybe if p not in candidates]
            inside = bool(candidates) and all(same_repo(p, link.target, project_root) for p in candidates)
            for path in candidates:
                place = _named_place(path, path_dirs) if inside else place_of(path, path_dirs)
                if place is not None:
                    hits.append(PersistenceHit(path, link.target_raw, place, "link"))
                    break
            else:
                place = (_named_target_place(link.target) if (inside and link.target)
                         else target_place(link.target))
                if place is not None:
                    hits.append(PersistenceHit(link.path or "?", link.target_raw, place, "target"))
    return hits


def persistence_hits(command: str, cwd: str = "", project_root: str = "",
                     path_dirs: Sequence[str] = ()) -> List[PersistenceHit]:
    """Links the command creates in a persistence location, or pointing to
    one: ln / cp -s / link / New-Item / mklink, and inline Python or Node code.
    No filesystem access: when the last path may or may not be a folder, both
    possible link paths are checked."""
    return link_hits(find_links(command, cwd, None), project_root, path_dirs)


def script_persistence_hits(script: "object", project_root: str = "",
                            path_dirs: Sequence[str] = ()) -> List[PersistenceHit]:
    """persistence_hits for a script file F4 read (scriptsource.ScriptFile)."""
    return link_hits(script_links(script), project_root, path_dirs)
