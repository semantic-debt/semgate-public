"""Where a provider's API key comes from. One list of places for every
provider, the doctor and `semgate init`:

  1. the semgate-only environment variable SEMGATE_<NAME>
     (SEMGATE_TYPESAFE_API_KEY, SEMGATE_OPENROUTER_API_KEY)
  2. ~/.semgate/.env           (pip installs; `semgate init` uses that folder)
  3. .env in the semgate source checkout (development)
  4. when that checkout is a git worktree: .env in the main checkout (a new
     worktree has no .env of its own; .env is not tracked by git)
  5. the generic environment variable (TYPESAFE_API_KEY, OPENROUTER_API_KEY)

The generic variable comes last: agent CLIs set OPENROUTER_API_KEY for their
own model, and a hook runs with the agent's environment. Found live
(2026-09-25): OpenCode passed a stale user-level OPENROUTER_API_KEY to
semgate, which then answered 401 on every judgment although semgate's own
.env had a valid key. The judge's key is semgate's, not the agent's.

Only the API key is taken from a .env file, and only from these fixed
files. Never the agent's working folder, and never other variables: a base
URL in a planted .env would send every judgment to a server of the
attacker's choosing.

Nothing here prints, logs or returns a key except `find_key`, whose value
goes only into a provider's Authorization header.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

KEY_ENV = {"typesafe": "TYPESAFE_API_KEY", "openrouter": "OPENROUTER_API_KEY"}

# The source checkout's .env: <checkout>/.env (this file is <checkout>/semgate/providers/keys.py).
CHECKOUT_ENV = Path(__file__).resolve().parents[2] / ".env"
_DEFAULT_CHECKOUT_ENV = CHECKOUT_ENV

HOME_LABEL = "file ~/.semgate/.env"
CHECKOUT_LABEL = "file .env in the semgate source checkout"
MAIN_CHECKOUT_LABEL = "file .env in the main git checkout (the semgate source is a git worktree)"


def main_checkout_env(checkout_dir: Path) -> Optional[Path]:
    """<main checkout>/.env when `checkout_dir` is a linked git worktree, else
    None. Reads two small git files and runs no git:
      <worktree>/.git                      a file: "gitdir: <common>/worktrees/<name>"
      <common>/worktrees/<name>/commondir  the common .git folder, usually "../.."
    The main checkout is the folder that holds the common .git folder. None
    for a normal checkout (.git is a folder), a submodule (no commondir file)
    and a bare repository (the common folder is not named .git)."""
    base = Path(checkout_dir)
    dotgit = base / ".git"
    try:
        if not dotgit.is_file():
            return None
        text = dotgit.read_text(encoding="utf-8", errors="ignore").strip()
        if not text.startswith("gitdir:"):
            return None
        gitdir = Path(text[len("gitdir:"):].strip())
        if not gitdir.is_absolute():
            gitdir = base / gitdir
        commondir = gitdir / "commondir"
        if not commondir.is_file():
            return None
        common = Path(commondir.read_text(encoding="utf-8", errors="ignore").strip())
        if not common.is_absolute():
            common = gitdir / common
        common = common.resolve()
    except (OSError, ValueError):
        return None
    if common.name != ".git":
        return None
    return common.parent / ".env"


def env_files(home: Optional[Path] = None, checkout: Optional[Path] = None) -> List[Tuple[str, Path]]:
    """The .env files a key is read from, in order, with a label for messages."""
    home = Path.home() if home is None else Path(home)
    files = [(HOME_LABEL, home / ".semgate" / ".env")]
    path = CHECKOUT_ENV if checkout is None else Path(checkout)
    # SEMGATE_SKIP_CHECKOUT_ENV=1 drops the real checkout .env and, in a git
    # worktree, the main checkout's .env too (the test suite sets it: a
    # developer's real key must never reach a test or its output). It only
    # removes sources, so a missing key fails closed (ask). A test's own file
    # (a patched CHECKOUT_ENV or another `checkout`) still counts.
    if os.environ.get("SEMGATE_SKIP_CHECKOUT_ENV") == "1" and path == _DEFAULT_CHECKOUT_ENV:
        return files
    files.append((CHECKOUT_LABEL, path))
    main = main_checkout_env(path.parent)
    if main is not None and main != path:
        files.append((MAIN_CHECKOUT_LABEL, main))
    return files


def env_file_value(path: Path, name: str) -> str:
    """The value of `name` in a .env file, or "" (no file, no line, empty
    value). Standard library only: `NAME=value`, optional `export `, optional
    matching quotes, an unquoted value ends at ` #` (a comment)."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""
    except OSError:
        return ""
    found = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("export "):
            s = s[7:].lstrip()
        if not s.startswith(name) or "=" not in s:
            continue
        key, value = s.split("=", 1)
        if key.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0]
        value = value.strip().strip("'\"").strip()
        if value:
            found = value          # the last assignment wins, as in python-dotenv
    return found


def find_key(name: str, environ: Optional[Mapping[str, str]] = None,
             home: Optional[Path] = None, checkout: Optional[Path] = None) -> Tuple[str, str]:
    """(value, where) for the key variable `name`; ("", "") when not found.
    `where` is a label (never the value)."""
    environ = os.environ if environ is None else environ
    own = "SEMGATE_" + name
    value = str(environ.get(own, "") or "").strip()
    if value:
        return value, f"environment variable {own}"
    for label, path in env_files(home, checkout):
        value = env_file_value(path, own) or env_file_value(path, name)
        if value:
            return value, label
    value = str(environ.get(name, "") or "").strip()
    if value:
        return value, "environment variable"
    return "", ""


def key_status(provider: str, environ: Optional[Mapping[str, str]] = None,
               home: Optional[Path] = None, checkout: Optional[Path] = None) -> Dict[str, Any]:
    """{"found": bool, "location": label} for a provider's key. No value, no length."""
    _, where = find_key(KEY_ENV[provider], environ, home, checkout)
    return {"found": bool(where), "location": where}
