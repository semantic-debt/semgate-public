"""Pi project trust: will Pi load a project-level semgate extension?

Pi (0.87.1, docs/security.md "Understand project trust" and
dist/core/project-trust.js) loads <project>/.pi/extensions/* only for a
trusted project. The decision, in Pi's order:

  1. `--approve` / `--no-approve` on the command line (one run).
  2. A user-level extension that answers the `project_trust` event.
  3. A saved decision in <agent dir>/trust.json: {"<canonical folder>": true |
     false}; the entry of the folder or its closest parent applies. `/trust`
     in interactive Pi writes it.
  4. defaultProjectTrust in <agent dir>/settings.json: "always" | "never" |
     "ask" (default "ask"; only the agent-dir settings count).
  5. "ask": interactive Pi shows a prompt at start. Print, JSON and RPC modes
     (`pi -p`) cannot ask: Pi skips the project extension with no message, and
     the agent runs without semgate.

<agent dir> is $PI_CODING_AGENT_DIR, else ~/.pi/agent. User-level extensions
(<agent dir>/extensions/) load without project trust.

This module only reads trust.json and settings.json (steps 3 and 4). It never
writes them: semgate does not change Pi's trust settings.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .base import HostEnv

TRUSTED, ASK, NOT_TRUSTED, UNKNOWN = "trusted", "ask", "not trusted", "unknown"


def agent_dir(env: HostEnv) -> Path:
    return env.dir_from("PI_CODING_AGENT_DIR", env.home / ".pi" / "agent")


def user_extension(env: HostEnv) -> Path:
    return agent_dir(env) / "extensions" / "semgate.ts"


def project_of(extension: Path, env: HostEnv) -> Optional[Path]:
    """The project folder of a project-level extension <project>/.pi/extensions/x.ts,
    or None (the user-level file, or a path Pi does not load as a project extension)."""
    p = Path(os.path.abspath(extension))
    if _same(p, Path(os.path.abspath(user_extension(env)))):
        return None
    if p.parent.name == "extensions" and p.parent.parent.name == ".pi":
        return p.parent.parent.parent
    return None


def _same(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a)) == os.path.normcase(str(b))


def _read_object(path: Path) -> Optional[Dict[str, Any]]:
    """{} when the file is missing; None when it cannot be read or is not a JSON object."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class TrustStatus:
    status: str          # TRUSTED | ASK | NOT_TRUSTED | UNKNOWN
    why: str             # where the answer comes from, one sentence
    project: Path        # the canonical project folder (the trust.json key Pi uses)
    agent_dir: Path

    @property
    def trust_file(self) -> Path:
        return self.agent_dir / "trust.json"

    @property
    def settings_file(self) -> Path:
        return self.agent_dir / "settings.json"


def trust_status(project: Path, env: HostEnv) -> TrustStatus:
    adir = agent_dir(env)
    canon = Path(os.path.realpath(project))
    trust_file, settings_file = adir / "trust.json", adir / "settings.json"
    entries = _read_object(trust_file)
    if entries is None:
        return TrustStatus(UNKNOWN, f"{trust_file} is not readable as a JSON object", canon, adir)
    folded = {os.path.normcase(k): v for k, v in entries.items()}
    cur = canon
    while True:
        value = folded.get(os.path.normcase(str(cur)))
        if value is True:
            return TrustStatus(TRUSTED, f"{trust_file} trusts {cur}", canon, adir)
        if value is False:
            return TrustStatus(NOT_TRUSTED, f"{trust_file} has \"Do not trust\" for {cur}", canon, adir)
        if cur.parent == cur:
            break
        cur = cur.parent
    settings = _read_object(settings_file)
    if settings is None:
        return TrustStatus(UNKNOWN, f"no entry in {trust_file}, and {settings_file} is not readable as a JSON object",
                           canon, adir)
    default = settings.get("defaultProjectTrust")
    if default == "always":
        return TrustStatus(TRUSTED, f"no entry in {trust_file}; defaultProjectTrust is \"always\" in {settings_file}",
                           canon, adir)
    if default == "never":
        return TrustStatus(NOT_TRUSTED, f"no entry in {trust_file}; defaultProjectTrust is \"never\" in {settings_file}",
                           canon, adir)
    shown = f"\"{default}\"" if default == "ask" else "not set (Pi's default is \"ask\")"
    return TrustStatus(ASK, f"no entry in {trust_file}; defaultProjectTrust is {shown} in {settings_file}", canon, adir)


def warning_lines(extension: Path, st: TrustStatus) -> list:
    """The warning for a project-level extension in a project that is not known
    to be trusted: what happens, and the ways to fix it. [] when trusted."""
    if st.status == TRUSTED:
        return []
    what = {
        ASK: "interactive `pi` asks at start; `pi -p` (print, JSON and RPC modes) skips the extension without a message",
        NOT_TRUSTED: "Pi skips the extension in every mode, without a message",
        UNKNOWN: "semgate cannot tell whether Pi loads it",
    }[st.status]
    key = json.dumps(str(st.project))
    return [
        f"Pi loads {extension} only for a trusted project. Trust status of {st.project}: {st.status} ({st.why}).",
        f"  Now: {what}; then the agent runs WITHOUT semgate.",
        "  Fix, one of:",
        f"    - trust the project: run `pi` in {st.project} and choose \"Trust\" (or type /trust), "
        f"or add {key}: true to {st.trust_file}",
        "    - trust it for one run: pi --approve ...",
        "    - install at user level instead (Pi loads it without project trust): "
        f"semgate init pi --purpose \"...\"  (writes {st.agent_dir / 'extensions' / 'semgate.ts'}), "
        f"then remove the project copy: semgate uninstall pi --hooks-file \"{extension}\"",
        "  semgate does not change Pi's trust settings.",
    ]
