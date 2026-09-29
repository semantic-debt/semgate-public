"""Production mode and fail closed.

semgate has one production mode: enforce. `semgate init <host>` and
`semgate harness init` write a complete config: "mode": "enforce",
enforcement.enabled true, enforcement.block_when_unsure = not
hosts.host_shows_ask(host) (the HTTP gate: false, the caller's harness
shows the ask), and the dev policy, which has router.chat_approval on.

A config without "mode" is an enforce config (mode()). It still needs
enforcement.enabled true, like every enforce config (mode_problem()).

Developer switch: "mode": "shadow" in semgate.json, written only by the
hidden `--mode shadow` of `semgate init` / `semgate harness init`
(docs/development.md). semgate then judges and records every call and
answers ask (record only; it blocks nothing where the host runs asks
unattended). The switch lives in the config file, which the operator
writes outside the workspace, and not in an environment variable: the hook
inherits the agent host's environment, and a variable there must not turn
the gate off.

Fail closed. A config problem (a "mode" other than enforce or shadow,
enforcement.enabled not true, no grant_file, an unknown provider) or a hook
failure (the config cannot be read, the grant file is missing, ...) never
becomes a silent run (fail_closed()):
- on a host that cannot show semgate's ask to a person in every mode
  (hosts.host_shows_ask is False: agy, Codex, Droid, OpenCode, Pi, Copilot
  CLI, VS Code, Devin CLI, an unknown host) the answer is a deny that says
  what is wrong and what the user can do;
- on a host that shows the ask (Claude Code), and on the HTTP gate and the
  Python API (host None: the caller's harness gets the ask with an approval
  id), the answer is an ask;
- with the developer switch, an ask (record only), as before.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

ENFORCE = "enforce"
SHADOW = "shadow"
MODES = (ENFORCE, SHADOW)

# Manifest names -> the host name `semgate init` takes.
_INIT_HOST = {"opencode-v1": "opencode", "opencode-v2": "opencode", "devin": "claude", "vscode": "claude"}


def _enforcement(config: Any) -> Mapping[str, Any]:
    enf = config.get("enforcement") if isinstance(config, Mapping) else None
    return enf if isinstance(enf, Mapping) else {}


def mode(config: Any) -> str:
    """The config's mode. No "mode" (or null / "") is enforce, the
    production default; any other value is returned as written."""
    raw = config.get("mode") if isinstance(config, Mapping) else None
    return ENFORCE if raw is None or raw == "" else str(raw)


def is_shadow(config: Any) -> bool:
    """The developer switch is on ("mode": "shadow")."""
    return mode(config) == SHADOW


def enforcing(config: Any) -> bool:
    """A complete enforce config: mode enforce and enforcement.enabled true."""
    return mode(config) == ENFORCE and _enforcement(config).get("enabled") is True


def mode_problem(config: Any) -> str:
    """Why the config is neither a complete enforce config nor the developer
    switch ("" when it is one of the two)."""
    m = mode(config)
    if m == SHADOW:
        return ""
    if m != ENFORCE:
        return f"semgate.json has mode {m!r}; the only production mode is \"enforce\""
    if _enforcement(config).get("enabled") is not True:
        raw = config.get("mode") if isinstance(config, Mapping) else None
        where = "has no \"mode\" and " if raw is None or raw == "" else ""
        return ("semgate enforcement requested but not explicitly enabled "
                f"(semgate.json {where}enforcement.enabled is not true)")
    return ""


def shows_ask(host: Optional[str]) -> bool:
    """True when `host` shows semgate's ask to a person in every mode
    (hosts.host_shows_ask). None is the HTTP gate / Python API: the
    caller's harness gets the ask with an approval id, so True."""
    if host is None:
        return True
    from .hosts import host_shows_ask
    return host_shows_ask(str(host))


def block_when_unsure(config: Any, host: Optional[str] = None) -> bool:
    """enforcement.block_when_unsure as the hook applies it: only in enforce
    mode; an explicit true or false is kept; a config without the key gets
    the rule `semgate init` writes (not shows_ask(host)), so an older or
    hand-written enforce config never lets an ask run unattended on a host
    that cannot show it."""
    if mode(config) != ENFORCE:
        return False
    enf = _enforcement(config)
    if "block_when_unsure" not in enf or enf.get("block_when_unsure") is None:
        return not shows_ask(host)
    return enf.get("block_when_unsure") is True


def init_host(host: Optional[str]) -> str:
    """The `semgate init` host name for a manifest host name."""
    return _INIT_HOST.get(str(host or ""), str(host or "<host>"))


def fix_text(host: Optional[str] = None) -> str:
    """What the agent is told when semgate could not check a call (a config
    problem or a hook failure). It does not offer `semgate feedback allow`
    or a chat yes: neither is read before the config is fixed."""
    try:
        from .skill import command
        cmd = command()
    except Exception:
        cmd = "semgate"
    return ("semgate could not check this call, so it is blocked. Tell the user plainly what happened (the reason "
            f"above). The user runs `{cmd} doctor` in their own terminal and fixes what it reports (a new config: "
            f"`{cmd} init {init_host(host)} --force --purpose \"...\"`). If this command is needed before that, the "
            "user runs it themselves. Do not try to bypass, rename, or disable the gate.")


def fail_closed(problem: str, host: Optional[str], config: Any = None, ask_as: str = "ask") -> Dict[str, str]:
    """The answer for a config problem or a hook failure (module text).
    `host`: the host's manifest name (HostChat.manifest_host, the
    claude_hook --host, serve's host) or None (HTTP gate / Python API).
    `ask_as`: the ask word where an ask is the answer (agy: force_ask)."""
    problem = str(problem or "semgate config problem").strip()
    if (isinstance(config, Mapping) and is_shadow(config)) or shows_ask(host):
        return {"decision": ask_as, "reason": f"{problem}; asking human"[:1000]}
    tail = " | " + fix_text(host)
    return {"decision": "deny", "reason": ("semgate blocked this: " + problem)[:max(0, 1000 - len(tail))] + tail}
