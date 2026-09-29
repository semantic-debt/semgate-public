"""Host adapters and capability manifests. See base.py for the interface."""
from __future__ import annotations

from typing import Dict, List

from .base import (CAPABILITIES, Capability, ConfigPaths, Detection, Finding, HostAdapter, HostEnv, Manifest,
                   fit_decision, load_manifest)
from .builtin import (AntigravityHost, ClaudeHost, CodexHost, CopilotHost, DroidHost, OpenCodeHost, PiHost,
                      VSCodeHost)

# Order = owner priority, then the rest.
ADAPTERS: Dict[str, HostAdapter] = {a.name: a for a in (
    ClaudeHost(), DroidHost(), AntigravityHost(), OpenCodeHost(), CodexHost(), PiHost(), VSCodeHost(), CopilotHost(),
)}


def get(name: str) -> HostAdapter:
    return ADAPTERS[name]


def installable() -> List[str]:
    return sorted(n for n, a in ADAPTERS.items() if a.installable)


def host_shows_ask(host: str) -> bool:
    """True when `host` shows semgate's ask to a person in every mode it has,
    or at worst turns it into a deny; never runs the tool unattended. This is
    the one rule for `enforcement.block_when_unsure`: `semgate init` writes
    block_when_unsure = not host_shows_ask(host), and `semgate doctor` warns
    about a missing block_when_unsure only where this is False.

    Needs, in every manifest of the host (OpenCode has two):
    - C2 = yes: the host honors a hook ask (a prompt; headless, a deny with
      the reason); and
    - C2b = yes and measured: the ask is honored in every bypass / YOLO mode
      too (hookconf A2b). A docs-only claim is not enough: agy's docs-level
      C2 = yes did not hold under --dangerously-skip-permissions.

    Evidence (semgate/data/hosts/*.json):
    - claude: C2 yes (hookconf A2 pass), C2b yes (A2b pass under
      --dangerously-skip-permissions and defaultMode bypassPermissions) -> True
    - antigravity: C2 yes (interactive), C2b no (agy 1.2.10 ran a force_ask
      under --dangerously-skip-permissions) -> False
    - droid: C2 yes from docs only, C2b unknown -> False (kept conservative
      until measured)
    - codex: C2 no (A2 fail: the ask ran) -> False
    - opencode (v1 and v2): C2 no (no plugin ask) -> False
    - pi: C2 partial (no ask UI in print / JSON mode) -> False
    - copilot, vscode, unknown names: no manifest, all cells unknown -> False
    """
    adapter = ADAPTERS.get(host)
    names = (adapter.manifest_names or (adapter.name,)) if adapter is not None else (host,)
    return all(load_manifest(n).shows_ask for n in names)


__all__ = ["ADAPTERS", "CAPABILITIES", "Capability", "ConfigPaths", "Detection", "Finding", "HostAdapter", "HostEnv",
           "Manifest", "fit_decision", "get", "host_shows_ask", "installable", "load_manifest"]
