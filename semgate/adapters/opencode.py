"""OpenCode adapter, based on OpenCode's current permission flow.

OpenCode resolves each action against its `permission` config: static "allow"
runs, static "deny" is blocked, and everything else lands in the residual
"ask" bucket and prompts the user. Plugins observe that bucket through the
`permission.asked` event.

Shadow-mode wiring: a tiny plugin (examples/opencode-plugin/semgate-shadow.js)
subscribes to `permission.asked`, ships the event here, and logs our decision.
It never calls `permission.replied` and never influences the host. We judge.
The host acts.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from ..envelope import Envelope, Environment, ProposedAction, Trajectory, TrajectoryEntry, UserGrant

ADAPTER_NAME = "opencode"


def envelope_from_permission_event(
    event: Mapping[str, Any],
    grant: UserGrant,
    directory: str = "",
    session_id: str = "",
) -> Envelope:
    """Translate an OpenCode `permission.asked` event into an envelope.

    Tolerant extraction: the event shape has moved between versions, so we
    read the fields that exist and leave the rest empty (missing evidence
    then routes to ASK rather than to a guess).
    """
    props: Mapping[str, Any] = event.get("properties") or event
    permission = str(props.get("permission") or props.get("tool") or "")
    patterns = props.get("patterns") or []
    metadata: Mapping[str, Any] = props.get("metadata") or {}

    arguments: Dict[str, Any] = {}
    if permission == "bash":
        command = metadata.get("command") or (patterns[0] if patterns else "")
        arguments["command"] = command
    elif permission in ("read", "edit", "glob", "grep"):
        path = metadata.get("path") or metadata.get("filePath") or (patterns[0] if patterns else "")
        arguments["path"] = path
    elif permission == "webfetch":
        arguments["url"] = metadata.get("url") or (patterns[0] if patterns else "")
    else:
        if patterns:
            arguments["patterns"] = list(patterns)
        for key, value in metadata.items():
            arguments.setdefault(key, value)

    environment = Environment(
        project_root=directory,
        cwd=directory,
        harness=ADAPTER_NAME,
        session_id=session_id or str(props.get("sessionID") or ""),
    )
    return Envelope(
        schema="semgate-envelope/1",
        action=ProposedAction(tool=permission or "unknown", arguments=arguments),
        grant=grant,
        environment=environment,
        trajectory=Trajectory(recent=()),
    )


def grant_from_config(d: Mapping[str, Any]) -> UserGrant:
    """Build the immutable grant from an adapter config dict. The grant is
    supplied by the operator wiring the plugin, never inferred from the
    agent's own request."""
    return UserGrant.from_dict(d)
