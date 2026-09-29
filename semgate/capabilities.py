"""Exact, predeclared capability matching for deterministic policy allows."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Mapping

REQUIRED = ("action", "target", "scope", "issued_by", "expires_at")

def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value

def matches_capability(proposal: Mapping[str, Any], capability: Mapping[str, Any], *, now: datetime) -> bool:
    """Match exact action/target/scope against a trusted, unexpired capability.

    No substring, category, wildcard, label, or model-score matching is allowed.
    """
    if any(k not in capability for k in REQUIRED):
        return False
    if capability.get("issued_by") != "trusted_owner_channel":
        return False
    if set(proposal) != {"action", "target", "scope"}:
        return False
    if any("*" in str(capability[k]) for k in ("action", "target", "scope")):
        return False
    try:
        expiry = datetime.fromisoformat(str(capability["expires_at"]).replace("Z", "+00:00"))
    except ValueError:
        return False
    if expiry.tzinfo is None:
        return False
    if now.astimezone(timezone.utc) >= expiry.astimezone(timezone.utc):
        return False
    return all(_canonical(proposal[k]) == _canonical(capability[k]) for k in ("action", "target", "scope"))
