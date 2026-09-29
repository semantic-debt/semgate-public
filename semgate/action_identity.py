"""Lossless request identity, not an approval or an authorization mechanism.

V1 feedback/history keys are intentionally not accepted or migrated here.
A digest identifies data; it does not authenticate its sender or freeze files.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

SCHEMA = "semgate-action/2"
CONTEXT_FIELDS = (
    "harness", "harness_version", "session_id", "cwd", "project_root", "shell"
)


def _json_value(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        raise ValueError("JSON nesting exceeds 32 levels")
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is str:
        value.encode("utf-8")  # Reject unpaired surrogates, never normalize text.
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("JSON object keys must be strings")
        return {key: _json_value(item, depth + 1) for key, item in value.items()}
    if type(value) is list:
        return [_json_value(item, depth + 1) for item in value]
    raise ValueError("only finite JSON values are supported")


def canonical_json(value: Any) -> str:
    """Sort object keys only. Preserve case, whitespace, types and list order."""
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def request_identity(*, tool: str, arguments: Mapping[str, Any],
                     context: Mapping[str, Any], grant: Mapping[str, Any],
                     policy_version: str, provider: str) -> str:
    """Bind complete arguments, grant, policy/provider and execution context.

    All strings are compared exactly. False misses are preferable to merging
    distinct commands. This is an audit/correlation key, NOT a reusable permit.
    A future approval receipt additionally needs a trusted issuer, pending-call
    binding, one-shot consumption, expiry and execution-time revalidation.
    """
    required = {"tool": tool, "policy_version": policy_version, "provider": provider}
    required.update({key: context.get(key) for key in CONTEXT_FIELDS})
    if any(type(value) is not str or not value.strip() for value in required.values()):
        raise ValueError("identity requires explicit tool, policy, provider and context")
    if not isinstance(arguments, Mapping) or not isinstance(grant, Mapping) or not grant:
        raise ValueError("arguments and a nonempty grant must be JSON objects")
    payload = {"schema": SCHEMA, "tool": tool, "arguments": arguments,
               "context": context, "grant": grant,
               "policy_version": policy_version, "provider": provider}
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return SCHEMA + ":" + digest
