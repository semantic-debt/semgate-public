"""Typed evidence checking. A predicate may only fire when every piece of
evidence it declared is present in the provider state. Missing or empty
evidence means the predicate abstains, and abstention routes to ASK.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Tuple

from .predicates import Predicate


def _resolve(state: Mapping[str, Any], dotted: str) -> Tuple[bool, Any]:
    node: Any = state
    for part in dotted.split("."):
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        else:
            return False, None
    return True, node


def missing_evidence(predicate: Predicate, state: Mapping[str, Any]) -> List[str]:
    missing: List[str] = []
    for requirement in predicate.evidence_required:
        present, value = _resolve(state, requirement)
        if not present:
            missing.append(requirement)
        elif value is None or (isinstance(value, str) and not value.strip()):
            missing.append(requirement)
    return missing
