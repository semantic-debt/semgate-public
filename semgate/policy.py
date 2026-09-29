"""Policy loading and the deterministic combination of predicate answers.

The policy file is data (JSON). Its version is a content hash, so every
judgment records exactly which rules produced it and any predicate change
produces a new, replayable version.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

from .envelope import envelope_digest
from .predicates import Predicate


class Policy:
    def __init__(self, raw: Mapping[str, Any], source: str = "<memory>"):
        self.raw = dict(raw)
        self.source = source
        self.name = str(raw.get("name", "unnamed-policy"))
        self.version = envelope_digest(raw)[:12]
        self.confidence_floor = float(raw.get("confidence_floor", 0.40))
        self.hard_allow_tools: Tuple[str, ...] = tuple(raw.get("hard_allow_tools") or ())
        self.predicates: List[Predicate] = [Predicate.from_dict(p) for p in raw.get("predicates") or []]
        # "predicates": noul predicates combined by `combine`. "router": see router.py.
        self.kind = str(raw.get("kind", "predicates"))
        if self.kind not in ("predicates", "router"):
            raise ValueError(f"unknown policy kind: {self.kind}")
        self.router: Mapping[str, Any] = dict(raw.get("router") or {})

    @staticmethod
    def load(path: str) -> "Policy":
        text = Path(path).read_text(encoding="utf-8")
        return Policy(json.loads(text), source=path)


def combine(
    policy: Policy,
    predicate_results: Mapping[str, Any],
    missing: Mapping[str, List[str]],
) -> Dict[str, Any]:
    """Combine predicate answers into allow/ask/deny.

    - any predicate with missing evidence        -> ask (abstain)
    - any violation probability >= deny_min      -> deny
    - all violation probabilities <= allow_max
      and every confidence >= confidence_floor   -> allow
    - anything else                              -> ask
    """
    reasons: List[str] = []
    votes: List[Dict[str, Any]] = []

    for predicate in policy.predicates:
        gaps = missing.get(predicate.predicate_id) or []
        if gaps:
            reasons.append(f"{predicate.predicate_id} abstains: missing evidence {', '.join(gaps)}")
            votes.append({"predicate": predicate.predicate_id, "vote": "abstain", "missing": gaps})
            continue
        answer = predicate_results.get(predicate.predicate_id)
        if answer is None or answer.probability is None:
            reasons.append(f"{predicate.predicate_id} abstains: no usable answer")
            votes.append({"predicate": predicate.predicate_id, "vote": "abstain"})
            continue

        probability = answer.probability
        if predicate.polarity == "clearance":
            probability = 1.0 - probability
        confidence = answer.confidence if answer.confidence is not None else abs(probability - 0.5) * 2.0

        if probability >= predicate.deny_min and confidence >= policy.confidence_floor:
            reason = f"{predicate.predicate_id} violated (p={probability:.3f})"
            if predicate.label:
                reason += f": the judge is confident that {predicate.label}"
            reasons.append(reason)
            votes.append({"predicate": predicate.predicate_id, "vote": "deny", "p": probability, "confidence": confidence})
        elif probability <= predicate.allow_max and confidence >= policy.confidence_floor:
            votes.append({"predicate": predicate.predicate_id, "vote": "clear", "p": probability, "confidence": confidence})
        else:
            reason = f"{predicate.predicate_id} uncertain (p={probability:.3f}, confidence={confidence:.3f})"
            if predicate.label:
                reason += f": the judge is not sure whether {predicate.label}"
            reasons.append(reason)
            votes.append({"predicate": predicate.predicate_id, "vote": "uncertain", "p": probability, "confidence": confidence})

    if any(v["vote"] == "abstain" for v in votes):
        decision, reason_code = "ask", "missing_evidence_ask"
    elif any(v["vote"] == "deny" for v in votes):
        decision, reason_code = "deny", "predicate_violated_deny"
    elif votes and all(v["vote"] == "clear" for v in votes):
        decision, reason_code = "allow", "all_clear_allow"
        reasons.append("all predicates clear at policy thresholds")
    else:
        decision, reason_code = "ask", "uncertain_ask"

    return {"decision": decision, "reason_code": reason_code, "reasons": reasons, "votes": votes}
