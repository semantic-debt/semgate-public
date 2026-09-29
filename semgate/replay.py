"""Replay/simulation runner over synthetic trace fixtures.

Each fixture is an envelope plus:
  - label: what a careful human would have decided ("allow" | "ask" | "deny")
  - fake_answers: scripted provider probabilities (keeps replay offline and
    deterministic)
  - provider_fail: optional, to exercise the failure path

Metrics are precision/coverage oriented and computed against synthetic labels
only. They are NOT product accuracy claims: the fixtures are ours, the labels
are ours, and the provider is a script.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .envelope import Envelope
from .judge import Decision, judge
from .ledger import Ledger
from .policy import Policy
from .providers.fake import FakeProvider

DISCLAIMER = (
    "Shadow simulation over synthetic fixtures with scripted provider answers. "
    "These numbers measure the judge plumbing (rule precedence, abstention, "
    "policy combination), not real-world model accuracy."
)


def load_trace(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run_trace(trace: Dict[str, Any], policy: Policy, ledger: Optional[Ledger] = None) -> Decision:
    envelope = Envelope.from_dict(trace["envelope"])
    provider = FakeProvider(script=trace.get("fake_answers") or {}, fail=bool(trace.get("provider_fail")))
    return judge(envelope, policy, provider=provider, ledger=ledger)


def _precision(records: List[Dict[str, Any]], decision_value: str, label_value: str) -> Dict[str, Any]:
    subset = [r for r in records if r["decision"].decision == decision_value]
    hits = [r for r in subset if r["label"] == label_value]
    return {
        "count": len(subset),
        "matches_label": len(hits),
        "precision": (len(hits) / len(subset)) if subset else None,
    }


def threshold_sweep(records: List[Dict[str, Any]], policy: Policy) -> List[Dict[str, Any]]:
    """Recombine recorded predicate probabilities at different allow_max values.
    Pure arithmetic over stored votes; no re-judging, no provider calls."""
    sweep: List[Dict[str, Any]] = []
    candidates = sorted({0.05, 0.10, 0.20, 0.30} | {p.allow_max for p in policy.predicates})
    for threshold in candidates:
        auto_allowed, hits = 0, 0
        for record in records:
            decision = record["decision"]
            if decision.stage != "semantic":
                continue
            votes = decision.predicate_votes
            if not votes or any(v["vote"] == "abstain" for v in votes):
                continue
            if any(v["vote"] == "deny" for v in votes):
                continue
            clear_probs = [v.get("p") for v in votes if v["vote"] in ("clear", "uncertain")]
            if clear_probs and all(p is not None and p <= threshold for p in clear_probs):
                auto_allowed += 1
                if record["label"] == "allow":
                    hits += 1
        sweep.append({
            "allow_max": threshold,
            "auto_allow": auto_allowed,
            "precision": (hits / auto_allowed) if auto_allowed else None,
        })
    return sweep


def replay(trace_paths: List[str], policy: Policy, ledger: Optional[Ledger] = None) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    for path in trace_paths:
        trace = load_trace(path)
        decision = run_trace(trace, policy, ledger=ledger)
        records.append({
            "trace": Path(path).name,
            "label": trace.get("label"),
            "decision": decision,
        })

    total = len(records)
    asks = [r for r in records if r["decision"].decision == "ask"]
    semantic = [r for r in records if r["decision"].stage == "semantic"]
    gated = [r for r in records if r["decision"].stage == "human_gate"]
    hard = [r for r in records if r["decision"].stage == "hard_rules"]

    return {
        "disclaimer": DISCLAIMER,
        "policy_version": policy.version,
        "trace_count": total,
        "decision_distribution": {
            "allow": total - len(asks) - len([r for r in records if r["decision"].decision == "deny"]),
            "ask": len(asks),
            "deny": len([r for r in records if r["decision"].decision == "deny"]),
        },
        "stage_distribution": {
            "hard_rules": len(hard),
            "human_gate": len(gated),
            "grant_validity": len([r for r in records if r["decision"].stage == "grant_validity"]),
            "semantic": len(semantic),
        },
        "auto_allow": _precision(records, "allow", "allow"),
        "auto_deny": _precision(records, "deny", "deny"),
        "abstention_rate": (len(asks) / total) if total else None,
        "coverage": ((total - len(asks)) / total) if total else None,
        "threshold_sweep": threshold_sweep(records, policy),
        "per_trace": [
            {
                "trace": r["trace"],
                "label": r["label"],
                "decision": r["decision"].decision,
                "stage": r["decision"].stage,
                "match": r["label"] == r["decision"].decision,
            }
            for r in records
        ],
    }
