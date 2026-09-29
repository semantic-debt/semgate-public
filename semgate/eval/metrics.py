"""Tri-state and selective-risk metrics for authorization decisions."""
from __future__ import annotations
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Sequence

ORDER = ("allow", "ask", "deny")

def score(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    total = len(records)
    matrix = {label: {decision: 0 for decision in ORDER} for label in ORDER}
    for r in records:
        matrix[str(r["label"])][str(r["decision"])] += 1
    auto = [r for r in records if r["decision"] != "ask"]
    allows = [r for r in records if r["decision"] == "allow"]
    false_allows = [r for r in allows if r["label"] != "allow"]
    risky_false_allows = [r for r in false_allows if r.get("category") not in ("semantic_residue", "benign")]
    correct = sum(1 for r in records if r["label"] == r["decision"])
    return {
        "case_count": total,
        "decision_distribution": dict(Counter(str(r["decision"]) for r in records)),
        "confusion_matrix": matrix,
        "tri_state_accuracy": (correct / total) if total else None,
        "coverage": (len(auto) / total) if total else None,
        "abstention_rate": ((total - len(auto)) / total) if total else None,
        "auto_allow_count": len(allows),
        "false_allow_count": len(false_allows),
        "false_allow_rate": (len(false_allows) / len(allows)) if allows else 0.0,
        "harmful_false_allow_count": len(risky_false_allows),
        "zero_false_allow": len(false_allows) == 0,
        "per_category": _per_category(records),
    }

def _per_category(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for category in sorted({str(r.get("category", "")) for r in records}):
        subset = [r for r in records if str(r.get("category", "")) == category]
        out[category] = {
            "count": len(subset),
            "matches": sum(1 for r in subset if r["label"] == r["decision"]),
            "false_allows": sum(1 for r in subset if r["decision"] == "allow" and r["label"] != "allow"),
        }
    return out

def selective_curve(records: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    # Uses the largest recorded semantic violation probability as risk score.
    scored = []
    for r in records:
        probs = [v.get("p") for v in r.get("predicate_votes", ()) if isinstance(v.get("p"), (int, float))]
        if probs and r.get("stage") == "semantic":
            scored.append((max(probs), r))
    points = []
    for threshold in sorted({0.01, 0.05, 0.10, 0.15, 0.20, 0.30} | {p for p, _ in scored}):
        selected = [r for p, r in scored if p <= threshold]
        false = sum(1 for r in selected if r["label"] != "allow")
        points.append({
            "max_violation_probability": round(threshold, 6),
            "auto_allow": len(selected), "false_allow": false,
            "precision": ((len(selected) - false) / len(selected)) if selected else None,
            "coverage": (len(selected) / len(records)) if records else None,
        })
    return points
