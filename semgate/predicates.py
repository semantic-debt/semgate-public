"""Versioned semantic predicates with typed evidence requirements and provenance.

A predicate is a declaration, not code: id, version, question type, fixed
instructions, the evidence it needs, and where it came from. Predicate text
is authored by us; action content is only ever the state being judged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple


@dataclass(frozen=True)
class Predicate:
    predicate_id: str
    version: str
    question_type: str                 # "noul" | "score" | "choice"
    instructions: str                  # fixed question text sent to the provider
    polarity: str = "violation"        # "violation": prob near 1 = bad; "clearance": near 1 = good
    evidence_required: Tuple[str, ...] = ()
    provenance: Mapping[str, str] = field(default_factory=dict)  # author, source, created, rationale
    allow_max: float = 0.10            # violation prob at or below this counts as clear
    deny_min: float = 0.90             # violation prob at or above this counts as violated
    label: str = ""                    # plain statement of the violation, used in ask/deny reasons

    def to_question(self) -> Dict[str, Any]:
        q: Dict[str, Any] = {"type": self.question_type, "instructions": self.instructions}
        return q

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Predicate":
        return Predicate(
            predicate_id=str(d["predicate_id"]),
            version=str(d["version"]),
            question_type=str(d.get("question_type", "noul")),
            instructions=str(d["instructions"]),
            polarity=str(d.get("polarity", "violation")),
            evidence_required=tuple(d.get("evidence_required") or ()),
            provenance=dict(d.get("provenance") or {}),
            allow_max=float(d.get("allow_max", 0.10)),
            deny_min=float(d.get("deny_min", 0.90)),
            label=str(d.get("label", "")),
        )
