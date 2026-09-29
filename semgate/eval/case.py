"""Portable benchmark case schema.

Cases contain canonical semgate envelopes, never host-native events. Host
adapters have separate conformance tests and do not participate in scoring.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Tuple
from ..envelope import Envelope

CASE_SCHEMA_VERSION = "semgate-eval-case/1"
VALID_LABELS = ("allow", "ask", "deny")
DETERMINISTIC_CATEGORIES = frozenset({
    "money", "credentials_secrets", "external_communication",
    "destructive_irreversible", "privilege_escalation",
})

@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    source: str
    source_id: str
    label: str
    category: str
    envelope: Envelope
    tags: Tuple[str, ...] = ()
    rationale: str = ""
    fake_answers: Mapping[str, float] = field(default_factory=dict)
    provider_fail: bool = False
    schema: str = CASE_SCHEMA_VERSION
    # Synthetic workspace facts for evals (no filesystem, no ledger):
    #   {"synthetic": true,
    #    "files": {abs path: content}             served to F4 instead of the disk,
    #    "agent_created": {abs path: sha256}}     F6: files the agent created in this
    #                                             trajectory and did not change since.
    #    "path_env": "C:\\x;C:\\y" or "/x:/y"}   a fixed fake PATH for the
    #                                             persistence_link gate (without
    #                                             it: the fixed list only).
    # Built by importers from the trajectory, never from the case label.
    workspace: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.schema != CASE_SCHEMA_VERSION:
            raise ValueError(f"unsupported eval case schema: {self.schema}")
        if self.label not in VALID_LABELS:
            raise ValueError(f"invalid tri-state label: {self.label}")
        if not self.case_id or not self.source or not self.source_id:
            raise ValueError("case_id, source, and source_id are required")

    @property
    def deterministic_only(self) -> bool:
        return self.category in DETERMINISTIC_CATEGORIES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema, "case_id": self.case_id,
            "source": self.source, "source_id": self.source_id,
            "label": self.label, "category": self.category,
            "tags": list(self.tags), "rationale": self.rationale,
            "envelope": self.envelope.to_dict(),
            "fake_answers": dict(self.fake_answers),
            "provider_fail": self.provider_fail,
            **({"workspace": dict(self.workspace)} if self.workspace else {}),
        }

    @staticmethod
    def from_dict(raw: Mapping[str, Any]) -> "BenchmarkCase":
        return BenchmarkCase(
            schema=str(raw.get("schema", CASE_SCHEMA_VERSION)),
            case_id=str(raw.get("case_id", "")), source=str(raw.get("source", "")),
            source_id=str(raw.get("source_id", "")), label=str(raw.get("label", "")),
            category=str(raw.get("category", "semantic_residue")),
            tags=tuple(str(x) for x in (raw.get("tags") or ())),
            rationale=str(raw.get("rationale", "")),
            envelope=Envelope.from_dict(raw.get("envelope") or {}),
            fake_answers={str(k): float(v) for k, v in (raw.get("fake_answers") or {}).items()},
            provider_fail=bool(raw.get("provider_fail", False)),
            workspace=dict(raw.get("workspace") or {}),
        )
