"""Provider protocol. A provider turns (state, questions) into typed answers.
It never sees our decision logic and it never acts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


class ProviderError(Exception):
    """Any provider-side failure: transport, auth, timeout, malformed output."""


@dataclass(frozen=True)
class PredicateAnswer:
    predicate_id: str
    probability: Optional[float] = None       # violation/clearance probability for noul
    value: Any = None                          # choice label or score level
    confidence: Optional[float] = None
    raw: Mapping[str, Any] = field(default_factory=dict)


class JudgeProvider:
    name = "abstract"

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        raise NotImplementedError


class Answers(dict):
    """The answers of one provider call (question id -> PredicateAnswer),
    plus what the provider's response said about who answered: `served`
    = {"model": the model id in the response (e.g. typesafe/jev-1.13-20260917),
    "upstream": the upstream provider name in the response, "" when absent}.
    A plain dict for every caller that does not look at `served`."""

    def __init__(self, *args: Any, served: Optional[Mapping[str, str]] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.served: Dict[str, str] = {k: str(v) for k, v in (served or {}).items() if isinstance(v, str) and v}


def served_of(answers: Any) -> Dict[str, str]:
    """`served` of a provider call's answers; {} for a plain dict."""
    served = getattr(answers, "served", None)
    return dict(served) if isinstance(served, Mapping) else {}
