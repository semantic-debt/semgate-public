"""Offline fake provider for tests and replay.

Two modes:
  - scripted: an explicit map of predicate_id -> probability. Deterministic and
    exactly reproducible; used by every replay fixture.
  - heuristic fallback: derives a stable probability from the sha256 of the
    state + predicate id, so ad-hoc envelopes still get deterministic answers.

It can also be told to fail, to exercise the provider-failure abstention path.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Mapping, Optional

from .base import Answers, JudgeProvider, PredicateAnswer, ProviderError


class FakeProvider(JudgeProvider):
    name = "fake"

    def __init__(self, script: Optional[Mapping[str, float]] = None, fail: bool = False, served_model: str = "",
                 served_upstream: str = ""):
        self.script = dict(script or {})
        self.fail = fail
        # What a live provider's response names as the answering model and
        # upstream provider (providers.base.Answers); "" = not named.
        self.served = {k: v for k, v in (("model", served_model), ("upstream", served_upstream)) if v}
        self.calls = 0  # spy: tests assert the provider was/was not consulted

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        self.calls += 1
        if self.fail:
            raise ProviderError("fake provider configured to fail")
        answers: Dict[str, PredicateAnswer] = Answers(served=self.served)
        for predicate_id in questions:
            if questions[predicate_id].get("type", "noul") in ("choice", "score"):
                # Scripted as {"value": ..., "confidence": ...}. Unscripted answers
                # carry no value, so the router abstains and the judge asks.
                scripted = self.script.get(predicate_id)
                scripted = scripted if isinstance(scripted, Mapping) else {}
                answers[predicate_id] = PredicateAnswer(
                    predicate_id=predicate_id,
                    value=scripted.get("value"),
                    confidence=scripted.get("confidence"),
                    raw={"source": "fake", "probabilities": dict(scripted.get("probabilities") or {})},
                )
                continue
            if predicate_id in self.script:
                probability = float(self.script[predicate_id])
            else:
                digest = hashlib.sha256((predicate_id + repr(sorted(state.items()))).encode("utf-8")).hexdigest()
                probability = int(digest[:8], 16) / 0xFFFFFFFF
            probability = min(1.0, max(0.0, probability))
            answers[predicate_id] = PredicateAnswer(
                predicate_id=predicate_id,
                probability=probability,
                confidence=abs(probability - 0.5) * 2.0,
                raw={"source": "fake"},
            )
        return answers
