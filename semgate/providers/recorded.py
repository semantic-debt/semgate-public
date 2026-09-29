"""Recorded provider: demo mode without a TypeSafe key.

It answers ONLY judge inputs that were recorded from a live Jev run. The key
is the sha256 of the exact judge input: the state and the questions (with
their instruction text), as canonical JSON. Any other input, even one that
differs by a single character, has no answer: `evaluate` raises
NoRecordedAnswer (a ProviderError), and every caller treats a provider error
as "no answer": the judge asks, a chat approval or a trust request is not
granted. So demo mode can never allow something the live judge was not
recorded allowing for exactly that input.

The file (semgate/data/demo_recorded.json, schema semgate-recorded-answers/1)
holds only what semgate reads from an answer: per question the probability
(noul) or the value, confidence and label probabilities (choice, score). No
key, no request id, no account data. `semgate demo --record PATH` writes it
from a live run (maintainers only; it needs a key).
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .base import JudgeProvider, PredicateAnswer, ProviderError

SCHEMA = "semgate-recorded-answers/1"
DEFAULT_FILE = Path(__file__).resolve().parent.parent / "data" / "demo_recorded.json"
NOT_RECORDED = ("demo mode (no key): this exact input has no recorded Jev answer, so semgate asks. "
                "With a TypeSafe key, semgate asks Jev live.")


class NoRecordedAnswer(ProviderError):
    """The judge input is not in the recording. Callers abstain (fail closed)."""


def input_digest(state: Mapping[str, Any], questions: Mapping[str, Any]) -> str:
    """sha256 of the exact judge input (state + questions), canonical JSON."""
    blob = json.dumps({"state": state, "questions": questions}, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _unit(x: Any) -> Optional[float]:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and 0.0 <= v <= 1.0 else None


def answer_record(answer: PredicateAnswer) -> Dict[str, Any]:
    """The part of a live answer semgate uses. Nothing else is stored."""
    out: Dict[str, Any] = {}
    if answer.probability is not None:
        out["p"] = float(answer.probability)
    if answer.value is not None:
        out["value"] = answer.value
    if answer.confidence is not None and answer.probability is None:
        out["confidence"] = float(answer.confidence)
    probs = dict((answer.raw or {}).get("probabilities") or {})
    if probs:
        out["probabilities"] = {str(k): float(v) for k, v in probs.items()}
    return out


def _answer(qid: str, rec: Any) -> Optional[PredicateAnswer]:
    """A PredicateAnswer from a stored record, or None when the record is
    malformed (then the whole input counts as not recorded)."""
    if not isinstance(rec, Mapping):
        return None
    raw = {"source": "recorded"}
    if "p" in rec:
        p = _unit(rec["p"])
        if p is None:
            return None
        return PredicateAnswer(predicate_id=qid, probability=p, confidence=abs(p - 0.5) * 2.0, raw=raw)
    value = rec.get("value")
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    conf = _unit(rec.get("confidence")) if rec.get("confidence") is not None else None
    probs_in = rec.get("probabilities") or {}
    if not isinstance(probs_in, Mapping):
        return None
    probs: Dict[str, float] = {}
    for k, v in probs_in.items():
        u = _unit(v)
        if u is None:
            return None
        probs[str(k)] = u
    return PredicateAnswer(predicate_id=qid, value=value, confidence=conf, raw={**raw, "probabilities": probs})


def load(path: "str | Path | None" = None) -> Dict[str, Dict[str, Any]]:
    """{input digest: {question id: record}} from a recording file. A missing
    or unreadable file, or another schema, gives {} (everything abstains)."""
    try:
        doc = json.loads(Path(path or DEFAULT_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, Mapping) or doc.get("schema") != SCHEMA or not isinstance(doc.get("inputs"), Mapping):
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for digest, entry in doc["inputs"].items():
        answers = entry.get("answers") if isinstance(entry, Mapping) else None
        if isinstance(answers, Mapping):
            out[str(digest)] = dict(answers)
    return out


class RecordedProvider(JudgeProvider):
    """Answers only the recorded inputs; raises NoRecordedAnswer otherwise."""

    name = "recorded"

    def __init__(self, path: "str | Path | None" = None, inputs: Optional[Mapping[str, Mapping[str, Any]]] = None):
        self.inputs = dict(inputs) if inputs is not None else load(path)
        self.hits = 0
        self.misses = 0

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        stored = self.inputs.get(input_digest(state, questions))
        answers: Dict[str, PredicateAnswer] = {}
        if isinstance(stored, Mapping) and set(stored) == set(questions):
            for qid in questions:
                a = _answer(qid, stored[qid])
                if a is None:
                    break
                answers[qid] = a
            else:
                self.hits += 1
                return answers
        self.misses += 1
        raise NoRecordedAnswer(NOT_RECORDED)


class RecordingProvider(JudgeProvider):
    """Wraps a live provider and keeps each answer under its input digest
    (used by `semgate demo --record`)."""

    def __init__(self, inner: JudgeProvider, label: str = "") -> None:
        self.inner = inner
        self.name = getattr(inner, "name", "provider")
        self.label = label
        self.inputs: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        answers = self.inner.evaluate(state, questions)
        self.inputs[input_digest(state, questions)] = {
            "scenario": self.label, "questions": sorted(questions),
            "answers": {qid: answer_record(answers[qid]) for qid in questions if qid in answers}}
        return answers
