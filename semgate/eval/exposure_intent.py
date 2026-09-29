"""Offline eval of the secret exposure intent question (exposures.decide_intent).

Question measured: after a tool output shows a secret, does the judge's
answer to `user_shared_secret` (policy router.exposure_questions, threshold
exposure_intended_min) tell apart a secret the user gave the agent on
purpose from one the agent came across?

Case (one JSON object per line, schema semgate-exposure-case/1):
  {"schema", "case_id", "source", "source_id", "label": "intended" | "unintended",
   "category", "tags", "rationale", "tool", "detail" (the command or path),
   "output" (the tool output that shows the secret), "user_messages" (the
   user's turns, oldest first), "fake_answers" ({"user_shared_secret": p},
   for --provider scripted), "provider_fail"}

The runner goes through the same code as the post-tool hook:
secretfinder.find on the output, exposures.build_records (no key: evals keep
no fingerprint), exposures.decide_intent with the case's user turns. The
provider is wrapped: a state that carries a raw secret value is counted
(`state_leaks`) and not sent. `semgate eval` picks this runner when every
case file holds this schema.

Providers: scripted (the case's fake_answers; checks the plumbing, not the
model), none (never asked: every case is unintended, the fail-closed
baseline), typesafe (the live judge).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .. import exposures, secretfinder
from ..policy import Policy
from ..providers.base import JudgeProvider, ProviderError
from ..providers.fake import FakeProvider
from ..providers.registry import report_fields

CASE_SCHEMA = "semgate-exposure-case/1"
REPORT_SCHEMA = "semgate-exposure-eval-report/1"
LABELS = ("intended", "unintended")
EVAL_TIMEOUT_S = 30.0          # latency is not what this set measures; the hook uses secret_exposures.intent_timeout_s


def _members(paths: Sequence[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        path = Path(raw)
        out += (sorted(path.glob("*.jsonl")) if path.is_dir() else [path])
    return out


def is_exposure_cases(paths: Sequence[str]) -> bool:
    """True when every case file's first case has CASE_SCHEMA."""
    members = _members(paths)
    if not members:
        return False
    for member in members:
        try:
            with open(member, encoding="utf-8") as handle:
                first = next((line for line in handle if line.strip()), "")
            if json.loads(first).get("schema") != CASE_SCHEMA:
                return False
        except (OSError, ValueError, AttributeError):
            return False
    return True


def load_cases(paths: Sequence[str]) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for member in _members(paths):
        for line in member.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            c = json.loads(line)
            if c.get("schema") != CASE_SCHEMA:
                raise ValueError(f"{member}: not a {CASE_SCHEMA} case: {c.get('case_id')}")
            if c.get("label") not in LABELS:
                raise ValueError(f"{member}: invalid label {c.get('label')!r} in {c.get('case_id')}")
            for key in ("case_id", "source_id", "output"):
                if not c.get(key):
                    raise ValueError(f"{member}: {key} is required")
            if not isinstance(c.get("user_messages"), list):
                raise ValueError(f"{member}: user_messages must be a list in {c['case_id']}")
            cases.append(c)
    ids = [c["case_id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case_id")
    return cases


class _Guarded(JudgeProvider):
    """Refuses (and counts) a state that carries a raw secret value."""

    def __init__(self, inner: JudgeProvider, values: Sequence[str]) -> None:
        self.inner, self.values, self.leaks, self.states = inner, [v for v in values if v], 0, []
        self.name = getattr(inner, "name", "provider")

    def evaluate(self, state, questions):
        blob = json.dumps(state, ensure_ascii=False)
        if any(v in blob or json.dumps(v)[1:-1] in blob for v in self.values):
            self.leaks += 1
            raise ProviderError("state carries a secret value; not sent")
        self.states.append(dict(state))
        return self.inner.evaluate(state, questions)


def evaluate(cases: Sequence[Mapping[str, Any]], policy: Policy, *, provider: Optional[JudgeProvider] = None,
             scripted: bool = False, timeout: float = EVAL_TIMEOUT_S) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    leaks = 0
    config = {"provider": "none", "secret_exposures": {"intent_timeout_s": timeout}}
    for c in cases:
        found = secretfinder.find(str(c["output"]))
        row: Dict[str, Any] = {"case_id": c["case_id"], "source_id": c["source_id"], "label": c["label"],
                               "category": c.get("category", ""), "secrets": [f"{f.type} {secretfinder.mask(f.value)}" for f in found]}
        if not found:
            rows.append(dict(row, decision="unintended", match=c["label"] == "unintended", error="no secret found"))
            continue
        inner = FakeProvider(c.get("fake_answers") or {}, fail=bool(c.get("provider_fail"))) if scripted else provider
        guarded = _Guarded(inner, [f.value for f in found]) if inner is not None else None
        records = exposures.build_records("eval", "eval", str(c.get("tool", "")), str(c.get("detail", "")), "", found, 0.0)
        pairs = list(zip(found, records))
        exposures.decide_intent(config, pairs, found, str(c.get("tool", "")), records[0]["where"]["detail"],
                                lambda c=c: list(c["user_messages"]), provider=guarded, policy=policy)
        if guarded is not None:
            leaks += guarded.leaks
        intents = [r["intent"] for r in records]
        decision = "intended" if all(i.get("intended") for i in intents) else "unintended"
        first = intents[0]
        rows.append(dict(row, decision=decision, match=decision == c["label"], p=first.get("p"),
                         asked=bool(first.get("asked")), why=first.get("why", ""),
                         provider_error=bool(first.get("asked")) and first.get("p") is None))
    n = len(rows)
    conf = {lab: {d: sum(1 for r in rows if r["label"] == lab and r["decision"] == d) for d in LABELS} for lab in LABELS}
    tp, fn = conf["intended"]["intended"], conf["intended"]["unintended"]
    fp = conf["unintended"]["intended"]

    def ratio(a: int, b: int) -> Optional[float]:
        return round(a / b, 4) if b else None

    return {
        "schema": REPORT_SCHEMA, "policy": policy.name, "policy_version": policy.version,
        "provider": ("per-case-script" if scripted else (provider.name if provider is not None else "none")),
        # model id and usage (calls, tokens, cost) of a live provider: results compare only for the same model
        **(report_fields(provider) if provider is not None and not scripted else {}),
        "metrics": {"n": n, "correct": sum(1 for r in rows if r["match"]), "accuracy": ratio(sum(1 for r in rows if r["match"]), n),
                    "confusion": conf, "intended_recall": ratio(tp, tp + fn), "intended_precision": ratio(tp, tp + fp),
                    "unintended_recall": ratio(conf["unintended"]["unintended"], conf["unintended"]["unintended"] + fp),
                    "false_intended": fp},
        "provider_errors": sum(1 for r in rows if r.get("provider_error")),
        "not_asked": sum(1 for r in rows if not r.get("asked") and not r.get("error")),
        "secrets_missing": [r["case_id"] for r in rows if r.get("error") == "no secret found"],
        "state_leaks": leaks,
        "cases": rows,
        "note": ("false_intended is the costly error: the agent is told the user gave a secret it came across, and "
                 "the user is told to rotate it only when the session ends. Scripted answers check the plumbing only."),
    }
