"""The test-damage and slow-drift eval sets: the committed public fixtures
match their generators, their labels are the ones the feature should produce,
and S4 / session drift fire exactly on the intended cases. No network, no model.
The test-damage generator needs the git-ignored SWE row cache (MAIN repo); its
regeneration check is skipped when the cache is absent."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from semgate import codesignals as cs
from semgate.eval.runner import load_cases
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import JudgeProvider, PredicateAnswer

ROOT = Path(__file__).parents[1]
DEV = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
SDRIFT = Policy.load(str(ROOT / "policies" / "router_policy_dev_sdrift.json"))


def _without_session_drift(policy):
    raw = json.loads(json.dumps(policy.raw))
    for k in ("drift_session_ask_max", "drift_session_window"):
        raw["router"]["thresholds"].pop(k, None)
    return Policy(raw)


# dev as it was before session drift was adopted (2026-09-23): the drift-off comparison point
DEV_NO_SDRIFT = _without_session_drift(DEV)
TD =ROOT / "fixtures" / "eval" / "test-damage.jsonl"
SD = ROOT / "fixtures" / "eval" / "slow-drift.jsonl"


def _gen(num, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "evals" / f"{num}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _kind(case):
    return next(t.split(":", 1)[1] for t in case.tags if t.startswith("kind:"))


# ---------- test-damage ----------

def test_test_damage_labels_and_s4():
    cases = load_cases([str(TD)])
    assert cases, "test-damage fixture is empty"
    seen = set()
    for c in cases:
        kind = _kind(c)
        seen.add(kind)
        fired = bool(cs.compute(c.envelope, enabled=["S4_test_damage"]))
        if kind == "damaged":
            assert c.label == "ask" and fired, c.case_id
        else:                                    # clean_add, clean_fix, justified
            assert c.label == "allow" and not fired, c.case_id
    assert {"damaged", "clean_add", "clean_fix"} <= seen


def test_test_damage_regenerates_if_rows_present():
    gen = _gen("17-gen-test-damage", "gen17")
    if not gen.ROWS_DIR.is_dir():
        pytest.skip("SWE row cache absent (git-ignored, MAIN repo only)")
    cases, _ = gen.generate(gen.SEED)
    public = [c for c in cases if not gen.heldout.is_private(gen.base_of(c))]
    import json
    text = "".join(json.dumps(c, sort_keys=True) + "\n" for c in public)
    assert TD.read_text(encoding="utf-8") == text, "committed test-damage.jsonl is stale; rerun evals/17-gen-test-damage.py"
    assert not any(gen.GEN.case_waf_hits(c) for c in cases)


# ---------- slow-drift ----------

class _Model(JudgeProvider):
    """Aligned read (allow under dev) plus a chosen current on_task."""
    name = "m"

    def __init__(self, on_task):
        self.on_task = on_task

    def evaluate(self, state, questions):
        out = {"route": PredicateAnswer("route", value="run", confidence=0.95,
                                        raw={"probabilities": {"run": 0.95, "review": 0.04, "block": 0.01}}),
               "effect": PredicateAnswer("effect", value=0.0, confidence=0.9, raw={"probabilities": {}})}
        for q, s in questions.items():
            if q in out:
                continue
            if s.get("type") == "score":
                out[q] = PredicateAnswer(q, value=0.0, confidence=0.9, raw={"probabilities": {}})
            elif s.get("type") == "choice":
                out[q] = PredicateAnswer(q, value=list(s["criteria"])[0], confidence=0.5,
                                         raw={"probabilities": {k: 0.5 for k in s["criteria"]}})
            else:
                p = {"on_task": self.on_task, "user_asked": 0.85}.get(q, 0.05)
                out[q] = PredicateAnswer(q, probability=p, confidence=abs(p - 0.5) * 2)
        return out


@pytest.mark.parametrize("on_task", [0.55, 0.75, 1.0])
def test_slow_drift_dev_allows_but_sdrift_asks_the_drift_cases(on_task):
    """Without the session-drift knobs every case is allowed; with them (dev
    since 2026-09-23, and dev_sdrift) the drift cases ask."""
    cases = load_cases([str(SD)])
    assert cases
    for c in cases:
        prior = list(c.envelope.environment.prior_on_task_p or [])
        assert prior, c.case_id
        off = judge(c.envelope, DEV_NO_SDRIFT, provider=_Model(on_task), prior_on_task=prior)
        dev = judge(c.envelope, DEV, provider=_Model(on_task), prior_on_task=prior)
        sdrift = judge(c.envelope, SDRIFT, provider=_Model(on_task), prior_on_task=prior)
        assert off.decision == "allow", (c.case_id, on_task, off.decision)
        for d in (dev, sdrift):
            assert d.decision == c.label, (c.case_id, on_task, d.decision)
            if _kind(c) == "drift":
                assert d.reason_code == "session_drift_review"


def test_slow_drift_is_synthetic_and_regenerates():
    gen = _gen("18-gen-slow-drift", "gen18")
    import json
    cases = gen.generate(gen.SEED)
    public = [c for c in cases if not gen.heldout.is_private(gen.base_of(c))]
    text = "".join(json.dumps(c, sort_keys=True) + "\n" for c in public)
    assert SD.read_text(encoding="utf-8") == text, "committed slow-drift.jsonl is stale; rerun evals/18-gen-slow-drift.py"
    for c in load_cases([str(SD)]):
        assert c.envelope.environment.prior_on_task_p is not None      # the synthetic fact is present
        assert "prior_on_task_p" not in json.dumps(c.envelope.provider_state())   # and never sent to the model
    assert not any(gen.GEN.case_waf_hits(c) for c in cases)
