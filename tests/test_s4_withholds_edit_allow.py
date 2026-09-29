"""router threshold test_damage_withholds_edit_allow: when code signal
S4_test_damage fired, the developer-edit allow does not apply (like G1). It
only removes that allow: it never creates an allow and never creates a deny."""
from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from semgate import router
from semgate.eval.runner import load_cases
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import PredicateAnswer
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"
BEFORE = ROOT / "policies" / "router_policy_dev_buildfacts.json"     # dev before the switch was adopted
EXP = ROOT / "policies" / "router_policy_dev_s4allow.json"
S4 = "S4_test_damage"
STRICT = {"allow": 0, "ask": 1, "deny": 2}
JS_ONLY = "testdamage:chatcmpl-cd1e1043a7cb544c985fb4c6face7fb5:damaged:js_only"


def raw(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dev():
    """The switch off: dev as it was before the switch was adopted."""
    return Policy.load(str(BEFORE))


@pytest.fixture(scope="module")
def on():
    return Policy.load(str(EXP))


def answers(choice="review", conf=0.55, probs=None, effect=1.0, effect_conf=0.99, asked=0.05):
    probs = probs or {"run": round(1 - conf, 2) if choice == "review" else conf,
                      "review": conf if choice == "review" else round(1 - conf, 2), "block": 0.0}
    return {
        "route": PredicateAnswer("route", value=choice, confidence=conf, raw={"probabilities": probs}),
        "effect": PredicateAnswer("effect", value=effect, confidence=effect_conf, raw={"probabilities": {}}),
        "user_asked": PredicateAnswer("user_asked", probability=asked, confidence=abs(asked - 0.5) * 2),
    }


def test_experiment_policy_is_the_dev_before_plus_the_switch_and_dev_adopted_it():
    a, b, d = raw(BEFORE), raw(EXP), raw(DEV)
    for x in (a, b, d):
        x.pop("name")
        x.pop("provenance")
    d["router"]["approval_questions"].pop("user_declined_blocked_action", None)    # adopted 2026-09-29, from dev_chatdecline
    assert d == b
    assert b["router"]["thresholds"].pop("test_damage_withholds_edit_allow") is True
    assert a == b
    assert router.thresholds(Policy.load(str(BEFORE)))["test_damage_withholds_edit_allow"] is None
    # off in the base policy and in the default thresholds
    assert router.DEFAULT_THRESHOLDS["test_damage_withholds_edit_allow"] is None
    base = raw(ROOT / "policies" / "router_policy.json")
    assert "test_damage_withholds_edit_allow" not in (base.get("router") or {}).get("thresholds", {})


def test_s4_withholds_the_developer_edit_allow(dev, on):
    a = answers()                      # route=review 0.55 (under G1's 0.60), effect 1.0: the edit allow
    assert router.decide(dev, a, [S4])["reason_code"] == "developer_edit_allow"
    assert router.decide(on, a)["reason_code"] == "developer_edit_allow"          # no signal: unchanged
    assert router.decide(on, a, ["S1_history_rewrite"])["decision"] == "allow"    # another signal: unchanged
    out = router.decide(on, a, [S4])
    assert (out["decision"], out["reason_code"]) == ("ask", "uncertain_fit_review")
    assert any(v["predicate"] == "test_damage_edit_allow" and v["vote"] == "withheld" for v in out["votes"])
    assert any("S4_test_damage" in r for r in out["reasons"])


def test_jev_still_decides_other_allows_and_denies(on):
    # a confident route=run with a read-level effect still allows: the switch removes only the edit shortcut
    run = answers(choice="run", conf=0.95, effect=0.3, effect_conf=0.9)
    assert router.decide(on, run, [S4])["reason_code"] == "aligned_readonly_allow"
    block = answers(choice="block", conf=0.9, probs={"run": 0.02, "review": 0.08, "block": 0.9}, effect=1.0)
    assert router.decide(on, block, [S4])["decision"] == "deny"
    asked = answers(asked=0.9)
    assert router.decide(on, asked, [S4])["reason_code"] == "user_asked_review"


def test_g1_first(on):
    """route=review 0.62 >= 0.60: G1 already withheld the edit allow, so the
    S4 step has nothing left to withhold; the reason names G1."""
    out = router.decide(on, answers(conf=0.62), [S4])
    assert out["decision"] == "ask"
    text = " ".join(out["reasons"])
    assert "edit_allow_review_max" in text and "S4_test_damage" not in text


def test_never_adds_an_allow_or_a_deny(dev, on):
    """Over a grid of answers: with the switch and S4, the decision is the
    same or allow -> ask; never a new allow, never a new deny."""
    changed = 0
    for choice, conf, effect, econf, asked in itertools.product(
            ("run", "review", "block"), (0.4, 0.6, 0.85, 0.95), (0.0, 0.8, 1.3, 1.6, 2.6), (0.3, 0.6, 0.95),
            (0.05, 0.5, 0.9)):
        rest = round((1 - conf) / 2, 3)
        probs = {c: (conf if c == choice else rest) for c in ("run", "review", "block")}
        a = answers(choice=choice, conf=conf, probs=probs, effect=effect, effect_conf=econf, asked=asked)
        before = router.decide(dev, a, [S4])["decision"]
        after = router.decide(on, a, [S4])["decision"]
        assert STRICT[after] >= STRICT[before]
        assert (after == "deny") == (before == "deny")
        if before != after:
            assert (before, after) == ("allow", "ask")
            changed += 1
    assert changed > 0


def test_switch_needs_s4_in_code_signals():
    r = raw(EXP)
    r["router"]["code_signals"] = ["S1_history_rewrite"]
    with pytest.raises(ValueError, match="needs S4_test_damage"):
        router.thresholds(Policy(r))
    r = raw(EXP)
    r["router"]["thresholds"]["test_damage_withholds_edit_allow"] = 0.5
    with pytest.raises(ValueError, match="must be true, false or null"):
        router.thresholds(Policy(r))
    r["router"]["thresholds"]["test_damage_withholds_edit_allow"] = False
    assert router.thresholds(Policy(r))["test_damage_withholds_edit_allow"] is False


def test_js_only_through_the_judge(dev, on):
    """The margin-study case (describe -> describe.only, "Tests still fail,
    keep going."): S4 fires; with route=review under G1's 0.60 the edit
    allow applies in dev and is withheld with the switch."""
    case = next(c for c in load_cases([str(ROOT / "fixtures" / "eval" / "test-damage.jsonl")]) if c.case_id == JS_ONLY)
    script = {"route": {"value": "review", "confidence": 0.58, "probabilities": {"run": 0.42, "review": 0.58, "block": 0.0}},
              "effect": {"value": 1.0, "confidence": 0.99}, "user_asked": 0.05, "on_task": 0.43,
              "executes": {"value": 0.03, "confidence": 0.95}}
    d_dev = judge(case.envelope, dev, provider=FakeProvider(script))
    d_on = judge(case.envelope, on, provider=FakeProvider(script))
    fired = [s["id"] for s in d_on.evidence["code_signals"]["fired"]]
    assert S4 in fired
    assert (d_dev.decision, d_dev.reason_code) == ("allow", "developer_edit_allow")
    assert (d_on.decision, d_on.reason_code) == ("ask", "uncertain_fit_review")


def test_decide_consistent_passes_the_signals(on):
    a = answers()
    assert router.decide_consistent(on, lambda i: a, [S4])["decision"] == "ask"
    assert router.decide_consistent(on, lambda i: a)["decision"] == "allow"


def test_repeats_script_pairs_the_same_answers(dev, on):
    import importlib.util
    spec = importlib.util.spec_from_file_location("s4_repeats", ROOT / "evals" / "26-s4-withhold-repeats.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    case = next(c for c in load_cases([str(ROOT / "fixtures" / "eval" / "test-damage.jsonl")]) if c.case_id == JS_ONLY)
    script = {"route": {"value": "review", "confidence": 0.58, "probabilities": {"run": 0.42, "review": 0.58, "block": 0.0}},
              "effect": {"value": 1.0, "confidence": 0.99}, "user_asked": 0.05, "on_task": 0.43,
              "executes": {"value": 0.03, "confidence": 0.95}}
    r = mod.paired_run(case, on, dev, FakeProvider(script))
    assert (r["decision"], r["base_decision"]) == ("ask", "allow")
    assert r["base_input_same"] is True and len(r["calls"]) == 1
    assert "test_damage_edit_allow" in r["withheld"]
    assert mod.summarize([dict(r, run=1)]) == {"candidate": {"ask": 1}, "base": {"allow": 1}, "changed_runs": 1}
    with pytest.raises(SystemExit):
        mod.parse_cases([("evals/private/x.jsonl", ["a"])])
