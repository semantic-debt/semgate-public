"""evals/24-margin-study.py: pure helpers. No network, no model, no key."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from semgate import router
from semgate.policy import Policy
from semgate.providers.base import PredicateAnswer
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("margin_study", ROOT / "evals" / "24-margin-study.py")
ms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ms)

DEV = ROOT / "policies" / "router_policy_dev.json"


def _answers(run=0.93, review=0.07, block=0.0, effect=0.4, effect_conf=0.6, asked=0.2, **extra):
    route_value = max((("run", run), ("review", review), ("block", block)), key=lambda x: x[1])[0]
    out = {
        "route": PredicateAnswer("route", value=route_value, confidence=max(run, review, block),
                                 raw={"probabilities": {"run": run, "review": review, "block": block}}),
        "effect": PredicateAnswer("effect", value=effect, confidence=effect_conf, raw={"probabilities": {}}),
        "user_asked": PredicateAnswer("user_asked", probability=asked, confidence=abs(asked - 0.5) * 2),
    }
    for qid, p in extra.items():
        out[qid] = PredicateAnswer(qid, probability=p, confidence=abs(p - 0.5) * 2)
    return out


@pytest.fixture(scope="module")
def dev():
    return Policy.load(str(DEV))


def test_nearest_threshold_is_the_one_that_flips(dev):
    a = _answers()
    assert router.decide(dev, a)["decision"] == "allow"
    margins = ms.threshold_margins(dev, a)
    # Three allow paths share effect confidence >= 0.5; route confidence alone
    # cannot flip this allow (the edit and probability paths still allow).
    assert margins[0]["threshold"] == "allow_effect_confidence"
    assert margins[0]["distance"] == pytest.approx(0.1)
    assert margins[0]["flips_to"] == "ask"
    assert "allow_route_confidence" not in {m["threshold"] for m in margins}


def test_effect_distance_is_scaled_by_its_range(dev):
    a = _answers(effect=1.40, effect_conf=0.9)   # allow by the edit path (<= 1.5)
    m = {x["threshold"]: x for x in ms.threshold_margins(dev, a)}
    assert m["allow_edit_effect_max"]["distance"] == pytest.approx(0.10)
    assert m["allow_edit_effect_max"]["norm"] == pytest.approx(0.10 / 3, abs=1e-4)


def test_injection_threshold(dev):
    a = _answers(asked=0.1, instructed_by_context=0.72)
    assert router.decide(dev, a)["decision"] == "deny"
    m = ms.threshold_margins(dev, a)[0]
    assert (m["threshold"], m["flips_to"]) == ("injection_deny_min", "allow")
    assert m["distance"] == pytest.approx(0.02)


def test_answers_from_votes_reproduce_the_decision(dev):
    a = _answers(effect=0.9, effect_conf=0.55, asked=0.8)
    votes = router.decide(dev, a)["votes"]
    again = ms.answers_from_votes(votes)
    assert router.decide(dev, again)["decision"] == router.decide(dev, a)["decision"]


def test_approval_margin():
    m = ms.approval_margin("pin", 0.86)
    assert (m["decision"], m["flips_to"], m["threshold"]) == ("approve", "reject", "pin_request_min")
    assert m["distance"] == pytest.approx(0.01)
    assert ms.approval_margin("chat", 0.84)["decision"] == "reject"
    assert ms.approval_margin("chat", None) is None


def test_direction_and_harm():
    assert ms.direction("ask", "allow") == "toward_allow"
    assert ms.direction("allow", "ask") == "toward_ask"
    assert ms.direction("deny", "ask") == "toward_allow"
    assert ms.direction("reject", "approve") == "toward_allow"
    assert ms.stricter("allow", "ask") == "ask" and ms.stricter("deny", "ask") == "deny"
    assert ms.harmful("ask", "allow") and ms.harmful("reject", "approve")
    assert not ms.harmful("allow", "allow") and not ms.harmful("deny", "ask")
    assert ms.label_group("approve") == "allow-labeled" and ms.label_group("deny") == "ask/deny-labeled"


def test_spread():
    s = ms.spread([0.82, 0.88, None, 0.85])
    assert s["n"] == 3 and s["min"] == 0.82 and s["max"] == 0.88 and s["range"] == pytest.approx(0.06)
    assert s["stdev"] == pytest.approx(0.0245, abs=1e-4)
    assert ms.spread([])["stdev"] is None


def test_strict_policy_is_memory_only(dev):
    before = DEV.read_bytes()
    strict = ms.strict_policy(dev, 0.05)
    t0, t1 = router.thresholds(dev), router.thresholds(strict)
    assert t1["allow_route_confidence"] == pytest.approx(t0["allow_route_confidence"] + 0.05)
    assert t1["allow_effect_max"] == pytest.approx(t0["allow_effect_max"] - 0.15)
    assert t1["exec_block_allow_min"] == pytest.approx(t0["exec_block_allow_min"] - 0.10)
    assert t1["injection_deny_min"] == pytest.approx(t0["injection_deny_min"] - 0.05)
    assert t1["drift_deny_max"] == pytest.approx(t0["drift_deny_max"] + 0.05)
    # deny-side and approval thresholds are not moved by this helper
    assert t1["deny_route_confidence"] == t0["deny_route_confidence"]
    assert t1["chat_approval_min"] == t0["chat_approval_min"]
    assert router.thresholds(Policy.load(str(DEV))) == t0
    assert DEV.read_bytes() == before


def test_strict_policy_removes_a_near_allow(dev):
    a = _answers(effect_conf=0.53)
    assert router.decide(dev, a)["decision"] == "allow"
    assert router.decide(ms.strict_policy(dev, 0.05), a)["decision"] == "ask"


def test_recorder_and_replay_round_trip():
    script = {"route": {"value": "run", "confidence": 0.95, "probabilities": {"run": 0.95, "review": 0.05, "block": 0.0}},
              "effect": {"value": 0.2, "confidence": 0.8}, "user_asked": 0.3}
    rec = ms.Recorder(FakeProvider(script), clock=iter([0.0, 0.25]).__next__)
    state = {"command": "ls", "b": 1}
    questions = {"route": {"type": "choice"}, "effect": {"type": "score"}, "user_asked": {"type": "noul"}}
    rec.evaluate(state, questions)
    calls = rec.take()
    assert rec.calls == [] and len(calls) == 1
    call = calls[0]
    assert call["latency_s"] == 0.25 and call["cost"] is None
    assert call["input_sha"] == ms.input_hash({"b": 1, "command": "ls"}, questions)
    replay = ms.ReplayProvider([call["answers"]])
    got = replay.evaluate(state, questions)
    assert replay.seen == [call["input_sha"]]
    assert got["route"].value == "run" and got["route"].raw["probabilities"]["run"] == 0.95
    assert got["user_asked"].probability == 0.3
    with pytest.raises(RuntimeError):
        replay.evaluate(state, questions)


def test_recorder_keeps_failures():
    rec = ms.Recorder(FakeProvider(fail=True))
    with pytest.raises(Exception):
        rec.evaluate({"command": "x"}, {"q": {"type": "noul"}})
    assert rec.take()[0]["error"] == "ProviderError"


def test_budget():
    b = ms.Budget(0.0002)
    b.add(0.0001)
    b.add(None)
    assert not b.over() and b.unknown == 1
    b.add(0.00015)
    assert b.over()


def test_pick_spreads_over_sets_and_thresholds():
    def row(cid, s, thr, norm):
        return {"case_id": cid, "set": s, "nearest": {"threshold": thr, "norm": norm}}
    cands = [row("a1", "A", "t1", 0.01), row("a2", "A", "t1", 0.02), row("a3", "A", "t2", 0.05),
             row("b1", "B", "t1", 0.09), row("b2", "B", "t1", 0.30),
             row("a1", "A", "t2", 0.005)]          # same case again, nearer
    got = ms.pick(cands, 3, band=0.10)
    ids = [g["case_id"] for g in got]
    assert len(ids) == len(set(ids)) == 3
    assert "b1" in ids and "b2" not in ids        # every set gets a turn; b2 is outside the band
    assert next(g for g in got if g["case_id"] == "a1")["nearest"]["norm"] == 0.005
    assert ms.pick(cands, 10, band=0.10, taken={"a1"}) and "a1" not in [g["case_id"] for g in ms.pick(cands, 10, 0.10, taken={"a1"})]


def _chat_case(label, ps):
    runs = [{"decision": "approve" if p >= 0.85 else "reject", "p": p, "run": i + 1, "calls": []} for i, p in enumerate(ps)]
    return {"case_id": f"c-{label}-{ps}", "set": "chat-approval", "label": label, "runs": runs}


def test_simulate_designs(dev):
    risky = _chat_case("reject", [0.86, 0.80, 0.80, 0.80, 0.80])      # one false approval in five
    wanted = _chat_case("approve", [0.86, 0.84, 0.90, 0.90, 0.90])
    res = ms.simulate([risky, wanted], dev, band=0.03)
    base, band, twice = res["base"], res["band"], res["allow2"]
    assert base["harmful_allows"] == 1 and base["extra_calls"] == 0
    assert band["harmful_allows"] == 0 and twice["harmful_allows"] == 0
    # band: first calls within 0.03 of 0.85 re-ask: 0.86 (risky), 0.86 and 0.84 (wanted)
    assert band["extra_calls"] == 3
    assert band["friction_asks"] == base["friction_asks"] + 1
    # allow twice: a second call for every approval (1 + 4)
    assert twice["extra_calls"] == 5
    # wanted: run 1 (0.86) pairs with run 2 (0.84) -> lost in both designs; run 2 is a reject already
    assert twice["friction_asks"] == base["friction_asks"] + 1


def test_replay_decision_matches_the_recorded_run(dev):
    from semgate.eval.runner import load_cases
    case = load_cases([str(ROOT / "fixtures" / "eval" / "trace-drift.jsonl")])[0]
    script = {"route": {"value": "run", "confidence": 0.95, "probabilities": {"run": 0.95, "review": 0.05, "block": 0.0}},
              "effect": {"value": 0.2, "confidence": 0.52}, "user_asked": 0.3, "on_task": 0.9,
              "instructed_by_context": 0.1, "executes": {"value": 0.0, "confidence": 0.9}}
    rec = ms.Recorder(FakeProvider(script))
    result = ms.run_case("trace-drift", case, dev, rec)
    run = dict(result, calls=rec.take())
    if not run["calls"]:
        pytest.skip("this case is decided by a gate")
    assert ms.replay_decision("trace-drift", case, dev, run) == result["decision"]
    if result["decision"] == "allow":
        assert ms.replay_decision("trace-drift", case, ms.strict_policy(dev, 0.05), run) == "ask"


def test_live_provider_reads_only_the_given_file(tmp_path, monkeypatch, capsys):
    env = tmp_path / "given.env"
    env.write_text("OPENROUTER_API_KEY=sk-from-given-file\n", encoding="utf-8")
    monkeypatch.setenv("SEMGATE_OPENROUTER_API_KEY", "sk-from-environment")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-from-generic-environment")
    p = ms.live_provider(str(env), "typesafe/jev-1.13")
    assert p._key.value == "sk-from-given-file"
    out = capsys.readouterr()
    assert "sk-from" not in out.out + out.err
    with pytest.raises(SystemExit):
        ms.live_provider(str(tmp_path / "missing.env"), "typesafe/jev-1.13")


def test_normal_tail_and_allow_probability():
    assert ms.normal_tail(0.0, 0.1) == pytest.approx(0.5)
    assert ms.normal_tail(0.1, 0.1) == pytest.approx(0.1587, abs=1e-4)
    assert ms.normal_tail(0.1, 0.0) == 0.0 and ms.normal_tail(-0.1, 0.0) == 1.0
    # route confidence 0.65/0.69/0.60/0.67/0.70 against 0.60 (the js_only case in the study)
    got = ms.allow_probability([0.65, 0.69, 0.60, 0.67, 0.70], 0.60)
    assert got["mean"] == pytest.approx(0.662) and got["sd"] == pytest.approx(0.0354, abs=1e-4)
    assert got["p"] == pytest.approx(0.0401, abs=5e-4)
    stricter = ms.allow_probability([0.65, 0.69, 0.60, 0.67, 0.70], 0.60, shift=0.05)
    assert stricter["p"] < got["p"]
    wider = ms.allow_probability([0.65, 0.69, 0.60, 0.67, 0.70], 0.60, sd_floor=0.0952)
    assert wider["sd"] == pytest.approx(0.0952) and wider["p"] > got["p"]


def test_allow_side_distance(dev):
    # route=review at 0.62 withholds the developer-edit allow (edit_allow_review_max 0.6)
    a = _answers(run=0.2, review=0.8, block=0.0, effect=1.0, effect_conf=0.99, asked=0.05)
    a["route"] = PredicateAnswer("route", value="review", confidence=0.62,
                                 raw={"probabilities": {"run": 0.2, "review": 0.8, "block": 0.0}})
    assert router.decide(dev, a)["decision"] == "ask"
    m = ms.allow_side_distance(dev, a)
    assert (m["threshold"], m["flips_to"]) == ("edit_allow_review_max", "allow")
    assert m["distance"] == pytest.approx(0.02)
    b = _answers(run=0.0, review=0.1, block=0.9, effect=2.8, effect_conf=0.9, asked=0.05)
    assert ms.allow_side_distance(dev, b) is None


def test_merge_repeats():
    a = {"policy_version": "v", "model": "m", "spend_usd": 0.01, "provider_usage": {"served_models": {"x": 2}},
         "cases": [{"case_id": "c1"}, {"case_id": "c2"}]}
    b = {"policy_version": "v", "model": "m", "spend_usd": 0.02, "provider_usage": {"served_models": {"x": 1}},
         "cases": [{"case_id": "c2", "late": True}, {"case_id": "c3"}]}
    got = ms.merge_repeats([a, b])
    assert [c["case_id"] for c in got["cases"]] == ["c1", "c2", "c3"] and "late" not in got["cases"][1]
    assert got["spend_usd"] == pytest.approx(0.03) and got["provider_usage"]["served_models"] == {"x": 3}
    with pytest.raises(SystemExit):
        ms.merge_repeats([a, dict(b, model="other")])
