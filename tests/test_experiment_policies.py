"""The experiment policies of 2026-09-23 (S4, crit, sdrift, turns) and the
combined dev_all with its leave-one-out variants: each is the previous dev
(policies/experiments/router_policy_dev_base_2026-09-23.json) plus exactly its
parts; dev is that base plus the adopted parts (S4, crit, turns, session drift,
the post-tool secret-intent question, and approval by chat reply); every text
is WAF-safe."""
import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from semgate import router
from semgate.policy import Policy

ROOT = Path(__file__).parents[1]
P = ROOT / "policies"


def load(name):
    return json.loads((P / f"router_policy_{name}.json").read_text(encoding="utf-8"))


def load_base():
    """dev before it adopted S4, crit and turns (2026-09-23 (2)): the base the
    experiment policies were built on."""
    return json.loads((P / "experiments" / "router_policy_dev_base_2026-09-23.json").read_text(encoding="utf-8"))


spec = importlib.util.spec_from_file_location("gen_nonsense_steps_pol", ROOT / "evals" / "14-gen-nonsense-steps.py")
GEN = importlib.util.module_from_spec(spec)
sys.modules["gen_nonsense_steps_pol"] = GEN
spec.loader.exec_module(GEN)

S1, S2, S3, S3F, S4 = ("S1_history_rewrite", "S2_dependency_manifest", "S3_claim_contradicts_results",
                       "S3_last_check", "S4_test_damage")
NEW = ("dev_s4", "dev_crit", "dev_sdrift", "dev_turns", "dev_all", "dev_all_no_s3", "dev_all_no_lastcheck",
       "dev_all_no_s4", "dev_all_no_crit", "dev_all_no_sdrift")


def strip(raw):
    raw = copy.deepcopy(raw)
    raw.pop("name")
    raw.pop("provenance")
    return raw


def compose(ids=(S1, S2, S3, S3F, S4), crit=True, sdrift=True):
    """base (the previous dev) + the parts, taken from the single-feature policies."""
    raw = strip(load_base())
    raw["router"]["code_signals"] = list(ids)
    if crit:
        for q, spec_ in load("dev_crit")["router"]["questions"].items():
            if "criteria" in spec_:
                raw["router"]["questions"][q]["criteria"] = spec_["criteria"]
    if sdrift:
        for k in ("drift_session_ask_max", "drift_session_window"):
            raw["router"]["thresholds"][k] = load("dev_sdrift")["router"]["thresholds"][k]
    turns = load("dev_turns")["router"]
    raw["router"]["turn_attribution"] = turns["turn_attribution"]
    raw["router"]["shadow_questions"]["can_judge"] = turns["shadow_questions"]["can_judge"]
    return raw


DRIFT_SESSION = ("drift_session_ask_max", "drift_session_window")
EXPOSURE_MIN = "exposure_intended_min"


def without_exposure(raw):
    """dev minus the secret-intent question and its threshold (adopted
    2026-09-23 from router_policy_dev_exposure.json; post-tool only)."""
    raw = copy.deepcopy(raw)
    raw["router"].pop("exposure_questions")
    raw["router"]["thresholds"].pop(EXPOSURE_MIN)
    return raw


S6 = "S6_link_placement"


def without_s6(raw):
    """dev minus the S6_link_placement code signal (adopted 2026-09-24 from
    router_policy_dev_s6.json)."""
    raw = copy.deepcopy(raw)
    raw["router"]["code_signals"].remove(S6)
    return raw


CHAT_MIN = "chat_approval_min"
CHAT_KEYS = ("chat_approval", "approval_questions", "chat_approval_limits")


def without_chat_approval(raw):
    """dev minus approval by chat reply: the switch, its question, its limits
    and chat_approval_min (adopted 2026-09-24 from
    router_policy_dev_chatapprove.json)."""
    raw = copy.deepcopy(raw)
    for key in CHAT_KEYS:
        raw["router"].pop(key)
    raw["router"]["thresholds"].pop(CHAT_MIN)
    return raw


CRIT_NOULS = {"user_asked", "on_task", "instructed_by_context"}


TRUST_KEYS = ("trust_requests", "trust_questions", "pin_requests", "pin_questions")
TRUST_MINS = ("trust_request_min", "pin_request_min")


def without_trust(raw):
    """dev before trusted commands and pinned instruction-file lines (adopted
    2026-09-24 from dev_trust)."""
    raw = json.loads(json.dumps(raw))
    for key in TRUST_KEYS:
        raw["router"].pop(key)
    for key in TRUST_MINS:
        raw["router"]["thresholds"].pop(key)
    return raw


def without_test_run(raw):
    """dev before the test-run facts (router.test_run_facts, adopted
    2026-09-25 from dev_testrun)."""
    raw = copy.deepcopy(raw)
    raw["router"].pop("test_run_facts")
    return raw


PIN_Q = "user_trusts_instruction_lines"


def with_trust_pin_question(raw):
    """dev before the pin question wording of 2026-09-25 (adopted from
    dev_pinq): the pin question as dev_trust measured it."""
    raw = copy.deepcopy(raw)
    raw["router"]["pin_questions"] = copy.deepcopy(load("dev_trust")["router"]["pin_questions"])
    return raw


def without_build_facts(raw):
    """dev before the build facts (router.test_run_build_facts, adopted
    2026-09-26 from dev_buildfacts)."""
    raw = copy.deepcopy(raw)
    raw["router"].pop("test_run_build_facts")
    return raw


DECLINE_Q = "user_declined_blocked_action"


def without_decline_question(raw):
    """dev before router.approval_questions.user_declined_blocked_action
    (adopted 2026-09-29 from dev_chatdecline, owner decision; measured on one
    live run, EVALS.md 2026-09-29)."""
    raw = copy.deepcopy(raw)
    raw["router"]["approval_questions"].pop(DECLINE_Q)
    return raw


def without_s4_withhold(raw):
    """dev before router threshold test_damage_withholds_edit_allow (adopted
    2026-09-26 from dev_s4allow)."""
    raw = copy.deepcopy(raw)
    raw["router"]["thresholds"].pop("test_damage_withholds_edit_allow")
    return raw


def test_dev_is_dev_s4allow_and_before_it_dev_buildfacts_dev_pinq_and_dev_testrun():
    """dev = dev_s4allow (the measured candidate) except name and provenance;
    dev without test_damage_withholds_edit_allow = dev_buildfacts; that
    without router.test_run_build_facts = dev_pinq; that with dev_trust's pin
    question = dev_testrun, whose only difference to the dev before it is
    router.test_run_facts."""
    dev = load("dev")
    assert strip(dev) == strip(load("dev_chatdecline"))
    assert set(dev["router"]["approval_questions"]) == {"user_approved_blocked_action", DECLINE_Q}
    dev = without_decline_question(dev)
    assert strip(dev) == strip(load("dev_s4allow"))
    assert dev["router"]["thresholds"]["test_damage_withholds_edit_allow"] is True
    dev = without_s4_withhold(dev)
    assert strip(dev) == strip(load("dev_buildfacts"))
    assert dev["router"]["test_run_facts"] is True and dev["router"]["test_run_build_facts"] is True
    before = without_build_facts(dev)
    assert strip(before) == strip(load("dev_pinq"))
    assert strip(with_trust_pin_question(before)) == strip(load("dev_testrun"))
    assert "test_run_facts" not in without_test_run(before)["router"]


def test_the_pin_question_changed_only_its_text():
    """dev_pinq changes the instructions and the true criteria of the pin
    question; its false criteria and threshold are dev_trust's."""
    new, old = load("dev_pinq")["router"], load("dev_trust")["router"]
    q, o = new["pin_questions"][PIN_Q], old["pin_questions"][PIN_Q]
    assert set(new["pin_questions"]) == {PIN_Q} and q["type"] == o["type"] == "noul"
    assert q["criteria"]["false"] == o["criteria"]["false"]
    assert q["instructions"] != o["instructions"] and q["criteria"]["true"] != o["criteria"]["true"]
    assert "`question_check`" in q["instructions"]
    assert new["thresholds"]["pin_request_min"] == old["thresholds"]["pin_request_min"] == 0.85
    assert GEN.waf_hits([q["instructions"], q["criteria"]["true"], q["criteria"]["false"]]) == []


def test_base_has_none_of_the_new_features():
    base = load_base()
    assert base["router"]["code_signals"] is True
    assert "turn_attribution" not in base["router"] and "can_judge" not in base["router"]["shadow_questions"]
    assert not set(DRIFT_SESSION) & set(base["router"]["thresholds"])
    assert all("criteria" not in q for q in base["router"]["questions"].values() if q["type"] == "noul")


def test_dev_is_base_plus_the_adopted_features():
    """dev = base + S4 in code_signals + criteria on the three nouls (question
    text unchanged) + the turns shadow questions (serves_turn through
    turn_attribution, can_judge) + the two session-drift knobs (adopted
    2026-09-23 after the cross-process lock fix, formal U3) + the post-tool
    secret-intent question and exposure_intended_min (adopted 2026-09-23 from
    dev_exposure) + approval by chat reply (router.chat_approval,
    approval_questions, chat_approval_limits, chat_approval_min; adopted
    2026-09-24 from dev_chatapprove) + S6_link_placement (adopted 2026-09-24
    from dev_s6) + trusted commands and pinned instruction-file lines (adopted
    2026-09-24 from dev_trust). Not adopted: S3 and S3_last_check."""
    full_dev, base = without_test_run(with_trust_pin_question(without_build_facts(without_s4_withhold(
        without_decline_question(load("dev")))))), load_base()
    assert full_dev["router"]["code_signals"] == [S1, S2, S4, S6]
    trust = load("dev_trust")["router"]
    assert {k: full_dev["router"][k] for k in TRUST_KEYS} == {k: trust[k] for k in TRUST_KEYS}
    # dev = each measured candidate plus the other one's part, except name/provenance
    assert strip(without_trust(full_dev)) == strip(load("dev_s6"))
    assert strip(without_s6(full_dev)) == strip(load("dev_trust"))
    dev = without_s6(without_trust(full_dev))
    r, b = dev["router"], base["router"]
    assert r["code_signals"] == [S1, S2, S4]
    assert S3 not in r["code_signals"] and S3F not in r["code_signals"]
    assert r["thresholds"]["drift_session_ask_max"] == 0.5 and r["thresholds"]["drift_session_window"] == 5
    assert r["thresholds"][EXPOSURE_MIN] == 0.7 and EXPOSURE_MIN not in b["thresholds"]
    assert r["exposure_questions"] == load("dev_exposure")["router"]["exposure_questions"]
    assert "exposure_questions" not in b
    assert r["chat_approval"] is True and r["thresholds"][CHAT_MIN] == 0.85 and CHAT_MIN not in b["thresholds"]
    chat = load("dev_chatapprove")["router"]
    assert {k: r[k] for k in CHAT_KEYS} == {k: chat[k] for k in CHAT_KEYS}
    assert not set(CHAT_KEYS) & set(b)
    assert {k: v for k, v in r["thresholds"].items() if k not in (*DRIFT_SESSION, EXPOSURE_MIN, CHAT_MIN)} == b["thresholds"]
    crit = load("dev_crit")["router"]["questions"]
    assert {q for q, spec_ in r["questions"].items() if spec_["type"] == "noul" and "criteria" in spec_} == CRIT_NOULS
    for q in CRIT_NOULS:
        assert r["questions"][q]["type"] == "noul"
        assert r["questions"][q]["instructions"] == b["questions"][q]["instructions"], q
        assert r["questions"][q]["criteria"] == crit[q]["criteria"], q
        assert set(r["questions"][q]["criteria"]) == {"true", "false"}
    for q in set(r["questions"]) - CRIT_NOULS:
        assert r["questions"][q] == b["questions"][q], q
    turns = load("dev_turns")["router"]
    assert r["turn_attribution"] is True and "turn_attribution" not in b
    assert r["shadow_questions"]["can_judge"] == turns["shadow_questions"]["can_judge"]
    assert {k: v for k, v in r["shadow_questions"].items() if k != "can_judge"} == b["shadow_questions"]
    # the whole file: base + exactly these parts, nothing else
    before = without_chat_approval(dev)
    assert strip(without_exposure(before)) == compose(ids=(S1, S2, S4), sdrift=True)
    # dev minus both post-2026-09-23 features = dev_final (the measured candidate) except name/provenance
    assert strip(without_exposure(before)) == strip(load("dev_final"))
    # dev minus chat approval = dev_exposure (the measured secret-intent candidate) except name/provenance
    assert strip(before) == strip(load("dev_exposure"))
    # dev = dev_chatapprove (the measured chat-approval candidate) except name/provenance
    assert strip(dev) == strip(load("dev_chatapprove"))


def test_dev_all_is_dev_plus_every_part():
    assert strip(load("dev_all")) == compose()
    assert load("dev_all")["router"]["code_signals"] == [S1, S2, S3, S3F, S4]


@pytest.mark.parametrize("name,kwargs", [
    ("dev_all_no_s3", dict(ids=(S1, S2, S3F, S4))),
    ("dev_all_no_lastcheck", dict(ids=(S1, S2, S3, S4))),
    ("dev_all_no_s4", dict(ids=(S1, S2, S3, S3F))),
    ("dev_all_no_crit", dict(crit=False)),
    ("dev_all_no_sdrift", dict(sdrift=False)),
])
def test_leave_one_out_drops_exactly_one_part(name, kwargs):
    assert strip(load(name)) == compose(**kwargs)
    assert strip(load(name)) != strip(load("dev_all"))


@pytest.mark.parametrize("name", NEW)
def test_new_policies_load_and_are_waf_safe(name):
    pol = Policy.load(str(P / f"router_policy_{name}.json"))
    router.questions(pol)
    router.thresholds(pol)
    router.enabled_code_signals(pol)
    # Instructions of every question and the new noul criteria. The choice and
    # score criteria are dev's, unchanged (dev's effect rubric has an
    # apostrophe the heuristic regex counts as a quote; it runs live unblocked).
    texts = []
    for q in list(pol.router["questions"].values()) + list(pol.router["shadow_questions"].values()):
        texts.append(q["instructions"])
        if q.get("type", "noul") == "noul":
            texts += list((q.get("criteria") or {}).values())
    assert GEN.waf_hits(texts) == [] and GEN.PASSWD_PATH not in json.dumps(pol.raw)
    assert pol.name == "semgate-router-" + name.replace("_", "-")
