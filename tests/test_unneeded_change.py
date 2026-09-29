"""F7 (experimental policy router_policy_f7.json): `unneeded_change` can turn
an allow into an ask. It never creates an allow or a deny, its vote is always
recorded, and it is asked only when a user_message exists."""
from pathlib import Path

import pytest

from semgate import router
from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import JudgeProvider, PredicateAnswer
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).parents[1]
F7 = Policy.load(str(ROOT / "policies" / "router_policy_f7.json"))
DEV = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
# dev before 2026-09-23 (2) (S4, criteria, turns); f7 was built as this file plus one question
BASE = Policy.load(str(ROOT / "policies" / "experiments" / "router_policy_dev_base_2026-09-23.json"))


def answers(route="run", route_conf=1.0, effect=0.0, user_asked=0.9, unneeded=None):
    a = {
        "route": PredicateAnswer("route", value=route, confidence=route_conf, raw={"probabilities": {route: route_conf, "block": 0.0 if route != "block" else route_conf}}),
        "effect": PredicateAnswer("effect", value=effect, confidence=1.0, raw={"probabilities": {}}),
        "user_asked": PredicateAnswer("user_asked", probability=user_asked),
        "executes": PredicateAnswer("executes", value=0.0, confidence=1.0),
    }
    if unneeded is not None:
        a["unneeded_change"] = PredicateAnswer("unneeded_change", probability=unneeded)
    return a


def vote(out):
    return next(v for v in out["votes"] if v["predicate"] == "unneeded_change")


def test_would_allow_and_high_p_becomes_ask():
    assert router.decide(F7, answers())["decision"] == "allow"
    out = router.decide(F7, answers(unneeded=0.85))
    assert out["decision"] == "ask" and out["reason_code"] == "unneeded_change_review"
    assert vote(out) == {"predicate": "unneeded_change", "vote": "unneeded", "p": 0.85}


def test_low_p_leaves_the_allow_and_records_the_vote():
    out = router.decide(F7, answers(unneeded=0.2))
    assert out["decision"] == "allow" and vote(out)["vote"] == "clear"


@pytest.mark.parametrize("kw,decision", [
    ({"effect": 3.0}, "ask"),                                            # high effect review
    ({"route": "block", "route_conf": 0.95, "user_asked": 0.1}, "deny"),  # confident misaligned deny
    ({"route": "review", "route_conf": 0.6, "effect": 2.0, "user_asked": 0.1}, "ask"),
])
def test_ask_and_deny_are_unchanged(kw, decision):
    before = router.decide(F7, answers(**kw))
    after = router.decide(F7, answers(unneeded=0.99, **kw))
    assert before["decision"] == after["decision"] == decision
    assert before["reason_code"] == after["reason_code"] and vote(after)["vote"] == "unneeded"


def test_a_low_p_never_creates_an_allow():
    out = router.decide(F7, answers(effect=3.0, unneeded=0.0))
    assert out["decision"] == "ask"


def test_dev_policy_ignores_the_answer_except_for_the_vote():
    out = router.decide(DEV, answers(unneeded=0.99))
    assert out["decision"] == "allow" and vote(out)["vote"] == "clear"
    assert "unneeded_change" not in router.questions(DEV)
    assert "unneeded_change" in router.questions(F7)


class Recording(JudgeProvider):
    name = "recording"

    def __init__(self):
        self.asked = []

    def evaluate(self, state, questions):
        self.asked.append(set(questions))
        return FakeProvider({"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0},
                             "user_asked": 0.9, "executes": {"value": 0.0, "confidence": 1.0},
                             "unneeded_change": 0.9}).evaluate(state, questions)


def _env(user):
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "chmod 644 notes.txt"}),
                    grant=UserGrant(grant_id="g", principal="p", purpose="dev"),
                    environment=Environment(project_root="/p", cwd="/p"), user_message=user)


def test_question_is_asked_only_with_a_user_message():
    p = Recording()
    judge(_env(""), F7, provider=p)
    assert "unneeded_change" not in p.asked[0]
    p = Recording()
    d = judge(_env("count the files in docs/"), F7, provider=p)
    assert "unneeded_change" in p.asked[0]
    assert d.decision == "ask" and d.reason_code == "unneeded_change_review"


def test_f7_is_dev_plus_one_question():
    """F7 stays "dev plus one question" after dev adopted task context, G1
    and G2 (2026-09-23): every key of the policy except name/provenance, the
    unneeded_change question and its threshold is identical to that dev
    (BASE; dev later adopted S4, criteria and turns without F7)."""
    DEV = BASE
    dev_t, f7_t = DEV.router["thresholds"], F7.router["thresholds"]
    assert {k: v for k, v in f7_t.items() if k != "unneeded_change_ask_min"} == dev_t
    assert f7_t["unneeded_change_ask_min"] == 0.7
    dev_q = dict(DEV.router["questions"])
    f7_q = dict(F7.router["questions"])
    unneeded = f7_q.pop("unneeded_change")
    assert f7_q == dev_q
    assert F7.router.get("task_context") is True and "task_requests" in unneeded["instructions"]
    strip = lambda raw: {k: v for k, v in raw.items() if k not in ("name", "provenance", "router")}
    assert strip(F7.raw) == strip(DEV.raw)
    same = lambda r: {k: v for k, v in r.items() if k not in ("questions", "thresholds")}
    assert same(F7.router) == same(DEV.router)
