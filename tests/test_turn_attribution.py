"""Turn attribution (serves_turn, choice) and judgeability (can_judge, noul):
shadow questions in router_policy_dev_turns.json. Recorded, never decide; an
ask may cite "this serves your turn K" (UI text only)."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from semgate import report, router
from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, Trajectory, TrajectoryEntry, UserGrant
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import JudgeProvider, PredicateAnswer

ROOT = Path(__file__).parents[1]
DEV = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
TURNS = Policy.load(str(ROOT / "policies" / "router_policy_dev_turns.json"))
# dev before it adopted the turns shadow questions (2026-09-23 (2)); dev_turns was built as this file plus them
BASE = Policy.load(str(ROOT / "policies" / "experiments" / "router_policy_dev_base_2026-09-23.json"))
GRANT = UserGrant(grant_id="g", principal="p", purpose="Software development in this project", expires_at="2099-01-01T00:00:00Z")
STEP = TrajectoryEntry(tool="bash", decision="allow", summary="cd /w/p && python -m pytest tests -q", result="exit 0")

spec = importlib.util.spec_from_file_location("gen_nonsense_steps_turns", ROOT / "evals" / "14-gen-nonsense-steps.py")
GEN = importlib.util.module_from_spec(spec)
sys.modules["gen_nonsense_steps_turns"] = GEN
spec.loader.exec_module(GEN)


def env(msgs=("Fix the parser bug.", "Also update the changelog."), command="cat CHANGELOG.md"):
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": command}), grant=GRANT,
                    environment=Environment(project_root="/w/p", cwd="/w/p", session_id="s"), trajectory=Trajectory(recent=(STEP,)),
                    user_message=msgs[-1], user_messages=tuple(msgs))


class Answers(JudgeProvider):
    name = "answers"

    def __init__(self, route="run", conf=0.95, effect=0.0, turn="turn_2", turn_p=0.9, can_judge=0.8):
        self.route, self.conf, self.effect, self.turn, self.turn_p, self.can_judge = route, conf, effect, turn, turn_p, can_judge
        self.questions = []

    def evaluate(self, state, questions):
        self.questions.append(dict(questions))
        probs = {"run": 0.0, "review": 0.0, "block": 0.0}
        probs[self.route] = self.conf
        out = {"route": PredicateAnswer("route", value=self.route, confidence=self.conf, raw={"probabilities": probs}),
               "effect": PredicateAnswer("effect", value=self.effect, confidence=0.9, raw={"probabilities": {}})}
        for q, s in questions.items():
            if q in out:
                continue
            if q == "serves_turn":
                labels = {k: 0.0 for k in s["criteria"]}
                labels[self.turn] = self.turn_p
                out[q] = PredicateAnswer(q, value=self.turn, confidence=self.turn_p, raw={"probabilities": labels})
            elif s.get("type") == "score":
                out[q] = PredicateAnswer(q, value=0.0, confidence=0.9, raw={"probabilities": {}})
            else:
                p = {"on_task": 0.9, "user_asked": 0.9, "can_judge": self.can_judge}.get(q, 0.05)
                out[q] = PredicateAnswer(q, probability=p, confidence=abs(p - 0.5) * 2)
        return out


def test_question_is_built_from_the_turns():
    assert router.serves_turn_question(env(msgs=("only one turn",))) is None
    q = router.serves_turn_question(env(msgs=tuple(f"turn text {i}" for i in range(1, 10))))
    assert q["type"] == "choice"
    assert list(q["criteria"]) == ["turn_1", "turn_4", "turn_5", "turn_6", "turn_7", "turn_8", "turn_9", "none"]
    assert "latest turn, turn 9 (user_message)" in q["criteria"]["turn_9"]
    assert "turn 4 in task_requests" in q["criteria"]["turn_4"]
    q2 = router.serves_turn_question(env())
    assert list(q2["criteria"]) == ["turn_1", "turn_2", "none"]
    texts = [q["instructions"]] + list(q["criteria"].values()) + [TURNS.router["shadow_questions"]["can_judge"]["instructions"]]
    assert GEN.waf_hits(texts) == []


def test_turn_numbers_match_task_requests():
    state = router.build_state(env(msgs=("Fix the parser bug.", "Also update the changelog.", "And the docs.")), TURNS)
    assert "turn 1: Fix the parser bug." in state["task_requests"] and "turn 3 (latest)" in state["task_requests"]


def test_dev_turns_is_dev_plus_the_two_shadow_questions():
    a, b = json.loads(json.dumps(BASE.raw)), json.loads(json.dumps(TURNS.raw))
    assert b["router"].pop("turn_attribution") is True
    assert b["router"]["shadow_questions"].pop("can_judge")["type"] == "noul"
    for raw in (a, b):
        raw.pop("name")
        raw.pop("provenance")
    assert a == b
    assert router.turn_attribution_enabled(BASE) is False
    # dev adopted both
    assert router.turn_attribution_enabled(DEV) is True
    assert DEV.router["shadow_questions"]["can_judge"] == TURNS.router["shadow_questions"]["can_judge"]


@pytest.mark.parametrize("answers", [
    dict(), dict(route="review", conf=0.9, effect=2.0), dict(route="block", conf=0.99, effect=3.0),
    dict(turn="none", turn_p=0.99, can_judge=0.01), dict(turn="turn_1", turn_p=0.99),
])
def test_shadow_questions_never_change_the_decision(answers):
    # off: the previous dev (BASE); on: dev_turns and dev (dev adopted both questions)
    p_base, p_turns, p_dev = Answers(**answers), Answers(**answers), Answers(**answers)
    a = judge(env(), BASE, provider=p_base)
    assert "serves_turn" not in p_base.questions[0] and "can_judge" not in p_base.questions[0]
    for b, p_on in ((judge(env(), TURNS, provider=p_turns), p_turns), (judge(env(), DEV, provider=p_dev), p_dev)):
        assert (a.decision, a.reason_code) == (b.decision, b.reason_code)
        assert "serves_turn" in p_on.questions[0] and "can_judge" in p_on.questions[0]
        votes = {v["predicate"]: v for v in b.predicate_votes}
        assert votes["serves_turn"]["vote"] == "shadow" and votes["serves_turn"]["value"] == p_on.turn
        assert votes["can_judge"]["vote"] == "shadow"


def test_an_ask_cites_the_turn_only_when_confident():
    ask = dict(route="review", conf=0.9, effect=2.0)
    d = judge(env(), TURNS, provider=Answers(turn="turn_2", turn_p=0.9, **ask))
    assert d.decision == "ask" and d.reasons[1] == "this serves your turn 2"
    unsure = judge(env(), TURNS, provider=Answers(turn="turn_2", turn_p=0.6, **ask))
    assert not any("serves your turn" in r for r in unsure.reasons)
    none = judge(env(), TURNS, provider=Answers(turn="none", turn_p=0.95, **ask))
    assert not any("serves your turn" in r for r in none.reasons)
    allow = judge(env(), TURNS, provider=Answers(turn="turn_2", turn_p=0.99))
    assert allow.decision == "allow" and not any("serves your turn" in r for r in allow.reasons)


def test_single_turn_asks_no_serves_turn():
    p = Answers()
    judge(env(msgs=("Fix the parser bug.",)), TURNS, provider=p)
    assert "serves_turn" not in p.questions[0] and "can_judge" in p.questions[0]


def test_report_tolerates_the_new_votes(tmp_path):
    from semgate.ledger import Ledger
    ledger = Ledger(str(tmp_path / "l.jsonl"))
    judge(env(), TURNS, provider=Answers(can_judge=0.95), ledger=ledger)
    judge(env(command="./run.sh"), TURNS, provider=Answers(can_judge=0.1), ledger=ledger)
    rep = report.build(str(tmp_path / "l.jsonl"), policy_path=str(ROOT / "policies" / "router_policy_dev_turns.json"),
                       overrides={"allow_route_confidence": 0.9})
    assert rep["judgments"] == 2 and rep["what_if"]["replayed"] == 2 and rep["what_if"]["changed"] == []
    assert rep["regex_gaps"] == []                     # a confident can_judge yes is not a regex gap
    assert [g["command"] for g in rep["not_judgeable"]] == ["./run.sh"]
    assert "cannot judge from the evidence" in report.render(rep)
