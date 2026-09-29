import json
from pathlib import Path

import pytest

from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, TrajectoryEntry, UserGrant
from semgate.history import ToolHistory
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider
from semgate import router

POLICY_PATH = Path(__file__).parents[1] / "policies" / "router_policy.json"
POLICY = Policy.load(str(POLICY_PATH))


def envelope(command="Get-ChildItem tests", purpose="read-only inspection of this machine", user_message=""):
    grant = UserGrant(grant_id="g", principal="p", purpose=purpose, expires_at="2099-01-01T00:00:00Z")
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command, "toolSummary": "narration"}),
                    grant=grant, environment=Environment(project_root="/workspace/project", session_id="c"), user_message=user_message)


def answers(route="run", route_conf=1.0, effect=0.0, effect_conf=1.0, user_asked=0.05):
    return {"route": {"value": route, "confidence": route_conf}, "effect": {"value": effect, "confidence": effect_conf}, "user_asked": user_asked}


def decide(env=None, **kw):
    return judge(env or envelope(), POLICY, provider=FakeProvider(answers(**kw)))


def test_state_fields_and_no_model_narration():
    state = router.build_state(envelope(user_message="list the tests"))
    assert state == {"command": "Get-ChildItem tests", "operator_purpose": "read-only inspection of this machine",
                     "user_message": "list the tests", "recent_actions": "",   # recent_actions empty with no trajectory
                     "untrusted_context": ""}                                  # no tool output overlaps the command


def test_confident_read_only_action_is_allowed():
    d = decide()
    assert (d.decision, d.stage) == ("allow", "semantic")
    assert d.predicate_votes[0]["value"] == "run" and d.predicate_votes[0]["confidence"] == 1.0


@pytest.mark.parametrize("kw", [
    {"route_conf": 0.89},                      # route not confident enough
    {"effect": 0.6},                           # changes something
    {"effect_conf": 0.4},                      # effect answer is unsure
    {"route": "review"},
])
def test_anything_short_of_a_confident_read_asks(kw):
    assert decide(**kw).decision == "ask"


def test_confident_block_without_user_request_is_denied():
    assert decide(route="block", route_conf=0.9, effect=2.0, user_asked=0.07).decision == "deny"


def test_user_request_turns_a_block_into_an_ask_with_a_plain_reason():
    d = decide(route="block", route_conf=0.9, effect=2.0, user_asked=0.98)
    assert d.decision == "ask" and d.reasons[0].startswith("Approve? You asked for this")


def test_user_request_never_allows_by_default():
    assert decide(route="run", route_conf=1.0, effect=1.0, user_asked=1.0).decision == "ask"


def test_destructive_effect_always_asks_even_when_route_says_run():
    d = decide(route="run", route_conf=1.0, effect=2.6, user_asked=1.0)
    assert d.decision == "ask" and d.reasons[0].startswith("a human must review this")


def test_operator_can_opt_in_to_allowing_user_requested_edits(tmp_path):
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8")); raw["router"]["thresholds"]["user_asked_allow_effect_max"] = 1.5
    policy = Policy(raw)
    ok = judge(envelope(), policy, provider=FakeProvider(answers(route="review", route_conf=0.8, effect=1.2, user_asked=0.97)))
    blocked = judge(envelope(), policy, provider=FakeProvider(answers(route="block", route_conf=0.6, effect=1.2, user_asked=0.97)))
    too_big = judge(envelope(), policy, provider=FakeProvider(answers(route="review", route_conf=0.8, effect=2.0, user_asked=0.97)))
    assert (ok.decision, blocked.decision, too_big.decision) == ("allow", "ask", "ask")


def test_missing_purpose_unscripted_answers_and_provider_failure_all_ask():
    assert judge(envelope(purpose=""), POLICY, provider=FakeProvider(answers())).decision == "ask"
    assert judge(envelope(), POLICY, provider=FakeProvider({})).decision == "ask"
    failed = judge(envelope(), POLICY, provider=FakeProvider(answers(), fail=True))
    assert failed.decision == "ask" and failed.error


def test_hard_rules_and_gates_run_before_the_router():
    spy = FakeProvider(answers())
    assert judge(envelope("rm -rf /"), POLICY, provider=spy).decision == "deny"
    gated = judge(envelope("git push origin main"), POLICY, provider=spy)
    assert (gated.decision, gated.stage) == ("ask", "human_gate") and spy.calls == 0


def test_learned_allow_still_applies_to_router_asks(tmp_path):
    h = ToolHistory(str(tmp_path / "h.jsonl")); env = envelope("py -m pip list")
    for i in range(2):
        h.record_pending("c", i, "bash", env.action.arguments, "ask", "semantic"); h.record_executed("c", i)
    d = judge(env, POLICY, provider=FakeProvider(answers(route="review", route_conf=0.7)), history=h)
    assert (d.decision, d.stage) == ("allow", "auto_allow")


def test_unknown_threshold_name_is_rejected():
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8")); raw["router"]["thresholds"]["allow_everything"] = 1
    with pytest.raises(ValueError):
        router.thresholds(Policy(raw))


# --- v3 execution guard ----------------------------------------------------
def test_executes_guard_blocks_allow_only_when_configured():
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    raw["router"]["questions"]["executes"] = {"type": "score", "instructions": "x", "criteria": ["a", "b", "c"]}
    raw["router"]["thresholds"]["exec_block_allow_min"] = 1.5
    raw["router"]["thresholds"]["allow_run_probability"] = 0.60
    policy = Policy(raw)
    def ans(exec_score):
        a = answers(route="run", route_conf=1.0, effect=0.0, effect_conf=1.0)
        a["route"] = {"value": "run", "confidence": 1.0, "probabilities": {"run": 1.0, "review": 0.0, "block": 0.0}}
        a["executes"] = {"value": exec_score, "confidence": 0.9}
        return a
    low = judge(envelope(), policy, provider=FakeProvider(ans(0.1)))
    high = judge(envelope(), policy, provider=FakeProvider(ans(1.9)))
    assert low.decision == "allow"                     # reads still auto-allow
    assert high.decision == "ask"                       # arbitrary execution is held back
    assert high.reasons[0].startswith("this action runs a script")


# --- self-consistency (v3c) ------------------------------------------------
class _CyclingProvider:
    """Returns a different scripted answer set on each call, to force flips."""
    name = "cycling"
    def __init__(self, script_list): self.script_list = script_list; self.calls = 0
    def evaluate(self, state, questions):
        script = self.script_list[min(self.calls, len(self.script_list) - 1)]; self.calls += 1
        from semgate.providers.base import PredicateAnswer
        out = {}
        for qid in questions:
            s = script[qid]
            if qid == "route":
                out[qid] = PredicateAnswer(qid, value=s["value"], confidence=s["confidence"], raw={"probabilities": s.get("probabilities", {})})
            elif qid == "user_asked":
                out[qid] = PredicateAnswer(qid, probability=s)
            else:
                out[qid] = PredicateAnswer(qid, value=s["value"], confidence=s.get("confidence"))
        return out

def _v3c():
    raw = json.loads((Path(__file__).parents[1] / "policies" / "router_policy_v3c.json").read_text(encoding="utf-8"))
    return Policy(raw)

def _borderline_run(run_p):
    # a benign read whose P(run) sits right at the 0.60 allow threshold
    return {"route": {"value": "run", "confidence": 0.6, "probabilities": {"run": run_p, "review": 1 - run_p - 0.01, "block": 0.01}},
            "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.1, "executes": {"value": 0.0, "confidence": 1.0}}

def test_borderline_case_reasks_and_takes_majority():
    policy = _v3c()
    # 3 reps say allow (run_p 0.63), 2 say ask (run_p 0.57) -> majority allow
    scripts = [_borderline_run(p) for p in (0.63, 0.57, 0.63, 0.57, 0.63)]
    prov = _CyclingProvider(scripts)
    d = judge(envelope(), policy, provider=prov)
    assert d.decision == "allow" and prov.calls == 5
    assert d.reasons[0].startswith("self-consistency")

def test_clearly_safe_case_does_not_reask():
    policy = _v3c()
    strong = {"route": {"value": "run", "confidence": 1.0, "probabilities": {"run": 0.99, "review": 0.005, "block": 0.005}},
              "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.05, "executes": {"value": 0.0, "confidence": 1.0}}
    prov = _CyclingProvider([strong])
    d = judge(envelope(), policy, provider=prov)
    assert d.decision == "allow" and prov.calls == 1   # not borderline: single call


# --- developer profile (allow_edit_effect_max) -----------------------------
def _dev():
    raw = json.loads((Path(__file__).parents[1] / "policies" / "router_policy_dev.json").read_text(encoding="utf-8"))
    return Policy(raw)

def test_developer_profile_allows_in_project_edits_but_not_higher_effect():
    policy = _dev()
    def ans(route, effect, conf=0.7):
        a = answers(route=route, route_conf=conf, effect=effect, effect_conf=0.9, user_asked=0.1)
        a["route"] = {"value": route, "confidence": conf, "probabilities": {"run": 0.5, "review": 0.4, "block": 0.1}}
        a["executes"] = {"value": 0.0, "confidence": 0.9}
        return a
    # in-project edit (effect ~1) -> allow, for route=run and for a route=review
    # below G1's edit_allow_review_max (0.6, adopted in dev 2026-09-23)
    for route, conf in (("run", 0.7), ("review", 0.55)):
        d = judge(envelope(), policy, provider=FakeProvider(ans(route, 1.0, conf)))
        assert d.decision == "allow" and d.reasons[0].startswith("developer profile"), (route, conf)
    # G1: a confident route=review (0.7 >= 0.6) withholds the edit allow
    assert judge(envelope(), policy, provider=FakeProvider(ans("review", 1.0))).decision == "ask"
    # install / outside-project / higher effect -> not allowed
    assert judge(envelope(), policy, provider=FakeProvider(ans("review", 2.0))).decision == "ask"
    # route=block is never allowed even at low effect
    blk = ans("block", 1.0); blk["route"] = {"value": "block", "confidence": 0.7, "probabilities": {"run": 0.1, "review": 0.2, "block": 0.7}}
    assert judge(envelope(), policy, provider=FakeProvider(blk)).decision != "allow"
    # arbitrary execution still blocked from allow even at low effect
    ex = ans("run", 1.0); ex["executes"] = {"value": 1.9, "confidence": 0.9}
    assert judge(envelope(), policy, provider=FakeProvider(ex)).decision == "ask"


def test_render_action_describes_url_and_file_reads_clearly():
    from semgate import router
    from semgate.envelope import Envelope, ProposedAction, SCHEMA_VERSION, UserGrant
    def env(tool, args):
        return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool, args),
                        grant=UserGrant(grant_id="g", principal="p", purpose="dev"))
    assert "read-only HTTP GET" in router.render_action(env("read_url_content", {"url": "https://th3nolo.com"}))
    assert "read the file" in router.render_action(env("read", {"path": "src/app.py"}))
    # a shell command still renders as the command line
    assert router.render_action(env("bash", {"command": "git status"})) == "git status"


# --- drift deny via the optional on_task question (trace policy) --------------
TRACE_POLICY = Policy.load(str(Path(__file__).parents[1] / "policies" / "router_policy_trace.json"))

def _trace_prov(on_task, effect=0.0):
    # A benign command (route=run) that would otherwise allow when read-only;
    # on_task is the drift signal from the recent-action trace.
    return FakeProvider({"route": {"value": "run", "confidence": 1.0},
                         "effect": {"value": effect, "confidence": 1.0},
                         "user_asked": 0.05, "on_task": on_task,
                         "executes": {"value": 0.0, "confidence": 1.0}})

def _env_with_trace():
    # on_task is only asked when a trajectory exists (drift is a trajectory property).
    e = envelope()
    return Envelope(schema=SCHEMA_VERSION, action=e.action, grant=e.grant, environment=e.environment,
                    trajectory=Trajectory(recent=(TrajectoryEntry(tool="read", decision="", summary="cat .env"),)),
                    user_message=e.user_message)

def test_low_on_task_read_only_command_goes_to_a_human_not_allow_or_deny():
    d = judge(_env_with_trace(), TRACE_POLICY, provider=_trace_prov(0.1))
    assert d.decision == "ask" and d.reason_code == "drift_review"

def test_low_on_task_command_that_changes_something_is_denied():
    d = judge(_env_with_trace(), TRACE_POLICY, provider=_trace_prov(0.1, effect=2.0))
    assert d.decision == "deny" and d.reason_code == "drift_deny"

def test_high_on_task_allows_the_same_command():
    d = judge(_env_with_trace(), TRACE_POLICY, provider=_trace_prov(0.95))
    assert d.decision == "allow"  # on-task + read-only -> the drift path does not fire

def test_no_trajectory_skips_on_task_so_a_lone_command_is_not_drift_denied():
    # even if the provider would answer on_task low, no trajectory => on_task is not asked
    d = judge(envelope(), TRACE_POLICY, provider=_trace_prov(0.1))
    assert d.decision == "allow" and d.reason_code != "drift_deny"


def test_shadow_questions_are_recorded_but_never_decide():
    from semgate.policy import Policy as _P
    raw = dict(DEV_FOR_SHADOW.raw)
    raw["router"] = {**DEV_FOR_SHADOW.router, "shadow_questions": {"leaks_secrets": {"type": "noul", "instructions": "x"}}}
    pol = _P(raw)
    assert "leaks_secrets" in router.questions(pol)
    base = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "executes": {"value": 0.0, "confidence": 1.0}}
    for p in (0.01, 0.99):
        d = judge(envelope(), pol, provider=FakeProvider({**base, "leaks_secrets": p}))
        assert d.decision == "allow"                     # same decision whatever the shadow answer
        shadow = [v for v in d.predicate_votes if v["predicate"] == "leaks_secrets"]
        assert shadow and shadow[0]["vote"] == "shadow" and abs(shadow[0]["p"] - p) < 1e-9


DEV_FOR_SHADOW = Policy.load(str(Path(__file__).parents[1] / "policies" / "router_policy_dev.json"))
