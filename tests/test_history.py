from semgate.history import ToolHistory, action_key, normalize_args


def test_normalization_is_lowercase_and_collapsed_whitespace():
    assert normalize_args({"command": "Get-ChildItem   C:\\Users"}) == normalize_args({"command": "get-childitem c:\\users"})


def test_model_narration_is_not_part_of_the_action_key():
    a = action_key("bash", {"command": "ls", "toolSummary": "first"})
    b = action_key("bash", {"command": "ls", "toolSummary": "second", "toolAction": "Listing"})
    assert a == b
    assert a != action_key("bash", {"command": "ls -la"})


def test_executed_joins_pending_by_conversation_and_step(tmp_path):
    h = ToolHistory(str(tmp_path / "h.jsonl"))
    h.record_pending("c1", 4, "bash", {"command": "ls"}, "ask", "semantic", "j1")
    executed = h.record_executed("c1", 4)
    assert executed["tool"] == "bash" and executed["prior_decision"] == "ask"
    assert h.count_executed_after_ask("bash", {"command": "LS"}) == 1


def test_unmatched_failed_and_non_ask_executions_do_not_count(tmp_path):
    h = ToolHistory(str(tmp_path / "h.jsonl"))
    assert h.record_executed("c1", 9) is None                       # no pending record
    h.record_pending("c1", 1, "bash", {"command": "ls"}, "ask", "semantic")
    h.record_executed("c1", 1, error="exit status 1")               # failed or rejected
    h.record_pending("c1", 2, "bash", {"command": "ls"}, "allow", "hard_rules")
    h.record_executed("c1", 2)                                      # was not an ask
    h.record_pending("c1", 3, "bash", {"command": "ls"}, "ask", "semantic")  # never executed
    assert h.count_executed_after_ask("bash", {"command": "ls"}) == 0


# --- learned auto-allow inside the judge -----------------------------------
from pathlib import Path
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant
from semgate.judge import judge
from semgate.policy import Policy

POLICY = Policy.load(str(Path(__file__).parents[1] / "policies" / "default_policy.json"))


def _envelope(command, expires_at="2099-01-01T00:00:00Z"):
    grant = UserGrant(grant_id="g", principal="p", purpose="list files", expires_at=expires_at)
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}), grant=grant,
                    environment=Environment(project_root="/workspace/project", session_id="c"))


def _approve(history, command, times, stage="semantic"):
    for i in range(times):
        history.record_pending("c", i, "bash", {"command": command}, "ask", stage)
        history.record_executed("c", i)


def test_semantic_ask_becomes_learned_allow_after_two_approved_executions(tmp_path):
    h = ToolHistory(str(tmp_path / "h.jsonl"))
    _approve(h, "ls -la", 1)
    assert judge(_envelope("ls -la"), POLICY, history=h).decision == "ask"
    _approve(h, "ls -la", 2)
    d = judge(_envelope("LS   -la"), POLICY, history=h)
    assert (d.decision, d.stage) == ("allow", "auto_allow")
    assert d.reasons[0] == "auto_allow/learned (n=3)"


def test_deny_human_gate_and_expired_grant_are_never_learned(tmp_path):
    h = ToolHistory(str(tmp_path / "h.jsonl"))
    for command in ("rm -rf /", "git push origin main", "ls -la"):
        _approve(h, command, 5)
    assert judge(_envelope("rm -rf /"), POLICY, history=h).decision == "deny"
    gated = judge(_envelope("git push origin main"), POLICY, history=h)
    assert (gated.decision, gated.stage) == ("ask", "human_gate")
    expired = judge(_envelope("ls -la", expires_at="2000-01-01T00:00:00Z"), POLICY, history=h)
    assert (expired.decision, expired.stage) == ("ask", "grant_validity")
