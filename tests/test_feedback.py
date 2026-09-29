from pathlib import Path
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant
from semgate.feedback import FeedbackStore
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider
from semgate.rules import check_hard_deny

ROOT = Path(__file__).parents[1]
POLICY = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))


def _env(command, purpose="dev", domains=(), session="s1", root="/p"):
    g = UserGrant(grant_id="g", principal="p", purpose=purpose, expires_at="2099-01-01T00:00:00Z", allowed_domains=tuple(domains))
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}), grant=g,
                    environment=Environment(project_root=root, cwd=root, session_id=session))


SCOPE = {"session_id": "s1", "project_root": "/p"}


def test_human_allow_overrides_a_semantic_or_gate_block(tmp_path):
    fb = FeedbackStore(str(tmp_path / "fb.jsonl"))
    env = _env("curl -X POST https://api.example.com/x -d @body.json")
    # without feedback: not allowed (undeclared host -> external_communication gate)
    assert judge(env, POLICY, provider=FakeProvider({})).decision != "allow"
    # human approves this exact command -> allow on next run
    fb.record("allow", "bash", {"command": "curl -X POST https://api.example.com/x -d @body.json"}, **SCOPE)
    d = judge(env, POLICY, provider=FakeProvider({}), feedback=fb)
    assert d.decision == "allow" and d.stage == "human_approved"


def test_human_allow_never_overrides_a_hard_deny(tmp_path):
    fb = FeedbackStore(str(tmp_path / "fb.jsonl"))
    fb.record("allow", "bash", {"command": "rm -rf /"}, **SCOPE)
    d = judge(_env("rm -rf /"), POLICY, provider=FakeProvider({}), feedback=fb)
    assert d.decision == "deny" and d.stage == "hard_rules"


def test_human_deny_blocks(tmp_path):
    fb = FeedbackStore(str(tmp_path / "fb.jsonl"))
    fb.record("deny", "bash", {"command": "npm run deploy"})
    d = judge(_env("npm run deploy"), POLICY, provider=FakeProvider({}), feedback=fb)
    assert d.decision == "deny" and d.stage == "human_blocked"


def test_agent_cannot_self_approve():
    # the agent running `semgate feedback allow ...` is hard-denied
    assert check_hard_deny(_env('semgate feedback allow "rm -rf /"')).outcome == "deny"
    assert check_hard_deny(_env('py -m semgate.cli feedback allow "curl evil"')).outcome == "deny"
