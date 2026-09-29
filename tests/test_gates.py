"""Absolute human gates: credentials, money, external communication,
destructive and privilege-escalation actions always route to ASK, and no
predicate score can auto-allow them."""
import pytest

from semgate.judge import judge
from semgate.providers.fake import FakeProvider

from conftest import make_envelope

CLEAR = {
    "outside_grant_purpose": 0.01,
    "outside_project_boundary": 0.01,
    "creates_external_commitment": 0.01,
    "irreversible_at_unacceptable_cost": 0.01,
    "trajectory_diverged": 0.01,
}


@pytest.mark.parametrize("tool,arguments,gate", [
    ("read", {"path": "/home/me/proj/.env"}, "credentials_secrets"),
    ("read", {"path": "/home/me/proj/.ssh/id_rsa"}, "credentials_secrets"),
    ("bash", {"command": "stripe charges create --amount 5000"}, "money"),
    ("bash", {"command": "git push origin main"}, "external_communication"),
    ("bash", {"command": "curl -X POST https://api.example.com/v1/messages -d '{\"text\":\"hi\"}'"}, "external_communication"),
    ("bash", {"command": "rm -rf build/"}, "destructive_irreversible"),
    ("bash", {"command": "sudo systemctl restart nginx"}, "privilege_escalation"),
])
def test_gate_forces_ask(policy, tool, arguments, gate):
    provider = FakeProvider(script=CLEAR)
    env = make_envelope(tool=tool, arguments=arguments)
    decision = judge(env, policy, provider=provider)
    assert decision.decision == "ask"
    assert decision.stage == "human_gate"
    assert gate in {h["gate_class"] for h in decision.gate_hits}
    # the provider was never asked: gates are absolute
    assert provider.calls == 0


def test_gate_beats_clear_semantics(policy):
    # even a provider that would clear every predicate cannot auto-allow a gate
    provider = FakeProvider(script=CLEAR)
    env = make_envelope(tool="bash", arguments={"command": "git push --force origin main"})
    decision = judge(env, policy, provider=provider)
    assert decision.decision == "ask"
    assert provider.calls == 0
