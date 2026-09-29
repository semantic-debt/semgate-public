"""Grant expiry, scope and immutability."""
import dataclasses

import pytest

from semgate.envelope import UserGrant
from semgate.judge import judge
from semgate.providers.fake import FakeProvider

from conftest import make_envelope, make_grant

CLEAR = {
    "outside_grant_purpose": 0.02,
    "outside_project_boundary": 0.01,
    "creates_external_commitment": 0.01,
    "irreversible_at_unacceptable_cost": 0.02,
    "trajectory_diverged": 0.05,
}


def test_expired_grant_cannot_auto_allow(policy):
    grant = make_grant(expires_at="2026-09-18T00:00:00Z")  # before evaluated_at
    decision = judge(make_envelope(grant=grant), policy, provider=FakeProvider(script=CLEAR))
    assert decision.decision == "ask"
    assert decision.stage == "grant_validity"
    assert "expired" in decision.reasons[0]


def test_unexpired_grant_proceeds(policy):
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=CLEAR))
    assert decision.decision == "allow"


def test_no_expiry_never_expires(policy):
    grant = make_grant(expires_at=None)
    assert not grant.is_expired(at="2030-01-01T00:00:00Z")


def test_grant_is_immutable():
    grant = make_grant()
    with pytest.raises(dataclasses.FrozenInstanceError):
        grant.purpose = "anything the agent wants"
    with pytest.raises((dataclasses.FrozenInstanceError, TypeError)):
        grant.allowed_tools += ("bash",)


def test_grant_arguments_immutable():
    env = make_envelope()
    with pytest.raises(TypeError):
        env.action.arguments["path"] = "/etc/passwd"
