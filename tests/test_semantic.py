"""Semantic layer: evidence, abstention, provider failure, uncertainty."""
from semgate.judge import judge
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider

from conftest import make_envelope, make_grant

CLEAR = {
    "outside_grant_purpose": 0.02,
    "outside_project_boundary": 0.01,
    "creates_external_commitment": 0.01,
    "irreversible_at_unacceptable_cost": 0.02,
    "trajectory_diverged": 0.05,
}


def test_semantic_allow_when_clear(policy):
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=CLEAR))
    assert decision.decision == "allow"
    assert decision.stage == "semantic"
    assert all(v["vote"] == "clear" for v in decision.predicate_votes)


def test_semantic_deny_on_violation(policy):
    script = dict(CLEAR, outside_grant_purpose=0.97)
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=script))
    assert decision.decision == "deny"


def test_uncertainty_asks(policy):
    script = {k: 0.5 for k in CLEAR}
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=script))
    assert decision.decision == "ask"
    assert any("uncertain" in r for r in decision.reasons)


def test_missing_evidence_abstains(policy):
    grant = make_grant(purpose="")  # two predicates require grant.purpose
    decision = judge(make_envelope(grant=grant), policy, provider=FakeProvider(script=CLEAR))
    assert decision.decision == "ask"
    assert "outside_grant_purpose" in decision.missing_evidence
    assert "trajectory_diverged" in decision.missing_evidence
    # predicates with satisfied evidence still fired
    assert "outside_project_boundary" not in decision.missing_evidence


def test_provider_failure_abstains_and_records(policy):
    provider = FakeProvider(fail=True)
    decision = judge(make_envelope(), policy, provider=provider)
    assert decision.decision == "ask"
    assert decision.error is not None
    assert "provider failure" in decision.reasons[0]


def test_unexpected_provider_error_never_allows(policy):
    class Buggy(FakeProvider):
        def evaluate(self, state, questions):
            raise RuntimeError("bug in provider")

    decision = judge(make_envelope(), policy, provider=Buggy())
    assert decision.decision == "ask"
    assert decision.error is not None


def test_no_provider_abstains(policy):
    decision = judge(make_envelope(), policy, provider=None)
    assert decision.decision == "ask"
