"""Durable judgment, override and outcome records."""
from semgate.judge import judge
from semgate.ledger import Ledger
from semgate.providers.fake import FakeProvider

from conftest import make_envelope

CLEAR = {
    "outside_grant_purpose": 0.02,
    "outside_project_boundary": 0.01,
    "creates_external_commitment": 0.01,
    "irreversible_at_unacceptable_cost": 0.02,
    "trajectory_diverged": 0.05,
}


def test_judgment_recorded_with_policy_version(policy, tmp_path):
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=CLEAR), ledger=ledger)
    records = ledger.judgments()
    assert len(records) == 1
    record = records[0]
    assert record["record_type"] == "judgment"
    assert record["decision"]["decision"] == "allow"
    assert record["decision"]["policy_version"] == policy.version
    assert record["decision"]["envelope_digest"] == decision.envelope_digest
    assert record["envelope"]["action"]["tool"] == "edit"


def test_override_and_outcome_roundtrip(policy, tmp_path):
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    decision = judge(make_envelope(), policy, provider=FakeProvider(script=CLEAR), ledger=ledger)
    ledger.record_override(decision.envelope_digest, reviewer="me", verdict="should_have_asked", note="edit was broader than it looked")
    ledger.record_outcome(decision.envelope_digest, outcome="reverted", detail="broke staging")

    overrides = ledger.overrides()
    outcomes = ledger.outcomes()
    assert overrides[0]["judgment_id"] == decision.envelope_digest
    assert overrides[0]["verdict"] == "should_have_asked"
    assert outcomes[0]["outcome"] == "reverted"


def test_ledger_is_append_only_jsonl(policy, tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(str(path))
    judge(make_envelope(), policy, provider=FakeProvider(script=CLEAR), ledger=ledger)
    judge(make_envelope(tool="read", arguments={"path": "/home/me/proj/a.py"}), policy, provider=FakeProvider(script={}), ledger=ledger)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    import json
    assert all(json.loads(line)["record_type"] == "judgment" for line in lines)
