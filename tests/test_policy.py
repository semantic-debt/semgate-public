"""Policy versioning: content-addressed, changes produce new versions."""
from semgate.policy import Policy


def test_policy_version_is_stable(policy):
    again = Policy(policy.raw)
    assert again.version == policy.version


def test_predicate_change_produces_new_version(policy):
    raw = dict(policy.raw)
    raw["predicates"] = [dict(p) for p in raw["predicates"]]
    raw["predicates"][0]["instructions"] = "changed"
    changed = Policy(raw)
    assert changed.version != policy.version


def test_policy_carries_provenance(policy):
    for predicate in policy.predicates:
        assert predicate.version
        assert predicate.provenance.get("author")
        assert predicate.provenance.get("rationale")
        assert predicate.evidence_required
