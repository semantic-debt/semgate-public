from datetime import datetime, timezone
from semgate.capabilities import matches_capability

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
CAP = {"action":"write_file","target":{"repo":"semantic-debt/semgate","path":"README.md"},"scope":{"bytes_max":1000},"issued_by":"trusted_owner_channel","expires_at":"2026-09-18T13:00:00Z"}
PROPOSAL = {"action":"write_file","target":{"path":"README.md","repo":"semantic-debt/semgate"},"scope":{"bytes_max":1000}}

def test_exact_match(): assert matches_capability(PROPOSAL, CAP, now=NOW)
def test_wrong_target_rejected():
    p={**PROPOSAL,"target":{"repo":"semantic-debt/semgate","path":"pyproject.toml"}}
    assert not matches_capability(p,CAP,now=NOW)
def test_wildcard_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"target":"*"},now=NOW)
def test_expired_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"expires_at":"2026-09-18T11:00:00Z"},now=NOW)
def test_untrusted_provenance_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"issued_by":"dataset_label"},now=NOW)
