"""Replay determinism and metric sanity over the synthetic fixtures."""
from pathlib import Path

from semgate.replay import replay

TRACES = Path(__file__).resolve().parent.parent / "fixtures" / "traces"


def all_traces():
    return sorted(str(p) for p in TRACES.glob("*.json"))


def test_replay_is_deterministic(policy):
    first = replay(all_traces(), policy)
    second = replay(all_traces(), policy)
    assert first == second


def test_replay_labels_match(policy):
    report = replay(all_traces(), policy)
    misses = [t for t in report["per_trace"] if not t["match"]]
    assert misses == [], f"traces where decision != label: {misses}"


def test_replay_metrics_shape(policy):
    report = replay(all_traces(), policy)
    assert report["trace_count"] == len(all_traces())
    assert report["auto_allow"]["precision"] == 1.0
    assert report["auto_deny"]["precision"] == 1.0
    assert 0.0 <= report["abstention_rate"] <= 1.0
    assert report["disclaimer"]
    assert report["threshold_sweep"]


def test_replay_records_to_ledger(policy, tmp_path):
    from semgate.ledger import Ledger
    ledger = Ledger(str(tmp_path / "replay.jsonl"))
    replay(all_traces(), policy, ledger=ledger)
    assert len(ledger.judgments()) == len(all_traces())
