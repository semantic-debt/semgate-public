"""`semgate report --calibration` on synthetic ledgers: joins semantic asks
with human answers (ledger outcomes, feedback store, history store), splits
by time (older half tune, newer half validate) and suggests threshold ranges.
Read-only: it never writes a policy or any file."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from semgate import calibration
from semgate.cli import main
from semgate.feedback import FeedbackStore, _key

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _ts(i):
    return (T0 + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")


def judgment(i, user_asked, effect=1.0, decision="ask", stage="semantic", command=None):
    votes = [
        {"predicate": "route", "vote": "uncertain", "value": "review", "confidence": 0.8,
         "probabilities": {"run": round(user_asked * 0.5, 3), "review": 0.5, "block": 0.02}},
        {"predicate": "effect", "vote": "uncertain", "value": effect, "confidence": 0.9, "probabilities": {}},
        {"predicate": "user_asked", "vote": "clear", "p": user_asked},
        {"predicate": "session_drift", "vote": "clear", "mean": 0.8, "n": 5},
    ]
    return {"record_type": "judgment", "judgment_id": f"j{i}", "ts": _ts(i),
            "decision": {"decision": decision, "stage": stage, "reason_code": "uncertain_fit_review", "predicate_votes": votes},
            "envelope": {"action": {"tool": "bash", "arguments": {"command": command or f"make target{i}"}},
                         "environment": {"session_id": "s"}}}


def write(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def synthetic(tmp_path, n=40):
    """user_asked p spread over [0, 1] in a shuffled order; the human approved
    exactly the asks with p >= 0.6, except two low-p asks (label noise)."""
    records = []
    for i in range(n):
        p = round(((i * 17) % n) / n + 0.0125, 4)
        approved = (p >= 0.6) != (i in (3, 30))
        records.append(judgment(i, p))
        records.append({"record_type": "outcome", "judgment_id": f"j{i}", "outcome": "approved" if approved else "rejected",
                        "ts": _ts(i)})
    ledger = tmp_path / "ledger.jsonl"
    write(ledger, records)
    return ledger


def test_split_direction_auc_and_suggestion(tmp_path):
    rep = calibration.build(str(synthetic(tmp_path)), target=0.9, min_n=5)
    assert rep["samples"] == 40 and rep["tune"] == 20 and rep["validate"] == 20
    assert rep["sources"] == {"outcome": 40}
    q = rep["questions"]["user_asked"]
    assert q["direction"] == "higher_means_approved" and q["auc_tune"] > 0.85 and q["auc_validate"] > 0.85
    s = q["suggestion"]
    assert s["status"] == "ok" and s["side"] == "value >= cut"
    assert 0.4 <= s["cut"] <= 0.75 and s["cut_range_tune"][0] == s["cut"]
    assert s["tune_approval"] >= 0.9 and s["validate_n"] > 0
    assert sum(b["tune_n"] for b in q["bins"]) == 20 and sum(b["validate_n"] for b in q["bins"]) == 20
    assert {"route.run", "route.review", "route.block", "effect", "session_drift"} <= set(rep["questions"])
    assert [b["range"] for b in rep["questions"]["effect"]["bins"]] == [[1.0, 1.5]]   # score questions: 0.5-wide bins, empty bins left out


def test_time_split_uses_the_timestamp_not_the_file_order(tmp_path):
    ledger = synthetic(tmp_path)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    samples = calibration.collect(str(ledger))
    assert [s["judgment_id"] for s in samples] == [f"j{i}" for i in range(40)]


def test_only_answered_semantic_asks_count(tmp_path):
    records = [judgment(0, 0.9), judgment(1, 0.9, decision="allow"), judgment(2, 0.9, stage="human_gate"), judgment(3, 0.9),
               {"record_type": "outcome", "judgment_id": "j0", "outcome": "approved"},
               {"record_type": "outcome", "judgment_id": "j1", "outcome": "approved"},
               {"record_type": "outcome", "judgment_id": "j2", "outcome": "approved"},
               {"record_type": "outcome", "judgment_id": "j3", "outcome": "something else"}]
    write(tmp_path / "l.jsonl", records)
    assert [s["judgment_id"] for s in calibration.collect(str(tmp_path / "l.jsonl"))] == ["j0"]


def test_feedback_and_history_answers(tmp_path):
    write(tmp_path / "l.jsonl", [judgment(0, 0.9, command="make a"), judgment(1, 0.2, command="make b"),
                                 judgment(2, 0.8), judgment(3, 0.1), judgment(4, 0.5)])
    store = FeedbackStore(str(tmp_path / "fb.jsonl"))
    store.record("allow", "bash", {"command": "make a"}, session_id="s", project_root=str(tmp_path))
    store.record("deny", "bash", {"command": "make b"})
    history = [
        {"record_type": "pending", "conversation_id": "c", "step_idx": 1, "decision": "ask", "judgment_id": "j2"},
        {"record_type": "executed", "conversation_id": "c", "step_idx": 1, "judgment_id": "j2", "error": ""},
        {"record_type": "pending", "conversation_id": "c", "step_idx": 2, "decision": "ask", "judgment_id": "j3"},
        {"record_type": "pending", "conversation_id": "c", "step_idx": 3, "decision": "allow", "judgment_id": "jx"},
        {"record_type": "pending", "conversation_id": "c", "step_idx": 4, "decision": "ask", "judgment_id": "j4"},  # last step: unknown
    ]
    write(tmp_path / "h.jsonl", history)
    samples = {s["judgment_id"]: (s["approved"], s["source"])
               for s in calibration.collect(str(tmp_path / "l.jsonl"), str(tmp_path / "h.jsonl"), str(tmp_path / "fb.jsonl"))}
    # feedback written now is later than the 2026-09-01 judgments, so it applies
    assert samples == {"j0": (True, "feedback"), "j1": (False, "feedback"), "j2": (True, "history"), "j3": (False, "history")}
    assert _key("bash", {"command": "make a"}) != _key("bash", {"command": "make b"})


def test_outcome_beats_feedback_and_the_newest_outcome_wins(tmp_path):
    write(tmp_path / "l.jsonl", [judgment(0, 0.9, command="make a"),
                                 {"record_type": "outcome", "judgment_id": "j0", "outcome": "approved"},
                                 {"record_type": "override", "judgment_id": "j0", "verdict": "deny"}])
    FeedbackStore(str(tmp_path / "fb.jsonl")).record("allow", "bash", {"command": "make a"}, session_id="s", project_root=str(tmp_path))
    [s] = calibration.collect(str(tmp_path / "l.jsonl"), feedback_path=str(tmp_path / "fb.jsonl"))
    assert (s["approved"], s["source"]) == (False, "override")


def test_too_little_data_says_so(tmp_path):
    write(tmp_path / "l.jsonl", [judgment(0, 0.9), {"record_type": "outcome", "judgment_id": "j0", "outcome": "approved"},
                                 judgment(1, 0.1), {"record_type": "outcome", "judgment_id": "j1", "outcome": "rejected"}])
    rep = calibration.build(str(tmp_path / "l.jsonl"))
    assert rep["questions"]["user_asked"]["suggestion"]["status"] != "ok"
    empty = calibration.build(str(tmp_path / "missing.jsonl"))
    assert empty["samples"] == 0 and "no answered asks yet" in calibration.render(empty)


def test_auc():
    assert calibration.auc([(0.9, True), (0.1, False)]) == 1.0
    assert calibration.auc([(0.1, True), (0.9, False)]) == 0.0
    assert calibration.auc([(0.5, True), (0.5, False)]) == 0.5
    assert calibration.auc([(0.5, True)]) is None


def test_cli_is_read_only_and_prints(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    ledger = synthetic(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    policy_before = (tmp_path / "ledger.jsonl").read_bytes()
    assert main(["report", "--ledger", str(ledger), "--calibration"]) == 0
    out = capsys.readouterr().out
    assert "Calibration: 40 answered asks" in out and "user_asked:" in out and "suggested: value >= cut" in out
    assert "report only: no policy is written" in out
    assert main(["report", "--ledger", str(ledger), "--calibration", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["samples"] == 40
    assert sorted(p.name for p in tmp_path.iterdir()) == before and (tmp_path / "ledger.jsonl").read_bytes() == policy_before
