"""semgate report: reason codes, answers to asks, regex gaps, what-if replay; and
outcome recording that never turns on learning."""
import json
from pathlib import Path

from semgate.antigravity_hook import history_path, run
from semgate.history import ToolHistory
from semgate.report import build, render

DEV = str(Path(__file__).parents[1] / "policies" / "router_policy_dev.json")


def _config(tmp_path, answers, **extra):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "m", "purpose": "dev", "expires_at": "2099-01-01T00:00:00Z"}))
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": DEV, "provider": "fake", "fake_answers": answers,
           "ledger_file": str(tmp_path / "ledger.jsonl"),
           "auto_allow_learned": {"enabled": False, "history_file": str(tmp_path / "history.jsonl")},
           "enforcement": {"enabled": True, "auto_allow_tools": ["bash"], "block_when_unsure": False}}
    cfg.update(extra)
    return cfg


ASKING = {"route": {"value": "review", "confidence": 0.8}, "effect": {"value": 2.0, "confidence": 0.9}, "user_asked": 0.5,
          "on_task": 0.9, "executes": {"value": 0.0, "confidence": 1.0}, "leaks_secrets": 0.9,
          "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}


def test_record_outcomes_records_without_learning(tmp_path):
    assert history_path(_config(tmp_path, ASKING)) == ""
    cfg = _config(tmp_path, ASKING, record_outcomes=True)
    assert history_path(cfg).endswith("history.jsonl")
    event = {"toolCall": {"name": "run_command", "args": {"CommandLine": "pip install requests"}}, "conversationId": "c", "stepIdx": 1}
    for step in (1, 2, 3):
        event["stepIdx"] = step
        assert run(event, cfg)["decision"] == "force_ask"
        ToolHistory(str(tmp_path / "history.jsonl")).record_executed("c", step)   # the human approved each time
    event["stepIdx"] = 4
    assert run(event, cfg)["decision"] == "force_ask"   # 3 approvals, still asks: learning stays off


def test_report_sections(tmp_path):
    cfg = _config(tmp_path, ASKING, record_outcomes=True)
    from semgate.antigravity_hook import record_host_response
    for step, approve in ((1, True), (2, False)):
        event = {"toolCall": {"name": "run_command", "args": {"CommandLine": f"pip install pkg{step}"}}, "conversationId": "c", "stepIdx": step}
        result = run(event, cfg)
        record_host_response(event, cfg, result, {})
        if approve:
            ToolHistory(str(tmp_path / "history.jsonl")).record_executed("c", step)
    rep = build(str(tmp_path / "ledger.jsonl"), str(tmp_path / "history.jsonl"), DEV, {"always_review_effect_min": 1.5})
    assert rep["judgments"] == 2 and rep["outcomes_recorded"]
    assert list(rep["asks_answered"].values())[0] == {"approved (ran)": 1, "not run": 1}
    assert len(rep["regex_gaps"]) == 2 and rep["regex_gaps"][0]["question"] == "leaks_secrets"
    assert rep["what_if"]["replayed"] == 2
    text = render(rep)
    assert "approved 1/2 (50%)" in text and "Possible regex gaps" in text and "What if" in text


def test_what_if_detects_changes(tmp_path):
    edit = {**ASKING, "route": {"value": "run", "confidence": 1.0}, "effect": {"value": 1.4, "confidence": 1.0}, "user_asked": 0.9}
    cfg = _config(tmp_path, edit)
    run({"toolCall": {"name": "run_command", "args": {"CommandLine": "echo x > notes.md"}}, "conversationId": "c", "stepIdx": 1}, cfg)
    rep = build(str(tmp_path / "ledger.jsonl"), "", DEV, {"allow_edit_effect_max": 1.0})
    assert rep["what_if"]["changed"] and rep["what_if"]["changed"][0]["before"] == "allow" and rep["what_if"]["changed"][0]["after"] == "ask"
