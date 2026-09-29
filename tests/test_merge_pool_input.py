"""product-foundation x concurrency-fixes: the serve worker pool keeps the
input checks (bounded lines, session id, payload evidence) and claude_hook
keeps fit_decision after the fail-closed host_response record."""
import io
import json
import sys
from pathlib import Path

import pytest

from semgate import filelock
from semgate import serve as serve_mod
from semgate.ledger import Ledger

ROOT = Path(__file__).parents[1]
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.05, "unneeded_change": 0.05}


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("SEMGATE_CONFIG", str(tmp_path / "no-such-config.json"))


def _config(tmp_path, **extra):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(ROOT / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(tmp_path / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False}}
    cfg.update(extra)
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(cfg))
    return str(path)


def _records(tmp_path, kind):
    return [r for r in filelock.read_jsonl(tmp_path / "ledger.jsonl").records if r.get("record_type") == kind]


def _serve(cfg, lines):
    out = io.StringIO()
    code = serve_mod.serve(cfg, stdin=io.StringIO("".join(l + "\n" for l in lines)), stdout=out)
    return code, {a["id"]: a for a in map(json.loads, out.getvalue().splitlines())}


def test_pool_records_payload_evidence_with_the_line_size(tmp_path):
    cfg = _config(tmp_path)
    line = json.dumps({"id": 1, "host": "opencode", "request": {"tool": "bash", "args": {"command": "git status"},
                                                                "sessionID": "s1", "callID": "c1", "cwd": str(tmp_path)}})
    code, answers = _serve(cfg, [line])
    assert code == 0 and answers[1]["decision"] in ("allow", "ask", "deny")
    [judgment] = _records(tmp_path, "judgment")
    payload = judgment["decision"]["evidence"]["payload"]
    assert payload["hook_payload_bytes"] == len(line.encode("utf-8")) + 1          # the line with its newline
    assert payload["tool_input_bytes"] > 0
    [resp] = _records(tmp_path, "host_response")
    assert resp["conversation_id"] == "s1" and resp["native"]["decision"] == answers[1]["decision"]


def test_pool_bad_session_denies_with_incident_and_no_state_key(tmp_path):
    cfg = _config(tmp_path)
    bad = "../" + "x" * 10
    lines = [json.dumps({"id": 1, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls"}, "sessionID": bad,
                                                                  "callID": "c1"}}),
             json.dumps({"id": 2, "host": "opencode", "event": "after", "request": {"sessionID": bad, "callID": "c1"}})]
    code, answers = _serve(cfg, lines)
    assert answers[1]["decision"] == "deny" and "session id" in answers[1]["reason"]     # OpenCode has no ask
    assert answers[2] == {"id": 2, "recorded": True}
    assert [i["detail"]["reason"] for i in _records(tmp_path, "incident")] == ["invalid_session_id"]
    [resp] = _records(tmp_path, "host_response")
    assert resp["conversation_id"] == "" and resp["native"]["decision"] == "deny"     # the bad id is not stored
    assert _records(tmp_path, "judgment") == []                                           # never judged


def test_pool_oversize_line_denies_with_id_incident_and_host_response(tmp_path):
    cfg = _config(tmp_path, hook_max_payload_bytes=2048)
    big = json.dumps({"id": 7, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls", "pad": "z" * 5000},
                                                               "sessionID": "s1"}})
    small = json.dumps({"id": 8, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls"}, "sessionID": "s1",
                                                                 "callID": "c8", "cwd": str(tmp_path)}})
    code, answers = _serve(cfg, [big, small])
    assert answers[7]["decision"] == "deny" and "hook_max_payload_bytes" in answers[7]["reason"]
    assert 8 in answers                                                                  # the next line is still served
    [incident] = _records(tmp_path, "incident")
    assert incident["detail"]["reason"] == "payload_over_limit" and incident["detail"]["bytes"] > 2048
    over = [r for r in _records(tmp_path, "host_response") if "hook_max_payload_bytes" in r["native"]["reason"]]
    assert len(over) == 1 and over[0]["native"]["decision"] == "deny" and over[0]["conversation_id"] == ""


def test_claude_hook_fits_a_lock_timeout_ask_to_the_host(tmp_path, monkeypatch, capsys):
    """record_host_response turns an allow into force_ask on a ledger lock
    timeout; a host without an ask prompt must then get a deny."""
    from semgate import claude_hook
    cfg = _config(tmp_path)
    ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"},
          "session_id": "s1", "tool_use_id": "t1", "cwd": str(tmp_path)}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(ev).encode())))
    monkeypatch.setattr(claude_hook, "run", lambda *a, **k: {"decision": "allow", "reason": "ok"})
    monkeypatch.setattr(claude_hook, "record_host_response",
                        lambda event, config, result, meta: {"decision": "force_ask", "reason": "store lock timeout"})
    seen = []

    def fit(host, decision, reason):
        seen.append(decision)
        return ("deny", "no ask: " + reason) if decision == "ask" else (decision, reason)
    monkeypatch.setattr(claude_hook, "fit_decision", fit)
    assert claude_hook.main(["--config", cfg, "--host", "claude"]) == 0
    out = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "store lock timeout" in out["permissionDecisionReason"]
    assert seen == ["allow", "ask"]                        # before the record, and again after it


def test_judge_keeps_payload_evidence_when_the_ledger_lock_times_out(tmp_path, monkeypatch):
    from conftest import make_envelope
    from semgate.judge import judge
    from semgate.policy import Policy
    from semgate.providers.fake import FakeProvider
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", "0.2")
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    policy = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    env = make_envelope("bash", {"command": "git status"})
    payload = {"hook_payload_bytes": 10, "tool_input_bytes": 5, "model": "", "max_output_tokens": None,
               "expected_max_bytes": None, "anomaly": False}

    def boom(*a, **k):
        raise filelock.LockTimeout("held")
    monkeypatch.setattr(led, "record_judgment", boom)
    d = judge(env, policy, provider=FakeProvider(ALLOWING), ledger=led, payload=payload)
    assert (d.decision, d.stage, d.reason_code) == ("ask", "store_unavailable", "store_lock_timeout")
    assert d.evidence.get("payload") == payload
