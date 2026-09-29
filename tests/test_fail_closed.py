"""Fail closed (owner decision 2026-09-29): a missing, unreadable or
incomplete config is never an ask a host runs unattended. A host that
cannot show an ask (hosts.host_shows_ask False: agy, Codex, Droid, OpenCode,
Pi, Copilot CLI, VS Code, Devin CLI) gets a deny that says what to do;
Claude Code and the HTTP gate keep the ask (semgate/enforcement.py)."""
import io
import json
from pathlib import Path

import pytest

from semgate import antigravity_hook, claude_hook, enforcement, harness, serve
from semgate.hosts import host_shows_ask

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"


def _grant(tmp_path):
    g = tmp_path / "grant.json"
    g.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                             "expires_at": "2099-01-01T00:00:00Z", "allowed_path_prefixes": ["/workspace/project"]}))
    return str(g)


def _agy_event(command="rm -rf /"):
    return {"toolCall": {"name": "run_command", "args": {"CommandLine": command}}, "workspacePaths": ["/workspace/project"],
            "conversationId": "c1", "stepIdx": 1}


# ------------------------------------------------------------------ B. fail closed per host


def _agy_main(tmp_path, monkeypatch, capsys, config_path):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_agy_event("frobnicate --all"))))
    assert antigravity_hook.main(["--config", str(config_path)]) == 0
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("what", ["missing", "not json", "no mode, no enforcement", "enabled false", "unknown mode"])
def test_agy_broken_config_is_a_deny_with_what_to_do(tmp_path, monkeypatch, capsys, what):
    path = tmp_path / "semgate.json"
    good = {"mode": "enforce", "grant_file": _grant(tmp_path), "policy_file": str(DEV), "provider": "none",
            "ledger_file": str(tmp_path / "ledger.jsonl"), "enforcement": {"enabled": True}}
    if what == "not json":
        path.write_text("{ not json", encoding="utf-8")
    elif what == "no mode, no enforcement":
        path.write_text(json.dumps({k: v for k, v in good.items() if k not in ("mode", "enforcement")}), encoding="utf-8")
    elif what == "enabled false":
        path.write_text(json.dumps(dict(good, enforcement={"enabled": False})), encoding="utf-8")
    elif what == "unknown mode":
        path.write_text(json.dumps(dict(good, mode="block")), encoding="utf-8")
    out = _agy_main(tmp_path, monkeypatch, capsys, path)
    assert out["decision"] == "deny", what
    assert "semgate could not check this call" in out["reason"] and "doctor" in out["reason"]
    assert "Do not try to bypass" in out["reason"]
    assert "\u2014" not in out["reason"] and "\u2013" not in out["reason"]


def _claude_main(monkeypatch, capsys, config_path, host):
    event = {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "frobnicate --all"}, "cwd": "/p",
             "hook_event_name": "PreToolUse", "tool_use_id": "t1"}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    assert claude_hook.main(["--config", str(config_path), "--host", host]) == 0
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("host", ["codex", "droid", "copilot", "vscode", "devin"])
def test_claude_family_hosts_that_cannot_ask_get_a_deny_for_a_missing_config(tmp_path, monkeypatch, capsys, host):
    assert host_shows_ask(host) is False
    out = _claude_main(monkeypatch, capsys, tmp_path / "missing" / "semgate.json", host)
    if host == "devin":
        assert out["decision"] == "block" and "semgate could not check this call" in out["reason"]
    elif host == "copilot":
        assert out["permissionDecision"] == "deny" and "doctor" in out["permissionDecisionReason"]
    else:
        inner = out["hookSpecificOutput"]
        assert inner["permissionDecision"] == "deny" and "doctor" in inner["permissionDecisionReason"]


def test_claude_code_shows_the_ask_for_a_missing_or_incomplete_config(tmp_path, monkeypatch, capsys):
    assert host_shows_ask("claude") is True
    out = _claude_main(monkeypatch, capsys, tmp_path / "missing.json", "claude")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "semgate hook failure" in out["permissionDecisionReason"]
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps({"grant_file": _grant(tmp_path), "policy_file": str(DEV), "provider": "none",
                                "ledger_file": str(tmp_path / "ledger.jsonl")}), encoding="utf-8")
    out = _claude_main(monkeypatch, capsys, path, "claude")["hookSpecificOutput"]
    assert out["permissionDecision"] == "ask" and "not explicitly enabled" in out["permissionDecisionReason"]
    out = _claude_main(monkeypatch, capsys, path, "codex")["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "not explicitly enabled" in out["permissionDecisionReason"]


def _serve_cfg(tmp_path, **extra):
    cfg = {"grant_file": _grant(tmp_path), "policy_file": str(DEV), "provider": "none",
           "ledger_file": str(tmp_path / "ledger.jsonl")}
    cfg.update(extra)
    return cfg


@pytest.mark.parametrize("host", ["opencode", "pi"])
def test_opencode_and_pi_get_a_deny_for_an_incomplete_or_unreadable_config(tmp_path, host):
    req = {"tool": "bash", "args": {"command": "frobnicate --all"}, "sessionID": "ses1", "callID": "c1", "cwd": "/p",
           "messages": [], "entries": []}
    out = serve.judge_request(host, req, _serve_cfg(tmp_path))                       # no mode, no enforcement
    assert out["decision"] == "deny" and "not explicitly enabled" in out["reason"] and "doctor" in out["reason"]
    # a config serve cannot read: the answer line is a deny too
    lines = io.StringIO()
    missing = tmp_path / "nope" / "semgate.json"
    serve.serve(str(missing), stdin=io.StringIO(json.dumps({"id": 1, "host": host, "request": req}) + "\n"),
                stdout=lines, settings=(1, 20000, 1500), reload=(0.0, 0.0))
    answer = json.loads(lines.getvalue().splitlines()[0])
    assert answer["id"] == 1 and answer["decision"] == "deny" and "semgate could not check this call" in answer["reason"]


def test_http_gate_keeps_the_ask_for_an_incomplete_config(tmp_path):
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(_serve_cfg(tmp_path)), encoding="utf-8")
    d = harness.check({"tool": "bash", "arguments": {"command": "frobnicate --all"}, "session_id": "run-1",
                       "cwd": "/workspace/project", "user_messages": ["do the task"]}, config=str(path))
    assert d["decision"] == "ask" and "not explicitly enabled" in d["reason"]


def test_fail_closed_rule_per_host():
    for host in ("antigravity", "codex", "droid", "opencode-v1", "opencode-v2", "pi", "copilot", "vscode", "devin", "x"):
        assert enforcement.fail_closed("p", host)["decision"] == "deny", host
    assert enforcement.fail_closed("p", "claude")["decision"] == "ask"
    assert enforcement.fail_closed("p", None)["decision"] == "ask"
    long = enforcement.fail_closed("x" * 5000, "antigravity")["reason"]
    assert len(long) <= 1000 and long.endswith("Do not try to bypass, rename, or disable the gate.")
