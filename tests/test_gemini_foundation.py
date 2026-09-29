"""Offline unit/contract tests; no proposed shell commands are executed."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import sys

import pytest

from semgate.action_identity import canonical_json, request_identity
from semgate import gemini_gate as gate


def identity_input():
    return {"tool": "run_shell_command", "arguments": {"command": "pytest -q"},
            "context": {"harness": "gemini-cli", "harness_version": "v0.60.0",
                        "session_id": "session-a", "cwd": "/work/a", "project_root": "/work",
                        "shell": "bash"},
            "grant": {"grant_id": "grant-a", "purpose": "test", "expires_at": "2026-09-22T02:00:00Z"},
            "policy_version": "sha-policy-a", "provider": "typesafe:pinned-model"}


@pytest.mark.parametrize("first,second", [
    ("printf 'A'", "printf 'a'"),
    ("git status -s", "git status -S"),
    ("printf 'a b'", "printf 'a  b'"),
    ("pytest -q", "pytest -x"),
    ("pytest -q", " pytest -q"),
    ("printf '\u00e9'", "printf 'e\u0301'"),
    ("Write-Output 'a'", "Write-Output 'a'\n"),
    ("echo A\techo B", "echo A echo B"),
])
def test_command_content_never_normalized(first, second):
    a = identity_input(); b = deepcopy(a)
    a["arguments"]["command"] = first; b["arguments"]["command"] = second
    assert request_identity(**a) != request_identity(**b)


@pytest.mark.parametrize("field", ["harness", "harness_version", "session_id", "cwd", "project_root", "shell"])
def test_context_changes_identity(field):
    a = identity_input(); b = deepcopy(a); b["context"][field] += "-changed"
    assert request_identity(**a) != request_identity(**b)


@pytest.mark.parametrize("field", ["grant_id", "purpose", "expires_at"])
def test_grant_changes_identity(field):
    a = identity_input(); b = deepcopy(a); b["grant"][field] += "-changed"
    assert request_identity(**a) != request_identity(**b)


@pytest.mark.parametrize("field", ["tool", "policy_version", "provider"])
def test_policy_provider_and_tool_changes_identity(field):
    a = identity_input(); b = deepcopy(a); b[field] += "-changed"
    assert request_identity(**a) != request_identity(**b)


def test_non_shell_arguments_do_not_collapse_to_empty_command():
    a = identity_input(); a["tool"] = "write"
    a["arguments"] = {"path": "a.txt", "content": "ABC"}
    b = deepcopy(a); b["arguments"]["path"] = "b.txt"
    c = deepcopy(a); c["arguments"]["content"] = "abc"
    assert len({request_identity(**x) for x in (a, b, c)}) == 3


def test_only_object_key_order_is_normalized():
    assert canonical_json({"z": " A  B ", "a": [1, 2]}) == canonical_json({"a": [1, 2], "z": " A  B "})
    assert canonical_json([1, 2]) != canonical_json([2, 1])
    assert canonical_json(True) != canonical_json(1)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "x"}, object(), (1, 2), "\ud800"])
def test_non_json_or_invalid_unicode_rejected(value):
    with pytest.raises((ValueError, UnicodeError)):
        canonical_json(value)


@pytest.mark.parametrize("field", ["harness", "session_id", "cwd", "shell"])
def test_missing_identity_context_rejected(field):
    data = identity_input(); del data["context"][field]
    with pytest.raises(ValueError):
        request_identity(**data)


@pytest.mark.parametrize("text", ["", "[]", "null", "1", '{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"x":{"k":1,"k":2}}'])
def test_bad_json_rejected(text):
    with pytest.raises(ValueError):
        gate.parse_object(text)


def test_oversized_and_deep_input_rejected():
    with pytest.raises(ValueError):
        gate.parse_object(json.dumps({"x": "x" * gate.MAX_INPUT}))
    with pytest.raises(ValueError):
        gate.parse_object('{"x":' * 40 + '0' + '}' * 40)


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "workspace with \u00f1"; root.mkdir()
    trusted = tmp_path / "trusted"; trusted.mkdir()
    grant = {"grant_id": "g1", "principal": "operator", "purpose": "run project tests",
             "allowed_tools": ["bash"], "allowed_path_prefixes": [str(root)],
             "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
             "provenance": "operator-config"}
    gp = trusted / "grant.json"; gp.write_text(json.dumps(grant), encoding="utf-8")
    pp = trusted / "policy.json"; pp.write_text("{}", encoding="utf-8")
    config = {"schema": gate.CONFIG_SCHEMA, "project_root": str(root),
              "grant_file": str(gp), "policy_file": str(pp), "shell": "powershell",
              "harness_version": "v0.60.0", "provider": "none", "confirmation_probe": True}
    cp = trusted / "config.json"; cp.write_text(json.dumps(config), encoding="utf-8")
    event = {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
             "session_id": "s1", "cwd": str(root),
             "tool_input": {"command": "Write-Output 'Semgate  A'"}}
    return cp, config, event, grant


def test_valid_request_preserves_command_and_ignores_agent_grant(setup):
    cp, _, event, grant = setup
    event["grant"] = {"allowed_tools": ["*"]}
    event["provider"] = "fake"; event["feedback"] = {"decision": "allow"}
    request = gate.prepare_request(event, gate.load_config(str(cp)))
    assert request["arguments"] == event["tool_input"]
    assert request["grant"] == grant
    assert request["provider"] == "none"


@pytest.mark.parametrize("key,value", [
    ("hook_event_name", "AfterTool"), ("tool_name", "write_file"), ("tool_name", "mcp_unverified"),
    ("tool_input", []), ("tool_input", {"command": ""}), ("tool_input", {"command": 1}),
    ("tool_input", {"command": "x\x00y"}), ("tool_input", {"command": "x", "dir_path": "elsewhere"}),
    ("tool_input", {"command": "x", "is_background": True}),
    ("tool_input", {"command": "x", "is_background": 0}),
    ("tool_input", {"command": "x", "additional_permissions": {"network": True}}),
    ("tool_input", {"command": "x", "description": {"a": 1}}),
    ("session_id", ""), ("cwd", "relative/path"),
])
def test_invalid_or_unverified_events_rejected(setup, key, value):
    cp, _, event, _ = setup; event[key] = value
    with pytest.raises((ValueError, FileNotFoundError)):
        gate.prepare_request(event, gate.load_config(str(cp)))


def test_cwd_outside_workspace_rejected(setup):
    cp, _, event, _ = setup; event["cwd"] = str(cp.parent)
    with pytest.raises(ValueError):
        gate.prepare_request(event, gate.load_config(str(cp)))


@pytest.mark.parametrize("key,value", [
    ("expires_at", "bad"), ("expires_at", "2099-01-01T00:00:00Z"),
    ("expires_at", "2000-01-01T00:00:00Z"), ("expires_at", "2026-09-22T12:00:00"),
    ("expires_at", None), ("allowed_tools", ["*"]), ("allowed_tools", "bash"),
    ("allowed_path_prefixes", []), ("purpose", ""), ("principal", ""),
])
def test_grant_validation_fails_closed(setup, key, value):
    cp, config, event, grant = setup; grant[key] = value
    Path(config["grant_file"]).write_text(json.dumps(grant), encoding="utf-8")
    with pytest.raises(ValueError):
        gate.prepare_request(event, gate.load_config(str(cp)))


@pytest.mark.parametrize("key,value", [
    ("schema", "old"), ("provider", "fake"), ("provider", "attacker.Provider"),
    ("shell", "unknown"), ("deadline_seconds", True), ("deadline_seconds", 0),
    ("deadline_seconds", 31), ("confirmation_probe", "true"), ("feedback", {"enabled": True}),
])
def test_invalid_config_rejected(setup, key, value):
    cp, config, _, _ = setup; config[key] = value
    cp.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError): gate.load_config(str(cp))


def test_probe_disabled_by_default(setup):
    cp, config, _, _ = setup; config.pop("confirmation_probe")
    cp.write_text(json.dumps(config), encoding="utf-8")
    assert gate.load_config(str(cp))["confirmation_probe"] is False


def test_workspace_local_config_rejected(setup):
    _, config, _, _ = setup
    local = Path(config["project_root"]) / "config.json"
    local.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError): gate.load_config(str(local))


def result(decision="ask", stage="semantic", **kwargs):
    return {"schema": gate.WORKER_SCHEMA, "decision": decision, "stage": stage,
            "reasons": ["needs review"], "failed": False, "missing_evidence": False,
            "request_identity": request_identity(**identity_input()), **kwargs}


@pytest.mark.parametrize("decision,stage", [
    ("allow", "semantic"), ("ask", "semantic"), ("deny", "semantic"),
    ("ask", "human_gate"), ("allow", "hard_rules"),
])
def test_reviewable_results_always_ask_never_auto_allow(decision, stage):
    assert gate.map_result(result(decision, stage), True)["decision"] == "ask"
    assert gate.map_result(result(decision, stage), False)["decision"] == "deny"


@pytest.mark.parametrize("data", [
    result("deny", "hard_rules"), result("ask", "grant_validity"),
    result(failed=True), result(missing_evidence=True),
])
def test_failure_expiry_and_hard_deny_never_approvable(data):
    assert gate.map_result(data, True)["decision"] == "deny"


@pytest.mark.parametrize("key,value", [
    ("stage", "human_approved"), ("stage", "auto_allow"), ("stage", "unknown"),
    ("decision", "ALLOW"), ("schema", "old"), ("request_identity", "legacy-key"),
    ("failed", "false"), ("missing_evidence", 0), ("reasons", "not-a-list"),
])
def test_legacy_or_malformed_worker_result_rejected(key, value):
    data = result(); data[key] = value
    with pytest.raises(ValueError): gate.map_result(data, True)


def test_terminal_control_characters_not_rendered():
    mapped = gate.map_result(result(reasons=["\x1b[2Jhide\u202eTEXT"]), True)
    assert "\x1b" not in mapped["systemMessage"] and "\u202e" not in mapped["systemMessage"]


def invoke(monkeypatch, capsys, cp, event):
    monkeypatch.setattr(sys, "stdin", io.StringIO(event if isinstance(event, str) else json.dumps(event)))
    code = gate.main(["--config", str(cp)])
    output = capsys.readouterr()
    return code, json.loads(output.out), output.err


def test_main_deadline_failure_is_block_not_warning(setup, monkeypatch, capsys):
    cp, _, event, _ = setup
    def timeout(*args, **kwargs): raise subprocess.TimeoutExpired("judge", 0.1)
    monkeypatch.setattr(gate, "run_worker", timeout)
    code, response, err = invoke(monkeypatch, capsys, cp, event)
    assert code == 2 and response["decision"] == "deny" and "blocked" in err


def test_worker_uses_fixed_argv_json_stdin_and_no_shell(monkeypatch):
    request = {"arguments": {"command": "NEVER EXECUTE THIS; & $(payload)"}}
    def run(argv, **kwargs):
        # Isolated interpreter, fixed invocation; the command never reaches argv
        # (it is delivered on stdin), and no shell is used.
        assert argv[0] == sys.executable and "-I" in argv
        assert all(request["arguments"]["command"] not in part for part in argv)
        assert kwargs["shell"] is False and kwargs["timeout"] == 1.5
        assert json.loads(kwargs["input"]) == request
        return subprocess.CompletedProcess(argv, 0, json.dumps(result()), "")
    monkeypatch.setattr(subprocess, "run", run)
    assert gate.run_worker(request, 1.5)["decision"] == "ask"


@pytest.mark.parametrize("returncode,stdout", [(1, "{}"), (0, "not JSON"), (0, "x" * (gate.MAX_OUTPUT + 1)), (0, "{}\nnoise")])
def test_worker_failure_or_pollution_rejected(monkeypatch, returncode, stdout):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, returncode, stdout, ""))
    with pytest.raises(ValueError): gate.run_worker({}, 1)


def test_main_valid_json_only_and_no_permission_persistence(setup, monkeypatch, capsys):
    cp, _, event, _ = setup
    monkeypatch.setattr(gate, "run_worker", lambda *a: result("allow"))
    before = set(cp.parent.iterdir())
    code, response, _ = invoke(monkeypatch, capsys, cp, event)
    assert code == 0 and response["decision"] == "ask"
    assert set(cp.parent.iterdir()) == before


def test_expiry_rechecked_after_worker(setup, monkeypatch, capsys):
    cp, _, event, _ = setup
    original = gate._expiry; calls = []
    def expiry(value, now=None):
        calls.append(value)
        if len(calls) == 2: raise ValueError("expired while waiting")
        return original(value, now)
    monkeypatch.setattr(gate, "_expiry", expiry)
    monkeypatch.setattr(gate, "run_worker", lambda *a: result("allow"))
    code, response, _ = invoke(monkeypatch, capsys, cp, event)
    assert code == 2 and response["decision"] == "deny"


@pytest.mark.parametrize("text", ["[]", "not-json", '{"tool_name":"a","tool_name":"b"}'])
def test_main_malformed_input_emits_denial(setup, monkeypatch, capsys, text):
    cp, _, _, _ = setup
    code, response, _ = invoke(monkeypatch, capsys, cp, text)
    assert code == 2 and response["decision"] == "deny"


def test_command_is_data_not_executed(tmp_path):
    sentinel = tmp_path / "must-not-exist"
    payload = {"command": "touch " + str(sentinel)}
    completed = subprocess.run([sys.executable, "-m", "semgate.gemini_gate", "--worker"],
                               input=json.dumps(payload), capture_output=True, text=True)
    assert completed.returncode == 2
    assert json.loads(completed.stdout)["decision"] == "deny"
    assert not sentinel.exists()


@pytest.mark.parametrize("decision,stage", [("ask", "hard_rules"), ("allow", "human_gate"), ("deny", "human_gate"), ("allow", "grant_validity")])
def test_inconsistent_stage_decision_rejected(decision, stage):
    with pytest.raises(ValueError): gate.map_result(result(decision, stage), True)
