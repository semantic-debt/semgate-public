"""scripts/live_opencode.py (scripts/test-local.sh --live opencode): the
ledger checks and the SKIP path, offline. The live run itself needs the
owner's OpenCode 2 service and is not part of the test suite."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _live():
    spec = importlib.util.spec_from_file_location("_live_opencode", ROOT / "scripts" / "live_opencode.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _judgment(command="git status", decision="allow", error=None, jid="d1"):
    return {"record_type": "judgment", "judgment_id": jid,
            "decision": {"decision": decision, "stage": "semantic", "provider": "openrouter", "error": error},
            "envelope": {"action": {"tool": "bash", "arguments": {"command": command}}}}


def _host(decision="allow", jid="d1"):
    return {"record_type": "host_response", "content_digest": jid, "tool": "bash", "native": {"decision": decision}}


def test_allow_judgment_and_allow_host_response_pass():
    res = _live().evaluate([_judgment(), _host()])
    assert res["a"] and res["b"] and res["judgment"]["command"] == "git status"


def test_missing_judgment_fails_a():
    res = _live().evaluate([_judgment(command="ls")])
    assert not res["a"] and "no judgment for bash git status" in res["a_why"]


def test_provider_error_fails_a():
    res = _live().evaluate([_judgment(decision="ask", error="openrouter call failed: HTTP 402"), _host("ask")])
    assert not res["a"] and "HTTP 402" in res["a_why"]
    assert not res["b"] and "sent ask" in res["b_why"]


def test_missing_host_response_fails_b():
    res = _live().evaluate([_judgment()])
    assert res["a"] and not res["b"] and "no host_response" in res["b_why"]


def test_no_opencode2_is_skip(monkeypatch, capsys):
    live = _live()
    monkeypatch.setattr(live.shutil, "which", lambda name: None)
    assert live.main() == 3
    assert capsys.readouterr().out.strip().endswith("LIVE opencode: SKIP (opencode2 is not on PATH)")


def test_service_not_running_is_skip(monkeypatch, capsys):
    live = _live()
    monkeypatch.setattr(live.shutil, "which", lambda name: "opencode2")
    monkeypatch.setattr(live, "processes_naming", lambda needle: [])
    assert live.main() == 3
    out = capsys.readouterr().out
    assert "LIVE opencode: SKIP (the OpenCode 2 background service is not running" in out
