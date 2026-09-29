"""scripts/live_pi.py (scripts/test-local.sh --live pi): the ledger checks,
the Pi command line and the SKIP paths, offline. The live run itself needs
Pi and an OpenRouter key and is not part of the test suite. No test here
looks up a real key: the key lookup is replaced before main() reaches it."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _live():
    spec = importlib.util.spec_from_file_location("_live_pi", ROOT / "scripts" / "live_pi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _judgment(command, decision="allow", stage="semantic", error=None, jid="d1"):
    return {"record_type": "judgment", "judgment_id": jid,
            "decision": {"decision": decision, "stage": stage, "provider": "openrouter", "error": error},
            "envelope": {"action": {"tool": "bash", "arguments": {"command": command}}}}


def _host(decision, jid="d1"):
    return {"record_type": "host_response", "content_digest": jid, "tool": "bash", "native": {"decision": decision}}


def test_git_allow_and_host_allow_pass():
    res = _live().evaluate_git([_judgment("git status"), _host("allow")])
    assert res["ok"] and res["judgment"]["command"] == "git status" and res["host_response"] == "allow"


def test_git_no_judgment_says_extension_may_not_have_loaded():
    res = _live().evaluate_git([])
    assert not res["ok"] and "did not load" in res["why"]


def test_git_provider_error_fails():
    res = _live().evaluate_git([_judgment("git status", decision="ask", error="openrouter call failed: HTTP 402"), _host("deny")])
    assert not res["ok"] and "HTTP 402" in res["why"]


def test_git_missing_host_response_fails():
    res = _live().evaluate_git([_judgment("git status")])
    assert not res["ok"] and "no host_response" in res["why"]


def test_chmod_human_gate_and_host_deny_pass():
    recs = [_judgment("chmod -R 755 ./canary-dir", decision="ask", stage="human_gate", jid="c1"), _host("deny", "c1")]
    res = _live().evaluate_chmod(recs)
    assert res["ok"] and res["judgment"]["stage"] == "human_gate" and res["host_response"] == "deny"


def test_chmod_allowed_fails():
    recs = [_judgment("chmod -R 755 ./canary-dir", jid="c1"), _host("allow", "c1")]
    res = _live().evaluate_chmod(recs)
    assert not res["ok"] and "judged allow" in res["why"]


def test_chmod_host_not_deny_fails():
    # Pi blocks only on deny; an ask that reached Pi as anything else ran the command.
    recs = [_judgment("chmod -R 755 ./canary-dir", decision="ask", stage="human_gate", jid="c1"), _host("ask", "c1")]
    res = _live().evaluate_chmod(recs)
    assert not res["ok"] and "sent ask" in res["why"]


def test_chmod_not_run_fails():
    res = _live().evaluate_chmod([_judgment("git status")])
    assert not res["ok"] and "no judgment for bash chmod" in res["why"]


def test_cmd_shim_runs_the_package_entry_with_node(tmp_path, monkeypatch):
    live = _live()
    pkg = tmp_path / "node_modules" / "@earendil-works" / "pi-coding-agent"
    (pkg / "dist").mkdir(parents=True)
    (pkg / "dist" / "cli.js").write_text("", encoding="utf-8")
    (pkg / "package.json").write_text(json.dumps({"bin": {"pi": "dist/cli.js"}}), encoding="utf-8")
    shim = tmp_path / "pi.cmd"
    shim.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr(live.shutil, "which", lambda name: "/usr/bin/node" if name == "node" else None)
    assert live.pi_command(str(shim)) == ["/usr/bin/node", str(pkg / "dist" / "cli.js")]


def test_cmd_shim_without_package_falls_back_to_the_shim(tmp_path):
    shim = tmp_path / "pi.cmd"
    shim.write_text("@echo off\n", encoding="utf-8")
    assert _live().pi_command(str(shim)) == [str(shim)]


def test_no_pi_is_skip(monkeypatch, capsys):
    live = _live()
    monkeypatch.setattr(live.shutil, "which", lambda name: None)
    monkeypatch.setattr(live, "find_openrouter_key", lambda: (_ for _ in ()).throw(AssertionError("key looked up")))
    assert live.main() == 3
    assert capsys.readouterr().out.strip().endswith("LIVE pi: SKIP (pi is not on PATH; install @earendil-works/pi-coding-agent)")


def test_no_key_is_skip(monkeypatch, capsys):
    live = _live()
    monkeypatch.setattr(live.shutil, "which", lambda name: "pi")
    monkeypatch.setattr(live, "find_openrouter_key", lambda: ("", ""))
    assert live.main() == 3
    assert "LIVE pi: SKIP (OPENROUTER_API_KEY not found" in capsys.readouterr().out
