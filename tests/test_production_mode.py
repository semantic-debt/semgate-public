"""Production mode (owner decisions 2026-09-29): enforce is the only
production mode. Every `semgate init <host>` and `semgate harness init`
writes a complete enforce config (mode enforce, enforcement.enabled,
block_when_unsure from the host rule, a policy with chat approval on).
`--mode shadow` is a developer switch: accepted, hidden from --help, and it
still records only (docs/development.md)."""
import io
import json
from pathlib import Path

import pytest

from semgate import antigravity_hook, chatapproval as ca, enforcement
from semgate.cli import build_parser, main
from semgate.hosts import host_shows_ask
from semgate.init_antigravity import HOST_DEFAULTS
from semgate.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"
HOOK_FILES = {"claude": "settings.json", "copilot": "semgate.json", "opencode": "semgate.js", "pi": "semgate.ts"}


def _init(tmp_path, host, *extra):
    base = tmp_path / host
    argv = ["init", host, "--purpose", "Dev work in the demo project", "--provider", "none", "--no-skill",
            "--dir", str(base / "semgate"), "--hooks-file", str(base / "host" / HOOK_FILES.get(host, "hooks.json")), *extra]
    assert main(argv) == 0, host
    return json.loads((base / "semgate" / "semgate.json").read_text(encoding="utf-8"))


def _chat_on(policy_file):
    pol = Policy.load(str(policy_file))
    return ca.enabled(pol), ca.threshold(pol), ca.clarify_threshold(pol)


# ------------------------------------------------------------------ A. every init writes a complete enforce config


@pytest.mark.parametrize("host", sorted(HOST_DEFAULTS))
def test_every_init_writes_enforce_enabled_block_when_unsure_and_chat_approval(tmp_path, host):
    cfg = _init(tmp_path, host)                              # no --mode: the production default
    assert cfg["mode"] == "enforce" and cfg["enforcement"]["enabled"] is True
    assert cfg["enforcement"]["block_when_unsure"] is (not host_shows_ask(host))
    assert enforcement.mode_problem(cfg) == "" and enforcement.enforcing(cfg)
    assert _chat_on(cfg["policy_file"]) == (True, 0.85, 0.15)


def test_init_demo_and_harness_init_write_enforce_too(tmp_path):
    base = tmp_path / "demo"
    assert main(["init", "codex", "--demo", "--no-skill", "--dir", str(base / "semgate"),
                 "--hooks-file", str(base / "host" / "hooks.json")]) == 0
    cfg = json.loads((base / "semgate" / "semgate.json").read_text(encoding="utf-8"))
    assert cfg["mode"] == "enforce" and cfg["enforcement"]["enabled"] is True and cfg["enforcement"]["block_when_unsure"] is True
    assert main(["harness", "init", "--purpose", "harness work", "--provider", "none", "--dir", str(tmp_path / "http")]) == 0
    cfg = json.loads((tmp_path / "http" / "semgate.json").read_text(encoding="utf-8"))
    assert cfg["mode"] == "enforce" and cfg["enforcement"]["enabled"] is True
    assert cfg["enforcement"]["block_when_unsure"] is False                 # the harness shows the ask (approval id)
    assert _chat_on(cfg["policy_file"])[0] is True


def test_init_says_chat_approval_is_on(tmp_path, capsys):
    _init(tmp_path, "antigravity")
    out = capsys.readouterr().out
    assert "chat approval: on" in out and "p >= 0.85" in out and "shadow" not in out.lower()


# ------------------------------------------------------------------ A/4. the developer shadow switch


def _help(argv):
    parser = build_parser()
    buf = io.StringIO()
    with pytest.raises(SystemExit):
        import contextlib
        with contextlib.redirect_stdout(buf):
            parser.parse_args(argv)
    return buf.getvalue()


def test_shadow_is_hidden_from_help_but_accepted(tmp_path):
    for argv in (["init", "--help"], ["harness", "init", "--help"], ["--help"]):
        text = _help(argv)
        assert "shadow" not in text.lower() and "--mode" not in text, argv
    cfg = _init(tmp_path, "antigravity", "--mode", "shadow")
    assert cfg["mode"] == "shadow" and cfg["enforcement"]["enabled"] is False
    assert enforcement.is_shadow(cfg) and enforcement.mode_problem(cfg) == ""


def _grant(tmp_path):
    g = tmp_path / "grant.json"
    g.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                             "expires_at": "2099-01-01T00:00:00Z", "allowed_path_prefixes": ["/workspace/project"]}))
    return str(g)


def _agy_event(command="rm -rf /"):
    return {"toolCall": {"name": "run_command", "args": {"CommandLine": command}}, "workspacePaths": ["/workspace/project"],
            "conversationId": "c1", "stepIdx": 1}


def test_shadow_switch_still_records_only(tmp_path):
    """mode shadow: judged and recorded, every answer an ask (a hard deny too)."""
    cfg = {"mode": "shadow", "grant_file": _grant(tmp_path), "policy_file": str(DEV), "provider": "none",
           "ledger_file": str(tmp_path / "ledger.jsonl"), "enforcement": {"enabled": False}}
    out = antigravity_hook.run(_agy_event(), cfg)
    assert out["decision"] == "ask" and out["reason"].startswith("semgate shadow: hard_rules/deny")
    rows = [json.loads(x) for x in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(r.get("decision", {}).get("decision") == "deny" for r in rows if r.get("record_type", "judgment") == "judgment")
    # a hook failure with a shadow config keeps the old force_ask (record only)
    assert enforcement.fail_closed("semgate hook failure: X", "antigravity", cfg, ask_as="force_ask")["decision"] == "force_ask"
