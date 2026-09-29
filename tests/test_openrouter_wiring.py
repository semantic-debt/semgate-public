"""Provider name "openrouter" in every entry point that accepts "typesafe":
registry, CLI eval (report: provider, model, usage), semgate.json through the
hook pipeline (ledger: provider, judge_model), Python Gate, exposure check,
harness init, semgate init, doctor, gemini_gate. The fake server and the
fixtures come from test_openrouter_provider."""
import argparse
import json
from pathlib import Path

import pytest

from semgate.providers.openrouter import OpenRouterDecisionsProvider
from test_openrouter_provider import FAKE_KEY, fake, isolated_home, no_proxy  # noqa: F401  (pytest fixtures)

ROOT = Path(__file__).resolve().parents[1]
DEV = str(ROOT / "policies" / "router_policy_dev.json")
CASES = str(ROOT / "fixtures" / "eval" / "trace-drift.jsonl")


def _route_live_provider_to(fake, monkeypatch):
    """registry.live_provider as it is, except an openrouter provider talks to the fake."""
    from semgate.providers import registry
    made = []
    real = registry.live_provider

    def live(name, model=None):
        p = real(name, model)
        if name == "openrouter":
            p = OpenRouterDecisionsProvider(model=p.model, base_url=fake.base_url, api_key=FAKE_KEY, sleep=lambda s: None)
        made.append(p)
        return p

    monkeypatch.setattr(registry, "live_provider", live)
    return made


def test_registry_names_and_defaults(monkeypatch):
    from semgate.providers import registry
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    p = registry.live_provider("openrouter")
    assert isinstance(p, OpenRouterDecisionsProvider)
    assert p.model == "typesafe/jev-1.13" == registry.DEFAULT_MODELS["openrouter"]
    assert registry.live_provider("openrouter", "typesafe/jev-1.13-20260917").model == "typesafe/jev-1.13-20260917"
    assert registry.live_provider("openrouter", "").model == "typesafe/jev-1.13"
    assert registry.LIVE == ("typesafe", "openrouter")
    with pytest.raises(ValueError):
        registry.live_provider("openai")
    assert registry.report_fields(p) == {"model": "typesafe/jev-1.13", "provider_usage": p.usage_report()}


def test_cli_eval_provider_openrouter_records_provider_model_and_cost(fake, monkeypatch, tmp_path):
    from semgate import cli
    made = _route_live_provider_to(fake, monkeypatch)
    out = tmp_path / "report.json"
    rc = cli.main(["eval", "--provider", "openrouter", "--policy", DEV, "--cases", CASES, "--output", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    assert rc in (0, 2) and report["provider_errors"] == 0
    assert report["provider"] == "openrouter" and report["model"] == "typesafe/jev-1.13"
    usage = report["provider_usage"]
    assert usage["calls"] == len(fake.requests) > 0
    assert usage["cost"] == pytest.approx(0.000123 * usage["calls"])
    assert usage["served_models"] == {"typesafe/jev-1.13-20260917": usage["calls"]}
    assert all(json.loads(r["body"])["model"] == "typesafe/jev-1.13" for r in fake.requests)
    assert [type(p).__name__ for p in made] == ["OpenRouterDecisionsProvider"]
    cli.main(["eval", "--provider", "openrouter", "--model", "typesafe/jev-1.13-20260917", "--policy", DEV,
              "--cases", CASES, "--output", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["model"] == "typesafe/jev-1.13-20260917"


def test_scripted_eval_report_is_unchanged():
    from semgate.eval.runner import evaluate_cases, load_cases
    from semgate.policy import Policy
    report = evaluate_cases(load_cases([CASES]), Policy.load(DEV), scripted=True)
    assert report["provider"] == "per-case-script" and "model" not in report and "provider_usage" not in report


def test_semgate_json_provider_openrouter_through_the_hook_pipeline(fake, monkeypatch, tmp_path):
    from semgate import harness
    _route_live_provider_to(fake, monkeypatch)
    grant = {"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
             "expires_at": "2099-01-01T00:00:00Z"}
    (tmp_path / "grant.json").write_text(json.dumps(grant), encoding="utf-8")
    cfg = {"mode": "enforce", "grant_file": str(tmp_path / "grant.json"), "policy_file": DEV, "provider": "openrouter",
           "judge_model": "typesafe/jev-1.13-20260917", "ledger_file": str(tmp_path / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": False}}
    (tmp_path / "semgate.json").write_text(json.dumps(cfg), encoding="utf-8")
    d = harness.check({"tool": "bash", "arguments": {"command": "python -m pytest -q"}, "session_id": "s1",
                       "cwd": str(tmp_path), "user_messages": ["run the tests"]}, config=str(tmp_path / "semgate.json"))
    assert d["decision"] in ("allow", "ask", "deny") and fake.requests
    assert json.loads(fake.requests[0]["body"])["model"] == "typesafe/jev-1.13-20260917"
    text = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    judged = [r for r in map(json.loads, text.splitlines()) if r["record_type"] == "judgment"]
    assert judged and judged[-1]["decision"]["provider"] == "openrouter"
    assert judged[-1]["decision"]["judge_model"] == "typesafe/jev-1.13-20260917"
    assert not judged[-1]["decision"]["error"]
    assert FAKE_KEY not in text


def test_python_gate_accepts_openrouter(monkeypatch):
    from semgate import Gate
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    g = Gate("Software development in this repository", provider="openrouter", project_root="/p")
    assert isinstance(g.provider, OpenRouterDecisionsProvider) and g.provider.model == "typesafe/jev-1.13"
    g = Gate("Software development", provider="openrouter", model="~typesafe/jev-latest", project_root="/p")
    assert g.provider.model == "~typesafe/jev-latest"


def test_exposure_check_uses_the_configured_live_provider(monkeypatch):
    from semgate import exposures
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    p, why = exposures._intent_provider({"provider": "openrouter"})
    assert isinstance(p, OpenRouterDecisionsProvider) and why == ""


def test_harness_init_and_semgate_init_accept_openrouter(tmp_path, isolated_home):
    from semgate import cli
    from semgate.init_antigravity import _check_interpreter, add_parser
    rc = cli.main(["harness", "init", "--purpose", "dev work", "--dir", str(tmp_path / "http"), "--provider", "openrouter"])
    assert rc == 0
    assert json.loads((tmp_path / "http" / "semgate.json").read_text(encoding="utf-8"))["provider"] == "openrouter"
    problems = _check_interpreter("openrouter")
    assert len(problems) == 1 and problems[0].startswith("OPENROUTER_API_KEY not found")
    (isolated_home / ".semgate" / ".env").write_text("OPENROUTER_API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
    assert _check_interpreter("openrouter") == []          # stdlib only: no typesafe-sdk, no python-dotenv needed
    parser = argparse.ArgumentParser()
    add_parser(parser.add_subparsers(dest="command"))
    assert parser.parse_args(["init", "antigravity", "--provider", "openrouter"]).provider == "openrouter"


def test_doctor_reports_the_openrouter_key_without_the_value(isolated_home, monkeypatch):
    from semgate import doctor
    from semgate.hosts.base import HostEnv
    monkeypatch.setattr(doctor, "SOURCE_ENV", isolated_home / "no-source-env")
    env = HostEnv(isolated_home, {}, None, None)
    report = doctor.run_doctor(env)
    assert report["openrouter_key"] == {"found": False, "location": ""}
    assert "OpenRouter key: not found." in doctor.render(report)
    (isolated_home / ".semgate" / ".env").write_text("OPENROUTER_API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
    report = doctor.run_doctor(env)
    text = doctor.render(report) + json.dumps(report)
    assert report["openrouter_key"] == {"found": True, "location": "file ~/.semgate/.env"}
    assert "OpenRouter key: found (file ~/.semgate/.env)." in text
    assert FAKE_KEY not in text and FAKE_KEY[:12] not in text
    # semgate's own file wins over the generic variable an agent CLI may set
    report = doctor.run_doctor(HostEnv(isolated_home, {"OPENROUTER_API_KEY": FAKE_KEY}, None, None))
    assert report["openrouter_key"] == {"found": True, "location": "file ~/.semgate/.env"}
    report = doctor.run_doctor(HostEnv(isolated_home, {"SEMGATE_OPENROUTER_API_KEY": FAKE_KEY}, None, None))
    assert report["openrouter_key"] == {"found": True, "location": "environment variable SEMGATE_OPENROUTER_API_KEY"}
    assert FAKE_KEY not in doctor.render(report) + json.dumps(report)


def test_gemini_gate_accepts_openrouter_with_a_model_and_an_env_key(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from semgate import gemini_gate as gate
    root = tmp_path / "workspace"; root.mkdir()
    trusted = tmp_path / "trusted"; trusted.mkdir()
    grant = {"grant_id": "g1", "principal": "operator", "purpose": "run project tests", "allowed_tools": ["bash"],
             "allowed_path_prefixes": [str(root)], "provenance": "operator-config",
             "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
    (trusted / "grant.json").write_text(json.dumps(grant), encoding="utf-8")
    (trusted / "policy.json").write_text("{}", encoding="utf-8")
    config = {"schema": gate.CONFIG_SCHEMA, "project_root": str(root), "grant_file": str(trusted / "grant.json"),
              "policy_file": str(trusted / "policy.json"), "shell": "powershell", "harness_version": "v0.60.0",
              "provider": "openrouter", "model": "typesafe/jev-1.13"}
    cp = trusted / "config.json"
    cp.write_text(json.dumps(config), encoding="utf-8")
    assert gate.load_config(str(cp))["provider"] == "openrouter"
    config.pop("model")
    cp.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError):
        gate.load_config(str(cp))                                  # like typesafe: the model must be explicit
    event = {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "session_id": "s1", "cwd": str(root),
             "tool_input": {"command": "Write-Output hi"}}
    config["model"] = "typesafe/jev-1.13"
    cp.write_text(json.dumps(config), encoding="utf-8")
    request = gate.prepare_request(event, gate.load_config(str(cp)))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ValueError, match="explicit provider credentials required"):
        gate.evaluate_request(request)                             # the key must be in this process's environment


def test_smoke_script_makes_three_calls_and_never_prints_the_key(fake, monkeypatch, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("openrouter_smoke", ROOT / "scripts" / "openrouter_smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    assert smoke.main(["--base-url", fake.base_url]) == 0
    out = capsys.readouterr().out
    assert len(fake.requests) == 3 and out.count("call ") == 3 and FAKE_KEY not in out
    sent = json.loads(fake.requests[1]["body"])["questions"]["follows_read_text"]["criteria"]
    assert sent["false"] == "This does not apply: " + sent["true"]
    assert '"calls": 3' in out and '"cost": 0.000369' in out
    fake.script = [(401, {"error": {"message": "User not found " + FAKE_KEY}}, {})]
    assert smoke.main(["--base-url", fake.base_url]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out and "OpenRouterHTTPError: 401" in out and FAKE_KEY not in out
