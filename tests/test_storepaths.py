"""Store paths in semgate.json never depend on the current directory (semgate.storepaths).

A relative path resolves against the config's base folder (the folder holding
the config, or the folder above a dot folder such as .antigravity); an unset
ledger_file is ~/.semgate/<host>/ledger.jsonl and the other stores sit next
to the ledger. conftest gives every test a temp HOME, USERPROFILE and cwd."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from semgate import exposures, fingerprints, hookinput, ownmessages, storepaths, tooloutputs
from semgate.antigravity_hook import feedback_path, history_path
from semgate.hosts.builtin import check_semgate_config
from semgate.ledger import Ledger

ROOT = Path(__file__).parents[1]


# The structure of the owner's live .antigravity/semgate.json (keys and value
# shapes; the paths written relative to the repo root, the form they had when
# the hook resolved them against the current directory).
def _live_shape(prefix: str = "") -> dict:
    p = lambda rel: prefix + rel  # noqa: E731
    return {
        "mode": "enforce",
        "grant_file": p(".antigravity/semgate/grant.json"),
        "policy_file": p("policies/router_policy_dev.json"),
        "provider": "none",
        "ledger_file": p(".antigravity/semgate/ledger.jsonl"),
        "auto_allow_learned": {"enabled": False, "min_count": 2, "history_file": p(".antigravity/semgate/tool_history.jsonl")},
        "enforcement": {"enabled": True, "auto_allow_tools": ["read_url_content", "read", "view_file", "bash"],
                        "propagate_learned_allow": True, "semantic_deny_response": "deny", "block_when_unsure": False},
        "feedback": {"enabled": True, "feedback_file": p(".antigravity/semgate/feedback.jsonl")},
        "profiles": {"enabled": True, "file": p("policies/profiles.json"),
                     "state_file": p(".antigravity/semgate/profile_state.json"),
                     "default": "software-development", "override": ""},
        "git_facts": True, "record_outcomes": True, "script_source": True, "agent_files": {"enabled": True},
    }


PATHS = [("ledger_file",), ("grant_file",), ("policy_file",), ("auto_allow_learned", "history_file"),
         ("feedback", "feedback_file"), ("profiles", "file"), ("profiles", "state_file")]


def _get(cfg, keys):
    for k in keys:
        cfg = cfg[k]
    return cfg


def _write(path: Path, cfg: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return str(path)


def test_base_dir_and_host_guess(tmp_path):
    assert storepaths.base_dir(str(tmp_path / "repo" / ".antigravity" / "semgate.json")) == str(tmp_path / "repo")
    assert storepaths.base_dir(str(tmp_path / ".semgate" / "claude" / "semgate.json")) == str(tmp_path / ".semgate" / "claude")
    assert storepaths.base_dir(str(tmp_path / "x" / "semgate.json")) == str(tmp_path / "x")
    assert storepaths.guess_host(str(tmp_path / "repo" / ".antigravity" / "semgate.json")) == "antigravity"
    assert storepaths.guess_host(str(tmp_path / ".semgate" / "droid" / "semgate.json")) == "droid"
    assert storepaths.guess_host(str(tmp_path / "x" / "semgate.json")) == "unknown"


def test_relative_paths_do_not_depend_on_the_current_directory(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    config = _write(repo / ".antigravity" / "semgate.json", _live_shape())
    seen = []
    for cwd in (tmp_path, repo, repo / ".antigravity", tmp_path / "other-project"):
        cwd.mkdir(parents=True, exist_ok=True)
        monkeypatch.chdir(cwd)
        seen.append(storepaths.load(config, "antigravity"))
    assert all(s == seen[0] for s in seen)
    assert seen[0]["ledger_file"] == str(repo / ".antigravity" / "semgate" / "ledger.jsonl")


def test_live_config_shape_resolves_to_the_repo_root_files(tmp_path, monkeypatch):
    """Relative form: the same absolute files the hook used when it ran from
    the repo folder. Absolute form (the live file today): the same strings."""
    repo = tmp_path / "semgate"
    rel_cfg = _live_shape()
    config = _write(repo / ".antigravity" / "semgate.json", rel_cfg)
    monkeypatch.chdir(repo)                                 # what the relative paths meant before: cwd = repo root
    before = {keys: os.path.abspath(_get(rel_cfg, keys)) for keys in PATHS}
    monkeypatch.chdir(tmp_path)                             # the hook now runs from anywhere
    resolved = storepaths.load(config, "antigravity")
    assert {keys: _get(resolved, keys) for keys in PATHS} == before
    prefix = repo.as_posix() + "/"
    abs_cfg = _live_shape(prefix)
    resolved = storepaths.load(_write(repo / ".antigravity" / "abs.json", abs_cfg), "antigravity")
    assert {keys: _get(resolved, keys) for keys in PATHS} == {keys: _get(abs_cfg, keys) for keys in PATHS}
    # the stores the hooks compute from it
    assert history_path(resolved) == prefix + ".antigravity/semgate/tool_history.jsonl"
    assert feedback_path(resolved) == prefix + ".antigravity/semgate/feedback.jsonl"
    assert storepaths.agent_files_dir(resolved) == os.path.normpath(os.path.expanduser("~/.semgate"))


def test_unset_paths_default_to_the_home_state_folder(tmp_path):
    home = Path(os.path.expanduser("~"))
    config = _write(tmp_path / "proj" / ".antigravity" / "semgate.json",
                    {"record_outcomes": True, "feedback": {"enabled": True},
                     "enforcement": {"deny_escalation": {"enabled": True}}})
    cfg = storepaths.load(config, "antigravity")
    state = home / ".semgate" / "antigravity"
    assert cfg["ledger_file"] == str(state / "ledger.jsonl")
    assert history_path(cfg) == str(state / "tool_history.jsonl")
    assert feedback_path(cfg) == str(state / "feedback.jsonl")
    assert storepaths.deny_streak_file(cfg) == str(state / "deny_streak.json")
    claude = storepaths.load(_write(tmp_path / "c.json", {}), "claude")
    assert tooloutputs.store_dir(claude) == home / ".semgate" / "claude" / "tool_outputs"
    assert ownmessages.store_dir(cfg) == state / "own_messages"
    assert ownmessages.store_dir(storepaths.load(_write(tmp_path / "d.json", {"own_messages": {"dir": "om"}}), "claude"))         == tmp_path / "om"
    assert exposures.store_dir(claude) == home / ".semgate" / "claude" / "exposures"
    assert fingerprints.key_path(claude) == home / ".semgate" / "claude" / "fingerprint.key"
    # a config that never went through resolve() still never writes under the cwd
    assert storepaths.ledger_file({}) == str(home / ".semgate" / "unknown" / "ledger.jsonl")
    assert history_path({"record_outcomes": True}) == str(home / ".semgate" / "unknown" / "tool_history.jsonl")


def test_resolve_does_not_change_its_input_and_skips_non_strings(tmp_path):
    cfg = {"ledger_file": "l.jsonl", "tool_outputs": False, "secret_exposures": {"dir": ""}, "agent_files": True}
    snapshot = json.dumps(cfg, sort_keys=True)
    out = storepaths.resolve(cfg, str(tmp_path / "semgate.json"), "claude")
    assert json.dumps(cfg, sort_keys=True) == snapshot
    assert out["ledger_file"] == str(tmp_path / "l.jsonl")
    assert out["tool_outputs"] is False and out["secret_exposures"] == {"dir": ""} and out["agent_files"] is True
    assert storepaths.resolve({"ledger_file": "~/x/l.jsonl"}, str(tmp_path / "s.json"), "c")["ledger_file"] == \
        os.path.expanduser("~/x/l.jsonl")


def test_hook_writes_next_to_the_config_not_in_the_agent_project(tmp_path):
    """End to end: agy hook subprocess, relative paths, cwd = the agent's
    project. The ledger and tool history land under the config's base folder."""
    base = tmp_path / "home-of-config"
    (base / "policies").mkdir(parents=True)
    (base / "policies" / "p.json").write_text((ROOT / "policies" / "router_policy_dev.json").read_text(encoding="utf-8"),
                                              encoding="utf-8")
    _write(base / ".antigravity" / "semgate" / "grant.json",
           {"grant_id": "g", "principal": "p", "purpose": "Software development", "expires_at": "2099-01-01T00:00:00Z"})
    cfg = {"mode": "enforce", "provider": "none", "grant_file": ".antigravity/semgate/grant.json",
           "policy_file": "policies/p.json", "ledger_file": ".antigravity/semgate/ledger.jsonl", "record_outcomes": True,
           "auto_allow_learned": {"enabled": False, "history_file": ".antigravity/semgate/tool_history.jsonl"},
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"]}}
    config = _write(base / ".antigravity" / "semgate.json", cfg)
    project = tmp_path / "agent-project"
    project.mkdir()
    event = {"conversationId": "c1", "stepIdx": 1, "workspacePaths": [str(project)],
             "toolCall": {"name": "run_command", "args": {"CommandLine": "git status", "Cwd": str(project)}}}
    p = subprocess.run([sys.executable, "-m", "semgate.antigravity_hook", "--config", config],
                       input=json.dumps(event).encode(), capture_output=True, cwd=str(project), timeout=120)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["decision"] in {"ask", "force_ask", "allow", "deny"}
    ledger = base / ".antigravity" / "semgate" / "ledger.jsonl"
    assert [r["record_type"] for r in Ledger(str(ledger)).records()][-1] == "host_response"
    assert (base / ".antigravity" / "semgate" / "tool_history.jsonl").is_file()
    assert list(project.rglob("*")) == []                   # nothing written in the agent's project


def test_early_rejection_uses_the_resolved_ledger(tmp_path):
    config = _write(tmp_path / "repo" / ".antigravity" / "semgate.json", {"ledger_file": ".antigravity/semgate/l.jsonl"})
    assert hookinput.early_ledger_path(config, "antigravity") == str(tmp_path / "repo" / ".antigravity" / "semgate" / "l.jsonl")


def test_doctor_facts_list_the_resolved_store_paths(tmp_path):
    repo = tmp_path / "semgate"
    config = repo / ".antigravity" / "semgate.json"
    _write(config, _live_shape())
    facts: dict = {}
    check_semgate_config(config, facts, "antigravity")
    state = repo / ".antigravity" / "semgate"
    assert facts["store_base"] == str(repo)
    assert facts["store_paths"] == [
        ["ledger", str(state / "ledger.jsonl")], ["history", str(state / "tool_history.jsonl")],
        ["feedback", str(state / "feedback.jsonl")], ["profile_state", str(state / "profile_state.json")],
        ["own_messages", str(state / "own_messages")],
        ["agent_files", os.path.normpath(os.path.expanduser("~/.semgate"))],
        ["trust", os.path.join(os.path.expanduser("~"), ".semgate", "trust.jsonl")]]
    from semgate.doctor import render
    report = {"hosts": [{"host": "antigravity", "version": "1.2.8", "status": "OK", "headline": "h", "conformance": "c",
                         "findings": [], "facts": facts}],
              "typesafe_key": {"found": False, "location": ""},
              "summary": {"detected": 1, "by_status": {"OK": 1}, "typesafe_needed": False}}
    line = [l for l in render(report).splitlines() if "stores:" in l][0]
    assert line.strip() == ("stores: ledger " + str(state / "ledger.jsonl") + "; history " + str(state / "tool_history.jsonl")
                            + "; feedback " + str(state / "feedback.jsonl") + "; profile_state "
                            + str(state / "profile_state.json") + "; own_messages " + str(state / "own_messages")
                            + "; agent_files "
                            + os.path.normpath(os.path.expanduser("~/.semgate"))
                            + "; trust " + os.path.join(os.path.expanduser("~"), ".semgate", "trust.jsonl"))


@pytest.mark.parametrize("module", ["semgate.antigravity_hook", "semgate.antigravity_post_hook"])
def test_default_config_is_not_under_the_current_directory(module, tmp_path):
    """Without --config the agy hooks read ~/.semgate/antigravity/semgate.json,
    not ./.antigravity/semgate.json of the agent's project."""
    project = tmp_path / "p"
    _write(project / ".antigravity" / "semgate.json", {"mode": "enforce", "ledger_file": "PROJECT-LEDGER.jsonl"})
    env = dict(os.environ)
    env.pop("SEMGATE_ANTIGRAVITY_CONFIG", None)
    p = subprocess.run([sys.executable, "-m", module], input=b'{"conversationId": "c", "stepIdx": 1}',
                       capture_output=True, cwd=str(project), env=env, timeout=120)
    assert p.returncode == 0
    assert not (project / "PROJECT-LEDGER.jsonl").exists() and not (project / ".antigravity" / "PROJECT-LEDGER.jsonl").exists()


def test_default_config_path_under_home_is_read(tmp_path):
    """The agy hooks' default --config (~/.semgate/antigravity/semgate.json)
    is expanded, read, and its relative ledger resolves under that folder."""
    home = Path(os.path.expanduser("~"))
    _write(home / ".semgate" / "antigravity" / "semgate.json", {"mode": "enforce", "ledger_file": "ledger.jsonl",
                                                                "hook_max_payload_bytes": 2048})
    assert storepaths.load("~/.semgate/antigravity/semgate.json", "antigravity")["ledger_file"] == \
        str(home / ".semgate" / "antigravity" / "ledger.jsonl")
    assert hookinput.max_payload_bytes("~/.semgate/antigravity/semgate.json") == 2048
    project = tmp_path / "p"
    project.mkdir()
    env = dict(os.environ)
    env.pop("SEMGATE_ANTIGRAVITY_CONFIG", None)
    p = subprocess.run([sys.executable, "-m", "semgate.antigravity_hook"], input=b'{"conversationId": "c", "stepIdx": 1}',
                       capture_output=True, cwd=str(project), env=env, timeout=120)
    # enforce without enforcement.enabled: incomplete, so agy gets a deny (never an ask it could run unattended)
    assert p.returncode == 0 and json.loads(p.stdout)["decision"] == "deny"
    records = list(Ledger(str(home / ".semgate" / "antigravity" / "ledger.jsonl")).records())
    assert records and records[-1]["record_type"] == "host_response"
    assert list(project.rglob("*")) == []
