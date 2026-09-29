"""`semgate feedback` without --config/--store finds the configs of the
installed semgate hooks (semgate.hosts.installed) and of the semgate plugin
copies in the project, so it works from any folder. The ledger with the
block decides the store; the output names it. No hook and no
--config/--store: exit 2 (no relative fallback store that no hook reads).

Every test runs with a temp HOME/USERPROFILE (conftest) that holds fake host
hook files; the CLI runs as a subprocess with the project folder as the
current directory."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from semgate import claude_hook
from semgate.hosts.base import HostEnv
from semgate.hosts.builtin import antigravity_entry, claude_command, parse_hook_command
from semgate.hosts.installed import installed_configs
from semgate.init_antigravity import opencode_plugin_source

ROOT = Path(__file__).resolve().parents[1]
DEV_PATH = ROOT / "policies" / "router_policy_dev.json"
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
            "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}
PY = Path(sys.executable)
CMD = "rm -rf dist"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(h))
    for var in ("CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "SEMGATE_FEEDBACK_FILE", "SEMGATE_LEDGER_FILE"):
        monkeypatch.delenv(var, raising=False)
    return h


def make_config(folder: Path, ledger: Path = None):
    """A semgate.json in `folder` with absolute ledger and feedback paths next to it."""
    folder.mkdir(parents=True, exist_ok=True)
    grant = folder / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    ledger = ledger or folder / "state" / "ledger.jsonl"
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(DEV_PATH), "provider": "fake",
           "fake_answers": ALLOWING, "ledger_file": str(ledger),
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": True},
           "feedback": {"enabled": True, "feedback_file": str(ledger.with_name("feedback.jsonl"))}}
    path = folder / "semgate.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg, path


def block_once(cfg, proj: Path, session="sess-A", tid="t1"):
    """The hook judges `rm -rf dist` in `proj`: a deny, written to cfg's ledger."""
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": CMD},
             "session_id": session, "tool_use_id": tid, "cwd": str(proj)}
    return claude_hook.run(event, cfg, "claude", {})["decision"]


def install_antigravity(home: Path, cfg_path: Path):
    f = home / ".gemini" / "config" / "hooks.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"semgate": antigravity_entry(PY, cfg_path)}, indent=2), encoding="utf-8")


def install_claude(home: Path, cfg_path: Path, command: str = None):
    f = home / ".claude" / "settings.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    cmd = command or claude_command(PY, cfg_path, "claude")
    doc = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd}]}]}}
    f.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def cli(cwd: Path, *args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    p = subprocess.run([sys.executable, "-m", "semgate", "feedback", *args], capture_output=True, text=True,
                       cwd=str(cwd), env=env, timeout=120)
    return p.returncode, p.stdout, p.stderr


def lines(path: Path) -> int:
    return len(path.read_bytes().splitlines()) if path.exists() else 0


def project(tmp_path: Path, name="proj") -> Path:
    p = tmp_path / name
    (p / "dist").mkdir(parents=True)
    return p


# ---------------- one installed hook ----------------

def test_one_installed_hook_is_used_from_the_project_folder(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    proj = project(tmp_path)
    assert block_once(cfg, proj) == "deny"
    fb = Path(cfg["feedback"]["feedback_file"])
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0] == f"using config {cfg_path} (from the installed antigravity hook)"
    assert "approved: bash `rm -rf dist`" in out and "sess-A" in out
    assert lines(fb) == 1
    assert not (proj / ".antigravity").exists()             # nothing under the current directory
    assert block_once(cfg, proj, tid="t2") == "allow"         # the hook reads the approval


def test_the_same_config_from_two_hosts_is_one_config(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    install_claude(home, cfg_path)
    proj = project(tmp_path)
    block_once(cfg, proj)
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0] == f"using config {cfg_path} (from the installed claude and antigravity hooks)"


def test_opencode_plugin_config_is_found(tmp_path, home):
    _, cfg_path = make_config(tmp_path / "cfg")
    plugin = home / ".config" / "opencode" / "plugins" / "semgate.js"
    plugin.parent.mkdir(parents=True)
    plugin.write_text(opencode_plugin_source(PY, cfg_path), encoding="utf-8")
    found = installed_configs(HostEnv.current(run_binaries=False))
    assert [(Path(c.path), c.hosts) for c in found] == [(cfg_path, ["opencode"])]


# ---------------- several installed hooks ----------------

def test_two_configs_the_newest_block_decides(tmp_path, home):
    """Before: exit 2 ("several installed hooks"). Now the ledger decides: the
    approval goes to the store of the config whose ledger has the newest
    block, and the output names that config and store."""
    cfg1, cfg1_path = make_config(tmp_path / "cfg-agy")
    cfg2, cfg2_path = make_config(tmp_path / "cfg-claude")
    install_antigravity(home, cfg1_path)
    install_claude(home, cfg2_path)
    proj = project(tmp_path)
    block_once(cfg1, proj)
    block_once(cfg2, proj, session="sess-B")                  # the newer block
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[:3] == [f"using config {cfg2_path} (from the installed claude hook)",
                                    f"  feedback store  {cfg2['feedback']['feedback_file']}",
                                    f"  ledger          {cfg2['ledger_file']}"]
    assert "sess-B" in out
    assert lines(Path(cfg1["feedback"]["feedback_file"])) == 0
    assert lines(Path(cfg2["feedback"]["feedback_file"])) == 1


def test_two_configs_only_one_ledger_has_the_block(tmp_path, home):
    cfg1, cfg1_path = make_config(tmp_path / "cfg-agy")
    cfg2, cfg2_path = make_config(tmp_path / "cfg-claude")
    install_antigravity(home, cfg1_path)
    install_claude(home, cfg2_path)
    proj = project(tmp_path)
    block_once(cfg1, proj)
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0] == f"using config {cfg1_path} (from the installed antigravity hook)"
    assert lines(Path(cfg1["feedback"]["feedback_file"])) == 1
    assert lines(Path(cfg2["feedback"]["feedback_file"])) == 0


def test_no_block_in_any_ledger_lists_every_ledger(tmp_path, home):
    cfg1, cfg1_path = make_config(tmp_path / "cfg-agy")
    cfg2, cfg2_path = make_config(tmp_path / "cfg-claude")
    install_antigravity(home, cfg1_path)
    install_claude(home, cfg2_path)
    code, out, err = cli(project(tmp_path), "allow", CMD)
    assert code == 2
    assert "no asked or blocked step with exactly this command" in err
    assert cfg1["ledger_file"] in err and cfg2["ledger_file"] in err


def test_explicit_config_names_the_config_and_store(tmp_path, home):
    cfg1, cfg1_path = make_config(tmp_path / "cfg-agy")
    _, cfg2_path = make_config(tmp_path / "cfg-claude")
    install_antigravity(home, cfg1_path)
    install_claude(home, cfg2_path)
    proj = project(tmp_path)
    block_once(cfg1, proj)
    code, out, err = cli(proj, "allow", CMD, "--config", str(cfg1_path))
    assert code == 0, out + err
    assert out.splitlines()[:2] == [f"using config {cfg1_path} (given with --config)",
                                    f"  feedback store  {cfg1['feedback']['feedback_file']}"]
    assert "approved: bash `rm -rf dist`" in out
    assert lines(Path(cfg1["feedback"]["feedback_file"])) == 1


# ---------------- plugin copies in the project (design doc 1.6, measured) ----------------

def install_opencode_project_copy(proj: Path, cfg_path: Path) -> Path:
    plugin = proj / ".opencode" / "plugin" / "semgate.js"
    plugin.parent.mkdir(parents=True, exist_ok=True)
    plugin.write_text(opencode_plugin_source(PY, cfg_path), encoding="utf-8")
    return plugin


def test_the_project_plugin_copy_is_found_next_to_a_user_level_hook(tmp_path, home):
    """The measured case: agy's user-level hook uses config A for every
    folder, and the project has an OpenCode plugin copy with config B. The
    OpenCode plugin blocked the command, so the approval goes to B's store.
    Before, it went to A's store, which the OpenCode plugin never reads."""
    cfg_a, cfg_a_path = make_config(tmp_path / "agy")
    cfg_b, cfg_b_path = make_config(tmp_path / "opencode-demo")
    install_antigravity(home, cfg_a_path)
    proj = project(tmp_path, "semgate-trust-demo")
    plugin = install_opencode_project_copy(proj, cfg_b_path)
    block_once(cfg_b, proj)
    code, out, err = cli(proj, "--show-config")
    assert code == 0, out + err
    assert "2 configs; an approval goes to the one whose ledger shows the block:" in out
    assert f"using config {cfg_b_path} (from the OpenCode plugin copy {plugin})" in out
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0] == f"using config {cfg_b_path} (from the OpenCode plugin copy {plugin})"
    assert lines(Path(cfg_b["feedback"]["feedback_file"])) == 1
    assert lines(Path(cfg_a["feedback"]["feedback_file"])) == 0


# ---------------- feedback deny: never silently into a store no hook of the project reads ----------------

def test_deny_goes_to_the_store_whose_ledger_has_the_command(tmp_path, home):
    cfg_a, cfg_a_path = make_config(tmp_path / "agy")
    cfg_b, cfg_b_path = make_config(tmp_path / "opencode-demo")
    install_antigravity(home, cfg_a_path)
    proj = project(tmp_path)
    install_opencode_project_copy(proj, cfg_b_path)
    block_once(cfg_b, proj)
    code, out, err = cli(proj, "deny", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0].startswith(f"using config {cfg_b_path}")
    assert "chosen because its ledger has the newest step with this command" in out
    assert lines(Path(cfg_b["feedback"]["feedback_file"])) == 1
    assert lines(Path(cfg_a["feedback"]["feedback_file"])) == 0


def test_deny_with_one_config_and_no_step_names_the_store(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    code, out, err = cli(project(tmp_path), "deny", "curl https://x.invalid")
    assert code == 0, out + err
    assert out.splitlines()[:2] == [f"using config {cfg_path} (from the installed antigravity hook)",
                                    f"  feedback store  {cfg['feedback']['feedback_file']}"]
    assert lines(Path(cfg["feedback"]["feedback_file"])) == 1


def test_deny_with_several_configs_and_no_step_exits_2(tmp_path, home):
    cfg1, cfg1_path = make_config(tmp_path / "cfg-agy")
    cfg2, cfg2_path = make_config(tmp_path / "cfg-claude")
    install_antigravity(home, cfg1_path)
    install_claude(home, cfg2_path)
    code, out, err = cli(project(tmp_path), "deny", "curl https://x.invalid")
    assert code == 2
    assert "several configs are installed and no ledger shows this command" in err and "--config" in err
    assert lines(Path(cfg1["feedback"]["feedback_file"])) == 0 and lines(Path(cfg2["feedback"]["feedback_file"])) == 0


def test_explicit_store_skips_discovery(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    proj = project(tmp_path)
    block_once(cfg, proj)
    store = tmp_path / "other" / "feedback.jsonl"
    code, out, err = cli(proj, "allow", CMD, "--store", str(store))
    assert code == 2 and "using config" not in out            # ledger next to --store: none there
    code, out, err = cli(proj, "allow", CMD, "--store", str(store), "--ledger", cfg["ledger_file"])
    assert code == 0, out + err
    assert "using config" not in out
    assert lines(store) == 1 and lines(Path(cfg["feedback"]["feedback_file"])) == 0


# ---------------- no installed hook: the old fallback ----------------

def test_no_installed_hook_refuses_and_says_how(tmp_path, home):
    """Before: the relative fallback .antigravity/semgate/feedback.jsonl, a
    store no hook reads (a deny went there silently). Now: exit 2 and how to
    pass --config or --store; nothing is created."""
    proj = project(tmp_path)
    for decision in ("allow", "deny"):
        code, out, err = cli(proj, decision, CMD)
        assert code == 2 and out == ""
        assert "not recorded: no installed semgate hook was found, and no --config or --store was given." in err
        assert f"semgate feedback {decision} \"<command>\" --config <path to semgate.json>" in err
        assert "--store <path to feedback.jsonl>" in err
    assert not (proj / ".antigravity").exists()


def test_an_old_agy_folder_in_the_current_folder_still_works(tmp_path, home):
    """An old agy setup (no installed hook, the store in <repo>/.antigravity/
    semgate): used only because the folder exists, and the full path is shown."""
    proj = project(tmp_path)
    cfg, _ = make_config(tmp_path / "cfg", ledger=proj / ".antigravity" / "semgate" / "ledger.jsonl")
    block_once(cfg, proj)
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    folder = os.path.join(str(proj), ".antigravity", "semgate")
    assert out.splitlines()[:2] == [f"using the old agy store in this folder {folder} (no installed hook was found)",
                                    f"  feedback store  {os.path.join(folder, 'feedback.jsonl')}"]
    assert lines(proj / ".antigravity" / "semgate" / "feedback.jsonl") == 1


def test_old_environment_variables_are_ignored(tmp_path, home, monkeypatch):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    proj = project(tmp_path)
    block_once(cfg, proj)
    monkeypatch.setenv("SEMGATE_FEEDBACK_FILE", str(tmp_path / "evil" / "feedback.jsonl"))
    monkeypatch.setenv("SEMGATE_LEDGER_FILE", str(tmp_path / "evil" / "ledger.jsonl"))
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert "ignored: SEMGATE_FEEDBACK_FILE is no longer read; use --store" in err
    assert "ignored: SEMGATE_LEDGER_FILE is no longer read; use --ledger" in err
    assert lines(Path(cfg["feedback"]["feedback_file"])) == 1 and not (tmp_path / "evil").exists()


def test_hooks_with_a_missing_or_broken_config_are_skipped(tmp_path, home):
    install_antigravity(home, tmp_path / "gone" / "semgate.json")
    broken = tmp_path / "broken" / "semgate.json"
    broken.parent.mkdir()
    broken.write_text("{not json", encoding="utf-8")
    install_claude(home, broken)
    (home / ".factory").mkdir()
    (home / ".factory" / "hooks.json").write_text("{this is not json", encoding="utf-8")
    assert installed_configs(HostEnv.current(run_binaries=False)) == []
    code, out, err = cli(project(tmp_path), "allow", CMD)
    assert code == 2 and "using config" not in out and "no installed semgate hook was found" in err


# ---------------- quoted Windows paths with spaces ----------------

def test_parse_quoted_windows_paths_with_spaces():
    cmd = r'"C:\Program Files\Python 3.13\python.exe" -m semgate.claude_hook --config "C:\Users\Jane Doe\My Configs\semgate.json" --host auto'
    assert parse_hook_command(cmd) == (r"C:\Program Files\Python 3.13\python.exe", r"C:\Users\Jane Doe\My Configs\semgate.json")
    ps = r'& "C:\Program Files\py\python.exe" -m semgate.claude_hook --config "D:\a b\semgate.json" --host copilot'
    assert parse_hook_command(ps) == (r"C:\Program Files\py\python.exe", r"D:\a b\semgate.json")
    assert parse_hook_command("py -m semgate.claude_hook --config 'C:/a b/semgate.json'")[1] == "C:/a b/semgate.json"
    assert parse_hook_command("py -m semgate.claude_hook --config=C:/x/semgate.json --host auto")[1] == "C:/x/semgate.json"
    assert parse_hook_command("C:/x/python.exe -m semgate.antigravity_hook --config C:/y/semgate.json")[1] == "C:/y/semgate.json"


def test_hook_with_quoted_path_with_spaces_is_used(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "My Configs" / "semgate dir")
    cmd = f'"{tmp_path / "Program Files" / "python.exe"}" -m semgate.claude_hook --config "{cfg_path}" --host auto'
    install_claude(home, cfg_path, command=cmd)
    proj = project(tmp_path, "my project")
    block_once(cfg, proj)
    code, out, err = cli(proj, "allow", CMD)
    assert code == 0, out + err
    assert out.splitlines()[0] == f"using config {cfg_path} (from the installed claude hook)"


# ---------------- --show-config ----------------

def test_show_config_prints_and_writes_nothing(tmp_path, home):
    cfg, cfg_path = make_config(tmp_path / "cfg")
    install_antigravity(home, cfg_path)
    proj = project(tmp_path)
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    code, out, err = cli(proj, "--show-config")
    assert code == 0, out + err
    assert out.splitlines() == [
        f"using config {cfg_path} (from the installed antigravity hook)",
        f"  feedback store  {cfg['feedback']['feedback_file']}",
        f"  ledger          {cfg['ledger_file']}",
        "Nothing was written (--show-config).",
    ]
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


def test_show_config_without_hook_refuses(tmp_path, home):
    proj = project(tmp_path)
    code, out, err = cli(proj, "--show-config")
    assert code == 2 and out == ""
    assert "no installed semgate hook was found" in err and "--config" in err


def test_missing_decision_without_show_config_is_an_error(tmp_path, home):
    code, out, err = cli(project(tmp_path), "allow")
    assert code == 2 and "required" in err
