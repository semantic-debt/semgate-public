"""Stale plugin copies: stamps, doctor detection (user level, project,
recorded), and `semgate init <host> --refresh`.

Found live: a project copy of the OpenCode plugin written before
windowsHide was added kept opening a console window; later fixes in the
asset never reach copies `semgate init` wrote earlier.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from semgate import codestamp, doctor
from semgate.cli import main
from semgate.hosts import get
from semgate.hosts.base import HostEnv
from semgate.init_antigravity import opencode_plugin_source, pi_extension_source

PY = Path(sys.executable)


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A temp home; no variable may point a host at a real folder."""
    h = tmp_path / "home"
    h.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(h))
    for var in ("XDG_CONFIG_HOME", "PI_CODING_AGENT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(doctor, "SOURCE_ENV", tmp_path / "no-source-env")
    return h


def _semgate_dir(root: Path, name: str = "semgate") -> Path:
    d = root / name
    d.mkdir(parents=True)
    (d / "grant.json").write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "dev",
                                              "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    (d / "semgate.json").write_text(json.dumps({"mode": "shadow", "provider": "none", "grant_file": str(d / "grant.json"),
                                                "ledger_file": str(d / "ledger.jsonl")}), encoding="utf-8")
    return d


def _old_copy(text: str) -> str:
    """The copy as an older semgate wrote it: no stamp line, no windowsHide."""
    lines = text.splitlines(keepends=True)
    assert lines[0].startswith(codestamp.STAMP_PREFIX)
    return "".join(lines[1:]).replace(", windowsHide: true", "")


def _env(home: Path, project=None, cwd=None) -> HostEnv:
    return HostEnv(home, {"HOME": str(home), "USERPROFILE": str(home)}, project, None, cwd)


def _by_host(report):
    return {h["host"]: h for h in report["hosts"]}


# ---------------------------------------------------------------- stamps


def test_rendered_copies_carry_a_deterministic_stamp_of_the_source_asset(tmp_path):
    for host, render in (("opencode", opencode_plugin_source), ("pi", pi_extension_source)):
        name = codestamp.ASSETS[host]
        source = codestamp.asset_source(name)
        sha = hashlib.sha256(source.replace("\r\n", "\n").encode("utf-8")).hexdigest()
        a = render(PY, tmp_path / "a" / "semgate.json")
        b = render(Path("/other/python"), tmp_path / "b" / "semgate.json")
        first = a.splitlines()[0]
        assert first == f"// semgate-asset: {name} sha256={sha} version={codestamp.__version__}"
        assert b.splitlines()[0] == first                           # the stamp is of the source, not the copy
        assert a == render(PY, tmp_path / "a" / "semgate.json")     # same inputs, same bytes
        assert codestamp.ASSET_PLACEHOLDER not in a and a.count(f"{name} sha256={sha}") == 2   # stamp line + ASSET
        assert codestamp.copy_status(a, name) == ("current", f"sha {sha[:12]} version {codestamp.__version__}")
        # CRLF in a checkout gives the same sha
        assert codestamp.asset_sha256(name, source.replace("\n", "\r\n")) == sha


def test_copy_status_old_unstamped_and_foreign():
    name = "opencode_semgate.js"
    text = opencode_plugin_source(PY, Path("/x/semgate.json"))
    sha = codestamp.asset_sha256(name)
    older = text.replace(f"sha256={sha}", "sha256=" + "1" * 64, 1)
    status, detail = codestamp.copy_status(older, name)
    assert status == "outdated" and detail.startswith("installed sha 111111111111") and f"vs current {sha[:12]}" in detail
    assert codestamp.copy_status(_old_copy(text), name)[0] == "unstamped"
    assert codestamp.copy_status("export default {}\n", name)[0] == "foreign"
    assert not codestamp.is_semgate_copy("export default {}\n") and codestamp.is_semgate_copy(_old_copy(text))


# ---------------------------------------------------------------- doctor


def test_doctor_finds_a_project_copy_from_the_current_folder_and_from_project(home, tmp_path):
    d = _semgate_dir(home / ".semgate", "opencode")
    proj = tmp_path / "proj"
    (proj / ".opencode" / "plugin").mkdir(parents=True)
    copy = proj / ".opencode" / "plugin" / "semgate.js"
    copy.write_text(opencode_plugin_source(PY, d / "semgate.json"), encoding="utf-8")
    (home / ".config" / "opencode").mkdir(parents=True)             # OpenCode detected, no user-level plugin
    # before: only ~/.config/opencode/plugins/semgate.js was looked at
    for env in (_env(home, cwd=proj), _env(home, project=proj, cwd=tmp_path)):
        oc = _by_host(doctor.run_doctor(env))["opencode"]
        assert oc["status"] != "FAIL" and oc["headline"].startswith("hook installed"), oc
        assert [c["path"] for c in oc["facts"]["copies"]] == [str(copy)]
        assert not any("older than the installed semgate" in f["text"] for f in oc["findings"])
    oc = _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))["opencode"]
    assert oc["status"] == "FAIL" and "semgate plugin not installed" in oc["headline"] and str(proj) not in oc["headline"]


def test_a_project_copy_alone_makes_the_host_detected(home, tmp_path):
    """No `opencode` on PATH, no ~/.config/opencode: before, doctor did not
    list OpenCode at all."""
    d = _semgate_dir(home / ".semgate", "opencode")
    proj = tmp_path / "proj"
    (proj / ".opencode" / "plugin").mkdir(parents=True)
    (proj / ".opencode" / "plugin" / "semgate.js").write_text(opencode_plugin_source(PY, d / "semgate.json"), encoding="utf-8")
    oc = _by_host(doctor.run_doctor(_env(home, cwd=proj)))["opencode"]
    assert oc["detected_by"] == "semgate plugin copy" and oc["headline"].startswith("hook installed")
    assert "opencode" not in _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))


def test_doctor_warns_about_old_copies_with_the_refresh_command(home, tmp_path):
    d = _semgate_dir(home / ".semgate", "opencode")
    current = opencode_plugin_source(PY, d / "semgate.json")
    user = home / ".config" / "opencode" / "plugins" / "semgate.js"
    user.parent.mkdir(parents=True)
    user.write_text(current.replace(f"sha256={codestamp.asset_sha256('opencode_semgate.js')}", "sha256=" + "2" * 64, 1),
                    encoding="utf-8")
    proj = tmp_path / "proj"
    (proj / ".opencode" / "plugins").mkdir(parents=True)
    (proj / ".opencode" / "plugins" / "semgate.js").write_text(_old_copy(current), encoding="utf-8")
    oc = _by_host(doctor.run_doctor(_env(home, cwd=proj)))["opencode"]
    warns = [f["text"] for f in oc["findings"] if f["level"] == "WARN" and "older than the installed semgate" in f["text"]]
    assert len(warns) == 2 and oc["status"] == "WARN"
    assert f"plugin copy {user} is older than the installed semgate (installed sha 222222222222" in warns[0]
    assert "run `semgate init opencode --refresh`" in warns[0]
    assert "no stamp" in warns[1] and f'semgate init opencode --refresh --project "{proj}"' in warns[1]


def test_doctor_finds_a_copy_init_recorded_anywhere(home, tmp_path, monkeypatch, capsys):
    target = home / ".semgate" / "opencode"
    (home / ".config" / "opencode").mkdir(parents=True)                  # OpenCode detected
    elsewhere = tmp_path / "work" / "app" / ".opencode" / "plugin" / "semgate.js"
    assert main(["init", "opencode", "--purpose", "t", "--provider", "none", "--hooks-file", str(elsewhere),
                 "--no-skill"]) == 0
    rec = json.loads((target / "installed_files.json").read_text(encoding="utf-8"))
    assert rec["files"] == [{"host": "opencode", "path": str(elsewhere.resolve())}]
    oc = _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))["opencode"]
    assert [c["path"] for c in oc["facts"]["copies"]] == [str(elsewhere.resolve())] and oc["status"] != "FAIL"


def test_doctor_pi_project_extension(home, tmp_path):
    d = _semgate_dir(home / ".semgate", "pi")
    (home / ".pi" / "agent").mkdir(parents=True)
    proj = tmp_path / "proj"
    ext = proj / ".pi" / "extensions" / "semgate.ts"
    ext.parent.mkdir(parents=True)
    ext.write_text(_old_copy(pi_extension_source(PY, d / "semgate.json")), encoding="utf-8")
    pi = _by_host(doctor.run_doctor(_env(home, project=proj)))["pi"]
    assert pi["headline"].startswith("hook installed")
    assert any("no stamp" in f["text"] and "semgate init pi --refresh --project" in f["text"] for f in pi["findings"])


def test_doctor_warns_when_the_running_host_loaded_an_old_plugin(home, tmp_path):
    from semgate.ledger import Ledger
    d = _semgate_dir(home / ".semgate", "opencode")
    user = home / ".config" / "opencode" / "plugins" / "semgate.js"
    user.parent.mkdir(parents=True)
    user.write_text(opencode_plugin_source(PY, d / "semgate.json"), encoding="utf-8")   # the file is current
    ledger = Ledger(str(d / "ledger.jsonl"))
    ledger.record_serve_event("client", {"pid": 4242, "host": "opencode", "plugin_stamp": "", "outdated": True})
    oc = _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))["opencode"]
    [w] = [f["text"] for f in oc["findings"] if "running OpenCode" in f["text"]]
    assert "serve pid 4242" in w and "no stamp" in w and "restart OpenCode" in w
    ledger.record_serve_event("client", {"pid": 4343, "host": "opencode", "plugin_stamp": codestamp.stamp("opencode_semgate.js"),
                                         "outdated": False})
    oc = _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))["opencode"]
    assert not any("running OpenCode" in f["text"] for f in oc["findings"])


def test_doctor_warns_about_an_old_json_hook_command(home, tmp_path):
    d = _semgate_dir(home / ".semgate", "claude")
    cmd = f'"{PY}" -m semgate.claude_hook --config "{d / "semgate.json"}" --host auto'     # before 2026-09-24
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 30}]}]}}),
        encoding="utf-8")
    cl = _by_host(doctor.run_doctor(_env(home, cwd=tmp_path)))["claude"]
    assert any("differs from what the installed semgate writes" in f["text"] and "semgate init claude --refresh" in f["text"]
               for f in cl["findings"])


# ---------------------------------------------------------------- init --refresh


def _snapshot(folder: Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir()) if p.is_file()}


def _backups(path: Path):
    return sorted(path.parent.glob(path.name + ".semgate-bak-*"))


def test_refresh_rewrites_only_the_plugin_and_keeps_config_grant_and_stores(home, tmp_path, capsys):
    target = tmp_path / "sg"
    plugin = tmp_path / "proj" / ".opencode" / "plugin" / "semgate.js"
    assert main(["init", "opencode", "--purpose", "t", "--provider", "none", "--dir", str(target),
                 "--hooks-file", str(plugin), "--no-skill"]) == 0
    current = plugin.read_text(encoding="utf-8")
    old = _old_copy(current)
    plugin.write_text(old, encoding="utf-8")
    for name in ("ledger.jsonl", "feedback.jsonl", "tool_history.jsonl"):
        (target / name).write_text('{"record_type": "x"}\n', encoding="utf-8")
    before = _snapshot(target)
    capsys.readouterr()
    assert main(["init", "opencode", "--refresh", "--hooks-file", str(plugin), "--no-skill"]) == 0
    out = capsys.readouterr().out
    assert "refreshed" in out and str(plugin) in out and "backup" in out
    assert plugin.read_text(encoding="utf-8") == current                       # same interpreter and config as before
    assert "windowsHide: true" in current
    [bak] = _backups(plugin)
    assert bak.read_text(encoding="utf-8") == old
    assert _snapshot(target) == before                                           # semgate.json, grant, ledger, stores
    # nothing more to do: no new backup
    assert main(["init", "opencode", "--refresh", "--hooks-file", str(plugin), "--no-skill"]) == 0
    assert "unchanged (current)" in capsys.readouterr().out and len(_backups(plugin)) == 1


def test_refresh_finds_user_level_project_and_recorded_copies(home, tmp_path, monkeypatch, capsys):
    target = home / ".semgate" / "opencode"
    user = home / ".config" / "opencode" / "plugins" / "semgate.js"
    recorded = tmp_path / "elsewhere" / ".opencode" / "plugins" / "semgate.js"
    assert main(["init", "opencode", "--purpose", "t", "--provider", "none", "--no-skill"]) == 0
    assert main(["init", "opencode", "--purpose", "t", "--provider", "none", "--no-skill", "--hooks-file", str(recorded)]) == 0
    proj = tmp_path / "proj"
    project_copy = proj / ".opencode" / "plugin" / "semgate.js"
    project_copy.parent.mkdir(parents=True)
    current = user.read_text(encoding="utf-8")
    for p in (user, recorded, project_copy):
        p.write_text(_old_copy(current), encoding="utf-8")
    cfg_before = _snapshot(target)
    monkeypatch.chdir(proj)                                                       # project = the current folder
    capsys.readouterr()
    assert main(["init", "opencode", "--refresh", "--no-skill"]) == 0
    out = capsys.readouterr().out
    assert out.count("refreshed") == 3
    for p in (user, recorded, project_copy):
        assert p.read_text(encoding="utf-8") == current and len(_backups(p)) == 1
    assert _snapshot(target) == cfg_before
    oc = _by_host(doctor.run_doctor(HostEnv.current(run_binaries=False)))["opencode"]
    assert not any("older than the installed semgate" in f["text"] for f in oc["findings"])


def test_refresh_refuses_a_file_without_semgate_mark_unless_force(home, tmp_path, capsys):
    foreign = tmp_path / "plugins" / "semgate.js"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("export default { id: 'someone else' }\n", encoding="utf-8")
    assert main(["init", "opencode", "--refresh", "--hooks-file", str(foreign), "--no-skill"]) == 2
    assert "carries no semgate stamp or marker" in capsys.readouterr().err
    assert foreign.read_text(encoding="utf-8") == "export default { id: 'someone else' }\n" and not _backups(foreign)
    target = tmp_path / "sg"
    assert main(["init", "opencode", "--refresh", "--force", "--hooks-file", str(foreign), "--dir", str(target),
                 "--no-skill"]) == 0
    text = foreign.read_text(encoding="utf-8")
    assert codestamp.copy_status(text, "opencode_semgate.js")[0] == "current"
    assert f'"{(target / "semgate.json").as_posix()}"' in text
    [bak] = _backups(foreign)
    assert bak.read_text(encoding="utf-8").startswith("export default")
    assert not target.exists()                                                   # --refresh --force writes no config
    # nothing installed anywhere: refused, nothing written
    assert main(["init", "opencode", "--refresh", "--no-skill", "--project", str(tmp_path / "empty")]) == 2


def test_refresh_pi_extension_and_json_hook_entry(home, tmp_path, monkeypatch, capsys):
    agent = tmp_path / "agent"
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent))
    assert main(["init", "pi", "--purpose", "t", "--provider", "none", "--no-skill"]) == 0
    ext = agent / "extensions" / "semgate.ts"
    current = ext.read_text(encoding="utf-8")
    ext.write_text(_old_copy(current), encoding="utf-8")
    assert main(["init", "pi", "--refresh", "--no-skill"]) == 0
    assert ext.read_text(encoding="utf-8") == current and len(_backups(ext)) == 1

    d = _semgate_dir(home / ".semgate", "claude")
    cfg_before = _snapshot(d)
    old_cmd = f'"{PY}" -m semgate.claude_hook --config "{d / "semgate.json"}" --host auto'
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"model": "keep-me", "hooks": {"PreToolUse": [
        {"matcher": "*", "hooks": [{"type": "command", "command": old_cmd, "timeout": 30}]},
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool check"}]}]}}, indent=2), encoding="utf-8")
    assert main(["init", "claude", "--refresh", "--no-skill"]) == 0
    doc = json.loads(settings.read_text(encoding="utf-8"))
    cmds = [h["command"] for g in doc["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "other-tool check" in cmds and doc["model"] == "keep-me"
    assert any(c.endswith("--host claude") and str(d / "semgate.json") in c for c in cmds) and old_cmd not in cmds
    assert "PostToolUse" in doc["hooks"] and "Stop" in doc["hooks"]
    assert len(_backups(settings)) == 1 and _snapshot(d) == cfg_before
    # a settings file without semgate's entry is refused without --force
    other = tmp_path / "other-settings.json"
    other.write_text('{"model": "x"}\n', encoding="utf-8")
    assert main(["init", "claude", "--refresh", "--hooks-file", str(other), "--no-skill"]) == 2
    assert other.read_text(encoding="utf-8") == '{"model": "x"}\n'


def test_refresh_rewrites_the_skill_only_when_it_is_semgates(home, tmp_path, capsys):
    from semgate import skill
    assert main(["init", "opencode", "--purpose", "t", "--provider", "none"]) == 0
    path = skill.path_for("opencode")
    path.write_text(path.read_text(encoding="utf-8") + "\nA line an older semgate wrote.\n", encoding="utf-8")
    capsys.readouterr()
    assert main(["init", "opencode", "--refresh"]) == 0
    assert "skill: write" in capsys.readouterr().out
    assert path.read_text(encoding="utf-8") == skill.text(skill.command()) and len(_backups(path)) == 1
    path.write_text("# my own skill\n", encoding="utf-8")
    assert main(["init", "opencode", "--refresh"]) == 0
    assert "skill: refused" in capsys.readouterr().out and path.read_text(encoding="utf-8") == "# my own skill\n"
    path.unlink()                                          # a missing skill is not added by a refresh
    assert main(["init", "opencode", "--refresh"]) == 0
    assert "skill: not installed, not written" in capsys.readouterr().out and not path.exists()
