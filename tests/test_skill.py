"""The `semgate` agent skill (semgate/skill.py, semgate/assets/semgate_skill.md):
its text, and `semgate init` / `semgate uninstall` writing it into each host's
user-level skills folder. HOME and USERPROFILE are temp dirs (conftest)."""
import os
import re
from pathlib import Path

import pytest

from semgate import skill
from semgate.cli import main

HOME_PATHS = {"claude": (".claude", "skills", "semgate", "SKILL.md"),
              "antigravity": (".gemini", "config", "skills", "semgate", "SKILL.md"),
              "codex": (".agents", "skills", "semgate", "SKILL.md"),
              "opencode": (".agents", "skills", "semgate", "SKILL.md"),
              "pi": (".agents", "skills", "semgate", "SKILL.md"),
              "droid": (".agents", "skills", "semgate", "SKILL.md"),
              "copilot": (".agents", "skills", "semgate", "SKILL.md")}


def home():
    return Path(os.path.expanduser("~"))


def init(tmp_path, host, *extra):
    return main(["init", host, "--purpose", "Dev work in the demo project", "--provider", "none",
                 "--dir", str(tmp_path / "semgate" / host), "--hooks-file", str(tmp_path / "hooks" / host / "hooks.file"),
                 *extra])


def home_hooks(host):
    """The host's default user-level hooks file under the temp HOME (so
    hook_configs finds the installed hook)."""
    from semgate.hosts import ADAPTERS
    from semgate.hosts.base import HostEnv
    return ADAPTERS[host].config_paths(HostEnv.current(run_binaries=False)).hooks_file


def test_skill_text_is_short_literal_and_covers_the_rules():
    body = skill.text()
    front = re.match(r"---\nname: semgate\ndescription: (.+)\n---\n", body)
    assert front and len(front.group(1)) < 400
    assert len(body.splitlines()) <= 80 and skill.MARKER in body
    for must in ("permission prompt", "Do not ask the user again", "one time", "cannot be approved in chat",
                 "Never retry", "semgate trust add \"<exact command>\" --days N", "security review", "at most 30",
                 "Never on your own", "semgate feedback allow", "~/.semgate", "instruction file",
                 "semgate trust file <file>", "Show that text to the user exactly"):
        assert must in body, must
    for figurative in ("smoke detector", "mirror", "gatekeeper", "guardian", "like a "):
        assert figurative not in body.lower()


@pytest.mark.parametrize("host", sorted(HOME_PATHS))
def test_init_writes_the_skill_where_the_host_reads_it(tmp_path, host, capsys):
    assert init(tmp_path, host) == 0
    path = home().joinpath(*HOME_PATHS[host])
    assert path.read_text(encoding="utf-8") == skill.text(skill.command())
    assert "skill: write" in capsys.readouterr().out
    assert init(tmp_path, host) == 0                                        # idempotent
    assert "skill: unchanged" in capsys.readouterr().out


def test_every_init_host_has_a_skill_location():
    from semgate.init_antigravity import HOST_DEFAULTS
    assert set(HOST_DEFAULTS) <= set(skill.LOCATIONS)


def test_no_skill_flag_and_dry_run(tmp_path, capsys):
    assert init(tmp_path, "claude", "--no-skill") == 0
    assert not home().joinpath(*HOME_PATHS["claude"]).exists()
    assert init(tmp_path, "claude", "--dry-run", "--force") == 0
    assert "skill: would write" in capsys.readouterr().out
    assert not home().joinpath(*HOME_PATHS["claude"]).exists()


def test_a_users_own_skill_named_semgate_is_never_overwritten_or_removed(tmp_path, capsys, human_terminal):
    path = home().joinpath(*HOME_PATHS["claude"])
    path.parent.mkdir(parents=True)
    path.write_text("---\nname: semgate\ndescription: mine\n---\nmy notes\n", encoding="utf-8")
    assert init(tmp_path, "claude") == 0
    assert "skill: refused" in capsys.readouterr().out and "my notes" in path.read_text(encoding="utf-8")
    assert main(["uninstall", "claude", "--hooks-file", str(tmp_path / "hooks" / "claude" / "hooks.file")]) == 0
    assert path.is_file()


def test_uninstall_removes_the_hosts_own_skill_and_the_shared_one_only_after_the_last_host(tmp_path, capsys, human_terminal):
    for host in ("claude", "codex", "pi"):
        assert init(tmp_path, host, "--hooks-file", str(home_hooks(host))) == 0
    assert main(["uninstall", "claude", "--hooks-file", str(home_hooks("claude"))]) == 0
    assert not home().joinpath(*HOME_PATHS["claude"]).exists()
    assert not home().joinpath(*HOME_PATHS["claude"][:-1]).exists()        # the empty semgate/ folder too
    capsys.readouterr()
    assert main(["uninstall", "codex", "--hooks-file", str(home_hooks("codex"))]) == 0
    assert "kept: pi still use it" in capsys.readouterr().out
    assert home().joinpath(*HOME_PATHS["codex"]).is_file()
    assert main(["uninstall", "pi", "--hooks-file", str(home_hooks("pi"))]) == 0
    assert "skill: removed" in capsys.readouterr().out
    assert not home().joinpath(*HOME_PATHS["pi"]).exists()


def test_the_skill_is_package_data():
    text = Path(__file__).resolve().parents[1].joinpath("pyproject.toml").read_text(encoding="utf-8")
    assert '"semgate.assets" = ["*.js", "*.ts", "*.md"]' in text


VENV_CMD = "C:/Users/a/.venv/Scripts/semgate.exe"


def test_the_skill_names_this_installs_semgate_command():
    """A venv's Scripts folder is not on the agent shell's PATH, so the skill
    names the absolute command: no quotes, no backslash, no space."""
    cmd = skill.command()
    assert cmd == "semgate" or not re.search(r"""[\s"'\\]""", cmd.replace(" -m semgate", "")), cmd
    body = skill.text(VENV_CMD)
    assert f"`{VENV_CMD} trust add \"<exact command>\" --days N`" in body
    assert f"`{VENV_CMD} trust file <file>`" in body and "`semgate trust " not in body
    assert f"In this install the semgate command is `{VENV_CMD}`" in body
    assert "Never run `semgate feedback allow`" in body          # the user's command, unchanged
    assert skill.text("semgate") == skill.text()


@pytest.mark.parametrize("cmd", [VENV_CMD, "/home/a/venv/bin/semgate", "C:/PROGRA~1/Python312/python.exe -m semgate",
                                 "/usr/bin/python3.10 -m semgate"])
def test_the_trust_gate_reads_the_command_the_skill_names(cmd):
    from semgate import trust
    assert trust.parse_add(f'{cmd} trust add "npm test" --days 7') == trust.AddRequest("npm test", 7, True)
    assert trust.parse_file(f"{cmd} trust file AGENTS.md").command == "AGENTS.md"
    assert trust.harmless(f"{cmd} trust list")
    assert trust.request_hit(f'{cmd} trust add "npm test"')


def _fake_semgate(folder):
    folder.mkdir(parents=True, exist_ok=True)
    for name in ("semgate", "semgate.exe"):
        (folder / name).write_text("", encoding="utf-8")
        (folder / name).chmod(0o755)


def test_a_semgate_on_path_is_used_bare(tmp_path, monkeypatch):
    """pipx, `pip install --user`, a system install: `semgate` is on PATH and
    a bare `semgate trust add` has no path for the grant's scope to block."""
    _fake_semgate(tmp_path / "bin")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert skill.command() == "semgate"


def test_a_semgate_only_in_the_active_venv_is_written_absolute(tmp_path, monkeypatch):
    """The live agy case: `semgate init` ran with the venv active, so its
    Scripts folder was on PATH; the agent's shell does not activate it."""
    import sys
    scripts = tmp_path / "venv" / ("Scripts" if os.name == "nt" else "bin")
    _fake_semgate(scripts)
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(python))
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))
    monkeypatch.setenv("PATH", str(scripts))
    cmd = skill.command()
    name = "semgate.exe" if os.name == "nt" else "semgate"
    if skill._bare(scripts / name) is not None:            # a temp path without spaces
        assert cmd == skill._bare(scripts / name) and cmd.endswith("/" + name) and "\\" not in cmd
