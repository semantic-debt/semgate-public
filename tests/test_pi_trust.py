"""Pi project trust (semgate/hosts/pitrust.py): Pi 0.87.1 loads a
project-level extension only for a trusted project, and `pi -p` skips it
without a message. `semgate init pi` and `semgate doctor` must say so, with the
fix, and never change Pi's trust files.

Every test uses a temp HOME/USERPROFILE (conftest) and a temp
PI_CODING_AGENT_DIR with a fake Pi config. No real ~/.pi is read."""
import json
import os
from pathlib import Path

import pytest

from semgate import doctor
from semgate.cli import main
from semgate.hosts import pitrust
from semgate.hosts.base import HostEnv
from semgate.hosts.builtin import PiHost


@pytest.fixture
def pi(tmp_path, monkeypatch):
    home = tmp_path / "home"
    agent = tmp_path / "agent"
    project = tmp_path / "work" / "proj"
    for d in (home, agent, project):
        d.mkdir(parents=True)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent))
    monkeypatch.setattr(doctor, "SOURCE_ENV", tmp_path / "no-source-env")
    return {"home": home, "agent": agent, "project": project, "tmp": tmp_path,
            "ext": project / ".pi" / "extensions" / "semgate.ts"}


def _init(pi, *extra):
    argv = ["init", "pi", "--purpose", "Dev work", "--provider", "none", "--no-skill",
            "--dir", str(pi["tmp"] / "sg"), *extra]
    return main(argv)


def _init_project(pi):
    return _init(pi, "--project", str(pi["project"]), "--hooks-file", str(pi["ext"]))


def _key(path: Path) -> str:
    return os.path.realpath(path)


def _write(path: Path, doc) -> None:
    path.write_text(json.dumps(doc), encoding="utf-8")


def _pi_files(agent: Path):
    return sorted(p.name for p in agent.iterdir() if p.name != "extensions")


def test_init_project_level_without_trust_warns_with_the_fix(pi, capsys):
    assert _init_project(pi) == 0
    out = capsys.readouterr().out
    assert f"WARNING: Pi loads {pi['ext']} only for a trusted project." in out
    assert f"Trust status of {_key(pi['project'])}: ask" in out
    assert "defaultProjectTrust is not set (Pi's default is \"ask\")" in out
    assert "`pi -p` (print, JSON and RPC modes) skips the extension without a message" in out
    assert "the agent runs WITHOUT semgate" in out
    assert f"add {json.dumps(_key(pi['project']))}: true to {pi['agent'] / 'trust.json'}" in out
    assert "pi --approve" in out
    assert f"semgate init pi --purpose \"...\"  (writes {pi['agent'] / 'extensions' / 'semgate.ts'})" in out
    assert f"semgate uninstall pi --hooks-file \"{pi['ext']}\"" in out
    assert "semgate does not change Pi's trust settings." in out
    assert pi["ext"].is_file()
    assert _pi_files(pi["agent"]) == []            # no trust.json, no settings.json written


def test_init_dry_run_warns_too_and_writes_nothing(pi, capsys):
    assert _init(pi, "--project", str(pi["project"]), "--hooks-file", str(pi["ext"]), "--dry-run") == 0
    assert "WARNING: Pi loads" in capsys.readouterr().out
    assert not pi["ext"].exists() and _pi_files(pi["agent"]) == []


def test_default_ask_is_named(pi, capsys):
    _write(pi["agent"] / "settings.json", {"defaultProjectTrust": "ask", "theme": "dark"})
    assert _init_project(pi) == 0
    assert "defaultProjectTrust is \"ask\" in" in capsys.readouterr().out


def test_init_trusted_project_prints_no_warning(pi, capsys):
    _write(pi["agent"] / "trust.json", {_key(pi["project"]): True})
    before = (pi["agent"] / "trust.json").read_bytes()
    assert _init_project(pi) == 0
    out = capsys.readouterr().out
    assert "WARNING: Pi loads" not in out
    assert "Pi project trust: trusted" in out and "trusts" in out
    assert (pi["agent"] / "trust.json").read_bytes() == before


def test_trusted_parent_counts_and_the_closest_entry_wins(pi):
    env = HostEnv.current(run_binaries=False)
    parent = pi["project"].parent
    _write(pi["agent"] / "trust.json", {_key(parent): True})
    assert pitrust.trust_status(pi["project"], env).status == pitrust.TRUSTED
    _write(pi["agent"] / "trust.json", {_key(parent): True, _key(pi["project"]): False})
    st = pitrust.trust_status(pi["project"], env)
    assert st.status == pitrust.NOT_TRUSTED and "Do not trust" in st.why


def test_saved_decision_beats_default_project_trust(pi):
    env = HostEnv.current(run_binaries=False)
    _write(pi["agent"] / "settings.json", {"defaultProjectTrust": "always"})
    assert pitrust.trust_status(pi["project"], env).status == pitrust.TRUSTED
    _write(pi["agent"] / "trust.json", {_key(pi["project"]): False})
    assert pitrust.trust_status(pi["project"], env).status == pitrust.NOT_TRUSTED


def test_default_never_warns_for_every_mode(pi, capsys):
    _write(pi["agent"] / "settings.json", {"defaultProjectTrust": "never"})
    assert _init_project(pi) == 0
    out = capsys.readouterr().out
    assert "Trust status of" in out and ": not trusted (" in out
    assert "Pi skips the extension in every mode, without a message" in out


@pytest.mark.parametrize("bad", ["trust.json", "settings.json"])
def test_unreadable_pi_config_is_unknown_and_still_warns(pi, capsys, bad):
    (pi["agent"] / bad).write_text("{not json", encoding="utf-8")
    assert _init_project(pi) == 0
    out = capsys.readouterr().out
    assert ": unknown (" in out and "semgate cannot tell whether Pi loads it" in out
    assert "WARNING: Pi loads" in out
    assert (pi["agent"] / bad).read_text(encoding="utf-8") == "{not json"


def test_user_level_install_has_no_trust_notice(pi, capsys):
    assert _init(pi) == 0
    out = capsys.readouterr().out
    assert (pi["agent"] / "extensions" / "semgate.ts").is_file()
    assert "WARNING: Pi loads" not in out and "Pi project trust" not in out


def test_other_hosts_have_no_trust_notice(pi, capsys):
    argv = ["init", "opencode", "--purpose", "Dev work", "--provider", "none", "--no-skill",
            "--dir", str(pi["tmp"] / "sg-oc"), "--hooks-file", str(pi["tmp"] / "oc" / "semgate.js")]
    assert main(argv) == 0
    assert "Pi loads" not in capsys.readouterr().out


def test_project_of():
    env = HostEnv(Path("/h"), {"PI_CODING_AGENT_DIR": "/h/agent"})
    assert pitrust.project_of(Path("/w/proj/.pi/extensions/semgate.ts"), env) == Path(os.path.abspath("/w/proj"))
    assert pitrust.project_of(Path("/h/agent/extensions/semgate.ts"), env) is None
    assert pitrust.project_of(Path("/w/elsewhere/semgate.ts"), env) is None


# ---------------------------------------------------------------- doctor

def _doctor_env(pi):
    return HostEnv(Path.home(), dict(os.environ), pi["project"], None)


def test_doctor_warns_for_an_untrusted_project_copy(pi, capsys):
    assert _init_project(pi) == 0
    capsys.readouterr()
    findings, facts = PiHost().verify(_doctor_env(pi))
    warns = [f.text for f in findings if f.level == "WARN"]
    assert any(t.startswith(f"Pi loads {pi['ext']} only for a trusted project.") and "pi --approve" in t
               and "the agent runs WITHOUT semgate" in t for t in warns), warns
    assert facts["pi_trust"] == [{"path": str(pi["ext"]), "project": _key(pi["project"]), "status": "ask",
                                  "why": facts["pi_trust"][0]["why"]}]
    report = doctor.check_host(PiHost(), _doctor_env(pi))
    assert report["status"] == "WARN"
    assert _pi_files(pi["agent"]) == []            # doctor wrote nothing either


def test_doctor_is_quiet_when_trusted(pi, capsys):
    assert _init_project(pi) == 0
    _write(pi["agent"] / "trust.json", {_key(pi["project"]): True})
    findings, facts = PiHost().verify(_doctor_env(pi))
    assert not any("only for a trusted project" in f.text for f in findings)
    assert any(f.level == "INFO" and "Pi trusts project" in f.text for f in findings)
    assert facts["pi_trust"][0]["status"] == "trusted"


def test_doctor_render_shows_the_warning(pi, capsys):
    assert _init_project(pi) == 0
    report = {"hosts": [doctor.check_host(PiHost(), _doctor_env(pi))], "typesafe_key": {"found": False, "location": ""},
              "openrouter_key": {"found": False, "location": ""}, "semgate_command": {},
              "summary": {"detected": 1, "by_status": {"WARN": 1}, "typesafe_needed": False, "openrouter_needed": False,
                          "demo_hosts": []}}
    text = doctor.render(report)
    assert f"[WARN] pi: Pi loads {pi['ext']} only for a trusted project." in text
