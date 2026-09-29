"""`semgate doctor`: read only, one line per detected host, warnings, key location."""
import builtins
import io
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

from semgate import doctor
from semgate.cli import main
from semgate.hosts.base import HostEnv
from semgate.init_antigravity import opencode_plugin_source

SECRET = "sk-test-DO-NOT-PRINT-1234567890"
VERSIONS = {"claude": "2.1.280", "codex": "0.160.0", "opencode": "1.18.31", "agy": "1.2.8", "pi": "0.86.0", "droid": ""}


def _bin(bindir: Path, name: str) -> None:
    for fname in (name, name + ".exe"):
        p = bindir / fname
        p.write_text("", encoding="utf-8")
        p.chmod(0o755)


def build_home(root: Path) -> dict:
    """A temp home with fake installs of every priority host."""
    home = root / "home"
    bindir = root / "bin"
    for d in (home, bindir):
        d.mkdir(parents=True)
    for name in VERSIONS:
        _bin(bindir, name)
    py = Path(sys.executable).resolve()
    # semgate's own config for claude (enforce) and opencode (shadow)
    grant = {"grant_id": "g", "principal": "p", "purpose": "dev", "expires_at": "2099-01-01T00:00:00Z"}
    for host, mode in (("claude", "enforce"), ("opencode", "shadow")):
        d = home / ".semgate" / host
        d.mkdir(parents=True)
        (d / "grant.json").write_text(json.dumps(grant), encoding="utf-8")
        (d / "semgate.json").write_text(json.dumps({
            "mode": mode, "provider": "typesafe", "grant_file": str(d / "grant.json"),
            "enforcement": {"enabled": mode == "enforce", "block_when_unsure": True, "auto_allow_tools": ["read"]}}), encoding="utf-8")
    (home / ".semgate" / ".env").write_text(f"TYPESAFE_API_KEY={SECRET}\n", encoding="utf-8")
    # Claude Code: hook installed, but bypassPermissions
    cfg = home / ".semgate" / "claude" / "semgate.json"
    cmd = f'"{py}" -m semgate.claude_hook --config "{cfg}" --host auto'
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"defaultMode": "bypassPermissions"},
        "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 30}]}]}}), encoding="utf-8")
    # OpenCode: plugin installed, bash "*": "allow" in a JSONC config
    oc = home / ".config" / "opencode"
    (oc / "plugins").mkdir(parents=True)
    (oc / "plugins" / "semgate.js").write_text(opencode_plugin_source(py, home / ".semgate" / "opencode" / "semgate.json"), encoding="utf-8")
    (oc / "opencode.jsonc").write_text('{\n  // mine\n  "permission": {"bash": {"*": "allow"}},\n}\n', encoding="utf-8")
    # agy: installed, no semgate hook, yolo
    (home / ".gemini" / "config").mkdir(parents=True)
    (home / ".gemini" / "settings.json").write_text(json.dumps({"general": {"defaultApprovalMode": "yolo"}}), encoding="utf-8")
    # Codex: never asks
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('approval_policy = "never"\nmodel = "gpt-5.5"\n', encoding="utf-8")
    # Pi
    (home / ".pi" / "agent").mkdir(parents=True)
    # VS Code settings (JSONC) with auto-approve
    vs = home / "AppData" / "Code" / "User"
    vs.mkdir(parents=True)
    (vs / "settings.json").write_text('{\n  // editor\n  "chat.tools.autoApprove": true\n}\n', encoding="utf-8")
    environ = {"PATH": str(bindir), "HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home / "AppData"),
               "XDG_CONFIG_HOME": str(home / ".config")}
    return {"home": home, "environ": environ}


def probe(binary: str) -> str:
    return VERSIONS.get(Path(binary).stem, "")


@pytest.fixture
def fake(tmp_path, monkeypatch):
    info = build_home(tmp_path)
    for k, v in info["environ"].items():
        monkeypatch.setenv(k, v)
    for k in ("TYPESAFE_API_KEY", "OPENROUTER_API_KEY", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "PI_CODING_AGENT_DIR"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(doctor, "SOURCE_ENV", tmp_path / "no-source-env")
    return info


def run(fake):
    return doctor.run_doctor(HostEnv(fake["home"], fake["environ"], None, probe))


def test_one_line_per_detected_host_and_findings(fake):
    report = run(fake)
    by = {h["host"]: h for h in report["hosts"]}
    assert set(by) == {"claude", "droid", "antigravity", "opencode", "codex", "pi", "vscode"}
    text = doctor.render(report)
    host_lines = [l for l in text.splitlines() if l.split(" ")[0] in by]
    assert len(host_lines) == 7

    assert by["claude"]["status"] == "WARN" and by["claude"]["version"] == "2.1.280"
    assert "Claude Code 2.1.280: core L4*, ask supported" in by["claude"]["conformance"]
    assert any("bypassPermissions" in f["text"] and "only gate" in f["text"] for f in by["claude"]["findings"])
    assert any(f["level"] == "OK" and f["text"].startswith("enforce, block_when_unsure on: every ask is a block")
               and "Claude Code would show it as its own prompt" in f["text"] for f in by["claude"]["findings"])

    assert by["opencode"]["conformance"] == "OpenCode V1 1.18.31: core none, ask no -> ask maps to deny"
    assert any('bash "*" is "allow"' in f["text"] for f in by["opencode"]["findings"])
    assert any(f["level"] == "WARN" and f["text"].startswith("developer shadow mode") and "init opencode --force" in f["text"]
               for f in by["opencode"]["findings"])

    assert by["antigravity"]["status"] == "FAIL" and "semgate hook not installed" in by["antigravity"]["headline"]
    assert any("'yolo'" in f["text"] for f in by["antigravity"]["findings"])
    assert by["droid"]["status"] == "FAIL"

    codex = by["codex"]
    assert any("0.160.0 is not measured (manifest measured 0.153.1)" in f["text"] for f in codex["findings"])
    assert any('approval_policy = "never"' in f["text"] for f in codex["findings"])
    assert codex["manifest"]["ask_maps_to"] == "deny"
    assert by["pi"]["status"] == "FAIL"
    assert any("semgate Pi extension not installed" in f["text"] for f in by["pi"]["findings"])
    assert by["vscode"]["status"] == "WARN" and any("chat.tools.autoApprove" in f["text"] for f in by["vscode"]["findings"])

    assert report["typesafe_key"] == {"found": True, "location": "file ~/.semgate/.env"}
    assert "Summary: 7 host(s) detected" in text and "TypeSafe key: found (file ~/.semgate/.env)" in text


def test_key_is_never_printed(fake, capsys):
    report = run(fake)
    blob = json.dumps(report) + doctor.render(report)
    assert SECRET not in blob and SECRET[:8] not in blob
    assert set(report["typesafe_key"]) == {"found", "location"}          # no value, no length
    fake["environ"]["SEMGATE_TYPESAFE_API_KEY"] = SECRET
    report = run(fake)
    assert report["typesafe_key"] == {"found": True, "location": "environment variable SEMGATE_TYPESAFE_API_KEY"}
    assert SECRET not in json.dumps(report)


def test_key_not_found_is_reported(fake):
    (fake["home"] / ".semgate" / ".env").write_text("OTHER=1\nTYPESAFE_API_KEY=\n", encoding="utf-8")
    report = run(fake)
    assert report["typesafe_key"] == {"found": False, "location": ""}
    assert "no key was found" in doctor.render(report)


def test_hook_pointing_at_a_missing_interpreter_fails(fake):
    s = fake["home"] / ".claude" / "settings.json"
    s.write_text(s.read_text(encoding="utf-8").replace(Path(sys.executable).resolve().name, "gone-python.exe"), encoding="utf-8")
    by = {h["host"]: h for h in run(fake)["hosts"]}
    assert by["claude"]["status"] == "FAIL" and any("interpreter missing" in f["text"] for f in by["claude"]["findings"])


def _snapshot(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.stat()
        out[str(p)] = (p.is_dir(), st.st_size, st.st_mtime_ns, None if p.is_dir() else p.read_bytes())
    return out


def test_doctor_never_writes(fake, tmp_path, monkeypatch, capsys):
    root = tmp_path
    for p in root.rglob("*"):
        if p.is_file():
            p.chmod(stat.S_IREAD)
    before = _snapshot(root)

    def forbid(name):
        def f(*a, **k):
            raise AssertionError(f"doctor tried to write: {name} {a[:1]}")
        return f
    real_open = builtins.open

    def guarded_open(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"doctor opened {file} for writing")
        return real_open(file, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    for mod, names in ((os, ("replace", "rename", "mkdir", "makedirs", "remove", "unlink", "rmdir")),
                       (shutil, ("copy", "copy2", "copyfile", "move", "rmtree"))):
        for n in names:
            monkeypatch.setattr(mod, n, forbid(n))
    for n in ("write_text", "write_bytes", "mkdir", "touch", "unlink", "rename", "replace"):
        monkeypatch.setattr(Path, n, forbid(n))
    try:
        run(fake)
        assert main(["doctor", "--no-exec"]) == 1            # agy and droid FAIL: hook not installed
        assert main(["doctor", "--no-exec", "--json"]) == 1
        out = capsys.readouterr().out
        assert json.loads(out[out.index("{"):])["hosts"]
    finally:
        monkeypatch.undo()
        for p in root.rglob("*"):
            if p.is_file():
                p.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert _snapshot(root) == before


def test_empty_home_reports_nothing_detected(tmp_path):
    home = tmp_path / "empty"
    home.mkdir()
    report = doctor.run_doctor(HostEnv(home, {"PATH": str(tmp_path / "nobin")}, None, None))
    assert report["hosts"] == [] and "no supported host detected" in doctor.render(report)


def test_hook_interpreter_that_cannot_import_semgate_fails(fake, tmp_path, monkeypatch):
    """A Linux venv hook written as the resolved /usr/bin/python3.x exists but
    cannot import semgate; doctor runs `<python> -c "import semgate"` (not
    with --no-exec)."""
    import venv
    venv.create(tmp_path / "bare", with_pip=False)
    bare = tmp_path / "bare" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    s = fake["home"] / ".claude" / "settings.json"
    escaped = lambda p: json.dumps(str(p))[1:-1]  # noqa: E731
    s.write_text(s.read_text(encoding="utf-8").replace(escaped(Path(sys.executable).resolve()), escaped(bare)), encoding="utf-8")
    monkeypatch.delenv("PYTHONPATH", raising=False)
    by = {h["host"]: h for h in run(fake)["hosts"]}
    assert by["claude"]["status"] == "FAIL"
    assert any("cannot import semgate" in f["text"] for f in by["claude"]["findings"]), by["claude"]["findings"]
    no_exec = doctor.run_doctor(HostEnv(fake["home"], fake["environ"], None, None))
    claude = next(h for h in no_exec["hosts"] if h["host"] == "claude")
    assert not any("cannot import semgate" in f["text"] for f in claude["findings"])


def test_doctor_says_whether_semgate_is_on_path(fake):
    report = run(fake)
    assert report["semgate_command"]["on_path"] == ""
    assert "semgate is not on PATH" in doctor.render(report) or "`semgate` is not on PATH" in doctor.render(report)
    _bin(Path(fake["environ"]["PATH"]), "semgate")
    report = run(fake)
    assert report["semgate_command"]["on_path"] and "not on PATH" not in doctor.render(report)


# ---------------------------------------------------------------- block_when_unsure by the init rule


@pytest.mark.parametrize("host,on,level,text", [
    ("claude", False, "OK", "enforce, block_when_unsure off: Claude Code shows semgate's ask as its own prompt"),
    ("claude", True, "OK", "enforce, block_when_unsure on: every ask is a block you approve in the chat"),
    ("antigravity", True, "OK", "enforce, block_when_unsure on"),
    ("antigravity", False, "WARN", "enforce without block_when_unsure: Antigravity CLI (agy) does not show semgate's ask"),
    ("droid", False, "WARN", "enforce without block_when_unsure: Factory Droid does not show"),
    ("codex", False, "WARN", "enforce without block_when_unsure: Codex CLI"),
    ("unknown", False, "WARN", "enforce without block_when_unsure: this host does not show"),
])
def test_block_when_unsure_finding_follows_the_init_rule(tmp_path, host, on, level, text):
    from semgate.hosts.builtin import check_semgate_config
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"purpose": "dev", "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = tmp_path / "semgate.json"
    cfg.write_text(json.dumps({"mode": "enforce", "grant_file": str(grant),
                               "enforcement": {"enabled": True, "block_when_unsure": on}}), encoding="utf-8")
    found = [f for f in check_semgate_config(cfg, {}, host) if "block_when_unsure" in f.text]
    assert len(found) == 1 and found[0].level == level and found[0].text.startswith(text), found
    if host == "antigravity" and on:
        assert found[0].text == "enforce, block_when_unsure on"
