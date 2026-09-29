"""Safe config merging (semgate/safemerge.py) and `semgate init` / `uninstall`
through the host adapters. Every test works in tmp_path with HOME and
USERPROFILE pointing there; conftest also sets SEMGATE_WRITE_ROOT so a write
outside the pytest temp root is refused."""
import json
import os
import sys
from pathlib import Path

import pytest

from semgate import safemerge
from semgate.cli import main
from semgate.hosts import get
from semgate.hosts.builtin import InstallRequest
from semgate.safemerge import MergePlan, MergeRefused

# init writes the absolute, NOT resolved, interpreter: a Linux venv's bin/python is a
# symlink to /usr/bin/python3.x, which cannot import the venv's semgate.
PY = Path(os.path.abspath(sys.executable))


@pytest.fixture(autouse=True)
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return home


def _under(path: Path, root: Path) -> Path:
    assert Path(path).resolve().is_relative_to(Path(root).resolve()), f"{path} is outside the test root"
    return path


def init(tmp_path, host, hooks_file, *extra):
    _under(hooks_file, tmp_path)
    return main(["init", host, "--purpose", "Dev work in the demo project", "--provider", "none",
                 "--dir", str(_under(tmp_path / "semgate", tmp_path)), "--hooks-file", str(hooks_file), *extra])


# ------------------------------------------------------------------ the old merge (113cf06), for equivalence


def _old_is_semgate(cmd):
    return isinstance(cmd, str) and ("semgate.claude_hook" in cmd or "semgate.antigravity_hook" in cmd or "semgate.antigravity_post_hook" in cmd)


def _old_without_semgate(groups):
    out = []
    for g in groups if isinstance(groups, list) else []:
        if not isinstance(g, dict):
            out.append(g)
            continue
        g = dict(g)
        g["hooks"] = [h for h in g.get("hooks", []) if not (isinstance(h, dict) and _old_is_semgate(h.get("command")))]
        if g["hooks"]:
            out.append(g)
    return out


def old_merge_hooks(host, existing, interpreter, config):
    data = dict(existing)
    if host == "antigravity":
        pre = f'"{interpreter}" -m semgate.antigravity_hook --config "{config}"'
        post = f'"{interpreter}" -m semgate.antigravity_post_hook --config "{config}"'
        data["semgate"] = {"enabled": True,
                           "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": pre}]}],
                           "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": post}]}]}
        return data
    # Since 2026-09-24 claude also gets an explicit --host (was --host auto).
    cmd = f'"{interpreter}" -m semgate.claude_hook --config "{config}" --host {host}'
    if host == "copilot":
        ps = f'& "{interpreter}" -m semgate.claude_hook --config "{config}" --host copilot'
        return {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": cmd, "powershell": ps, "timeoutSec": 30}]}}
    entry = {"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 30}]}
    post = {"matcher": "*", "hooks": [{"type": "command", "command": cmd + " --event post", "timeout": 30}]}
    if host == "claude":
        hooks = dict(data.get("hooks") or {})
        hooks["PreToolUse"] = _old_without_semgate(hooks.get("PreToolUse")) + [entry]
        hooks["PostToolUse"] = _old_without_semgate(hooks.get("PostToolUse")) + [post]
        # Added on purpose after 113cf06: Claude Code gets a Stop hook for the
        # secret exposure summary (semgate.exposures, manifest C34).
        stop = {"hooks": [{"type": "command", "command": cmd + " --event stop", "timeout": 10}]}
        hooks["Stop"] = _old_without_semgate(hooks.get("Stop")) + [stop]
        data["hooks"] = hooks
    else:
        data["PreToolUse"] = _old_without_semgate(data.get("PreToolUse")) + [entry]
        data["PostToolUse"] = _old_without_semgate(data.get("PostToolUse")) + [post]
    return data


OLD_SEMGATE = {"type": "command", "command": '"C:/old/python.exe" -m semgate.claude_hook --config "C:/old/semgate.json" --host auto'}
GUARD = {"type": "command", "command": "other-guard"}
EXISTING = {
    "claude": [
        {},
        {"theme": "dark"},
        {"hooks": {}},
        {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [GUARD]}]}},
        {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [OLD_SEMGATE]}, {"matcher": "Bash", "hooks": [GUARD]}],
                   "PostToolUse": [{"matcher": "*", "hooks": [dict(OLD_SEMGATE, command=OLD_SEMGATE["command"] + " --event post")]}],
                   "Stop": [{"hooks": [GUARD]}]},
         "permissions": {"deny": ["Bash(curl:*)"], "ask": ["Bash(git push:*)"], "defaultMode": "default"}},
        {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [GUARD, OLD_SEMGATE]}]}},
    ],
    "droid": [
        {},
        {"PreToolUse": [{"matcher": "Execute", "hooks": [GUARD]}], "SessionStart": [{"hooks": [GUARD]}]},
        {"PreToolUse": [{"matcher": "*", "hooks": [dict(OLD_SEMGATE, command=OLD_SEMGATE["command"].replace("auto", "droid"))]}]},
    ],
    "antigravity": [
        {},
        {"other": {"enabled": True}},
        {"other": {"enabled": True}, "semgate": {"enabled": False, "PreToolUse": []}},
    ],
    "copilot": [{}, {"version": 1, "hooks": {}}],
}


@pytest.mark.parametrize("host,existing", [(h, e) for h, cases in EXISTING.items() for e in cases])
def test_init_result_equals_the_previous_merge(tmp_path, host, existing):
    """Existing behaviour unchanged: for every well-formed input the file
    after `semgate init` parses to exactly what the old merge_hooks produced."""
    hooks = tmp_path / "host" / "hooks.json"
    hooks.parent.mkdir()
    hooks.write_text(json.dumps(existing), encoding="utf-8")
    assert init(tmp_path, host, hooks) == 0
    cfg = (tmp_path / "semgate" / "semgate.json").resolve()
    assert json.loads(hooks.read_text(encoding="utf-8")) == old_merge_hooks(host, existing, PY, cfg)
    # the pure helper still gives the same document
    from semgate.init_antigravity import merge_hooks
    assert merge_hooks(host, existing, PY, cfg) == old_merge_hooks(host, existing, PY, cfg)


def test_new_file_is_written_exactly_as_before(tmp_path):
    hooks = tmp_path / "host" / "settings.json"
    assert init(tmp_path, "claude", hooks) == 0
    cfg = (tmp_path / "semgate" / "semgate.json").resolve()
    assert hooks.read_text(encoding="utf-8") == json.dumps(old_merge_hooks("claude", {}, PY, cfg), indent=2) + "\n"


# ------------------------------------------------------------------ refuse on unexpected shape


@pytest.mark.parametrize("host,text", [
    ("claude", "{not json"),
    ("claude", "[1, 2]"),
    ("claude", json.dumps({"hooks": []})),
    ("claude", json.dumps({"hooks": {"PreToolUse": {"matcher": "*"}}})),
    ("claude", json.dumps({"hooks": {"PreToolUse": [{"matcher": "*"}]}})),
    ("claude", json.dumps({"hooks": {"PreToolUse": ["echo hi"]}})),
    ("claude", '{"a": 1, "a": 2}'),
    ("claude", '{"a": 1, // a comment\n}'),
    ("droid", json.dumps({"PreToolUse": "x"})),
    ("antigravity", json.dumps({"semgate": "on"})),
    ("antigravity", json.dumps("text")),
])
def test_unexpected_shape_is_refused_and_the_file_untouched(tmp_path, capsys, host, text):
    hooks = tmp_path / "host" / "hooks.json"
    hooks.parent.mkdir()
    hooks.write_bytes(text.encode("utf-8"))
    before = hooks.stat().st_mtime_ns
    assert init(tmp_path, host, hooks) == 2
    assert hooks.read_bytes() == text.encode("utf-8") and hooks.stat().st_mtime_ns == before
    assert not list(hooks.parent.glob("*.semgate-bak-*"))
    assert not (tmp_path / "semgate").exists()          # nothing else was written either
    assert f"semgate init {host}:" in capsys.readouterr().err


# ------------------------------------------------------------------ byte-for-byte preservation, idempotence, backup


CLAUDE_SETTINGS = """{
    "model": "opus",
    "permissions": {
        "deny": ["Bash(curl:*)", "Read(./.env)"],
        "ask": ["Bash(git push:*)"],
        "defaultMode": "default"
    },
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-guard"}]}
        ]
    },
    "theme": "dark"
}
"""


def test_existing_denies_and_asks_are_kept_byte_for_byte(tmp_path):
    settings = tmp_path / "host" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(CLAUDE_SETTINGS, encoding="utf-8", newline="")
    assert init(tmp_path, "claude", settings) == 0
    new = settings.read_text(encoding="utf-8")
    block = CLAUDE_SETTINGS[CLAUDE_SETTINGS.index('    "permissions"'):CLAUDE_SETTINGS.index('    "hooks"')]
    assert block in new                                           # deny/ask/defaultMode: same bytes, same place
    assert new.startswith(CLAUDE_SETTINGS[:CLAUDE_SETTINGS.index('    "hooks"')])
    assert new.endswith('    "theme": "dark"\n}\n')
    assert '{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-guard"}]}' in new
    data = json.loads(new)
    assert data["permissions"] == json.loads(CLAUDE_SETTINGS)["permissions"]
    cmds = [h["command"] for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert cmds[0] == "other-guard" and sum("semgate.claude_hook" in c for c in cmds) == 1


def test_rerun_is_idempotent_and_backs_up(tmp_path):
    settings = tmp_path / "host" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(CLAUDE_SETTINGS, encoding="utf-8", newline="")
    assert init(tmp_path, "claude", settings) == 0
    first = settings.read_bytes()
    assert init(tmp_path, "claude", settings) == 0
    assert init(tmp_path, "claude", settings) == 0
    assert settings.read_bytes() == first                          # re-run: same bytes, no rewrite
    backups = sorted(settings.parent.glob("settings.json.semgate-bak-*"))
    assert len(backups) == 1 and backups[0].read_text(encoding="utf-8") == CLAUDE_SETTINGS
    assert not list(settings.parent.glob(".*semgate-tmp*"))      # atomic write left no temp file
    # a changed entry (another --dir) is replaced, not duplicated, with a new backup
    assert main(["init", "claude", "--purpose", "p", "--provider", "none", "--dir", str(tmp_path / "semgate2"),
                 "--hooks-file", str(settings)]) == 0
    data = json.loads(settings.read_text(encoding="utf-8"))
    cmds = [h["command"] for ev in ("PreToolUse", "PostToolUse") for g in data["hooks"][ev] for h in g["hooks"]]
    assert sum("semgate.claude_hook" in c for c in cmds) == 2 and all("semgate2" in c for c in cmds if "semgate" in c)
    assert len(list(settings.parent.glob("settings.json.semgate-bak-*"))) == 2


def test_uninstall_removes_only_semgate(tmp_path, human_terminal):
    settings = tmp_path / "host" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(CLAUDE_SETTINGS, encoding="utf-8", newline="")
    assert init(tmp_path, "claude", settings) == 0
    assert main(["uninstall", "claude", "--hooks-file", str(settings)]) == 0
    after = json.loads(settings.read_text(encoding="utf-8"))
    assert after["permissions"] == json.loads(CLAUDE_SETTINGS)["permissions"]
    assert after["hooks"]["PreToolUse"] == json.loads(CLAUDE_SETTINGS)["hooks"]["PreToolUse"]
    assert "semgate" not in settings.read_text(encoding="utf-8")
    agy = tmp_path / "host" / "hooks.json"
    agy.write_text('{\n  "other": {"enabled": true}\n}\n', encoding="utf-8")
    assert init(tmp_path, "antigravity", agy) == 0
    assert main(["uninstall", "antigravity", "--hooks-file", str(agy)]) == 0
    assert agy.read_text(encoding="utf-8") == '{\n  "other": {"enabled": true}\n}\n'
    assert main(["uninstall", "antigravity", "--hooks-file", str(agy)]) == 0   # nothing left: no change


def test_opencode_plugin_install_backs_up_and_uninstall_deletes(tmp_path, human_terminal):
    plugin = tmp_path / "home" / ".config" / "opencode" / "plugins" / "semgate.js"
    assert init(tmp_path, "opencode", plugin) == 0
    assert "semgate.serve" in plugin.read_text(encoding="utf-8")
    assert init(tmp_path, "opencode", plugin) == 0
    assert len(list(plugin.parent.glob("semgate.js.semgate-bak-*"))) == 1
    assert main(["uninstall", "opencode", "--hooks-file", str(plugin)]) == 0
    assert not plugin.exists() and len(list(plugin.parent.glob("semgate.js.semgate-bak-*"))) == 2


# ------------------------------------------------------------------ JSONC editing


JSONC = """// user settings
{
  // keep this comment
  "theme": "dark", /* inline */
  "other": {"enabled": true}, // trailing comment
}
"""


def _jsonc_antigravity():
    host = get("antigravity")
    host = type("JsoncAgy", (type(host),), {"jsonc": True})()
    return host


def test_jsonc_comments_and_trailing_commas_survive(tmp_path):
    f = _under(tmp_path / "host" / "hooks.jsonc", tmp_path)
    f.parent.mkdir()
    f.write_text(JSONC, encoding="utf-8", newline="")
    host = _jsonc_antigravity()
    req = InstallRequest(tmp_path, f, PY, tmp_path / "semgate.json")
    plan = host.plan_install(req)
    text = plan.text
    for keep in ("// user settings", "// keep this comment", "/* inline */", "// trailing comment"):
        assert keep in text
    doc = safemerge.parse(text, jsonc=True).value
    assert doc["theme"] == "dark" and doc["other"] == {"enabled": True} and doc["semgate"]["enabled"] is True
    assert text.startswith(JSONC[:JSONC.index("}\n") - 1])     # everything before the insertion point: same bytes
    # replace on re-run keeps comments too
    f.write_text(text, encoding="utf-8", newline="")
    again = host.plan_install(req).text
    assert again == text


def test_jsonc_edit_that_cannot_be_verified_is_refused_with_a_snippet(tmp_path, monkeypatch):
    f = _under(tmp_path / "hooks.jsonc", tmp_path)
    f.write_text(JSONC, encoding="utf-8", newline="")
    host = _jsonc_antigravity()
    plan = host.merge_plan(InstallRequest(tmp_path, f, PY, tmp_path / "semgate.json"))
    broken = MergePlan(plan.validate, plan.merged, plan.strip, lambda ed, parsed: ed.add(0, 0, "garbage"), jsonc=True)
    with pytest.raises(MergeRefused) as err:
        safemerge.merge_file(f, broken)
    assert "has comments" in str(err.value) and '"semgate"' in err.value.snippet
    assert f.read_text(encoding="utf-8") == JSONC


def test_strict_json_falls_back_to_the_old_rewrite(tmp_path):
    f = _under(tmp_path / "hooks.json", tmp_path)
    f.write_text('{"other": 1}', encoding="utf-8")
    host = get("antigravity")
    plan = host.merge_plan(InstallRequest(tmp_path, f, PY, tmp_path / "semgate.json"))
    broken = MergePlan(plan.validate, plan.merged, plan.strip, lambda ed, parsed: ed.add(0, 0, "garbage"))
    r = safemerge.merge_file(f, broken)
    assert r.method == "rewrite" and json.loads(r.new_text) == plan.merged({"other": 1})


# ------------------------------------------------------------------ never loosen


def test_a_change_outside_semgates_entry_is_refused(tmp_path):
    f = _under(tmp_path / "settings.json", tmp_path)
    original = json.dumps({"permissions": {"deny": ["Bash(rm:*)"]}})
    f.write_text(original, encoding="utf-8")
    host = get("claude")
    plan = host.merge_plan(InstallRequest(tmp_path, f, PY, tmp_path / "semgate.json"))

    def loosen(doc):
        out = plan.merged(doc)
        out["permissions"] = {"deny": [], "defaultMode": "bypassPermissions"}
        return out
    with pytest.raises(MergeRefused, match="not semgate's own entry"):
        safemerge.merge_file(f, MergePlan(plan.validate, loosen, plan.strip, plan.edit))
    assert f.read_text(encoding="utf-8") == original


def test_semgate_entries_never_carry_bypass_or_auto_approve(tmp_path):
    for host in ("claude", "droid", "antigravity", "copilot"):
        plan = get(host).merge_plan(InstallRequest(tmp_path, tmp_path / "x.json", PY, tmp_path / "semgate.json"))
        text = json.dumps(plan.merged({})).lower()
        for word in ("bypass", "autoapprove", "defaultmode", "yolo", "\"allow\""):
            assert word not in text, (host, word)


# ------------------------------------------------------------------ write guard


def test_writes_outside_the_write_root_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_WRITE_ROOT", str(tmp_path / "allowed"))
    outside = tmp_path / "elsewhere" / "settings.json"
    with pytest.raises(MergeRefused, match="outside SEMGATE_WRITE_ROOT"):
        safemerge.safe_write(outside, "{}")
    assert not outside.exists()
    assert init(tmp_path, "claude", outside) == 2 and not outside.exists()


def test_default_paths_resolve_into_the_fake_home(tmp_path, fake_home):
    from semgate.hosts.base import HostEnv
    env = HostEnv(fake_home, dict(os.environ))
    for name in ("claude", "droid", "antigravity", "opencode", "codex", "pi"):
        paths = get(name).config_paths(env)
        for p in paths.user + ([paths.hooks_file] if paths.hooks_file else []):
            _under(p, fake_home)


# ------------------------------------------------------------------ the JSONC reader itself


def test_parser_offsets_and_refusals():
    p = safemerge.parse('{"a": [1, {"b": "x\\"y"}], "c": null}')
    assert p.value == {"a": [1, {"b": 'x"y'}], "c": None}
    arr = p.root.member("a")
    assert p.text[arr.start:arr.end] == '[1, {"b": "x\\"y"}]'
    for bad in ('{"a": 1,}', '{"a": 1} x', '{"a" 1}', "[1 2]", '{"a": 1, "a": 2}'):
        with pytest.raises(safemerge.ParseError):
            safemerge.parse(bad)
    assert safemerge.parse('{"a": 1,} // c', jsonc=True).value == {"a": 1}
    assert safemerge.parse("  \n").value == {}
    assert safemerge.parse('\ufeff{"a": 1}').bom == "\ufeff"


def test_array_rewrite_keeps_neighbours_and_commas():
    text = '{\n  "PreToolUse": [\n    {"x": 1},\n    {"sg": 1},\n    {"y": 2}\n  ]\n}\n'
    p = safemerge.parse(text)
    ed = safemerge.Editor(p)
    ed.rewrite_array(p.root.member("PreToolUse"), [1], [{"sg": 2}])
    out = ed.result()
    assert json.loads(out) == {"PreToolUse": [{"x": 1}, {"y": 2}, {"sg": 2}]}
    assert '    {"x": 1},\n    {"y": 2}' in out
    ed = safemerge.Editor(p)
    ed.rewrite_array(p.root.member("PreToolUse"), [2], [])
    assert json.loads(ed.result()) == {"PreToolUse": [{"x": 1}, {"sg": 1}]}
