"""Phase 1 of docs/project-profiles-design.md: the agent cannot run semgate's
admin commands, cannot switch semgate off in another agent's config, and
the plugins take no program or config from the environment.

1. rules.check_hard_deny: `semgate init | uninstall | harness init | ...` in
   any parsed form is the hard deny semgate_admin (adminguard.admin_hit).
   Forms the parser cannot read (`S=semgate; $S init`) are the human gate
   semgate_admin. Read-only commands are not touched.
2. The CLI refuses the admin commands when the process shows an agent sign
   (trustauth.agent_signs), and asks the typed word for the ones that lower
   protection. A person in their own terminal can still run them.
3. agent_config covers Pi (~/.pi/agent, project .pi/extensions), Droid
   (~/.factory/hooks.json ...) and project plugin copies, for shell commands,
   file tools and inline code.
4. Environment overrides: the plugin assets have none for the program and
   the config; SEMGATE_TRUST_FILE is not read; TYPESAFE_BASE_URL is not used.

Every test runs with a temp HOME/USERPROFILE (conftest) and, unless it says
otherwise, as a tool call of an unknown agent host that shows no agent sign
(conftest._trust_process_view). No command here is executed: dangerous
commands are only text in envelopes."""
import json
from pathlib import Path

import pytest

from conftest import as_person, fake_chain, make_envelope, make_grant
from semgate import adminguard, cli, codestamp, rules, trust, trustauth
from semgate.judge import judge
from semgate.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"


def bash(command, root="/home/me/proj"):
    return make_envelope(tool="bash", arguments={"command": command}, project_root=root,
                         grant=make_grant(allowed_path_prefixes=(), allowed_tools=("*",)))


def tool_env(tool, **args):
    return make_envelope(tool=tool, arguments=args, grant=make_grant(allowed_path_prefixes=(), allowed_tools=("*",)))


def gates(env):
    return [h.gate_class for h in rules.detect_gates(env)]


# ------------------------------------------------------------------ 1. the hook: hard deny

# The rows of section 1.7 of the design doc (before: no hard deny, no gate).
DOC_ROWS = [
    'semgate init claude --force --mode shadow --purpose "anything"',
    "semgate uninstall antigravity",
    "python -m semgate init pi --force --purpose x",
]

# Bypass attempts: quoting, escapes, paths, python -m, env prefixes and
# wrappers, chains, subshells, code in strings, runners.
BYPASSES = [
    "semgate init claude",
    "semgate uninstall pi",
    "semgate harness init --purpose x --force",
    "semgate enable claude", "semgate disable pi", "semgate migrate antigravity",
    "semgate install --all", "semgate project remove .", "semgate settings set enabled false",
    "semgate -- init claude",
    # quoting and escapes
    "sem''gate init claude",
    '"semgate" "in""it" claude',
    "'semgate' 'uninstall' 'pi'",
    r"s\emgate init claude",
    "se^mgate init claude",
    "SEMGATE init claude",
    # paths to the program
    '"C:/Users/Me/proj/.venv/Scripts/semgate.exe" init claude',
    r"C:\venv\Scripts\SEMGATE.EXE uninstall codex",
    r'& "C:\Program Files\x y\semgate.exe" init claude',
    "./.venv/bin/semgate uninstall claude",
    "~/.local/bin/semgate init pi --mode shadow",
    # python -m and the module forms
    "python -m semgate init pi",
    "python3 -m semgate uninstall claude",
    "py -3.13 -m semgate init claude",
    "python -X utf8 -I -m semgate.cli uninstall claude",
    "python -m semgate.__main__ init claude",
    "python -msemgate init claude",
    r"C:\Python313\python.exe -m semgate init claude",
    # environment prefixes and wrappers
    "SEMGATE_X=1 semgate init claude",
    "env -u CLAUDECODE -u AI_AGENT semgate init claude",
    "sudo -u root timeout 5 nohup semgate uninstall pi",
    "exec semgate init claude",
    "command semgate uninstall claude",
    # chains and subshells
    "git status && semgate init claude",
    "ls; semgate uninstall pi",
    "false || semgate init claude",
    "npm test | semgate uninstall claude",
    "(semgate init claude)",
    "{ semgate uninstall pi; }",
    "echo $(semgate init claude)",
    "x=`semgate uninstall pi`",
    "S=semgate && cd /tmp && semgate init claude",
    # code in strings, heredocs, other shells
    "bash -c 'semgate init claude --mode shadow'",
    'sh -c "cd /tmp && semgate uninstall claude"',
    'powershell -NoProfile -Command "semgate uninstall claude"',
    "pwsh -c 'semgate init claude'",
    "cmd /c semgate init claude",
    "cmd.exe /c \"semgate uninstall claude\"",
    "eval 'semgate init claude'",
    "bash <<EOF\nsemgate init claude\nEOF",
    "python -c \"import os; os.system('semgate init claude')\"",
    "python -c \"import subprocess; subprocess.run('semgate uninstall pi', shell=True)\"",
    "python -c \"from semgate.cli import main; main(['init', 'claude'])\"",
    "python - <<'EOF'\nimport subprocess\nsubprocess.run(['semgate', 'uninstall', 'pi'])\nEOF",
    "python -c \"import subprocess, sys; subprocess.run([sys.executable, '-m', 'semgate', 'init', 'pi'])\"",
    "node -e \"require('child_process').execFileSync('semgate', ['init', 'claude'])\"",
    # runners
    "uvx semgate init claude",
    "uvx --from semgate==0.9 semgate init claude",
    "pipx run semgate uninstall pi",
    "pipx run --spec semgate semgate init claude",
    "uv run semgate init claude",
    "uv run python -m semgate init claude",
    "poetry run semgate uninstall claude",
    "wsl semgate init claude",
    "call semgate init claude",
    "Start-Process semgate -ArgumentList 'init','claude'",
]


@pytest.mark.parametrize("command", DOC_ROWS + BYPASSES)
def test_admin_command_is_a_hard_deny(command):
    res = rules.check_hard_deny(bash(command))
    assert res.outcome == "deny" and res.rule == "semgate_admin", (command, res)
    assert adminguard.REASON in res.detail


# Forms the parser cannot read: the human gate semgate_admin (never allow).
HIDDEN = [
    "S=semgate; $S init claude",
    "S=semgate\nls\n$S uninstall pi",
    "$(echo semgate) init claude",
    "echo init | xargs semgate",
    "echo semgate init claude | bash",
    "printf 'semgate uninstall pi' | sh",
]


@pytest.mark.parametrize("command", HIDDEN)
def test_hidden_admin_command_is_the_human_gate(command):
    env = bash(command)
    assert rules.check_hard_deny(env).rule != "semgate_admin"
    assert "semgate_admin" in gates(env), command


READ_ONLY = [
    "semgate status",
    "semgate doctor --no-exec",
    "semgate doctor",
    "semgate feedback --show-config",
    "semgate report",
    "semgate report --exposures",
    "semgate trust list",
    "semgate --version",
    "python -m semgate doctor --no-exec",
    "semgate init --help",
    "semgate init claude -h",
    "python -m semgate uninstall --help",
    "semgate harness init --help",
]


@pytest.mark.parametrize("command", READ_ONLY)
def test_read_only_semgate_commands_are_not_admin(command):
    env = bash(command)
    assert rules.check_hard_deny(env).rule != "semgate_admin"
    assert "semgate_admin" not in gates(env)


BENIGN = [
    'grep -rn "semgate init" README.md',
    'git commit -m "semgate init now refuses under an agent"',
    "cat semgate/init_antigravity.py",
    "pytest tests/test_init_antigravity.py -k init",
    "pip install semgate",
    "pipx install semgate",
    "uv pip install -e .",
    "cd ~/semgate-trust-demo && npm install",
    "rg semgate init.py",
    "semgate doctor | grep install",
    'semgate feedback deny "npm install"',
    "ls ~/.semgate/opencode-demo",
    "cd semgate && make install",
]


@pytest.mark.parametrize("command", BENIGN)
def test_text_about_semgate_is_not_an_admin_command(command):
    env = bash(command)
    assert rules.check_hard_deny(env).rule != "semgate_admin"
    assert "semgate_admin" not in gates(env), command


def test_a_file_tool_writing_docs_about_init_is_not_gated():
    env = tool_env("write", file_path="/home/me/proj/README.md", content="Run `semgate init claude --purpose x`.\n")
    assert "semgate_admin" not in gates(env)
    assert rules.check_hard_deny(env).outcome == "none"


def test_judge_denies_and_the_reason_says_who_runs_it():
    policy = Policy.load(str(DEV))
    d = judge(bash('semgate init claude --force --mode shadow --purpose "anything"'), policy, provider=None)
    assert d.decision == "deny" and d.stage == "hard_rules" and d.reason_code == "semgate_admin"
    assert "only the user runs this, in their own terminal" in " ".join(d.reasons)
    d = judge(bash("S=semgate; $S init claude"), policy, provider=None)
    assert d.decision != "allow" and d.reason_code == "human_gate:semgate_admin"


def test_a_trust_never_opens_the_admin_gate():
    assert "semgate_admin" in trust.NOT_OVERRIDABLE_GATES
    assert trust.refuse_reason("semgate init claude")


# ------------------------------------------------------------------ 3. agent_config: Pi, Droid, plugin copies

SHELL_WRITES = [
    "rm .opencode/plugin/semgate.js",
    "rm -f /home/me/proj/.opencode/plugins/semgate.js",
    "mv .pi/extensions/semgate.ts /tmp/x",
    "rm ~/.pi/agent/extensions/semgate.ts",
    "echo {} > ~/.pi/agent/settings.json",
    "cp /tmp/t.json ~/.pi/agent/trust.json",
    "rm ~/.factory/hooks.json",
    "echo '{}' > ~/.factory/settings.json",
    "sed -i s/x/y/ .pi/settings.json",
    r"Remove-Item C:\Users\me\.pi\agent\trust.json",
    r"del C:\Users\me\.factory\hooks.json",
    "Set-Content -Path .opencode/plugin/semgate.js -Value ''",
    "truncate -s 0 .pi/extensions/semgate.ts",
    "rm ~/.gemini/config/settings.json",
    "rm ~/.claude/settings.json",                                 # unchanged: still gated
    "python -c \"open('/home/me/.factory/hooks.json','w').write('{}')\"",
    "node -e \"require('fs').writeFileSync('.pi/extensions/semgate.ts', '')\"",
]


@pytest.mark.parametrize("command", SHELL_WRITES)
def test_shell_writes_to_agent_config_are_the_agent_config_gate(command):
    assert "agent_config" in gates(bash(command)), command


@pytest.mark.parametrize("path", [
    "/home/me/proj/.opencode/plugin/semgate.js",
    "/home/me/proj/.opencode/plugins/other.js",
    "/home/me/.pi/agent/extensions/semgate.ts",
    "/home/me/.pi/agent/settings.json",
    "/home/me/.pi/agent/trust.json",
    "/home/me/proj/.pi/extensions/semgate.ts",
    "/home/me/proj/.pi/settings.json",
    r"C:\Users\me\.factory\hooks.json",
    r"C:\Users\me\.factory\settings.json",
    "/home/me/.claude/settings.json",
    "/home/me/.codex/hooks.json",
])
@pytest.mark.parametrize("tool", ["edit", "write", "Write", "multiedit"])
def test_file_tool_writes_to_agent_config_are_the_agent_config_gate(path, tool):
    assert "agent_config" in gates(tool_env(tool, file_path=path, old_string="a", new_string="b", content="x"))


def test_a_patch_that_changes_a_plugin_copy_is_the_agent_config_gate():
    patch = "*** Begin Patch\n*** Delete File: .opencode/plugin/semgate.js\n*** End Patch\n"
    assert "agent_config" in gates(tool_env("apply_patch", input=patch))


@pytest.mark.parametrize("command", [
    "cat ~/.pi/agent/settings.json",
    "ls .opencode/plugin",
    "grep -n semgate ~/.factory/hooks.json",
    "git diff .pi/extensions/semgate.ts",
])
def test_reading_agent_config_is_not_gated(command):
    assert "agent_config" not in gates(bash(command))


@pytest.mark.parametrize("path", ["/home/me/proj/src/app.py", "/home/me/proj/docs/pi-agent.md",
                                  "/home/me/proj/factory/hooks.json"])
def test_other_files_are_not_agent_config(path):
    assert "agent_config" not in gates(tool_env("edit", file_path=path, old_string="a", new_string="b"))


# ------------------------------------------------------------------ 2. the CLI: who runs it


def _init_argv(tmp_path, *extra):
    return ["init", "claude", "--purpose", "Dev work in the demo project", "--provider", "none", "--no-skill",
            "--dir", str(tmp_path / "sg"), "--hooks-file", str(tmp_path / "hooks" / "settings.json"), *extra]


AGENT_CHAINS = [
    (fake_chain(("python", "1"), ("bash", "2"), ("claude", "3")), {}, "claude (pid"),
    (fake_chain(("python", "1"), ("pwsh", "2"), ("windowsterminal", "3")), {"CLAUDECODE": "1"}, "CLAUDECODE is set"),
    (fake_chain(("python", "1"), ("node", "2"), ("windowsterminal", "3")), {"PI_CODING_AGENT": "true"}, "PI_CODING_AGENT"),
    (fake_chain(("python", "1"), ("bash", "2"), ("opencode2", "3")), {}, "an agent CLI"),
    (fake_chain(("python", "1"), ("pwsh", "2"), ("codex", "3")), {}, "an agent CLI"),
]


@pytest.mark.parametrize("chain,env,sign", AGENT_CHAINS)
@pytest.mark.parametrize("argv_kind", ["init", "uninstall", "refresh", "harness"])
def test_admin_commands_refuse_under_an_agent(tmp_path, monkeypatch, capsys, chain, env, sign, argv_kind):
    hooks = tmp_path / "hooks" / "settings.json"
    before = ""
    if argv_kind == "uninstall":
        with as_person():
            assert cli.main(_init_argv(tmp_path, "--mode", "enforce")) == 0
        before = hooks.read_text(encoding="utf-8")
    monkeypatch.setattr(trustauth, "ancestry", lambda pid=None, limit=64: chain)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    if argv_kind == "uninstall":
        argv = ["uninstall", "claude", "--hooks-file", str(hooks)]
    elif argv_kind == "refresh":
        argv = ["init", "opencode", "--refresh", "--no-skill", "--hooks-file", str(tmp_path / "p" / "semgate.js")]
    elif argv_kind == "harness":
        argv = ["harness", "init", "--purpose", "dev work", "--provider", "none", "--dir", str(tmp_path / "http")]
    else:
        argv = _init_argv(tmp_path, "--mode", "enforce")
    capsys.readouterr()
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "refused" in err and sign in err and "only the user runs this, in their own terminal" in err.lower()
    if argv_kind == "uninstall":
        assert hooks.read_text(encoding="utf-8") == before
    else:
        assert not (tmp_path / "sg").exists() and not (tmp_path / "http").exists() and not (tmp_path / "p").exists()


def test_dry_run_is_not_refused_under_an_agent(tmp_path, monkeypatch):
    chain = fake_chain(("python", "1"), ("bash", "2"), ("claude", "3"))
    monkeypatch.setattr(trustauth, "ancestry", lambda pid=None, limit=64: chain)
    assert cli.main(_init_argv(tmp_path, "--dry-run")) == 0
    assert not (tmp_path / "sg").exists()


def test_a_person_runs_init_without_a_word(tmp_path):
    with as_person(answer="wrong\n"):              # no word is asked for a first install
        assert cli.main(_init_argv(tmp_path, "--mode", "enforce")) == 0
    assert json.loads((tmp_path / "sg" / "semgate.json").read_text(encoding="utf-8"))["mode"] == "enforce"


def test_uninstall_needs_the_typed_word(tmp_path, capsys):
    hooks = tmp_path / "hooks" / "settings.json"
    with as_person():
        assert cli.main(_init_argv(tmp_path, "--mode", "enforce")) == 0
    before = hooks.read_text(encoding="utf-8")
    with as_person(answer="nope\n"):
        assert cli.main(["uninstall", "claude", "--hooks-file", str(hooks)]) == 2
    assert hooks.read_text(encoding="utf-8") == before
    assert "not confirmed" in capsys.readouterr().err
    with as_person():                                # types the word it prints (bakodi)
        assert cli.main(["uninstall", "claude", "--hooks-file", str(hooks)]) == 0
    out = capsys.readouterr().out
    assert "Type bakodi and press Enter" in out and "runs its tools without semgate" in out
    assert "semgate" not in hooks.read_text(encoding="utf-8")


def test_force_over_an_existing_config_needs_the_word(tmp_path, capsys):
    with as_person():
        assert cli.main(_init_argv(tmp_path, "--mode", "enforce")) == 0
    with as_person(answer="nope\n"):
        assert cli.main(_init_argv(tmp_path, "--mode", "shadow", "--force")) == 2
    cfg = json.loads((tmp_path / "sg" / "semgate.json").read_text(encoding="utf-8"))
    assert cfg["mode"] == "enforce"
    assert "mode enforce -> shadow" in capsys.readouterr().out
    with as_person():
        assert cli.main(_init_argv(tmp_path, "--mode", "shadow", "--force")) == 0
    assert json.loads((tmp_path / "sg" / "semgate.json").read_text(encoding="utf-8"))["mode"] == "shadow"


def test_switching_the_installed_hook_to_a_shadow_config_needs_the_word(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    settings = Path.home() / ".claude" / "settings.json"          # a temp home (conftest)
    base = ["init", "claude", "--purpose", "Dev work", "--provider", "none", "--no-skill"]
    with as_person():
        assert cli.main(base + ["--dir", str(tmp_path / "strict"), "--mode", "enforce"]) == 0
    with as_person(answer="nope\n"):
        assert cli.main(base + ["--dir", str(tmp_path / "weak"), "--mode", "shadow"]) == 2
    assert "in developer shadow mode: semgate records and never denies" in capsys.readouterr().out
    text = settings.read_text(encoding="utf-8")
    assert "strict" in text and "weak" not in text
    with as_person():
        assert cli.main(base + ["--dir", str(tmp_path / "weak"), "--mode", "shadow"]) == 0
    assert "weak" in settings.read_text(encoding="utf-8")


def test_harness_init_by_a_person_still_works(tmp_path):
    with as_person():
        assert cli.main(["harness", "init", "--purpose", "dev work", "--provider", "none",
                         "--dir", str(tmp_path / "http")]) == 0
    assert (tmp_path / "http" / "approve.token").exists()


# ------------------------------------------------------------------ 4. environment overrides


@pytest.mark.parametrize("host", ["opencode", "pi"])
def test_plugin_assets_take_no_program_or_config_from_the_environment(host):
    from semgate.init_antigravity import opencode_plugin_source, pi_extension_source
    render = opencode_plugin_source if host == "opencode" else pi_extension_source
    text = render(Path("C:/py/python.exe"), Path("C:/sg/semgate.json"))
    assert "process.env.SEMGATE_PYTHON" not in text and "process.env.SEMGATE_CONFIG" not in text
    from semgate.hosts import ADAPTERS
    interp, config = ADAPTERS[host].wiring(text)
    assert Path(interp) == Path("C:/py/python.exe") and Path(config) == Path("C:/sg/semgate.json")


@pytest.mark.parametrize("host", ["opencode", "pi"])
def test_an_old_copy_with_the_env_override_is_read_and_reported_outdated(host):
    """A copy written before this change: doctor and --refresh still read
    its interpreter and config, and the stamp says it is outdated."""
    from semgate.hosts import ADAPTERS
    from semgate.init_antigravity import opencode_plugin_source, pi_extension_source
    render = opencode_plugin_source if host == "opencode" else pi_extension_source
    text = render(Path("C:/py/python.exe"), Path("C:/sg/semgate.json"))
    if host == "opencode":
        old = (text.replace('const PYTHON = "', 'const PYTHON = process.env.SEMGATE_PYTHON || "')
                   .replace('const CONFIG = "', 'const CONFIG = process.env.SEMGATE_CONFIG || "'))
    else:
        old = (text.replace("const PYTHON = ", "const PYTHON = process.env.SEMGATE_PYTHON || ", 1)
                   .replace("const CONFIG = ", "const CONFIG = process.env.SEMGATE_CONFIG || ", 1))
    old = old.replace(codestamp.asset_sha256(codestamp.ASSETS[host]), "0" * 64)
    interp, config = ADAPTERS[host].wiring(old)
    assert Path(interp) == Path("C:/py/python.exe") and Path(config) == Path("C:/sg/semgate.json")
    assert codestamp.copy_status(old, codestamp.ASSETS[host])[0] == "outdated"


def test_the_trust_store_does_not_follow_semgate_trust_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SEMGATE_TRUST_FILE", str(tmp_path / "evil" / "trust.jsonl"))
    assert trust.default_store() == Path.home() / ".semgate" / "trust.jsonl"
    assert trust.store_path({}) == Path.home() / ".semgate" / "trust.jsonl"
    assert cli.main(["trust", "list"]) == 0
    assert "ignored: SEMGATE_TRUST_FILE is no longer read; use --store" in capsys.readouterr().err
    assert not (tmp_path / "evil").exists()


def test_typesafe_provider_passes_the_api_root_explicitly(monkeypatch):
    import sys
    import types
    from semgate.providers import typesafe as ts
    seen = {}

    class Client:
        def __init__(self, **kw):
            seen.update(kw)

    mod = types.ModuleType("typesafe_sdk")
    mod.TypeSafeClient = Client
    monkeypatch.setitem(sys.modules, "typesafe_sdk", mod)
    monkeypatch.setenv("TYPESAFE_BASE_URL", "http://127.0.0.1:9/evil")
    monkeypatch.setenv("SEMGATE_TYPESAFE_API_KEY", "fake-key-for-test")
    ts.TypeSafeProvider()._client()
    assert seen.get("base_url") == ts.BASE_URL == "https://api.typesafe.ai"


def test_pi_marker_is_an_agent_sign(tmp_path):
    chain = fake_chain(("python", "1"), ("pwsh", "2"), ("windowsterminal", "3"))
    signs = trustauth.agent_signs([tmp_path / "trust.jsonl"], env={"PI_CODING_AGENT": "true"}, chain=chain)
    assert any("PI_CODING_AGENT" in s for s in signs)
