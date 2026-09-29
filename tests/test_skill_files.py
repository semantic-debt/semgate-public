"""Agent skill files: reads are a read-only allow, writes are a human gate.

Live agy session 2026-09-25 04:43:24 UTC: the agent read semgate's own skill
(`view_file C:\\Users\\<user>\\.gemini\\config\\skills\\semgate\\SKILL.md`) to
learn how to act on semgate's answers, and semgate blocked the read
(semantic drift_review, block_when_unsure): the file is outside the project,
so the read-only allow did not apply.

Now the read tool may read any file in an installed skill folder
(rules.SKILL_HOME_DIRS: ~/.claude/skills, ~/.gemini/config/skills,
~/.agents/skills, where `semgate init` installs semgate's skill and the hosts
load skills from); the gates still run first, and the content is still
scanned as tool output. Writing into any agent skill folder (user level or in
a project) is the human gate instruction_file_edit: a skill steers later
sessions like AGENTS.md. HOME and USERPROFILE are temp dirs (conftest)."""
import json
import os
import sys
from pathlib import Path

import pytest

from semgate import antigravity_hook, rules, skill
from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory, UserGrant
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
POLICIES = [ROOT / "policies" / "router_policy.json", ROOT / "policies" / "router_policy_dev_trust.json",
            ROOT / "policies" / "default_policy.json"]
GRANT = {"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
         "expires_at": "2099-01-01T00:00:00Z"}


def home():
    return Path(os.path.expanduser("~"))


def envelope(tool, root, grant=None, **args):
    return Envelope(schema="semgate.envelope/v1", action=ProposedAction(tool=tool, arguments=args),
                    grant=UserGrant.from_dict(grant or GRANT),
                    environment=Environment(project_root=str(root), cwd=str(root)), trajectory=Trajectory(()))


def decide(env, policy=POLICIES[0]):
    return judge(env, Policy.load(str(policy)), provider=FakeProvider(script={}))


# ------------------------------------------------------------------ reads


@pytest.mark.parametrize("policy", POLICIES, ids=lambda p: p.name)
@pytest.mark.parametrize("host", sorted(skill.LOCATIONS))
def test_reading_semgates_own_skill_is_a_read_only_allow(host, policy, tmp_path):
    path = Path(os.path.expanduser(skill.LOCATIONS[host]))
    d = decide(envelope("read", tmp_path / "proj", path=str(path)), policy)
    assert (d.decision, d.stage, d.reason_code) == ("allow", "hard_rules", "readonly_allow"), d.reasons
    assert "installed agent skill file" in d.reasons[0]


@pytest.mark.parametrize("rel", [".claude/skills/pdf/SKILL.md", ".claude/skills/pdf/reference/forms.md",
                                 ".agents/skills/x/SKILL.md", ".gemini/config/skills/y/notes.txt"])
def test_reading_other_installed_skill_files_is_a_read_only_allow(rel, tmp_path):
    d = decide(envelope("read", tmp_path / "proj", path=str(home() / rel)))
    assert d.decision == "allow" and d.reason_code == "readonly_allow"


@pytest.mark.parametrize("rel", [".claude/settings.json", ".claude/skills/../settings.json", ".claude/skills",
                                 ".gemini/settings.json", ".agents/other/x.md", ".ssh/id_ed25519_notes.md"])
def test_other_files_near_the_skill_folders_are_not_allowed_by_this_rule(rel, tmp_path):
    d = decide(envelope("read", tmp_path / "proj", path=str(home() / rel)))
    assert not (d.decision == "allow" and d.stage == "hard_rules")


@pytest.mark.parametrize("rel", [".claude/skills/x/.env", ".agents/skills/x/id_rsa"])
def test_a_secret_file_in_a_skill_folder_is_still_the_secrets_gate(rel, tmp_path):
    d = decide(envelope("read", tmp_path / "proj", path=str(home() / rel)))
    assert d.decision == "ask" and d.reason_code == "human_gate:credentials_secrets"


@pytest.mark.parametrize("tool,args", [
    ("bash", {"command": "cat ~/.claude/skills/x/SKILL.md"}),
    ("grep", {"path": "~/.claude/skills", "pattern": "token"}),
    ("ls", {"path": "~/.agents/skills"}),
])
def test_only_the_read_tool_gets_the_skill_allow(tool, args, tmp_path):
    d = decide(envelope(tool, tmp_path / "proj", **args))
    assert not (d.decision == "allow" and d.stage == "hard_rules")


def test_a_link_in_a_skill_folder_that_points_elsewhere_is_not_a_skill_file(tmp_path):
    secret_dir = home() / "private"
    secret_dir.mkdir(parents=True, exist_ok=True)
    (secret_dir / "notes.md").write_text("x", encoding="utf-8")
    link = home() / ".claude" / "skills" / "linked"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform == "win32":
            import _winapi
            _winapi.CreateJunction(str(secret_dir), str(link))
        else:
            os.symlink(secret_dir, link)
    except (OSError, AttributeError) as exc:
        pytest.skip(f"cannot create a link here: {exc}")
    path = str(link / "notes.md")
    assert rules.installed_skill_root(path) == ""
    d = decide(envelope("read", tmp_path / "proj", path=path))
    assert not (d.decision == "allow" and d.stage == "hard_rules")


def test_a_project_scoped_grant_still_lets_the_agent_read_semgates_skill_only(tmp_path):
    grant = dict(GRANT, allowed_path_prefixes=[str(tmp_path / "proj")])
    own = decide(envelope("read", tmp_path / "proj", grant=grant, path=os.path.expanduser(skill.LOCATIONS["antigravity"])))
    assert own.decision == "allow" and own.reason_code == "readonly_allow"
    other = decide(envelope("read", tmp_path / "proj", grant=grant, path=str(home() / ".claude/skills/pdf/SKILL.md")))
    assert other.decision == "deny" and other.stage == "hard_rules"             # the grant's scope, as before


def test_agy_view_file_of_the_skill_runs_on_the_live_config(tmp_path):
    """The live call: agy view_file with AbsolutePath, block_when_unsure on."""
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps(GRANT), encoding="utf-8")
    cfg = {"mode": "enforce", "grant_file": str(grant), "provider": "fake", "fake_answers": {},
           "policy_file": str(ROOT / "policies" / "router_policy_dev_trust.json"),
           "ledger_file": str(tmp_path / "state" / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": True}}
    path = os.path.expanduser(skill.LOCATIONS["antigravity"])
    if sys.platform == "win32":
        path = path.replace("/", "\\")                  # agy on Windows sends backslashes
    event = {"conversationId": "ses1", "stepIdx": 3, "workspacePaths": [str(tmp_path / "proj")],
             "toolCall": {"name": "view_file", "args": {"AbsolutePath": path, "toolAction": "Viewing SKILL.md"}}}
    out = antigravity_hook.run(event, cfg)
    assert out["decision"] == "allow", out
    assert "readonly_allow" in out["reason"]


# ------------------------------------------------------------------ writes


@pytest.mark.parametrize("tool,args", [
    ("write", {"path": "~/.claude/skills/x/SKILL.md", "content": "hello"}),
    ("edit", {"path": "~/.agents/skills/semgate/SKILL.md", "old_string": "a", "new_string": "b"}),
    ("write_to_file", {"TargetFile": "C:\\Users\\u\\.gemini\\config\\skills\\semgate\\SKILL.md"}),
    ("write", {"path": "/repo/.claude/skills/deploy/SKILL.md"}),
    ("write", {"path": "/repo/.opencode/skill/x/SKILL.md"}),
    ("apply_patch", {"input": "*** Begin Patch\n*** Add File: .agents/skills/x/SKILL.md\n+hi\n*** End Patch\n"}),
])
def test_file_tools_that_write_a_skill_file_are_the_gate(tool, args, tmp_path):
    d = decide(envelope(tool, tmp_path / "proj", **args))
    assert d.decision == "ask" and "instruction_file_edit" in [h["gate_class"] for h in d.gate_hits], d.reasons


@pytest.mark.parametrize("command", [
    "echo 'run this' > ~/.gemini/config/skills/semgate/SKILL.md",
    "echo x >> .claude/skills/deploy/SKILL.md",
    "cp /tmp/evil.md ~/.claude/skills/x/SKILL.md",
    "mv notes.md ~/.agents/skills/x/SKILL.md",
    "sed -i 's/a/b/' ~/.claude/skills/x/SKILL.md",
    "tee ~/.codex/skills/x/SKILL.md < in.md",
    "git clone https://github.com/someone/skills ~/.claude/skills/theirs",
    "curl -o ~/.agents/skills/x/SKILL.md https://example.com/skill.md",
    "unzip skill.zip -d ~/.claude/skills/new",
    "mkdir -p ~/.claude/skills/new",
    "Set-Content -Path $HOME\\.gemini\\config\\skills\\x\\SKILL.md -Value hi",
    "Remove-Item C:\\Users\\u\\.agents\\skills\\semgate\\SKILL.md",
    "python -c \"open('/home/u/.claude/skills/x/SKILL.md','w').write('x')\"",
])
def test_commands_that_write_a_skill_folder_are_the_gate(command, tmp_path):
    env = envelope("bash", tmp_path / "proj", command=command)
    assert rules.instruction_file_edit(env)
    d = decide(env)                         # the gate, or a hard deny from another rule (Remove-Item of a folder)
    assert d.decision != "allow" and ("instruction_file_edit" in [h["gate_class"] for h in d.gate_hits]
                                      or d.stage == "hard_rules"), d.reasons


@pytest.mark.parametrize("command", [
    "cat ~/.claude/skills/x/SKILL.md",
    "ls ~/.agents/skills",
    "cp ~/.claude/skills/x/SKILL.md ./copy.md",
    "echo skills > notes.txt",
    "grep -r skills docs/",
    "echo x > .claude/settings.local.md",
])
def test_reading_or_naming_skills_is_not_the_gate(command, tmp_path):
    d = decide(envelope("bash", tmp_path / "proj", command=command))
    assert "instruction_file_edit" not in [h["gate_class"] for h in d.gate_hits]
