"""Harness tools (semgate/harnesstools.py): ask the user, to-do list, load a
skill. Per host tool name: what semgate decides, what the host gets under
enforcement, and that installers stay gated. Also the block text on hosts
without chat approval (manifest C35) and the served model on the judgment."""
import json
import os
from pathlib import Path

import pytest

from semgate import antigravity_hook, harness, harnesstools, rules, serve, storepaths
from semgate.adapters import claude_family, codex, opencode_tool
from semgate.antigravity_hook import _BLOCKED_SUFFIX, antigravity_decision, chat_can_approve, terminal_suffix
from semgate.envelope import UserGrant
from semgate.judge import Decision, judge
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
GRANT = UserGrant(grant_id="g", principal="p", purpose="Software development in this project", expires_at="2099-01-01T00:00:00Z")
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
            "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}
# A question that names dangerous commands: text for the person, not an action.
QUESTION = {"questions": [{"header": "Run it?", "question": "May I run `rm -rf /` or `git push --force origin main`?",
                           "options": [{"label": "Yes", "description": "run it"}, {"label": "No", "description": "skip"}]}]}
TODOS = {"todos": [{"content": "rm -rf dist, then git push", "status": "pending", "priority": "high", "id": "1"}]}


def opencode(tool, args, cwd="/p"):
    return opencode_tool.envelope_from_request({"tool": tool, "args": args, "sessionID": "s1", "cwd": cwd}, GRANT)


def claude(tool, args, cwd="/p", host="claude"):
    return claude_family.envelope_from_event({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args,
                                              "session_id": "s1", "cwd": cwd}, GRANT, host=host)


def decide(env, answers=None):
    provider = FakeProvider(script=answers if answers is not None else ALLOWING)
    return judge(env, POLICY, provider=provider), provider


# ---------------------------------------------------------------- tool names per host


@pytest.mark.parametrize("build,native,canonical", [
    (opencode, "question", "ask_user"), (opencode, "skill", "skill"), (opencode, "todowrite", "todo"),
    (opencode, "todoread", "todo"), (opencode, "list", "ls"), (opencode, "webfetch", "web_fetch"),
    (opencode, "execute", "execute"), (opencode, "task", "task"), (opencode, "codesearch", "codesearch"),
    (claude, "AskUserQuestion", "ask_user"), (claude, "TodoWrite", "todo"), (claude, "Skill", "skill"),
    (claude, "Task", "task"),
])
def test_host_tool_names_map_to_canonical_tools(build, native, canonical):
    assert build(native, {}).action.tool == canonical


def test_codex_and_http_gate_names():
    assert claude_family._tool_and_args({"tool_name": "request_user_input", "tool_input": {}})[1] == "ask_user"
    for name, canon in (("question", "ask_user"), ("ask_user", "ask_user"), ("todo", "todo"), ("skill", "skill")):
        assert harness.TOOL_ALIASES[name] == canon


# ---------------------------------------------------------------- what semgate decides


@pytest.mark.parametrize("env", [
    opencode("question", QUESTION), claude("AskUserQuestion", QUESTION),
    opencode("todowrite", TODOS), claude("TodoWrite", TODOS),
    opencode("skill", {"id": "semgate"}), opencode("skill", {"name": "deploy-notes"}),
], ids=["oc-question", "claude-askuserquestion", "oc-todowrite", "claude-todowrite", "oc-skill-id", "oc-skill-name"])
def test_harness_tools_are_allowed_by_code_without_the_model(env):
    d, provider = decide(env)
    assert (d.decision, d.stage, d.reason_code) == ("allow", "hard_rules", "harness_tool_allow")
    assert provider.calls == 0 and not d.gate_hits


def test_a_question_that_names_dangerous_commands_is_still_allowed():
    # The same text as a command is a hard deny; as a question it only reaches the person.
    d, _ = decide(opencode("question", QUESTION))
    assert d.decision == "allow"
    d, _ = decide(opencode("bash", {"command": "rm -rf /"}))
    assert d.decision == "deny"


def test_the_grant_still_scopes_harness_tools():
    grant = UserGrant(grant_id="g", principal="p", purpose="dev", expires_at="2099-01-01T00:00:00Z",
                      allowed_tools=("bash", "read"))
    env = opencode_tool.envelope_from_request({"tool": "question", "args": QUESTION, "sessionID": "s1", "cwd": "/p"}, grant)
    d, _ = decide(env)
    assert (d.decision, d.reason_code) == ("deny", "grant_scope")
    expired = UserGrant(grant_id="g", principal="p", purpose="dev", expires_at="2020-01-01T00:00:00Z")
    env = opencode_tool.envelope_from_request({"tool": "question", "args": QUESTION, "sessionID": "s1", "cwd": "/p"}, expired)
    d, _ = decide(env)
    assert (d.decision, d.stage) == ("ask", "grant_validity")


@pytest.mark.parametrize("env", [
    opencode("execute", {"code": "return await tools.shell({ command: \"git status\" })"}),
    opencode("task", {"description": "find tests", "prompt": "list the test files", "subagent_type": "explore"}),
    opencode("some_new_tool", {"x": 1}),
    claude("Task", {"description": "d", "prompt": "p", "subagent_type": "general-purpose"}),
], ids=["oc-execute", "oc-task", "oc-unknown", "claude-task"])
def test_other_harness_tools_are_judged_by_the_model(env):
    d, provider = decide(env)
    assert provider.calls >= 1 and d.stage == "semantic" and d.reason_code != "harness_tool_allow"


def test_execute_code_goes_through_the_hard_rules_and_gates():
    # `rm -rf /` inside a JS string: the command is taken out and hard-denied
    # (as a bash call), not left as a chat-approvable destructive gate.
    d, _ = decide(opencode("execute", {"code": "return await tools.shell({ command: \"rm -rf /\", workdir: \"/p\" })"}))
    assert d.decision == "deny" and d.stage == "hard_rules" and "execute code" in d.reasons[0]
    d, _ = decide(opencode("execute", {"code": "const r = await tools.shell({ cmd: `env` }); return r"}))
    assert d.stage == "human_gate" and d.gate_hits[0]["gate_class"] == "credentials_secrets"
    d, _ = decide(opencode("execute", {"code": "return await tools.shell({ command: \"git push origin main\" })"}))
    assert d.stage == "human_gate" and d.gate_hits[0]["gate_class"] == "external_communication"


# ---------------------------------------------------------------- Claude Code Skill: !`command` lines


def _skill(base: Path, name: str, body: str) -> Path:
    path = base / ".claude" / "skills" / name / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(f"---\nname: {name}\ndescription: test\n---\n{body}", encoding="utf-8")
    return path


def test_claude_skill_without_commands_is_allowed(tmp_path):
    home = Path(os.path.expanduser("~"))
    _skill(home, "notes", "Write short notes. Mention `!` only in text.\n")
    d, provider = decide(claude("Skill", {"skill": "notes"}, cwd=str(tmp_path)))
    assert (d.decision, d.reason_code) == ("allow", "harness_tool_allow") and provider.calls == 0
    assert d.evidence["skill"]["commands"] == [] and d.evidence["skill"]["allow"] is True


def test_claude_skill_whose_load_runs_commands_is_a_human_gate(tmp_path):
    _skill(tmp_path, "changes", "## Current changes\n\n!`git diff HEAD`\n\n```!\ngit status\n```\n")
    d, provider = decide(claude("Skill", {"skill": "changes"}, cwd=str(tmp_path)))
    assert (d.decision, d.stage) == ("ask", "human_gate") and provider.calls == 0
    assert d.gate_hits[0]["gate_class"] == "skill_commands"
    assert "git diff HEAD" in d.gate_hits[0]["matched"] and "git status" in d.gate_hits[0]["matched"]
    assert d.evidence["skill"]["commands"] == ["git diff HEAD", "git status"]


def test_claude_skill_command_lines_get_the_hard_rules_and_gates(tmp_path):
    _skill(tmp_path, "wipe", "!`rm -rf /`\n")
    d, _ = decide(claude("Skill", {"skill": "wipe"}, cwd=str(tmp_path)))
    assert d.decision == "deny" and d.stage == "hard_rules" and "skill 'wipe'" in d.reasons[0]
    _skill(tmp_path, "ship", "!`git push origin main`\n")
    d, _ = decide(claude("Skill", {"skill": "ship"}, cwd=str(tmp_path)))
    classes = [h["gate_class"] for h in d.gate_hits]
    assert classes[:2] == ["skill_commands", "external_communication"]


def test_a_command_file_is_checked_too(tmp_path):
    cmd = tmp_path / ".claude" / "commands" / "pr.md"
    cmd.parent.mkdir(parents=True)
    cmd.write_text("Context: !`gh pr diff`\n", encoding="utf-8")
    d, _ = decide(claude("Skill", {"skill": "pr"}, cwd=str(tmp_path)))
    assert d.gate_hits and d.gate_hits[0]["gate_class"] == "skill_commands"


@pytest.mark.parametrize("name", ["plugin:review", "../escape", "not-installed"])
def test_a_claude_skill_semgate_cannot_read_is_judged_by_the_model(tmp_path, name):
    d, provider = decide(claude("Skill", {"skill": name}, cwd=str(tmp_path)))
    assert provider.calls >= 1 and d.stage == "semantic"


# ---------------------------------------------------------------- installing skills, tools, MCP servers


@pytest.mark.parametrize("command", [
    "claude mcp add github -- npx -y @modelcontextprotocol/server-github",
    "claude mcp add-json weather '{\"command\":\"node\"}'",
    "claude plugin install formatter@marketplace",
    "claude plugin marketplace add owner/repo",
    "opencode mcp add",
    "codex mcp add docs -- npx -y docs-mcp",
    "gemini extensions install https://github.com/owner/ext",
    "npx skills add vercel-labs/agent-skills",
    "npx -y @smithery/cli install @owner/server --client claude",
])
def test_registering_mcp_servers_plugins_and_skills_is_a_human_gate(command):
    hits = rules.detect_gates(opencode("bash", {"command": command}))
    assert "agent_config" in [h.gate_class for h in hits]


@pytest.mark.parametrize("command,gate", [
    ("git clone https://github.com/owner/skills ~/.claude/skills/new", "instruction_file_edit"),
    ("cp -r ./my-skill ~/.agents/skills/my-skill", "instruction_file_edit"),
])
def test_writing_into_a_skill_folder_stays_a_human_gate(command, gate):
    assert gate in [h.gate_class for h in rules.detect_gates(opencode("bash", {"command": command}))]


@pytest.mark.parametrize("command", ["npm install lodash", "pip install requests", "claude mcp list", "opencode mcp list"])
def test_ordinary_installs_and_listing_go_to_the_model(command):
    hits = rules.detect_gates(opencode("bash", {"command": command}))
    assert "agent_config" not in [h.gate_class for h in hits]
    d, provider = decide(opencode("bash", {"command": command}))
    assert provider.calls >= 1 or d.stage == "human_gate"     # never a code allow


def test_writing_a_skill_file_with_the_write_tool_is_a_human_gate():
    d, _ = decide(opencode("write", {"filePath": "/home/u/.claude/skills/x/SKILL.md", "content": "hi"}))
    assert d.stage in ("human_gate", "hard_rules") and d.decision != "allow"


# ---------------------------------------------------------------- enforcement: the host gets an allow


def _config(tmp_path, answers=None, auto_allow=("read",), bwu=True, **extra):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(ROOT / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": answers if answers is not None else ALLOWING,
           "ledger_file": str(tmp_path / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": list(auto_allow), "block_when_unsure": bwu}}
    cfg.update(extra)
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return str(path)


def test_opencode_question_and_skill_run_although_not_in_auto_allow_tools(tmp_path):
    cfg = storepaths.load(_config(tmp_path), "opencode")
    for tool, args in (("question", QUESTION), ("skill", {"id": "semgate"}), ("todowrite", TODOS)):
        out = serve.judge_request("opencode", {"tool": tool, "args": args, "sessionID": "s1", "cwd": str(tmp_path)}, cfg)
        assert out["decision"] == "allow", (tool, out)
    # A model allow of a tool outside auto_allow_tools still does not run (block_when_unsure: a block).
    out = serve.judge_request("opencode", {"tool": "execute", "args": {"code": "return 1"}, "sessionID": "s1",
                                           "cwd": str(tmp_path)}, cfg)
    assert out["decision"] == "deny" and "outside the local auto-allow tool set" in out["reason"]


def test_claude_askuserquestion_is_allowed_through_the_hook(tmp_path):
    from semgate import claude_hook
    cfg = storepaths.load(_config(tmp_path, bwu=False), "claude")
    event = {"hook_event_name": "PreToolUse", "tool_name": "AskUserQuestion", "tool_input": QUESTION, "session_id": "s1",
             "cwd": str(tmp_path)}
    assert claude_hook.run(event, cfg, "claude", {})["decision"] == "allow"


def test_http_gate_allows_a_question(tmp_path):
    d = harness.check({"tool": "question", "arguments": QUESTION, "session_id": "s1", "cwd": str(tmp_path),
                       "user_messages": ["ask me before you push"]}, config=_config(tmp_path, bwu=False))
    assert d["decision"] == "allow" and d["reason_code"] == "harness_tool_allow"


# ---------------------------------------------------------------- block text without chat approval (C35)


@pytest.mark.parametrize("host,chat_ok", [
    ("claude", True), ("codex", True), ("antigravity", True), ("opencode-v1", True), ("opencode-v2", True), ("pi", True),
    ("droid", False), ("copilot", False), ("vscode", False), ("devin", False), ("some-new-host", False), (None, True),
])
def test_chat_approval_hosts_follow_manifest_c35(host, chat_ok):
    assert chat_can_approve(host) is chat_ok


def _unsure() -> Decision:
    return Decision(decision="ask", reasons=["route=review"], stage="semantic", reason_code="review")


CFG = {"mode": "enforce", "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": True}}


@pytest.mark.parametrize("host", ["claude", "codex", "antigravity", "opencode-v2", "pi", None])
def test_block_text_keeps_the_chat_instruction_where_chat_can_approve(host):
    out = antigravity_decision(_unsure(), CFG, "bash", chat_host=host)
    assert out["decision"] == "deny" and out["reason"].endswith(_BLOCKED_SUFFIX)
    assert "feedback allow" not in out["reason"]


@pytest.mark.parametrize("host", ["droid", "copilot", "vscode", "devin", "some-new-host"])
def test_block_text_names_the_terminal_command_where_chat_cannot_approve(host, monkeypatch):
    monkeypatch.setattr("semgate.skill.command", lambda: "C:/Users/me/.venv/Scripts/semgate.exe")
    out = antigravity_decision(_unsure(), CFG, "bash", chat_host=host)
    reason = out["reason"]
    assert out["decision"] == "deny" and not reason.endswith(_BLOCKED_SUFFIX)
    assert 'C:/Users/me/.venv/Scripts/semgate.exe feedback allow "<exact command>"' in reason
    assert "cannot approve" in reason and "semgate checks their reply" not in reason and "runs it themselves" in reason


def test_the_terminal_text_is_never_cut(monkeypatch):
    monkeypatch.setattr("semgate.skill.command", lambda: "semgate")
    long = Decision(decision="ask", reasons=["x" * 3000], stage="semantic", reason_code="review")
    reason = antigravity_decision(long, CFG, "bash", chat_host="droid")["reason"]
    assert len(reason) <= 1000 and reason.endswith(terminal_suffix())


@pytest.mark.parametrize("host,terminal", [("claude", False), ("droid", True), ("copilot", True), ("devin", True)])
def test_block_text_per_claude_format_host_end_to_end(tmp_path, monkeypatch, host, terminal):
    from semgate import claude_hook
    monkeypatch.setattr("semgate.skill.command", lambda: "semgate")
    cfg = storepaths.load(_config(tmp_path, answers={}, auto_allow=("read", "bash")), host)   # no answers: the router abstains
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "make deploy"},
             "session_id": "s1", "cwd": str(tmp_path)}
    out = claude_hook.run(event, cfg, host, {})
    assert out["decision"] == "deny"
    assert ('semgate feedback allow "<exact command>"' in out["reason"]) is terminal
    assert ("semgate checks their reply" in out["reason"]) is (not terminal)


def test_deny_escalation_note_follows_the_host(tmp_path):
    cfg = {"enforcement": {"deny_escalation": {"enabled": True, "consecutive": 1, "total": 20,
                                               "state_file": str(tmp_path / "streak.json")}}}
    blocked = {"decision": "deny", "reason": "r"}
    chat = antigravity_hook._apply_deny_escalation(dict(blocked), cfg, "s1", True)["reason"]
    term = antigravity_hook._apply_deny_escalation(dict(blocked), cfg, "s2", False)["reason"]
    assert "ask the user in the chat" in chat and "own terminal" not in chat
    assert "own terminal (semgate feedback allow)" in term and "in the chat to approve" not in term


# ---------------------------------------------------------------- the served model on the judgment


def test_served_model_and_upstream_are_on_the_decision():
    provider = FakeProvider(script=ALLOWING, served_model="typesafe/jev-1.13-20260917", served_upstream="TypeSafe")
    d = judge(opencode("bash", {"command": "git status"}), POLICY, provider=provider)
    out = d.to_dict()
    assert out["judge_served_model"] == "typesafe/jev-1.13-20260917" and out["judge_served_by"] == "TypeSafe"
    # No model call (hard rules): no served fields.
    d = judge(opencode("bash", {"command": "rm -rf /"}), POLICY, provider=provider)
    assert "judge_served_model" not in d.to_dict() and "judge_served_by" not in d.to_dict()


def _served_fake(monkeypatch):
    class Served(FakeProvider):
        def __init__(self, script=None, fail=False):
            super().__init__(script=script, fail=fail, served_model="typesafe/jev-1.13-20260917", served_upstream="TypeSafe")
    monkeypatch.setattr(antigravity_hook, "FakeProvider", Served)


def _judgments(tmp_path):
    rows = [json.loads(l) for l in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    return [r["decision"] for r in rows if r.get("record_type") == "judgment"]


@pytest.mark.parametrize("path", ["serve-opencode", "serve-pi", "claude-hook", "codex-hook", "antigravity-hook", "http-gate"])
def test_every_host_path_records_the_served_model(tmp_path, monkeypatch, path):
    from semgate import claude_hook
    _served_fake(monkeypatch)
    cfg_path = _config(tmp_path, auto_allow=("read", "bash"), bwu=False)
    if path.startswith("serve-"):
        host = path.split("-")[1]
        serve.judge_request(host, {"tool": "bash", "args": {"command": "git status"}, "sessionID": "s1",
                                   "cwd": str(tmp_path)}, storepaths.load(cfg_path, host))
    elif path in ("claude-hook", "codex-hook"):
        host = path.split("-")[0]
        claude_hook.run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"},
                         "session_id": "s1", "cwd": str(tmp_path)}, storepaths.load(cfg_path, host), host, {})
    elif path == "antigravity-hook":
        antigravity_hook.run({"toolCall": {"name": "run_command", "args": {"CommandLine": "git status", "Cwd": str(tmp_path)}},
                              "conversationId": "s1", "workspacePaths": [str(tmp_path)]},
                             storepaths.load(cfg_path, "antigravity"))
    else:
        harness.check({"tool": "bash", "arguments": {"command": "git status"}, "session_id": "s1", "cwd": str(tmp_path),
                       "user_messages": ["show me the git status"]}, config=cfg_path)
    rec = _judgments(tmp_path)[-1]
    assert rec["provider"] == "fake" and rec["stage"] == "semantic"
    assert rec["judge_served_model"] == "typesafe/jev-1.13-20260917" and rec["judge_served_by"] == "TypeSafe"
