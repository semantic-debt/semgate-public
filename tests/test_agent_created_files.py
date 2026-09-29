"""F6: a file the agent created in THIS session, unchanged since (hash checked
by code), with a snapshot kept, counts as restorable for the git-state check.
Every store lives under tmp_path; HOME and USERPROFILE point there too."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from semgate import agentfiles
from semgate.agentfiles import AgentFiles
from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
from semgate.gitstate import GitFacts, SyntheticFacts
from semgate.judge import judge, restore_status_text
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
ROOT = Path(__file__).parents[1]
POLICY = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
EDIT = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 1.0, "confidence": 1.0}, "user_asked": 0.9,
        "on_task": 0.9, "executes": {"value": 0.0, "confidence": 1.0}}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=r, check=True, capture_output=True)  # noqa: E731
    run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
    (r / "app.py").write_text("print(1)\n")
    run("add", "."); run("commit", "-qm", "init")
    return str(r)


def create(store, session, step, repo, rel, text="print('repro')\n", error=""):
    """What the hooks do around a Write tool call that creates `rel` with
    `text` (the pre hook records the expected hash from the tool input)."""
    store.record_pre(session, step, project_root=repo, cwd=repo, targets=[rel],
                     expected={rel: agentfiles.expected_hashes(text)})
    Path(repo, rel).parent.mkdir(parents=True, exist_ok=True)
    Path(repo, rel).write_text(text)
    return store.record_post(session, step, error)


def facts(store, session, repo):
    return GitFacts(agent_files=store, session_id=session, project_root=repo)


def test_created_then_deleted_in_same_session_is_restorable(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    out = create(store, "s1", 1, repo, "reproduce_issue.py")
    assert len(out["created"]) == 1 and Path(out["created"][0]["snapshot"]).is_file()
    assert facts(store, "s1", repo).state("reproduce_issue.py", repo).state == "agent_created"
    # the delete is no longer a human gate: it is judged, and the model is told why
    envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "rm reproduce_issue.py"}),
                        grant=UserGrant(grant_id="g", principal="p", purpose="dev"),
                        environment=Environment(project_root=repo, cwd=repo, session_id="s1"), user_message="clean up the scratch scripts")
    d = judge(envelope, POLICY, provider=FakeProvider(EDIT), facts=facts(store, "s1", repo))
    assert d.stage == "semantic" and d.decision == "allow"
    assert any("snapshot" in r and "agent_created" in r for r in d.reasons)


def test_user_modified_file_is_not_restorable(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    create(store, "s1", 1, repo, "scratch.py")
    Path(repo, "scratch.py").write_text("print('the user changed this')\n")
    assert facts(store, "s1", repo).state("scratch.py", repo).state == "untracked"


def test_file_created_in_another_session_is_not_restorable(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    create(store, "s1", 1, repo, "scratch.py")
    assert facts(store, "s2", repo).state("scratch.py", repo).state == "untracked"
    assert facts(store, "", repo).state("scratch.py", repo).state == "untracked"


def test_outside_project_root_is_never_eligible(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    pkg = os.path.join(repo, "pkg")
    os.makedirs(pkg)
    # project_root is repo/pkg; the file is in the repo but outside the project
    store.record_pre("s1", 1, project_root=pkg, cwd=repo, targets=["other.py"])
    Path(repo, "other.py").write_text("x = 1\n")
    assert store.record_post("s1", 1)["created"] == []
    assert GitFacts(agent_files=store, session_id="s1", project_root=pkg).state("other.py", repo).state == "untracked"


def test_missing_snapshot_is_not_eligible(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    out = create(store, "s1", 1, repo, "scratch.py")
    os.remove(out["created"][0]["snapshot"])
    assert facts(store, "s1", repo).state("scratch.py", repo).state == "untracked"


def test_tampered_snapshot_is_not_eligible(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    out = create(store, "s1", 1, repo, "scratch.py")
    Path(out["created"][0]["snapshot"]).write_text("something else\n")
    assert facts(store, "s1", repo).state("scratch.py", repo).state == "untracked"


def test_failed_step_or_preexisting_file_records_nothing(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    assert create(store, "s1", 1, repo, "a.py", error="tool failed")["created"] == []
    Path(repo, "b.py").write_text("old\n")
    assert create(store, "s1", 2, repo, "b.py")["created"] == []      # existed before: not created by the agent
    assert facts(store, "s1", repo).state("b.py", repo).state == "untracked"


def test_file_over_the_size_cap_is_not_recorded(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"), max_bytes=10)
    assert create(store, "s1", 1, repo, "big.py", text="x" * 100)["created"] == []


def test_symlink_is_not_eligible(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    create(store, "s1", 1, repo, "real.py")
    try:
        os.symlink(os.path.join(repo, "real.py"), os.path.join(repo, "link.py"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here")
    assert facts(store, "s1", repo).state("real.py", repo).state == "agent_created"
    assert facts(store, "s1", repo).state("link.py", repo).state == "untracked"


def test_session_id_never_becomes_a_path(tmp_path, repo):
    store = AgentFiles(str(tmp_path / "sg"))
    create(store, "../../evil", 1, repo, "scratch.py")
    names = {p.name for p in (tmp_path / "sg" / "agent_files").iterdir()}
    key = agentfiles.session_key("../../evil")
    assert names == {key + ".jsonl", key + ".jsonl.lock"}          # the .lock sidecar only carries the OS lock


def test_restore_status_text():
    from semgate.gitstate import TargetState
    assert restore_status_text([TargetState("a.py", "clean")]).endswith("can be restored with git.")
    text = restore_status_text([TargetState("r.py", "agent_created")])
    assert "created by the agent in this session; content unchanged since (checked by code); snapshot kept" in text


def test_synthetic_facts_for_evals():
    f = SyntheticFacts({"/w/p/repro.py": "ab" * 32}, "/w/p")
    assert [s.state for s in f.assess("cd /w/p && rm repro.py other.py", "/w/p")] == ["agent_created", "unknown"]
    assert f.state("/w/elsewhere/repro.py", "/w/p").state == "unknown"


def _config(tmp_path, repo):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(ROOT / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": EDIT, "ledger_file": str(tmp_path / "ledger.jsonl"), "git_facts": True,
           "agent_files": {"enabled": True, "dir": str(tmp_path / "sg")},
           "enforcement": {"enabled": True, "auto_allow_tools": ["bash"], "block_when_unsure": False}}
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(cfg))
    return cfg, str(path)


def test_antigravity_pre_and_post_hooks_end_to_end(tmp_path, repo):
    from semgate import antigravity_hook
    cfg, cfg_path = _config(tmp_path, repo)

    def pre(step, command):
        return antigravity_hook.run({"conversationId": "conv", "stepIdx": step, "workspacePaths": [repo],
                                     "toolCall": {"name": "run_command", "args": {"CommandLine": command, "Cwd": repo}}}, cfg)

    Path(repo, "user.py").write_text("mine\n")                       # untracked, made by the user
    assert pre(1, "rm user.py")["decision"] == "force_ask"             # not agent-created: the gate stays
    pre(2, "echo print(1) > shell.py")                                 # shell write: content unknown at decision time
    Path(repo, "shell.py").write_text("print(1)\n")
    subprocess.run([sys.executable, "-m", "semgate.antigravity_post_hook", "--config", cfg_path],
                   input=json.dumps({"conversationId": "conv", "stepIdx": 2}), capture_output=True, text=True,
                   env=dict(os.environ), timeout=60)
    assert pre(4, "rm shell.py")["decision"] == "force_ask"            # never recorded as agent-created
    # write_to_file: agy sends string args JSON-encoded
    antigravity_hook.run({"conversationId": "conv", "stepIdx": 5, "workspacePaths": [repo],
                          "toolCall": {"name": "write_to_file", "args": {"TargetFile": json.dumps(os.path.join(repo, "made.py")),
                                                                         "CodeContent": json.dumps("print(1)\n")}}}, cfg)
    Path(repo, "made.py").write_text("print(1)\n")
    p = subprocess.run([sys.executable, "-m", "semgate.antigravity_post_hook", "--config", cfg_path],
                       input=json.dumps({"conversationId": "conv", "stepIdx": 5}), capture_output=True, text=True,
                       env=dict(os.environ), timeout=60)
    assert p.returncode == 0 and p.stdout.strip() == "{}", p.stderr
    assert pre(3, "rm made.py")["decision"] == "allow"


def test_claude_post_event_records_and_prints_empty_object(tmp_path, repo):
    from semgate import claude_hook
    cfg, cfg_path = _config(tmp_path, repo)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": os.path.join(repo, "new.py"), "content": "x=1\n"},
             "session_id": "cs", "tool_use_id": "tu1", "cwd": repo}
    claude_hook.run(event, cfg, "claude", {})
    Path(repo, "new.py").write_text("x=1\n")
    post = dict(event, hook_event_name="PostToolUse", tool_response={"success": True})
    p = subprocess.run([sys.executable, "-m", "semgate.claude_hook", "--config", cfg_path], input=json.dumps(post),
                       capture_output=True, text=True, env=dict(os.environ), timeout=60)
    assert p.returncode == 0 and json.loads(p.stdout) == {}, p.stderr
    store = AgentFiles(str(tmp_path / "sg"))
    assert facts(store, "cs", repo).state("new.py", repo).state == "agent_created"
    # Devin/Copilot-style events without tool_use_id record nothing
    claude_hook.run({"tool_name": "exec", "tool_input": {"command": "echo 1 > d.py"}, "prompt_id": "p1", "session_id": "cs", "cwd": repo},
                    cfg, "devin", {})
    assert all(r.get("step_idx") != "p1" for r in store.records("cs"))


def test_opencode_after_event_through_serve(tmp_path, repo):
    import io
    from semgate import serve
    cfg, cfg_path = _config(tmp_path, repo)
    req = {"tool": "write", "args": {"filePath": os.path.join(repo, "oc.py"), "content": "y=2\n"}, "sessionID": "os", "callID": "c9", "cwd": repo}
    lines = [json.dumps({"id": 1, "host": "opencode", "request": req})]
    out = io.StringIO()
    serve.serve(cfg_path, stdin=io.StringIO(lines[0] + "\n"), stdout=out)
    Path(repo, "oc.py").write_text("y=2\n")
    out2 = io.StringIO()
    serve.serve(cfg_path, stdin=io.StringIO(json.dumps({"id": 2, "host": "opencode", "event": "after",
                                                          "request": {"sessionID": "os", "callID": "c9"}}) + "\n"), stdout=out2)
    assert json.loads(out2.getvalue()) == {"id": 2, "recorded": True}
    assert facts(AgentFiles(str(tmp_path / "sg")), "os", repo).state("oc.py", repo).state == "agent_created"
