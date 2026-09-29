"""The framework-free helper (semgate.client.guard / resolve) and the
examples in examples/harness: plain harness, function-calling loop, n8n
workflow, curl script, LangGraph (skipped without langgraph)."""
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from semgate.client import ApprovalFailed, LocalClient, guard, human_answer, resolve, safe_id

from test_harness_api import make_config, req

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "harness"


def example(name):
    sys.path.insert(0, str(EXAMPLES))
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(str(EXAMPLES))


class FakeClient:
    """Scripted semgate answers; records approve calls."""

    def __init__(self, *answers, approve_error=None):
        self.answers = list(answers)
        self.approved = []
        self.approve_error = approve_error

    def check(self, request):
        return self.answers.pop(0)

    def approve(self, approval_id, approved, by, note=""):
        self.approved.append((approval_id, approved, by))
        if self.approve_error:
            raise self.approve_error
        return {"approval_id": approval_id, "status": "approved" if approved else "denied"}


ALLOW = {"decision": "allow", "reason": "ok", "reason_code": "aligned_readonly_allow"}
DENY = {"decision": "deny", "reason": "no", "reason_code": "hard_deny"}
ASK = {"decision": "ask", "reason": "network install", "reason_code": "human_gate:external_communication",
       "approval_id": "a" * 32}


# ---------------------------------------------------------------- guard / resolve


def test_guard_allow_runs_and_deny_does_not():
    ran = []
    res = guard(FakeClient(ALLOW), {}, run=lambda: ran.append(1) or "out", ask_human=lambda d: pytest.fail("asked"))
    assert res.ran and res.output == "out" and ran == [1]
    res = guard(FakeClient(DENY), {}, run=lambda: pytest.fail("ran"), ask_human=lambda d: pytest.fail("asked"))
    assert not res.ran and "hard_deny" in res.message


def test_guard_ask_yes_approves_then_rechecks():
    c = FakeClient(ASK, ALLOW)
    res = guard(c, {}, run=lambda: "out", ask_human=lambda d: {"approved": True, "by": "manuel"})
    assert res.ran and c.approved == [("a" * 32, True, "manuel")]


def test_guard_ask_no_and_failures_never_run():
    c = FakeClient(ASK)
    res = guard(c, {}, run=lambda: pytest.fail("ran"), ask_human=lambda d: "no")
    assert not res.ran and c.approved == [("a" * 32, False, "human")] and "a human said no" in res.message
    # an ask the human cannot approve (no id): the human is not asked, nothing runs
    res = guard(FakeClient(dict(ASK, approval_id=None)), {}, run=lambda: pytest.fail("ran"),
                ask_human=lambda d: pytest.fail("asked"))
    assert not res.ran
    # approved, but the re-check is not an allow (e.g. the judge now denies)
    res = guard(FakeClient(ASK, DENY), {}, run=lambda: pytest.fail("ran"), ask_human=lambda d: True)
    assert not res.ran and "hard_deny" in res.message
    # the answer could not be recorded (401): nothing runs
    res = guard(FakeClient(ASK, ALLOW, approve_error=ApprovalFailed("bad token", 401)), {}, run=lambda: pytest.fail("ran"),
                ask_human=lambda d: True)
    assert not res.ran and "could not be recorded" in res.message
    # 409: recorded before (a resumed run) -> check again
    res = guard(FakeClient(ASK, ALLOW, approve_error=ApprovalFailed("already approved", 409)), {}, run=lambda: "out",
                ask_human=lambda d: True)
    assert res.ran


def test_resolve_with_an_answer_recorded_elsewhere():
    c = FakeClient(ALLOW)
    assert resolve(c, {}, ASK, {"approved": True, "already_recorded": True})["decision"] == "allow" and c.approved == []


def test_human_answer_and_safe_id():
    assert human_answer("Yes")["approved"] and not human_answer("sure")["approved"] and not human_answer(None)["approved"]
    assert not human_answer({"approved": "true"})["approved"]              # only a real true
    assert safe_id("thread 1/abc") == "thread_1_abc" and safe_id("").startswith("id-") and len(safe_id("x" * 500)) < 64


# ---------------------------------------------------------------- the examples, offline (fake provider)


def test_plain_harness_session(tmp_path):
    plain = example("plain_harness")
    cfg = make_config(tmp_path, auto_allow=("read", "bash"))
    ran = []
    s = plain.Session(LocalClient(cfg), str(tmp_path), tools={"bash": lambda a: ran.append(a["command"]) or "clean"},
                      ask_human=lambda d: pytest.fail("asked"))
    s.user("show me the git status")
    assert s.tool_call("bash", {"command": "git status"}) == "clean"
    out = s.tool_call("bash", {"command": "rm -rf /"})
    assert "hard_deny" in out and ran == ["git status"]
    assert [r["summary"] for r in s.recent] == ["git status", "rm -rf /"]


def test_plain_harness_ask_path(tmp_path):
    plain = example("plain_harness")
    cfg = make_config(tmp_path)                    # bash outside auto_allow_tools: ask
    asked = []
    s = plain.Session(LocalClient(cfg), str(tmp_path), tools={"bash": lambda a: "clean"},
                      ask_human=lambda d: asked.append(d["approval_id"]) or {"approved": True, "by": "manuel"})
    s.user("show me the git status")
    assert s.tool_call("bash", {"command": "git status"}) == "clean" and len(asked) == 1


def test_function_calling_loop(tmp_path):
    loop = example("function_calling_loop")
    cfg = make_config(tmp_path, auto_allow=("read", "bash"))
    script = [
        {"content": "checking", "tool_calls": [{"id": "call_1", "name": "bash", "arguments": json.dumps({"command": "git status"})},
                                               {"id": "call_2", "name": "bash", "arguments": json.dumps({"command": "rm -rf /"})}]},
        {"content": "all done", "tool_calls": []},
    ]
    seen = []

    def model(messages):
        seen.append([m.get("content") for m in messages if m["role"] == "tool"])
        return script.pop(0)
    ran = []
    out = loop.agent_loop(model, {"bash": lambda command: ran.append(command) or "clean"}, LocalClient(cfg),
                          session_id="fc-1", cwd=str(tmp_path), user_text="show me the git status",
                          ask_human=lambda d: pytest.fail("asked"))
    assert out == "all done" and ran == ["git status"]
    assert seen[1][0] == "clean" and "hard_deny" in seen[1][1]


def test_n8n_workflow_is_wired():
    wf = json.loads((EXAMPLES / "n8n" / "semgate-approval.workflow.json").read_text(encoding="utf-8"))
    nodes = {n["name"]: n for n in wf["nodes"]}
    assert len(nodes) == len(wf["nodes"])
    for src, conn in wf["connections"].items():
        assert src in nodes
        for branch in conn["main"]:
            for target in branch:
                assert target["node"] in nodes
    http = {n["name"]: n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"}
    assert http["semgate check"]["parameters"]["url"].endswith("/v1/check")
    assert http["semgate re-check"]["parameters"]["url"].endswith("/v1/check")
    assert http["semgate approve"]["parameters"]["url"].endswith("/v1/approve")
    # the approve step uses its own credential; no token is written in the file
    assert http["semgate approve"]["credentials"]["httpHeaderAuth"]["name"] != \
        http["semgate check"]["credentials"]["httpHeaderAuth"]["name"]
    assert "Bearer " not in json.dumps(wf).replace("Bearer <", "")
    # the tool runs only behind an allow branch (output 0 of an IF on decision == allow)
    for run in ("Run tool", "Run tool (approved)"):
        feeders = [(src, i) for src, conn in wf["connections"].items() for i, branch in enumerate(conn["main"])
                   for t in branch if t["node"] == run]
        assert len(feeders) == 1 and feeders[0][1] == 0
        cond = nodes[feeders[0][0]]["parameters"]["conditions"]["string"][0]
        assert cond["value1"] == "={{ $json.decision }}" and cond["value2"] == "allow"
    assert nodes["Wait for approval"]["type"] == "n8n-nodes-base.wait"


@pytest.mark.skipif(os.name == "nt" or not (shutil.which("bash") and shutil.which("curl")),
                    reason="needs bash and curl (the script is run on Linux/macOS)")
def test_curl_script(tmp_path):
    from semgate import httpserve
    cfg = make_config(tmp_path)
    (tmp_path / "check.token").write_text("c" * 24, encoding="utf-8")
    (tmp_path / "approve.token").write_text("a" * 24, encoding="utf-8")
    port_file = tmp_path / "port"
    proc = subprocess.Popen([sys.executable, "-m", "semgate", "serve", "--http", "--port", "0", "--config", cfg,
                             "--token-file", str(tmp_path / "check.token"), "--approve-token-file",
                             str(tmp_path / "approve.token"), "--port-file", str(port_file)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        port = httpserve.wait_for_port_file(str(port_file), timeout=60)
        env = dict(os.environ, SEMGATE_URL=f"http://127.0.0.1:{port}",
                   SEMGATE_CHECK_TOKEN_FILE=str(tmp_path / "check.token"),
                   SEMGATE_APPROVE_TOKEN_FILE=str(tmp_path / "approve.token"))
        out = subprocess.run(["bash", str(EXAMPLES / "curl.sh")], cwd=str(tmp_path), env=env, capture_output=True,
                             text=True, timeout=120)
        assert out.returncode == 0, out.stderr
        lines = [json.loads(l) for l in out.stdout.splitlines() if l.startswith("{")]
        assert lines[0]["ok"] and lines[1]["decision"] == "ask" and lines[2]["status"] == "approved"
        assert lines[3]["decision"] == "allow" and lines[3]["reason_code"] == "human_approved_once"
    finally:
        proc.terminate()
        proc.wait(timeout=20)


def test_langgraph_example(tmp_path):
    pytest.importorskip("langgraph")
    lg = example("langgraph_tool_node")
    cfg = make_config(tmp_path)                    # bash outside auto_allow_tools: ask
    ran = []
    graph = lg.build_graph(LocalClient(cfg), {"bash": lambda command: ran.append(command) or "clean tree"}, cwd=str(tmp_path))
    msgs = lg.run_with_human(graph, "show me the git status", "t-yes", lambda ask: {"approved": True, "by": "manuel"})
    assert ran == ["git status"] and any("clean tree" in str(m.content) for m in msgs)
    graph = lg.build_graph(LocalClient(cfg), {"bash": lambda command: ran.append(command) or "x"}, cwd=str(tmp_path))
    msgs = lg.run_with_human(graph, "show me the git status", "t-no", lambda ask: {"approved": False, "by": "manuel"})
    assert ran == ["git status"] and any("a human said no" in str(m.content) for m in msgs)
