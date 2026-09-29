"""Concurrency and fail-closed fixes (formal/REPORT.md): cross-process store
locks, torn lines, spill files, deny streak, scoped feedback approvals, F6
created files, the session-drift window and serve deadlines.

Isolation: HOME and USERPROFILE point at tmp_path/"home"; every store path is
under tmp_path. Only the offline fake provider (or an injected judge_fn) is
used. Multi-process tests use the "spawn" start method and module-level child
functions, so they run the same way on Windows and POSIX.
"""
from __future__ import annotations

import io
import json
import multiprocessing
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from semgate import agentfiles, claude_hook, filelock
from semgate import feedback as feedback_mod
from semgate import serve as serve_mod
from semgate.adapters import claude_family
from semgate.agentfiles import AgentFiles
from semgate.antigravity_hook import _apply_deny_escalation, _deny_streak_update
from semgate.envelope import (SCHEMA_VERSION, Envelope, Environment, ProposedAction, Trajectory, TrajectoryEntry,
                              UserGrant, utcnow_iso)
from semgate.feedback import FeedbackStore, time_now
from semgate.history import ToolHistory
from semgate.judge import judge
from semgate.ledger import IncompleteWindow, Ledger
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = Policy.load(str(ROOT / "policies" / "default_policy.json"))
DEV_PATH = ROOT / "policies" / "router_policy_dev.json"
SDRIFT = Policy.load(str(ROOT / "policies" / "router_policy_dev_sdrift.json"))
CLEAR = {p.predicate_id: 0.01 for p in DEFAULT.predicates}          # default policy: every predicate clear
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
            "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}
GRANT = UserGrant(grant_id="g", principal="p", purpose="Software development in this project",
                  allowed_tools=("bash", "read"), expires_at="2099-01-01T00:00:00Z")
LOCK_TIMEOUT = "0.3"
HOLD_CODE = ("from semgate import filelock; import sys, time; cm = filelock.exclusive(sys.argv[1]); cm.__enter__(); "
             "print('held', flush=True); time.sleep(30)")
SPAWN = multiprocessing.get_context("spawn")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("SEMGATE_CONFIG", str(tmp_path / "no-such-config.json"))
    monkeypatch.setenv("SEMGATE_ANTIGRAVITY_CONFIG", str(tmp_path / "no-such-config.json"))
    monkeypatch.setenv("SEMGATE_FEEDBACK_FILE", str(tmp_path / "no-such-feedback.jsonl"))
    monkeypatch.delenv("SEMGATE_LOCK_TIMEOUT_S", raising=False)


# ---------------- helpers ----------------

def child_env(**extra):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env.update(extra)
    return env


@contextmanager
def held(path):
    """Another process holds the cross-process lock of `path` until the block ends."""
    proc = subprocess.Popen([sys.executable, "-c", HOLD_CODE, str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=child_env(), text=True)
    try:
        line = proc.stdout.readline()
        if line.strip() != "held":
            proc.kill()
            raise AssertionError(f"lock holder did not start: {line!r} {proc.stderr.read()}")
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=10)


def run_spawn(target, arg_sets, timeout=60):
    procs = [SPAWN.Process(target=target, args=args) for args in arg_sets]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout)
    for p in procs:
        if p.is_alive():
            p.kill()
    assert [p.exitcode for p in procs] == [0] * len(procs)


def spilled(path):
    return [r for s in filelock.spill_files(path) for r in filelock.read_jsonl(s).records]


def bash_env(command, root, session="s1"):
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": command}), grant=GRANT,
                    environment=Environment(project_root=str(root), cwd=str(root), session_id=session))


def claude_event(command, session, cwd, tool_use_id):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
            "session_id": session, "tool_use_id": tool_use_id, "cwd": str(cwd)}


def hook_config(tmp_path, auto_allow_tools, block_when_unsure, feedback=False):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(DEV_PATH), "provider": "fake",
           "fake_answers": ALLOWING, "ledger_file": str(tmp_path / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": list(auto_allow_tools),
                           "block_when_unsure": block_when_unsure}}
    if feedback:
        cfg["feedback"] = {"enabled": True, "feedback_file": str(tmp_path / "feedback.jsonl")}
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return cfg, path


def hook_subprocess(cfg_path, event, cwd, **env):
    p = subprocess.run([sys.executable, "-m", "semgate.claude_hook", "--config", str(cfg_path)], input=json.dumps(event),
                       capture_output=True, text=True, timeout=120, env=child_env(**env), cwd=str(cwd))
    return json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"]


# ---------------- module-level children (spawn) ----------------

def _child_host_responses(path, worker, n, barrier):
    from semgate.ledger import Ledger
    led = Ledger(path)
    barrier.wait()
    for i in range(n):
        led.record_host_response(f"sess-{worker}", i, {"decision": "allow", "reason": "x" * 200}, tool="bash")


def _child_deny_blocks(state_file, n, barrier):
    from semgate.antigravity_hook import _deny_streak_update
    barrier.wait()
    for _ in range(n):
        _deny_streak_update(state_file, "sess", True)


def _child_record_post(base, session, step, barrier):
    from semgate.agentfiles import AgentFiles
    barrier.wait()
    AgentFiles(base).record_post(session, step)


# ---------------- 1-3: filelock ----------------

def test_ledger_append_times_out_and_spills_when_another_process_holds_the_lock(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", LOCK_TIMEOUT)
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    rec = {"record_type": "outcome", "judgment_id": "j1", "outcome": "reverted"}
    with held(led.path):
        t0 = time.monotonic()
        with pytest.raises(filelock.LockTimeout):
            led._append(rec)
        took = time.monotonic() - t0
    # The 0.3 s setting is honored, not the 5 s default. 2.5 s leaves room for
    # slow CI runners (windows-latest took 1.06 s on run 36045417666).
    assert took < 2.5
    assert spilled(led.path) == [dict(rec, lock_timeout=True)]
    assert filelock.read_jsonl(led.path).records == []


def test_append_after_a_torn_line_starts_on_its_own_line(tmp_path):
    # repair=True (the feedback store): the new record starts on its own line
    p = tmp_path / "store.jsonl"
    p.write_bytes(b'{"a": 1}\n{"b": ')
    filelock.append_record(p, {"c": 3}, repair=True)
    assert p.read_bytes() == b'{"a": 1}\n{"b": \n{"c": 3}\n'
    result = filelock.read_jsonl(p)
    assert result.records == [{"a": 1}, {"c": 3}]
    assert result.malformed == [9]
    assert result.partial_tail is False
    # hot stores skip the check (no read handle): the glued line is skipped, never misread
    q = tmp_path / "hot.jsonl"
    q.write_bytes(b'{"a": 1}\n{"b": ')
    filelock.append_record(q, {"c": 3})
    result = filelock.read_jsonl(q)
    assert result.records == [{"a": 1}] and result.malformed == [9]


def test_feedback_store_repairs_a_torn_last_line(tmp_path):
    from semgate.feedback import FeedbackStore
    p = tmp_path / "fb.jsonl"
    p.write_bytes(b'{"record_type": "feedback", "deci')
    fb = FeedbackStore(str(p))
    fb.record("deny", "bash", {"command": "npm run deploy"})
    assert fb.latest("bash", {"command": "npm run deploy"}, session_id="s", project_root=str(tmp_path)) == "deny"


def test_four_processes_append_600_host_responses_without_loss(tmp_path):
    path = str(tmp_path / "ledger.jsonl")
    barrier = SPAWN.Barrier(4)
    run_spawn(_child_host_responses, [(path, w, 150, barrier) for w in range(4)])
    result = filelock.read_jsonl(path)
    rows = [r for r in result.records if r.get("record_type") == "host_response"]
    assert len(rows) == 600
    assert result.malformed == [] and result.partial_tail is False
    assert len({(r["conversation_id"], r["step_idx"]) for r in rows}) == 600


# ---------------- 4-5: ledger lock in the judge and the hook ----------------

def test_judge_turns_an_allow_into_ask_when_the_ledger_lock_is_held(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", LOCK_TIMEOUT)
    e = bash_env("git status", tmp_path)
    free = judge(e, DEFAULT, provider=FakeProvider(CLEAR), ledger=Ledger(str(tmp_path / "free.jsonl")))
    assert free.decision == "allow"
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    with held(led.path):
        d = judge(e, DEFAULT, provider=FakeProvider(CLEAR), ledger=led)
    assert (d.decision, d.stage, d.reason_code) == ("ask", "store_unavailable", "store_lock_timeout")
    kept = spilled(led.path)
    assert [r["record_type"] for r in kept] == ["judgment"] and kept[0]["lock_timeout"] is True


def test_claude_hook_asks_and_spills_host_response_when_the_ledger_lock_is_held(tmp_path):
    cfg, cfg_path = hook_config(tmp_path, ["bash", "read"], block_when_unsure=False)
    proj = tmp_path / "proj"
    proj.mkdir()
    assert hook_subprocess(cfg_path, claude_event("git status", "sess-A", proj, "t1"), proj) == "allow"
    ledger = Path(cfg["ledger_file"])
    with held(ledger):
        decision = hook_subprocess(cfg_path, claude_event("git status", "sess-A", proj, "t2"), proj,
                                   SEMGATE_LOCK_TIMEOUT_S=LOCK_TIMEOUT)
    assert decision == "ask"
    responses = [r for r in spilled(ledger) if r.get("record_type") == "host_response"]
    assert len(responses) == 1
    assert responses[0]["step_idx"] == "t2" and responses[0]["lock_timeout"] is True
    assert responses[0]["native"]["decision"] != "allow"


# ---------------- 6-7: deny streak ----------------

def test_deny_streak_lock_held_raises_and_allow_becomes_force_ask(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", LOCK_TIMEOUT)
    state = tmp_path / "deny_streak.json"
    cfg = {"enforcement": {"deny_escalation": {"enabled": True, "consecutive": 3, "total": 20, "state_file": str(state)}}}
    with held(filelock.sidecar(state)):
        with pytest.raises(filelock.LockTimeout):
            _deny_streak_update(str(state), "sess", True)
        allow = _apply_deny_escalation({"decision": "allow", "reason": "ok"}, cfg, "sess")
        deny = _apply_deny_escalation({"decision": "deny", "reason": "no"}, cfg, "sess")
    assert allow["decision"] == "force_ask" and "deny-streak" in allow["reason"]
    assert deny["decision"] == "deny"
    assert not state.exists()


def test_deny_streak_corrupt_file_is_rewritten_from_zero(tmp_path):
    state = tmp_path / "deny_streak.json"
    state.write_bytes(b"{not json")
    assert _deny_streak_update(str(state), "sess", True) == {"consecutive": 1, "total": 1}
    assert json.loads(state.read_text(encoding="utf-8")) == {"sess": {"consecutive": 1, "total": 1}}


def test_deny_streak_four_processes_count_200_blocks_exactly(tmp_path):
    state = tmp_path / "streak" / "deny_streak.json"
    barrier = SPAWN.Barrier(4)
    run_spawn(_child_deny_blocks, [(str(state), 50, barrier) for _ in range(4)])
    assert json.loads(state.read_text(encoding="utf-8"))["sess"] == {"consecutive": 200, "total": 200}
    assert list(state.parent.glob("*.tmp")) == []


# ---------------- 8-10: feedback scope ----------------

def test_feedback_allow_scope(tmp_path):
    cmd = "rm -rf dist"
    proj, other = tmp_path / "projA", tmp_path / "projB"
    proj.mkdir()
    other.mkdir()
    now = time_now()

    def latest(store, command=cmd, session="sess-A", project=proj, at=now + 60):
        return store.latest("bash", {"command": command}, session_id=session, project_root=str(project), now=at)

    scoped = FeedbackStore(str(tmp_path / "scoped.jsonl"))
    scoped.record("allow", "bash", {"command": cmd}, session_id="sess-A", project_root=str(proj), now=now)
    assert latest(scoped) == "allow"
    assert latest(scoped) == "allow"                       # reusable inside its scope
    assert latest(scoped, session="sess-B") is None
    assert latest(scoped, project=other) is None
    assert latest(scoped, command="rm -rf DIST") is None

    expired = FeedbackStore(str(tmp_path / "expired.jsonl"), max_ttl_hours=4)
    expired.record("allow", "bash", {"command": cmd}, session_id="sess-A", project_root=str(proj), now=now - 5 * 3600)
    assert latest(expired, at=now) is None

    long_path = str(tmp_path / "long.jsonl")
    FeedbackStore(long_path, max_ttl_hours=24).record("allow", "bash", {"command": cmd}, session_id="sess-A",
                                                      project_root=str(proj), ttl_hours=24, now=now)
    assert latest(FeedbackStore(long_path, max_ttl_hours=24), at=now + 5 * 3600) == "allow"
    assert latest(FeedbackStore(long_path, max_ttl_hours=4), at=now + 5 * 3600) is None   # the hook's cap


def test_feedback_legacy_allow_ignored_and_legacy_deny_honored(tmp_path):
    cmd = "npm publish"
    path = tmp_path / "feedback.jsonl"
    legacy = {"record_type": "feedback", "decision": "allow", "tool": "bash",
              "action_key": feedback_mod._key("bash", {"command": cmd}), "ts": feedback_mod._iso(time_now() - 60)}
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    store = FeedbackStore(str(path))
    assert store.latest("bash", {"command": cmd}, session_id="sess-A", project_root=str(tmp_path)) is None
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(legacy, decision="deny")) + "\n")
    assert store.latest("bash", {"command": cmd}, session_id="sess-A", project_root=str(tmp_path)) == "deny"
    assert store.latest("bash", {"command": cmd}, session_id="sess-Z", project_root=str(tmp_path / "x")) == "deny"


def test_feedback_allow_without_session_or_project_raises(tmp_path):
    store = FeedbackStore(str(tmp_path / "feedback.jsonl"))
    with pytest.raises(ValueError):
        store.record("allow", "bash", {"command": "rm -rf dist"}, project_root=str(tmp_path))
    with pytest.raises(ValueError):
        store.record("allow", "bash", {"command": "rm -rf dist"}, session_id="sess-A")
    assert not (tmp_path / "feedback.jsonl").exists() or (tmp_path / "feedback.jsonl").read_bytes() == b""


# ---------------- 11-13: feedback in the judge, the hook and the CLI ----------------

def test_judge_asks_when_the_feedback_store_lock_is_held(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", LOCK_TIMEOUT)
    fb_path = tmp_path / "feedback.jsonl"
    fb_path.write_bytes(b"")
    fb = FeedbackStore(str(fb_path))
    e = bash_env("git status", tmp_path)
    assert judge(e, DEFAULT, provider=FakeProvider(CLEAR), feedback=fb).decision == "allow"
    with held(fb_path):
        d = judge(e, DEFAULT, provider=FakeProvider(CLEAR), feedback=fb)
    assert (d.decision, d.stage, d.reason_code) == ("ask", "store_unavailable", "feedback_unreadable")


def test_scoped_approval_lets_a_semantic_bash_allow_through_only_in_its_session(tmp_path):
    cfg, _ = hook_config(tmp_path, ["read"], block_when_unsure=True, feedback=True)
    proj = tmp_path / "projA"
    proj.mkdir()

    def hook(session, tid):
        return claude_hook.run(claude_event("npm run build", session, proj, tid), cfg, "claude", {})["decision"]

    assert hook("sess-A", "t1") == "deny"
    first = Ledger(cfg["ledger_file"]).judgments()[0]["decision"]
    assert (first["decision"], first["stage"]) == ("allow", "semantic")
    FeedbackStore(cfg["feedback"]["feedback_file"]).record("allow", "bash", {"command": "npm run build"},
                                                           session_id="sess-A", project_root=str(proj))
    assert hook("sess-A", "t2") == "allow"
    assert hook("sess-B", "t3") == "deny"


def test_cli_feedback_allow_binds_to_the_blocked_session_end_to_end(tmp_path):
    cfg, cfg_path = hook_config(tmp_path, ["read"], block_when_unsure=True, feedback=True)
    proj_a, proj_b = tmp_path / "projA", tmp_path / "projB"
    for p in (proj_a, proj_b):
        (p / "dist").mkdir(parents=True)
    fb_file = Path(cfg["feedback"]["feedback_file"])

    def hook(session, proj, tid):
        return claude_hook.run(claude_event("rm -rf dist", session, proj, tid), cfg, "claude", {})["decision"]

    def cli(*args):
        p = subprocess.run([sys.executable, "-m", "semgate", "feedback", *args, "--config", str(cfg_path)],
                           capture_output=True, text=True, cwd=str(proj_a), env=child_env(), timeout=120)
        return p.returncode, p.stdout + p.stderr

    def lines():
        return len(fb_file.read_bytes().splitlines()) if fb_file.exists() else 0

    assert hook("sess-A", proj_a, "t1") == "deny"
    assert hook("sess-B", proj_b, "t2") == "deny"
    code, out = cli("allow", "rm -rf dist")
    assert code == 0, out
    assert "approved" in out and "sess-A" in out and "sess-B" not in out
    assert lines() == 1
    assert hook("sess-A", proj_a, "t3") == "allow"
    assert hook("sess-B", proj_b, "t4") == "deny"
    code, out = cli("allow", "rm -rf dist/")
    assert code == 2 and "not recorded" in out
    assert lines() == 1


# ---------------- 14-16: malformed lines in history and ledger ----------------

def _executed(history, conv, step, command):
    history.record_pending(conv, step, "bash", {"command": command}, "ask", "semantic")
    history.record_executed(conv, step)


def test_history_skips_a_malformed_middle_line_and_warns_once(tmp_path, monkeypatch):
    path = tmp_path / "tool_history.jsonl"
    h = ToolHistory(str(path))
    _executed(h, "c", 1, "make deploy")
    with open(path, "ab") as handle:
        handle.write(b'{"record_type": "executed", ### not json\n')
    _executed(h, "c", 2, "make deploy")
    assert h.count_executed_after_ask("bash", {"command": "make deploy"}) == 2
    list(h.records())
    list(h.records())
    monkeypatch.setattr(filelock, "_warned", {})           # a new process: only the file-level dedup is left
    list(h.records())
    warnings = [r for r in filelock.read_jsonl(path).records if r.get("record_type") == "store_warning"]
    assert len(warnings) == 1 and warnings[0]["kind"] == "malformed_line"
    assert warnings[0]["offset"] == filelock.read_jsonl(path).malformed[0]


def test_history_never_counts_an_executed_record_cut_in_half(tmp_path):
    path = tmp_path / "tool_history.jsonl"
    h = ToolHistory(str(path))
    _executed(h, "c", 1, "make deploy")
    whole = [r for r in h.records() if r["record_type"] == "executed"][0]
    data = filelock.encode_record(dict(whole, step_idx=99))
    with open(path, "ab") as handle:
        handle.write(data[: len(data) // 2] + b"\n")
    _executed(h, "c", 2, "make deploy")
    _executed(h, "c", 3, "make deploy")
    assert h.count_executed_after_ask("bash", {"command": "make deploy"}) == 3
    assert all(r.get("step_idx") != 99 for r in h.records())


def test_ledger_records_skip_a_malformed_line(tmp_path):
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    led.record_outcome("j1", "approved")
    with open(led.path, "ab") as handle:
        handle.write(b"{broken\n")
    led.record_outcome("j2", "denied")
    rows = list(led.records())
    assert [r["judgment_id"] for r in rows if r["record_type"] == "outcome"] == ["j1", "j2"]


# ---------------- 17-20: F6 agent-created files ----------------

TEXT = "print('repro')\nprint('done')\n"


def test_f6_user_edit_before_post_is_not_recorded(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    store = AgentFiles(str(tmp_path / "sg"))
    store.record_pre("s1", 1, project_root=str(proj), cwd=str(proj), targets=["scratch.py"],
                     expected={"scratch.py": agentfiles.expected_hashes(TEXT)})
    (proj / "scratch.py").write_bytes(TEXT.encode("utf-8"))
    (proj / "scratch.py").write_bytes(b"print('the user changed this')\n")
    out = store.record_post("s1", 1)
    assert out["created"] == []
    assert [r["record_type"] for r in store.records("s1")].count("not_recorded") == 1
    resolved = agentfiles.resolve("scratch.py", str(proj))
    assert store.eligible("s1", resolved, str(proj)) is False


def test_f6_shell_write_is_never_recorded_as_created(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    store = AgentFiles(str(tmp_path / "sg"))
    store.record_pre("s1", 1, project_root=str(proj), cwd=str(proj), targets=["out.txt"])
    (proj / "out.txt").write_bytes(TEXT.encode("utf-8"))
    assert store.record_post("s1", 1)["created"] == []
    assert all(r["record_type"] != "created" for r in store.records("s1"))
    assert store.eligible("s1", agentfiles.resolve("out.txt", str(proj)), str(proj)) is False


def test_f6_crlf_file_for_lf_text_is_recorded_and_eligible(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    store = AgentFiles(str(tmp_path / "sg"))
    store.record_pre("s1", 1, project_root=str(proj), cwd=str(proj), targets=["win.py"],
                     expected={"win.py": agentfiles.expected_hashes(TEXT)})
    (proj / "win.py").write_bytes(TEXT.replace("\n", "\r\n").encode("utf-8"))
    out = store.record_post("s1", 1)
    assert len(out["created"]) == 1
    assert store.eligible("s1", agentfiles.resolve("win.py", str(proj)), str(proj)) is True


def test_f6_two_processes_record_same_content_at_once(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    base = str(tmp_path / "sg")
    store = AgentFiles(base)
    for step, rel in ((1, "a.py"), (2, "b.py")):
        store.record_pre("s1", step, project_root=str(proj), cwd=str(proj), targets=[rel],
                         expected={rel: agentfiles.expected_hashes(TEXT)})
        (proj / rel).write_bytes(TEXT.encode("utf-8"))
    barrier = SPAWN.Barrier(2)
    run_spawn(_child_record_post, [(base, "s1", 1, barrier), (base, "s1", 2, barrier)])
    created = {r["path"] for r in store.records("s1") if r["record_type"] == "created"}
    paths = {agentfiles.resolve(rel, str(proj)) for rel in ("a.py", "b.py")}
    assert created == paths
    assert all(store.eligible("s1", p, str(proj)) for p in paths)
    assert list((tmp_path / "sg" / "snapshots").rglob("*.tmp")) == []


# ---------------- 21-22: session drift window ----------------

def drift_envelope(session, command):
    return claude_family.envelope_from_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                              "tool_input": {"command": command}, "session_id": session,
                                              "tool_use_id": "t", "cwd": "/w/p"}, GRANT, host="claude")


def judgment_line(session, command, p, jid):
    return {"record_type": "judgment", "judgment_id": jid, "ts": utcnow_iso(),
            "envelope": drift_envelope(session, command).to_dict(),
            "decision": {"decision": "allow", "stage": "semantic",
                         "predicate_votes": [{"predicate": "on_task", "vote": "clear", "p": p}]}}


def drift_ledger(tmp_path, name="ledger.jsonl"):
    led = Ledger(str(tmp_path / name))
    led._append(judgment_line("sess-drift", "npm run step-0", 0.3, "j0"))
    led.record_host_response("sess-other", "t9", {"decision": "allow", "reason": "x"}, tool="bash")
    led._append(judgment_line("sess-drift", "npm run step-1", 0.9, "j1"))
    return led


def test_drift_window_clean_ledger_returns_values(tmp_path):
    led = drift_ledger(tmp_path)
    assert led.session_on_task(drift_envelope("sess-drift", "npm run next")) == [0.3, 0.9]


def test_drift_window_malformed_line_after_first_session_line_raises(tmp_path):
    led = drift_ledger(tmp_path)
    with open(led.path, "ab") as handle:
        handle.write(b'{"record_type": "judgment", broken\n')
    led._append(judgment_line("sess-drift", "npm run step-2", 0.3, "j2"))
    with pytest.raises(IncompleteWindow):
        led.session_on_task(drift_envelope("sess-drift", "npm run next"))


def test_drift_window_lock_held_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_LOCK_TIMEOUT_S", LOCK_TIMEOUT)
    led = drift_ledger(tmp_path)
    with held(led.path):
        with pytest.raises(IncompleteWindow):
            led.session_on_task(drift_envelope("sess-drift", "npm run next"))


def test_drift_window_spill_file_with_the_session_raises(tmp_path):
    led = drift_ledger(tmp_path)
    filelock.spill_record(led.path, judgment_line("sess-drift", "npm run step-2", 0.3, "j2"), "test")
    assert len(filelock.spill_files(led.path)) == 1
    with pytest.raises(IncompleteWindow):
        led.session_on_task(drift_envelope("sess-drift", "npm run next"))
    other = drift_envelope("sess-unrelated", "npm run next")
    assert led.session_on_task(other) == []                 # a spill of another session does not matter


def test_judge_drift_unreadable_window_turns_semantic_allow_into_ask(tmp_path):
    step = TrajectoryEntry(tool="bash", decision="allow", summary="python -m pytest tests -q", result="exit 0")
    e = Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "cat src/app.py"}),
                 grant=GRANT, environment=Environment(project_root="/w/p", cwd="/w/p", session_id="sess-drift-22"),
                 trajectory=Trajectory(recent=(step,)), user_message="Fix the parser bug.",
                 user_messages=("Fix the parser bug.",))
    led = Ledger(str(tmp_path / "ledger.jsonl"))
    first = judge(e, SDRIFT, provider=FakeProvider(ALLOWING), ledger=led)
    assert (first.decision, first.stage) == ("allow", "semantic")
    with open(led.path, "ab") as handle:
        handle.write(b'{"record_type": "judgment", broken\n')
    d = judge(e, SDRIFT, provider=FakeProvider(ALLOWING), ledger=led)
    assert (d.decision, d.stage, d.reason_code) == ("ask", "semantic", "session_drift_unreadable")
    vote = next(v for v in d.predicate_votes if v["predicate"] == "session_drift")
    assert vote["vote"] == "unknown"


# ---------------- 23-26: serve ----------------

class Out(io.StringIO):
    """Collects (seconds since start, answer) per written line."""

    def __init__(self, t0):
        super().__init__()
        self.t0 = t0
        self.answers = []
        self.guard = threading.Lock()

    def write(self, s):
        with self.guard:
            for line in s.splitlines():
                if line.strip():
                    self.answers.append((time.monotonic() - self.t0, json.loads(line)))
        return super().write(s)

    def for_id(self, rid):
        with self.guard:
            return [(t, a) for t, a in self.answers if a.get("id") == rid]


def serve_run(tmp_path, requests, judge_fn, settings):
    cfg = tmp_path / "serve.json"
    cfg.write_text(json.dumps({"ledger_file": str(tmp_path / "ledger.jsonl")}), encoding="utf-8")
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    restarts = []
    t0 = time.monotonic()
    out = Out(t0)
    code = serve_mod.serve(str(cfg), stdin=stdin, stdout=out, on_restart=restarts.append, judge_fn=judge_fn,
                           settings=settings)
    return code, out, restarts, time.monotonic() - t0


def req(rid, call, timeout_ms=None):
    r = {"id": rid, "host": "opencode", "request": {"sessionID": "sess-serve", "callID": call}}
    if timeout_ms is not None:
        r["timeout_ms"] = timeout_ms
    return r


def host_responses(tmp_path):
    return [r for r in filelock.read_jsonl(tmp_path / "ledger.jsonl").records if r.get("record_type") == "host_response"]


def wait_for(predicate, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_serve_judges_four_slow_requests_concurrently(tmp_path):
    def judge_fn(host, request, config, meta):
        time.sleep(0.8)
        return {"decision": "allow", "reason": "ok"}

    code, out, restarts, elapsed = serve_run(tmp_path, [req(i, f"c{i}") for i in range(1, 5)], judge_fn, (4, 5000, 500))
    assert code == 0 and restarts == []
    assert elapsed < 2.0
    for i in range(1, 5):
        answers = out.for_id(i)
        assert len(answers) == 1 and answers[0][1]["decision"] == "allow"
    assert sorted(r["step_idx"] for r in host_responses(tmp_path)) == ["c1", "c2", "c3", "c4"]


def test_serve_answers_ask_at_the_deadline_for_a_hanging_judgment(tmp_path):
    hang = threading.Event()

    def judge_fn(host, request, config, meta):
        hang.wait(20)
        return {"decision": "allow", "reason": "late"}

    try:
        code, out, restarts, _ = serve_run(tmp_path, [req(1, "c1")], judge_fn, (2, 1000, 500))
        answers = out.for_id(1)
        assert len(answers) == 1
        t, answer = answers[0]
        assert answer["decision"] == "ask" and answer["timeout"] is True
        assert 0.4 <= t < 1.5
        rows = host_responses(tmp_path)
        assert len(rows) == 1 and rows[0]["native"]["decision"] == "ask"
        assert code == serve_mod.RESTART_EXIT_CODE
        assert wait_for(lambda: len(restarts) == 1)
    finally:
        hang.set()


def test_serve_discards_a_late_allow(tmp_path):
    done = threading.Event()

    def judge_fn(host, request, config, meta):
        time.sleep(1.2)
        done.set()
        return {"decision": "allow", "reason": "late"}

    code, out, restarts, _ = serve_run(tmp_path, [req(1, "c1")], judge_fn, (2, 1000, 500))
    assert done.wait(5)
    time.sleep(0.2)                                     # let the worker try to answer
    answers = out.for_id(1)
    assert len(answers) == 1 and answers[0][1]["decision"] == "ask" and answers[0][1].get("timeout") is True
    assert all(a["decision"] != "allow" for _, a in out.answers)
    rows = host_responses(tmp_path)
    assert len(rows) == 1 and rows[0]["native"]["decision"] == "ask"


def test_serve_never_judges_a_request_queued_past_its_deadline(tmp_path):
    hang = threading.Event()
    calls = []

    def judge_fn(host, request, config, meta):
        calls.append(request["callID"])
        hang.wait(20)
        return {"decision": "allow", "reason": "late"}

    try:
        # One worker. c1 hangs (deadline 1.5 s); c2 waits in the queue (deadline 0.5 s).
        code, out, restarts, _ = serve_run(tmp_path, [req(1, "c1", 2000), req(2, "c2", 1000)], judge_fn, (1, 1000, 500))
        first, second = out.for_id(1), out.for_id(2)
        assert len(first) == 1 and len(second) == 1
        assert second[0][1]["decision"] == "ask" and second[0][1]["timeout"] is True and 0.4 <= second[0][0] < 1.2
        assert first[0][1]["decision"] == "ask" and first[0][1]["timeout"] is True and 1.4 <= first[0][0] < 2.4
        assert code == serve_mod.RESTART_EXIT_CODE
        assert wait_for(lambda: len(restarts) == 1)
        hang.set()                                      # the worker is free again: the queued c2 must be skipped
        time.sleep(0.3)
        assert calls == ["c1"]
        assert sorted((r["step_idx"], r["native"]["decision"]) for r in host_responses(tmp_path)) == [("c1", "ask"), ("c2", "ask")]
    finally:
        hang.set()


def test_serve_restart_answers_queued_requests_and_never_judges_them(tmp_path):
    # Same deadline for both: the restart (every worker stuck) races with the
    # second deadline. The queued c2 must get ask and must never be judged.
    for attempt in range(5):
        d = tmp_path / f"a{attempt}"
        d.mkdir()
        hang = threading.Event()
        calls = []

        def judge_fn(host, request, config, meta, calls=calls, hang=hang):
            calls.append(request["callID"])
            hang.wait(20)
            return {"decision": "allow", "reason": "late"}

        try:
            code, out, restarts, _ = serve_run(d, [req(1, "c1", 1000), req(2, "c2", 1000)], judge_fn, (1, 1000, 500))
            assert code == serve_mod.RESTART_EXIT_CODE
            assert [m["decision"] for _, m in out.for_id(1)] == ["ask"] and [m["decision"] for _, m in out.for_id(2)] == ["ask"]
            hang.set()
            time.sleep(0.2)
            assert calls == ["c1"]
            assert sorted((r["step_idx"], r["native"]["decision"]) for r in host_responses(d)) == [("c1", "ask"), ("c2", "ask")]
        finally:
            hang.set()
