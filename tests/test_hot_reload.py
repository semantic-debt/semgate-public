"""Hot reload of `semgate serve --stdio` (serve.py, codestamp.CodeWatcher).

Found live (2026-09-25): OpenCode's service (`opencode2 serve --service`)
kept the plugin and its serve child for days; after semgate was updated the
old code kept judging until the service restarted. Now serve watches its
package; on a change it sends {"id": null, "reload": true}, keeps answering
every request it already has with the old code, and exits when the plugin
closes its input. The next call goes to a new process. No request is lost
or answered by a failure.
"""
import io
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from semgate import codestamp, filelock
from semgate import serve as serve_mod
from semgate.init_antigravity import opencode_plugin_source, pi_extension_source

ROOT = Path(__file__).resolve().parents[1]
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
            "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}


# ---------------------------------------------------------------- CodeWatcher


def _package(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (pkg / "sub" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (pkg / "sub" / "data.json").write_text("{}\n", encoding="utf-8")
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "a.cpython.pyc").write_bytes(b"x")
    return pkg


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_watcher_sees_a_content_change_and_ignores_same_bytes_and_pycache(tmp_path):
    pkg = _package(tmp_path)
    clock = Clock()
    w = codestamp.CodeWatcher(pkg, interval=1.0, settle=0.0, clock=clock)
    assert len(w.fingerprint) == 64 and w.check(force=True) is None
    # rate limit: no scan inside `interval`
    (pkg / "sub" / "a.py").write_text("A = 2\n", encoding="utf-8")
    clock.t += 0.5
    assert w.check() is None
    # __pycache__ does not count; same bytes with a new mtime do not count
    (pkg / "__pycache__" / "a.cpython.pyc").write_bytes(b"yy")
    (pkg / "sub" / "a.py").write_text("A = 1\n", encoding="utf-8")
    os.utime(pkg / "sub" / "a.py", ns=(1, 1))
    clock.t += 1.0
    assert w.check() is None and w.changed_to == ""
    # a real change (and a version change) counts, once and then stays
    (pkg / "sub" / "a.py").write_text("A = 3\n", encoding="utf-8")
    (pkg / "__init__.py").write_text('__version__ = "1.0.1"\n', encoding="utf-8")
    clock.t += 1.0
    reason = w.check()
    assert reason and "code changed" in reason and "1.0.1" in reason and str(pkg) in reason
    assert w.changed_to and w.changed_to != w.fingerprint
    assert w.check() == reason


def test_watcher_waits_until_the_files_stop_changing(tmp_path):
    """pip writes files one by one: a file set must stay the same for
    `settle` seconds before it counts."""
    pkg = _package(tmp_path)
    clock = Clock()
    w = codestamp.CodeWatcher(pkg, interval=0.0, settle=2.0, clock=clock)
    (pkg / "sub" / "a.py").write_text("A = 2\n", encoding="utf-8")
    assert w.check() is None                         # first seen now
    clock.t += 1.0
    (pkg / "sub" / "b.py").write_text("B = 1\n", encoding="utf-8")
    assert w.check() is None                         # changed again: wait again
    clock.t += 1.5
    assert w.check() is None                         # stable for 1.5 s only
    clock.t += 1.0
    assert w.check() is not None                     # stable for 2.5 s


def test_watcher_never_raises(tmp_path):
    pkg = _package(tmp_path)
    w = codestamp.CodeWatcher(pkg, interval=0.0, settle=0.0)
    shutil.rmtree(pkg)
    assert w.check() is None


# ---------------------------------------------------------------- serve in process


class FakeWatcher:
    """Stands in for CodeWatcher: `change()` makes the code look updated."""

    def __init__(self):
        self.fingerprint, self.changed_to, self.version = "a" * 64, "", "0.4.0"
        self.flag = threading.Event()

    def change(self):
        self.changed_to = "b" * 64
        self.flag.set()

    def check(self, force=False):
        return "semgate code changed under /pkg (test)" if self.flag.is_set() else None


class Pipe:
    """A blocking stdin: lines are put by the test; "" is end of input."""

    def __init__(self):
        self.q = queue.Queue()
        self.closed = False

    def put(self, obj):
        self.q.put(json.dumps(obj) + "\n")

    def close(self):
        self.q.put("")

    def readline(self, limit=-1):
        if self.closed:
            return ""
        line = self.q.get()
        if line == "":
            self.closed = True
        return line


class Out(io.StringIO):
    def __init__(self):
        super().__init__()
        self.lines = []
        self.guard = threading.Lock()

    def write(self, s):
        with self.guard:
            self.lines += [json.loads(l) for l in s.splitlines() if l.strip()]
        return super().write(s)

    def snapshot(self):
        with self.guard:
            return list(self.lines)


def wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _ledger(path):
    return filelock.read_jsonl(path).records if Path(path).exists() else []


def _run_in_thread(tmp_path, pipe, out, judge_fn, watcher):
    cfg = tmp_path / "serve.json"
    cfg.write_text(json.dumps({"ledger_file": str(tmp_path / "ledger.jsonl")}), encoding="utf-8")
    result = {}

    def run():
        result["code"] = serve_mod.serve(str(cfg), stdin=pipe, stdout=out, on_restart=lambda why: None, judge_fn=judge_fn,
                                         settings=(4, 20000, 500), watcher=watcher, reload=(0.05, 0.0))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, result


def req(rid, call, client=True, host="opencode"):
    r = {"id": rid, "host": host, "timeout_ms": 20000, "request": {"sessionID": "sess-reload", "callID": call}}
    if client:
        r["client"] = {"stamp": codestamp.stamp(codestamp.ASSETS[host]), "reload": 1}
    return r


def test_reload_line_while_a_request_is_in_flight_old_code_answers_everything(tmp_path):
    release = threading.Event()
    judged = []

    def judge_fn(host, request, config, meta):
        judged.append(request["callID"])
        if request["callID"] == "c1":
            release.wait(10)
        return {"decision": "allow", "reason": "ok " + request["callID"]}

    pipe, out, watcher = Pipe(), Out(), FakeWatcher()
    t, result = _run_in_thread(tmp_path, pipe, out, judge_fn, watcher)
    try:
        pipe.put(req(1, "c1"))
        assert wait_for(lambda: judged == ["c1"])
        watcher.change()                                   # the update lands while c1 is judged
        assert wait_for(lambda: any(l.get("reload") for l in out.snapshot()))
        marker = [l for l in out.snapshot() if l.get("reload")]
        assert marker == [{"id": None, "reload": True, "reason": "semgate code changed under /pkg (test)"}]
        # the plugin wrote c2 before it read the reload line: this process still answers it
        pipe.put(req(2, "c2"))
        assert wait_for(lambda: any(l.get("id") == 2 for l in out.snapshot()))
        release.set()                                      # the in-flight request finishes with the old code
        assert wait_for(lambda: any(l.get("id") == 1 for l in out.snapshot()))
        pipe.close()                                       # the plugin closes this process's input
        t.join(10)
    finally:
        release.set()
        pipe.close()
    assert result["code"] == serve_mod.RELOAD_EXIT_CODE
    answers = {l["id"]: l for l in out.snapshot() if l.get("id") is not None}
    assert {i: (a["decision"], a["reason"]) for i, a in answers.items()} == {1: ("allow", "ok c1"), 2: ("allow", "ok c2")}
    assert all("timeout" not in a for a in answers.values())
    assert sum(1 for l in out.snapshot() if l.get("reload")) == 1
    events = [r for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "serve_event"]
    reload_ev = [e for e in events if e["event"] == "reload"]
    assert len(reload_ev) == 1 and reload_ev[0]["detail"]["how"].startswith("reload line sent")
    assert reload_ev[0]["detail"]["pid"] == os.getpid() and reload_ev[0]["detail"]["to"] == "b" * 64
    client = [e for e in events if e["event"] == "client"]
    assert len(client) == 1 and client[0]["detail"]["reload_supported"] is True and client[0]["detail"]["outdated"] is False


def test_old_plugin_without_client_reload_is_never_cut_off(tmp_path):
    """A plugin copy from before hot reload treats any exit as a crash of its
    open calls. serve keeps answering with the old code, sends nothing it
    does not understand, and records why."""
    def judge_fn(host, request, config, meta):
        return {"decision": "allow", "reason": "ok"}

    pipe, out, watcher = Pipe(), Out(), FakeWatcher()
    t, result = _run_in_thread(tmp_path, pipe, out, judge_fn, watcher)
    try:
        pipe.put(req(1, "c1", client=False))
        assert wait_for(lambda: any(l.get("id") == 1 for l in out.snapshot()))
        watcher.change()
        events = lambda: [r for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "serve_event"]  # noqa: E731
        assert wait_for(lambda: any(e["event"] == "reload" for e in events()))
        for i in range(2, 5):
            pipe.put(req(i, f"c{i}", client=False))
        assert wait_for(lambda: len([l for l in out.snapshot() if l.get("id")]) == 4)
        time.sleep(0.2)
        pipe.close()
        t.join(10)
    finally:
        pipe.close()
    assert result["code"] == 0
    assert not any(l.get("reload") for l in out.snapshot())
    assert [l["decision"] for l in out.snapshot()] == ["allow"] * 4
    ev = events()
    assert [e["detail"]["how"][:5] for e in ev if e["event"] == "reload"] == ["none:"]
    [client] = [e for e in ev if e["event"] == "client"]
    assert client["detail"]["plugin_stamp"] == "" and client["detail"]["outdated"] is True


def test_change_before_the_first_request_sends_the_line_after_it(tmp_path):
    def judge_fn(host, request, config, meta):
        return {"decision": "allow", "reason": "ok"}

    pipe, out, watcher = Pipe(), Out(), FakeWatcher()
    watcher.change()
    t, result = _run_in_thread(tmp_path, pipe, out, judge_fn, watcher)
    try:
        events = lambda: [r for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "serve_event"]  # noqa: E731
        assert wait_for(lambda: any(e["event"] == "reload" for e in events()))
        assert out.snapshot() == []
        pipe.put(req(1, "c1"))
        assert wait_for(lambda: len(out.snapshot()) == 2)
        pipe.close()
        t.join(10)
    finally:
        pipe.close()
    lines = out.snapshot()
    assert sorted(("reload" in l, l.get("decision")) for l in lines) == [(False, "allow"), (True, None)]
    assert [e["detail"]["how"][:7] for e in events() if e["event"] == "reload"] == ["waiting"]
    assert result["code"] == serve_mod.RELOAD_EXIT_CODE


def test_outdated_plugin_stamp_is_recorded_once_per_stamp(tmp_path):
    def judge_fn(host, request, config, meta):
        return {"decision": "allow", "reason": "ok"}

    pipe, out = Pipe(), Out()
    t, result = _run_in_thread(tmp_path, pipe, out, judge_fn, None)
    old = {"stamp": "opencode_semgate.js sha256=" + "0" * 64 + " version=0.3.0", "reload": 1}
    try:
        for i in range(1, 4):
            r = req(i, f"c{i}")
            r["client"] = old
            pipe.put(r)
        pipe.put(req(4, "c4"))
        assert wait_for(lambda: len(out.snapshot()) == 4)
        pipe.close()
        t.join(10)
    finally:
        pipe.close()
    client = [r["detail"] for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "serve_event"]
    assert [(c["outdated"], c["plugin_stamp"][:30]) for c in client] == [
        (True, old["stamp"][:30]), (False, codestamp.stamp("opencode_semgate.js")[:30])]
    assert client[0]["current_sha256"] == codestamp.asset_sha256("opencode_semgate.js")


def test_reload_settings_from_semgate_json():
    assert serve_mod._reload_settings({}) == (2.0, 2.0)
    assert serve_mod._reload_settings({"serve": {"reload_check_s": 0, "reload_settle_s": "x"}}) == (0.0, 2.0)
    assert serve_mod._reload_settings({"serve": {"reload_check_s": -5, "reload_settle_s": 999}}) == (0.0, 60.0)


# ---------------------------------------------------------------- real processes


def _copy_package(tmp_path):
    """A private copy of semgate, so the test can "update" it."""
    pkg = tmp_path / "pkg"
    shutil.copytree(ROOT / "semgate", pkg / "semgate", ignore=shutil.ignore_patterns("__pycache__"))
    return pkg


def _config(tmp_path):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = tmp_path / "semgate.json"
    cfg.write_text(json.dumps({
        "mode": "enforce", "grant_file": str(grant), "policy_file": str(ROOT / "policies" / "router_policy_dev.json"),
        "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(tmp_path / "ledger.jsonl"),
        "serve": {"reload_check_s": 0.1, "reload_settle_s": 0.2},
        "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read", "edit"], "block_when_unsure": False}}),
        encoding="utf-8")
    return cfg


def _update(pkg):
    """The "update": one module of the private copy changes."""
    with open(pkg / "semgate" / "judge.py", "a", encoding="utf-8") as handle:
        handle.write("\n# updated by test_hot_reload\n")


def _env(pkg):
    env = {k: v for k, v in os.environ.items() if k not in ("SEMGATE_PYTHON", "SEMGATE_CONFIG")}
    env["PYTHONPATH"] = str(pkg)
    return env


def _serve_events(tmp_path, event):
    return [r["detail"] for r in _ledger(tmp_path / "ledger.jsonl")
            if r.get("record_type") == "serve_event" and r.get("event") == event]


PI_ENTRIES = [{"type": "message", "id": "u1", "timestamp": "2026-09-25T10:00:00Z",
               "message": {"role": "user", "content": [{"type": "text", "text": "check the repo status"}]}}]


def _request(host, call):
    if host == "pi":
        return {"sessionID": "s1", "callID": call, "tool": "bash", "args": {"command": "git status"}, "cwd": "/tmp",
                "entries": PI_ENTRIES}
    return {"tool": "bash", "args": {"command": "git status"}, "sessionID": "s1", "callID": call}


class Proc:
    """`python -m semgate.serve --stdio` driven like a plugin does."""

    def __init__(self, pkg, cfg, cwd):
        self.p = subprocess.Popen([sys.executable, "-m", "semgate.serve", "--stdio", "--config", str(cfg)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=_env(pkg), cwd=str(cwd))
        self.lines = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.lines.put(json.loads(line))

    def send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def next(self, timeout=60):
        return self.lines.get(timeout=timeout)


@pytest.mark.parametrize("host", ["opencode", "pi"])
def test_stdio_protocol_reload_moves_the_next_call_to_a_new_process(tmp_path, host):
    pkg, cfg = _copy_package(tmp_path), _config(tmp_path)
    client = {"stamp": codestamp.stamp(codestamp.ASSETS[host]), "reload": 1}
    old = Proc(pkg, cfg, tmp_path)
    try:
        old.send({"id": 1, "host": host, "event": "before", "timeout_ms": 20000, "client": client, "request": _request(host, "c1")})
        assert old.next()["decision"] == "allow"
        _update(pkg)
        marker = old.next(timeout=30)                      # sent while idle, after the settle time
        assert marker["id"] is None and marker["reload"] is True and str(pkg / "semgate") in marker["reason"]
        # a call the plugin wrote before it read the reload line: still answered here
        old.send({"id": 2, "host": host, "event": "before", "timeout_ms": 20000, "client": client, "request": _request(host, "c2")})
        second = old.next()
        assert second["id"] == 2 and second["decision"] == "allow"
        old.p.stdin.close()                                # what the plugin does on the reload line
        assert old.p.wait(30) == serve_mod.RELOAD_EXIT_CODE
    finally:
        if old.p.poll() is None:
            old.p.kill()
    new = Proc(pkg, cfg, tmp_path)                         # the plugin's next call starts a new serve
    try:
        new.send({"id": 3, "host": host, "event": "before", "timeout_ms": 20000, "client": client, "request": _request(host, "c3")})
        assert new.next()["decision"] == "allow"
        new.p.stdin.close()
        assert new.p.wait(30) == 0
    finally:
        if new.p.poll() is None:
            new.p.kill()
    clients = _serve_events(tmp_path, "client")
    assert len(clients) == 2 and clients[0]["pid"] != clients[1]["pid"]
    [reload_ev] = _serve_events(tmp_path, "reload")
    assert reload_ev["pid"] == clients[0]["pid"] and reload_ev["how"].startswith("reload line sent")
    rows = [r for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "host_response"]
    assert sorted((r["step_idx"], r["native"]["decision"]) for r in rows) == [("c1", "allow"), ("c2", "allow"), ("c3", "allow")]


OPENCODE_DRIVER = r"""
import { pathToFileURL } from "node:url"
import { appendFileSync } from "node:fs"
const mod = await import(pathToFileURL(process.argv[2]).href)
const target = process.argv[3]
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const client = { session: { messages: async () => ({ data: [] }) } }
const v1 = await mod.default.server({ client, directory: process.cwd() })
const results = []
async function call(name) {
  try { await v1["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: name }, { args: { command: "git status" } }); results.push([name, "ok"]) }
  catch (e) { results.push([name, String(e.message).slice(0, 300)]) }
}
await call("a")
appendFileSync(target, "\n# updated by test_hot_reload\n")   // the update (a Python comment)
// calls in flight while the change is detected and the reload line arrives
const burst = []
for (let i = 0; i < 6; i++) { burst.push(call("b" + i)); await sleep(250) }
await Promise.all(burst)
await sleep(1500)
await call("c")
console.log(JSON.stringify(results))
process.exit(0)
"""

PI_DRIVER = r"""
import { pathToFileURL } from "node:url"
import { appendFileSync } from "node:fs"
const mod = await import(pathToFileURL(process.argv[2]).href)
const target = process.argv[3]
const entries = JSON.parse(process.argv[4])
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const handlers = {}
mod.default({ on: (name, fn) => { handlers[name] = fn } })
const ctx = { cwd: process.cwd(), sessionManager: { getSessionId: () => "s1", getBranch: () => entries } }
const results = []
async function call(name) {
  const r = await handlers.tool_call({ toolCallId: name, toolName: "bash", input: { command: "git status" } }, ctx)
  results.push([name, r === undefined ? "ok" : String(r.reason).slice(0, 300)])
}
await call("a")
appendFileSync(target, "\n# updated by test_hot_reload\n")
const burst = []
for (let i = 0; i < 6; i++) { burst.push(call("b" + i)); await sleep(250) }
await Promise.all(burst)
await sleep(1500)
await call("c")
await handlers.session_shutdown()
console.log(JSON.stringify(results))
process.exit(0)
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("host", ["opencode", "pi"])
def test_real_plugin_moves_to_a_new_serve_after_an_update_without_losing_a_call(tmp_path, host):
    pkg, cfg = _copy_package(tmp_path), _config(tmp_path)
    plugin = tmp_path / "semgate-plugin.mjs"       # the Pi extension has no TypeScript syntax: loaded as .mjs
    render = opencode_plugin_source if host == "opencode" else pi_extension_source
    plugin.write_text(render(Path(sys.executable), cfg), encoding="utf-8")
    driver = tmp_path / "driver.mjs"
    driver.write_text(OPENCODE_DRIVER if host == "opencode" else PI_DRIVER, encoding="utf-8")
    target = pkg / "semgate" / ("judge.py" if host == "pi" else "rules.py")
    args = ["node", str(driver), str(plugin), str(target)] + ([json.dumps(PI_ENTRIES)] if host == "pi" else [])
    run_dir = tmp_path / "cwd"
    run_dir.mkdir()
    p = subprocess.run(args, capture_output=True, text=True, timeout=240, env=_env(pkg), cwd=str(run_dir))
    assert p.returncode == 0, p.stderr
    results = json.loads(p.stdout.strip().splitlines()[-1])
    assert sorted(results) == sorted([n, "ok"] for n in ["a"] + [f"b{i}" for i in range(6)] + ["c"]), results
    clients = _serve_events(tmp_path, "client")
    pids = [c["pid"] for c in clients]
    assert len(pids) == 2 and pids[0] != pids[1], clients        # a new process after the update
    assert all(c["reload_supported"] and not c["outdated"] for c in clients)
    [reload_ev] = _serve_events(tmp_path, "reload")
    assert reload_ev["pid"] == pids[0] and reload_ev["how"].startswith("reload line sent")
    rows = [r for r in _ledger(tmp_path / "ledger.jsonl") if r.get("record_type") == "host_response"]
    assert len(rows) == 8 and {r["native"]["decision"] for r in rows} == {"allow"}
