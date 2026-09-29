"""Repro: `semgate serve --stdio` under a burst of requests with a slow or
hung judge (finding S5 in formal/REPORT.md).

Before the fix serve answered requests one at a time (`for line in stdin`),
and the OpenCode plugin gives each request its own timer (TIMEOUT_MS = 20000
in opencode_semgate.js) that starts when the request is SENT. Queue time
counted against the timer, so the later requests of a burst timed out even
when each single judgment was well under 20 s, and a hung model call blocked
serve forever.

Now (semgate/serve.py Server): a pool of worker threads (serve.workers,
default 4) judges requests concurrently. Every judge request has a deadline =
its `timeout_ms` (default 20000; this script sends it, like the real plugin)
minus a 1500 ms margin, counted from when serve read the line. At the deadline
serve answers {"decision": "ask", "timeout": true} for that id (never allow).
A judgment still running at its deadline is abandoned; when serve is idle
except for abandoned judgments, or every worker is held by one, it exits with
code 75 (the plugin starts a new serve). Every judge request writes one
host_response line to the ledger.

The real serve loop runs in a child process. The only change is in front of
the fake provider (FakeProvider.evaluate): a delay of --delay seconds stands
in for a slow model call, and with --hang N the first N requests of the burst
(commands `npm run build-1` .. `npm run build-N`) wait on a threading.Event
that is never set, instead of sleeping (a hung model call). No network.
Requests are sent all at once, the way parallel tool calls or several
sessions sharing one plugin process send them.

For each request the script prints serve's answer, the time from send to
answer, and what the plugin uses (the answer, or "ask" when it came after the
plugin timeout).

    .venv\\Scripts\\python.exe formal\\repro\\serve_queue.py --delay 6 --burst 5
    .venv\\Scripts\\python.exe formal\\repro\\serve_queue.py --hang 2 --delay 1 --burst 6
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, isolate, scan_jsonl  # noqa: E402
from stress_hook import ALLOWING  # noqa: E402

CHILD = r"""
import json, re, sys, threading, time
sys.path.insert(0, {repo!r})
from semgate.providers import fake
_orig = fake.FakeProvider.evaluate
HANG = set(range(1, {hang} + 1))
_never = threading.Event()          # never set: a hung model call
def slow(self, state, questions):
    m = re.search(r"npm run build-(\d+)\b", json.dumps(state, default=str))
    if m and int(m.group(1)) in HANG:
        _never.wait()
    time.sleep({delay})
    return _orig(self, state, questions)
fake.FakeProvider.evaluate = slow
from semgate import serve
sys.exit(serve.main(["--stdio", "--config", {cfg!r}]))
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=6.0, help="seconds added to every model call")
    ap.add_argument("--burst", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=20.0, help="plugin timeout (opencode_semgate.js TIMEOUT_MS)")
    ap.add_argument("--hang", type=int, default=0, help="the first N requests of the burst hang forever")
    a = ap.parse_args()
    tmp = isolate("semgate-formal-serve-")
    grant = tmp / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = tmp / "semgate.json"
    ledger = tmp / "ledger.jsonl"
    cfg.write_text(json.dumps({"mode": "enforce", "grant_file": str(grant),
                               "policy_file": str(REPO / "policies" / "router_policy_dev.json"),
                               "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(ledger),
                               "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"]}}), encoding="utf-8")
    script = tmp / "slow_serve.py"
    script.write_text(CHILD.format(repo=str(REPO), delay=a.delay, hang=a.hang, cfg=str(cfg)), encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, cwd=str(REPO))
    answers = {}
    t_sent = {}
    timeout_ms = int(a.timeout * 1000)

    def reader():
        for line in proc.stdout:
            msg = json.loads(line)
            answers[msg["id"]] = (time.monotonic(), msg)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    # warm-up request (imports), not counted
    proc.stdin.write(json.dumps({"id": 0, "host": "opencode", "timeout_ms": timeout_ms,
                                 "request": {"tool": "bash", "args": {"command": "git status"},
                                             "sessionID": "s", "callID": "c0", "cwd": str(tmp)}}) + "\n")
    proc.stdin.flush()
    while 0 not in answers:
        time.sleep(0.05)
    for i in range(1, a.burst + 1):
        req = {"id": i, "host": "opencode", "timeout_ms": timeout_ms,
               "request": {"tool": "bash", "args": {"command": f"npm run build-{i}"},
                           "sessionID": "s", "callID": f"c{i}", "cwd": str(tmp)}}
        t_sent[i] = time.monotonic()
        proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    deadline = time.monotonic() + max(a.burst * a.delay * 3, a.timeout) + 30
    while len(answers) < a.burst + 1 and time.monotonic() < deadline:
        time.sleep(0.1)
    try:
        proc.stdin.close()
    except OSError:
        pass                     # serve already exited (restart after abandoned judgments)
    try:
        code = proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        code = "killed after 60 s"
    stderr = proc.stderr.read().strip()
    late = timeouts = allows = 0
    for i in range(1, a.burst + 1):
        t, msg = answers.get(i, (None, {}))
        wait = (t - t_sent[i]) if t else float("inf")
        seen = msg.get("decision") if wait <= a.timeout else "ask (plugin timeout; late answer dropped)"
        late += wait > a.timeout
        timeouts += bool(msg.get("decision") == "ask" and msg.get("timeout"))
        allows += seen == "allow"
        hung = " (hung model call)" if i <= a.hang else ""
        print(f"request {i}{hung}: serve answered {msg.get('decision')!r}"
              f"{' timeout=true' if msg.get('timeout') else ''} after {wait:5.1f} s -> the plugin uses: {seen}")
    good, bad = scan_jsonl(ledger)
    hr = {g.get("step_idx") for g in good if g.get("record_type") == "host_response"}
    hr_burst = sum(1 for i in range(1, a.burst + 1) if f"c{i}" in hr)
    print(f"serve exit code: {code}" + (f"; serve stderr: {stderr[:300]}" if stderr else ""))
    print(f"ledger host_response lines for the burst: {hr_burst}/{a.burst}; ledger malformed lines: {len(bad)}")
    print(f"SUMMARY delay/model call={a.delay}s burst={a.burst} hang={a.hang}: {late}/{a.burst} requests past the "
          f"{a.timeout:.0f} s plugin timeout; answers \"ask\" with timeout: {timeouts}; allows: {allows}")
    print(f"temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
