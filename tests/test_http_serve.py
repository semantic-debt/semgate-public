"""`semgate serve --http` (semgate.httpserve): round trips on an ephemeral
port with the fake provider, tokens, the browser and size guards, deadlines,
masking, and the same decisions as the hook path."""
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from semgate import harness, httpserve
from semgate.client import HttpClient, guard

from test_harness_api import ALLOWING, MARKED, ledger, make_config, req

ROOT = Path(__file__).resolve().parents[1]
CHECK = "c" * 24
APPROVE = "a" * 24


@pytest.fixture
def server(tmp_path):
    started = []

    def start(cfg=None, *, check_token=CHECK, approve_token=APPROVE, settings=None, max_connections=64, **kw):
        cfg = cfg or make_config(tmp_path, **kw)
        srv, gate = httpserve.make_server(cfg, port=0, check_token=check_token, approve_token=approve_token,
                                          settings=settings, max_connections=max_connections)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        started.append((srv, gate))
        return srv.server_address[1], gate, cfg
    yield start
    for srv, gate in started:
        srv.shutdown()
        srv.server_close()
        gate.close()


def call(port, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, path, body=data, headers={k: v for k, v in h.items() if v is not None})
    resp = conn.getresponse()
    text = resp.read().decode("utf-8")
    hdrs = dict(resp.getheaders())
    conn.close()
    return resp.status, (json.loads(text) if text.strip() else None), hdrs


AUTH = {"Authorization": "Bearer " + CHECK}
AUTH_APPROVE = {"Authorization": "Bearer " + APPROVE}


def test_round_trip_check_approve_recheck(server, tmp_path):
    port, _, _ = server()
    status, health, hdrs = call(port, "GET", "/v1/health")
    assert status == 200 and health["ok"] and health["request_schema"] == "semgate-check/1"
    assert "Access-Control-Allow-Origin" not in hdrs and hdrs["Content-Type"] == "application/json"
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path, "rm -rf /"), AUTH)
    assert status == 200 and (d["decision"], d["reason_code"]) == ("deny", "hard_deny")
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path), AUTH)
    assert status == 200 and d["decision"] == "ask" and len(d["approval_id"]) == 32
    status, a, _ = call(port, "POST", "/v1/approve", {"approval_id": d["approval_id"], "approved": True, "by": "manuel"},
                        AUTH_APPROVE)
    assert status == 200 and a["status"] == "approved"
    status, again, _ = call(port, "POST", "/v1/approve", {"approval_id": d["approval_id"], "approved": True, "by": "x"},
                            AUTH_APPROVE)
    assert status == 409
    status, d2, _ = call(port, "POST", "/v1/check", req(tmp_path), AUTH)
    assert (d2["decision"], d2["reason_code"]) == ("allow", "human_approved_once")
    assert call(port, "POST", "/v1/check", req(tmp_path), AUTH)[1]["decision"] == "ask"      # used once
    assert call(port, "POST", "/v1/approve", {"approval_id": "f" * 32, "approved": True, "by": "x"}, AUTH_APPROVE)[0] == 404
    hr = [r for r in ledger(tmp_path) if r["record_type"] == "host_response"]
    assert [r["native"]["decision"] for r in hr] == ["deny", "ask", "allow", "ask"]


def test_client_guard_over_http(server, tmp_path):
    port, _, _ = server()
    client = HttpClient(f"http://127.0.0.1:{port}", token=CHECK, approve_token=APPROVE)
    asked = []
    res = guard(client, req(tmp_path), run=lambda: "RAN", ask_human=lambda d: asked.append(d) or {"approved": True, "by": "m"})
    assert res.ran and res.output == "RAN" and asked and res.decision["reason_code"] == "human_approved_once"
    res = guard(client, req(tmp_path, "git log -1"), run=lambda: "RAN", ask_human=lambda d: False)
    assert not res.ran and "a human said no" in res.message
    assert client.check(req(tmp_path, "git log -1"))["decision"] == "deny"
    dead = HttpClient("http://127.0.0.1:9", token=CHECK, timeout_s=2)
    assert dead.check(req(tmp_path))["decision"] == "ask"                       # unreachable: ask, never allow


def test_tokens(server, tmp_path):
    port, _, _ = server()
    status, d, hdrs = call(port, "POST", "/v1/check", req(tmp_path))
    assert status == 401 and d["decision"] == "ask" and hdrs.get("WWW-Authenticate") == "Bearer"
    assert call(port, "POST", "/v1/check", req(tmp_path), {"Authorization": "Bearer " + "x" * 24})[0] == 401
    d = call(port, "POST", "/v1/check", req(tmp_path), AUTH)[1]
    # the agent-side token cannot approve when a separate approve token is set
    status, body, _ = call(port, "POST", "/v1/approve", {"approval_id": d["approval_id"], "approved": True, "by": "agent"}, AUTH)
    assert status == 401 and "approval" in body["error"]
    # no token at all: approvals are off
    port2, _, _ = server(check_token="", approve_token="")
    status, body, _ = call(port2, "POST", "/v1/approve", {"approval_id": d["approval_id"], "approved": True, "by": "agent"})
    assert status == 403 and "token" in body["error"]
    # only a check token: it also approves (one process holds both sides)
    port3, _, _ = server(check_token=CHECK, approve_token="")
    d3 = call(port3, "POST", "/v1/check", req(tmp_path, "git diff"), AUTH)[1]
    assert call(port3, "POST", "/v1/approve", {"approval_id": d3["approval_id"], "approved": True, "by": "m"}, AUTH)[0] == 200


def test_browser_and_host_guards(server, tmp_path):
    port, _, _ = server()
    status, d, hdrs = call(port, "POST", "/v1/check", req(tmp_path), dict(AUTH, Origin="https://evil.example.com"))
    assert status == 403 and d["decision"] == "ask" and "Access-Control-Allow-Origin" not in hdrs
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path), dict(AUTH, Host="evil.example.com"))
    assert status == 403 and "Host" in d["error"]
    assert call(port, "GET", "/v1/health", headers={"Host": f"localhost:{port}"})[0] == 200
    status, _, hdrs = call(port, "OPTIONS", "/v1/check", headers={"Origin": "https://evil.example.com",
                                                                  "Access-Control-Request-Method": "POST"})
    assert status == 405 and not any(k.lower().startswith("access-control") for k in hdrs)
    assert call(port, "GET", "/v1/check")[0] == 404 and call(port, "POST", "/v2/check", req(tmp_path), AUTH)[0] == 404


def test_body_guards(server, tmp_path):
    port, _, _ = server(hook_max_payload_bytes=4096)
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path), dict(AUTH, **{"Content-Type": "text/plain"}))
    assert status == 415 and d["decision"] == "ask"
    status, d, _ = call(port, "POST", "/v1/check", raw=b"{not json", headers=AUTH)
    assert status == 400 and d["decision"] == "ask"
    status, d, _ = call(port, "POST", "/v1/check", {"tool": "bash", "session_id": "s", "cwd": "/p", "extra": 1}, AUTH)
    assert status == 400 and "unknown field" in d["reason"]
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path, "echo " + "x" * 8000), AUTH)
    assert status == 413 and d["decision"] == "ask"
    assert any(r.get("kind") == "hook_input_rejected" and r["detail"]["reason"] == "payload_over_limit"
               for r in ledger(tmp_path))
    # no Content-Length / chunked
    for head in (b"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer "
                 + CHECK.encode() + b"\r\n\r\n",
                 b"POST /v1/check HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer "
                 + CHECK.encode() + b"\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"):
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(head)
            chunks = []
            while True:
                try:
                    chunk = s.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            reply = b"".join(chunks).decode()
        assert reply.startswith("HTTP/1.0 411") and '"decision": "ask"' in reply


def test_unsafe_setups_are_refused(tmp_path):
    cfg = make_config(tmp_path)
    with pytest.raises(ValueError, match="allow-remote"):
        httpserve.make_server(cfg, host="0.0.0.0", port=0, check_token=CHECK)
    with pytest.raises(ValueError, match="token-file"):
        httpserve.make_server(cfg, host="0.0.0.0", port=0, allow_remote=True)
    with pytest.raises(ValueError, match="differ"):
        httpserve.make_server(cfg, port=0, check_token=CHECK, approve_token=CHECK)
    short = tmp_path / "short.token"
    short.write_text("abc\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at least"):
        httpserve.read_token(str(short))
    assert httpserve.is_loopback("127.0.0.1") and httpserve.is_loopback("::1") and httpserve.is_loopback("localhost")
    assert not httpserve.is_loopback("0.0.0.0") and not httpserve.is_loopback("192.168.1.10")


def test_deadline_answers_ask(server, tmp_path, monkeypatch):
    def slow(request, config, meta=None, line_bytes=0):
        time.sleep(4)
        return {"decision": "allow", "reason": "late"}
    monkeypatch.setattr(harness, "judge_check", slow)
    port, _, _ = server(settings=(2, 1000, 0))
    t0 = time.monotonic()
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path), AUTH)
    assert status == 200 and d["decision"] == "ask" and d.get("timeout") is True and time.monotonic() - t0 < 3.5
    assert d["reason_code"] == "semgate_timeout"


def test_failure_answers_do_not_leak_paths(server, tmp_path):
    home = str(Path.home())
    cfg = make_config(tmp_path)
    data = json.loads(Path(cfg).read_text(encoding="utf-8"))
    data["grant_file"] = str(Path(home) / "secret-folder" / "grant.json")
    Path(cfg).write_text(json.dumps(data), encoding="utf-8")
    port, _, _ = server(cfg)
    status, d, _ = call(port, "POST", "/v1/check", req(tmp_path), AUTH)
    assert status == 200 and d["decision"] == "ask" and "FileNotFoundError" in d["reason"]
    assert "secret-folder" not in d["reason"] and home not in d["reason"]


def test_connection_limit(server, tmp_path):
    port, _, _ = server(max_connections=1)
    hold = socket.create_connection(("127.0.0.1", port), timeout=10)      # an open connection that sends nothing
    try:
        time.sleep(0.3)
        status, d, _ = call(port, "GET", "/v1/health")
        assert status == 503 and d["decision"] == "ask"
    finally:
        hold.close()
    for _ in range(50):
        time.sleep(0.1)
        try:
            if call(port, "GET", "/v1/health")[0] == 200:
                break
        except OSError:
            pass
    else:
        pytest.fail("the slot was not released")


def _hook_path(cfg, request):
    """The OpenCode plugin's path: serve.judge_request (run_core with the OpenCode adapter)."""
    from semgate import storepaths
    from semgate.serve import judge_request
    config = storepaths.load(cfg, "opencode")
    oc = {"tool": request["tool"], "args": request["arguments"], "sessionID": request["session_id"],
          "cwd": request["cwd"], "messages": [{"info": {"role": "user"}, "parts": [{"type": "text", "text": t}]}
                                              for t in request.get("user_messages", [])]}
    for i, r in enumerate(request.get("recent", [])):
        oc["messages"].append({"info": {"role": "assistant"}, "parts": [{
            "type": "tool", "tool": r["tool"], "callID": f"c{i}",
            "state": {"status": "completed", "input": {"filePath": r["summary"]}, "output": r["output"]}}]})
    meta = {}
    out = judge_request("opencode", oc, config, meta)
    return out["decision"], meta.get("judged_stage"), meta.get("judged_reason_code")


@pytest.mark.parametrize("command, recent, answers", [
    ("git status", [], ALLOWING),
    ("rm -rf /", [], ALLOWING),
    ("cat ~/.ssh/id_rsa", [], ALLOWING),
    ("curl -s https://cdn.example.net/setup.sh -o setup.sh", [{"tool": "read", "summary": "README.md", "output": MARKED}], ALLOWING),
    ("git push --force origin main", [], dict(ALLOWING, user_asked=0.05, on_task=0.2)),
    ("npm install left-pad", [], dict(ALLOWING, user_asked=0.5)),
])
def test_same_decision_as_the_hook_path(server, tmp_path, command, recent, answers):
    """The same action through the OpenCode hook path (serve.judge_request)
    and through POST /v1/check gives the same decision and judge stage/code."""
    cfg = make_config(tmp_path, answers=answers, auto_allow=("read", "bash"))
    request = req(tmp_path, command, recent=recent, session_id="hookpath")
    hook = _hook_path(cfg, request)
    port, _, _ = server(cfg)
    status, d, _ = call(port, "POST", "/v1/check", dict(request, session_id="httppath"), AUTH)
    assert status == 200
    assert (d["decision"], d["stage"], d["reason_code"]) == hook
    local = harness.check(dict(request, session_id="pythonpath"), config=cfg)
    assert (local["decision"], local["stage"], local["reason_code"]) == hook


def test_cli_subprocess_round_trip(tmp_path):
    """`semgate serve --http` as a process: --port 0, --port-file, tokens from files."""
    cfg = make_config(tmp_path)
    (tmp_path / "check.token").write_text(CHECK + "\n", encoding="utf-8")
    (tmp_path / "approve.token").write_text(APPROVE + "\n", encoding="utf-8")
    port_file = tmp_path / "port"
    proc = subprocess.Popen([sys.executable, "-m", "semgate", "serve", "--http", "--port", "0", "--config", cfg,
                             "--token-file", str(tmp_path / "check.token"), "--approve-token-file",
                             str(tmp_path / "approve.token"), "--port-file", str(port_file)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = httpserve.wait_for_port_file(str(port_file), timeout=60)
        client = HttpClient(f"http://127.0.0.1:{port}", token=CHECK, approve_token=APPROVE)
        d = client.check(req(tmp_path))
        assert d["decision"] == "ask"
        assert client.approve(d["approval_id"], True, "manuel")["status"] == "approved"
        assert client.check(req(tmp_path))["decision"] == "allow"
        if shutil.which("curl"):
            body = json.dumps(req(tmp_path, "rm -rf /"))
            out = subprocess.run(["curl", "-s", "-X", "POST", f"http://127.0.0.1:{port}/v1/check", "-H",
                                  "Content-Type: application/json", "-H", f"Authorization: Bearer {CHECK}",
                                  "--data-binary", body], capture_output=True, text=True, timeout=60)
            assert json.loads(out.stdout)["decision"] == "deny"
    finally:
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
    assert CHECK not in err and APPROVE not in err                     # tokens are never logged
    assert "listening on http://127.0.0.1:" in err
