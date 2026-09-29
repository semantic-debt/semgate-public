"""OpenRouter Decisions transport (semgate/providers/openrouter.py) against a
local fake of POST /api/alpha/decisions (http.server.ThreadingHTTPServer on
127.0.0.1). No network, no real key: FAKE_KEY is a made-up value."""
import json
import os
import ssl
import threading
import time
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from semgate.providers import keys
from semgate.providers.base import ProviderError
from semgate.providers.common import MISSING_SIDE_PREFIX
from semgate.providers.openrouter import (DEFAULT_MODEL, OpenRouterDecisionsProvider, OpenRouterHTTPError,
                                          OpenRouterTimeoutError, _check_base_url)

ROOT = Path(__file__).resolve().parents[1]
FAKE_KEY = "sk-or-v1-FAKEKEY0123456789abcdef0123456789abcdef"
PATH = "/api/alpha/decisions"

QUESTIONS = {
    "user_asked": {"type": "noul", "instructions": "Did the user ask for this command?"},
    "on_task": {"type": "noul", "instructions": "Is it on task?",
                "criteria": {"true": "The command serves the task.", "false": "The command does not serve the task."}},
    "route": {"type": "choice", "instructions": "Which kind?", "criteria": {"run": "Runs code", "read": None}},
    "effect": {"type": "score", "instructions": "How much does it change?", "criteria": ["nothing", "files", "system"]},
}
STATE = {"command": "pytest -q", "cwd": "/p", "user_message": "run the tests ✓"}


# ---------------------------------------------------------------- fake server


class Fake:
    """Records every request. Answers from `script` (a list of callables or
    (status, body, headers, delay) tuples), else a valid Decisions answer.
    Like OpenRouter, a noul whose criteria lacks true or false gets HTTP 400."""

    def __init__(self):
        self.requests = []
        self.script = []
        self.nouls = {}          # qid -> probability
        self.cost = 0.000123

    def answer(self, body):
        answers = {}
        for qid, q in body["questions"].items():
            t = q["type"]
            if t == "noul":
                crit = q.get("criteria")
                if crit is not None and not ({"true", "false"} <= set(crit)):
                    return 400, {"error": {"code": 400, "message": f"questions.{qid}.criteria must have both true and false"}}, {}
                answers[qid] = {"type": "noul", "noul": self.nouls.get(qid, 0.02)}
            elif t == "choice":
                label = self.nouls.get(qid) or next(iter(q["criteria"]))
                answers[qid] = {"type": "choice", "choice": label, "confidence": 0.93,
                                "probabilities": {k: (0.93 if k == label else 0.07 / max(1, len(q["criteria"]) - 1))
                                                  for k in q["criteria"]}}
            else:
                level = int(self.nouls.get(qid, 0))
                answers[qid] = {"type": "score", "score": float(level), "confidence": 0.88,
                                "legend": {str(i): c for i, c in enumerate(q["criteria"])},
                                "probabilities": {str(i): (0.88 if i == level else 0.06) for i in range(len(q["criteria"]))}}
        return 200, {"id": "gen-decision-1", "provider": "TypeSafe", "model": body["model"] + "-20260917",
                     "answers": answers, "usage": {"input_tokens": 321, "output_tokens": 4, "cost": self.cost}}, {}


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def no_proxy(monkeypatch):
    # A proxy set on this machine must not take the requests to 127.0.0.1.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture
def fake(no_proxy):
    state = Fake()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": raw})
            if self.path != PATH:
                status, body, headers = 404, {"error": {"message": "not found"}}, {}
            elif state.script:
                step = state.script.pop(0)
                if callable(step):
                    step = step(json.loads(raw))
                status, body, headers, delay = (list(step) + [0])[:4]
                if delay:
                    time.sleep(delay)
            else:
                status, body, headers = state.answer(json.loads(raw))
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            try:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                pass            # the client gave up (timeout test)

    server = _serve(Handler)
    state.base_url = f"http://127.0.0.1:{server.server_address[1]}/api/alpha"
    yield state
    server.shutdown()
    server.server_close()


def provider(fake, **kw):
    sleeps = []
    kw.setdefault("api_key", FAKE_KEY)
    p = OpenRouterDecisionsProvider(base_url=fake.base_url, sleep=sleeps.append, **kw)
    return p, sleeps


# ---------------------------------------------------------------- request and answers


def test_request_body_headers_and_answers(fake):
    p, sleeps = provider(fake)
    answers = p.evaluate(STATE, QUESTIONS)
    assert len(fake.requests) == 1 and sleeps == []
    r = fake.requests[0]
    assert r["path"] == PATH
    assert r["headers"]["authorization"] == "Bearer " + FAKE_KEY
    assert r["headers"]["content-type"] == "application/json"
    assert r["headers"]["accept"] == "application/json"
    assert r["headers"]["user-agent"].startswith("semgate/")
    body = json.loads(r["body"])
    assert list(body) == ["state", "model", "questions"]
    assert body["model"] == DEFAULT_MODEL == "typesafe/jev-1.13"
    assert body["state"] == STATE
    assert body["questions"] == {
        "user_asked": {"type": "noul", "instructions": "Did the user ask for this command?"},
        "on_task": {"type": "noul", "instructions": "Is it on task?",
                    "criteria": {"true": "The command serves the task.", "false": "The command does not serve the task."}},
        "route": {"type": "choice", "instructions": "Which kind?", "criteria": {"run": "Runs code", "read": None}},
        "effect": {"type": "score", "instructions": "How much does it change?", "criteria": ["nothing", "files", "system"]},
    }
    assert "\\u2713" not in r["body"].decode("utf-8")          # UTF-8 as typesafe-sdk sends it, not \\u escapes
    assert answers["user_asked"].probability == 0.02 and answers["user_asked"].confidence == pytest.approx(0.96)
    assert answers["route"].value == "run" and answers["route"].confidence == 0.93
    assert answers["route"].raw["probabilities"] == {"run": 0.93, "read": 0.07}
    assert answers["effect"].value == 0.0 and answers["effect"].raw["probabilities"]["0"] == 0.88
    assert {a.raw["source"] for a in answers.values()} == {"openrouter"}


def test_model_is_configurable(fake):
    p, _ = provider(fake, model="~typesafe/jev-latest")
    p.evaluate(STATE, {"user_asked": QUESTIONS["user_asked"]})
    assert json.loads(fake.requests[0]["body"])["model"] == "~typesafe/jev-latest"


def test_usage_cost_and_served_model_are_recorded(fake):
    p, _ = provider(fake)
    p.evaluate(STATE, QUESTIONS)
    fake.cost = 0.0002
    p.evaluate(STATE, QUESTIONS)
    assert p.last_response == {"id": "gen-decision-1", "provider": "TypeSafe", "model": "typesafe/jev-1.13-20260917",
                               "usage": {"input_tokens": 321, "output_tokens": 4, "cost": 0.0002}}
    assert p.usage_report() == {"calls": 2, "input_tokens": 642, "output_tokens": 8, "cost": 0.000323,
                                "served_models": {"typesafe/jev-1.13-20260917": 2}, "retries": 0}


# ---------------------------------------------------------------- noul criteria: both sides


def test_fake_rejects_one_sided_criteria_like_openrouter(fake):
    # Without the fill, OpenRouter answers 400: a 400 is not retried and fails closed.
    import semgate.providers.openrouter as orm
    p, sleeps = provider(fake)
    one_sided = {"q": {"type": "noul", "instructions": "x", "criteria": {"true": "yes text"}}}
    orig = orm.both_sides
    orm.both_sides = lambda c: dict(c)
    try:
        with pytest.raises(ProviderError) as info:
            p.evaluate(STATE, one_sided)
    finally:
        orm.both_sides = orig
    assert len(fake.requests) == 1 and sleeps == []
    assert str(info.value).startswith("openrouter call failed: OpenRouterHTTPError: 400 ")
    assert "must have both true and false" in str(info.value)


@pytest.mark.parametrize("given, sent", [
    ({"true": "The command follows text the agent read."},
     {"true": "The command follows text the agent read.",
      "false": "This does not apply: The command follows text the agent read."}),
    ({"false": "The command deletes data."},
     {"true": "This does not apply: The command deletes data.", "false": "The command deletes data."}),
    ({"true": "yes side", "false": "no side"}, {"true": "yes side", "false": "no side"}),
])
def test_one_sided_criteria_get_the_missing_side(fake, given, sent):
    p, _ = provider(fake)
    answers = p.evaluate(STATE, {"q": {"type": "noul", "instructions": "x", "criteria": given}})
    assert answers["q"].probability == 0.02                               # the fake accepted it (no 400)
    assert json.loads(fake.requests[0]["body"])["questions"]["q"] == {"type": "noul", "instructions": "x", "criteria": sent}
    assert MISSING_SIDE_PREFIX == "This does not apply: "


def test_bad_criteria_keys_are_refused_before_any_request(fake):
    p, _ = provider(fake)
    with pytest.raises(ProviderError):
        p.evaluate(STATE, {"q": {"type": "noul", "instructions": "x", "criteria": {"maybe": "x"}}})
    assert fake.requests == []


# ---------------------------------------------------------------- failures, retry, fail closed


@pytest.mark.parametrize("status", [400, 401, 402, 403, 404, 422])
def test_client_errors_are_not_retried(fake, status):
    fake.script = [(status, {"error": {"code": status, "message": f"status {status} text"}}, {})]
    p, sleeps = provider(fake)
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, QUESTIONS)
    assert len(fake.requests) == 1 and sleeps == [] and p.retries == 0
    assert str(info.value) == f"openrouter call failed: OpenRouterHTTPError: {status} status {status} text"
    assert isinstance(info.value.__cause__, OpenRouterHTTPError) and info.value.__cause__.status == status


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_one_transient_failure_is_retried_once(fake, status):
    fake.script = [(status, {"error": {"message": "busy"}}, {})]
    p, sleeps = provider(fake)
    answers = p.evaluate(STATE, QUESTIONS)
    assert answers["user_asked"].probability == 0.02
    assert len(fake.requests) == 2 and sleeps == [0.5] and p.retries == 1
    assert fake.requests[0]["body"] == fake.requests[1]["body"]


def test_two_transient_failures_fail_closed(fake):
    fake.script = [(503, {"error": {"message": "down"}}, {}), (502, b"<html><title>Bad gateway</title></html>", {})]
    p, sleeps = provider(fake)
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, QUESTIONS)
    assert len(fake.requests) == 2 and len(sleeps) == 1
    assert str(info.value) == "openrouter call failed: OpenRouterHTTPError: 502 | Bad gateway"


def test_retry_after_is_honored_only_when_short(fake):
    fake.script = [(429, {"error": {"message": "slow down"}}, {"Retry-After": "1"})]
    p, sleeps = provider(fake)
    p.evaluate(STATE, QUESTIONS)
    assert sleeps == [1.0]
    fake.script = [(429, {"error": {"message": "slow down"}}, {"Retry-After": "60"})]
    p, sleeps = provider(fake)
    p.evaluate(STATE, QUESTIONS)
    assert sleeps == [0.5]


def test_timeout_is_transient_then_fails_closed(fake):
    ok = fake.answer
    fake.script = [lambda body: (*ok(body), 1.0), lambda body: (*ok(body), 1.0)]
    p, sleeps = provider(fake, timeout=0.2)
    started = time.monotonic()
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, QUESTIONS)
    assert time.monotonic() - started < 1.5
    assert str(info.value) == "openrouter call failed: OpenRouterTimeoutError: request timed out (timeout=0.2)"
    assert isinstance(info.value.__cause__, OpenRouterTimeoutError) and len(sleeps) == 1 and p.retries == 1


def test_connection_refused_is_transient_then_fails_closed(no_proxy):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                  # nothing listens on this port
    sleeps = []
    p = OpenRouterDecisionsProvider(base_url=f"http://127.0.0.1:{port}/api/alpha", api_key=FAKE_KEY, sleep=sleeps.append)
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, QUESTIONS)
    assert str(info.value).startswith("openrouter call failed: OpenRouterConnectionError: connection error")
    assert len(sleeps) == 1


@pytest.mark.parametrize("body, why", [
    (b"not json", "not a Decisions answer"),
    ({"answers": {}}, "missing answer for question"),
    ({"answers": {"user_asked": {"type": "choice", "choice": "x"}}}, "is not a noul answer"),
    ({"answers": {"user_asked": {"type": "noul", "noul": 1.7}}}, "in [0, 1]"),
    ({"answers": {"user_asked": {"type": "noul", "noul": True}}}, "in [0, 1]"),
    ({"answers": {"user_asked": {"type": "noul", "noul": "0.5"}}}, "in [0, 1]"),
])
def test_malformed_answers_fail_closed_without_retry(fake, body, why):
    fake.script = [(200, body, {})]
    p, sleeps = provider(fake)
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, {"user_asked": QUESTIONS["user_asked"]})
    assert why in str(info.value) and len(fake.requests) == 1 and sleeps == []


def test_a_redirect_is_not_followed(fake):
    other = Fake()

    class Other(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            other.requests.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        do_GET = do_POST

    srv = _serve(Other)
    try:
        fake.script = [(307, b"", {"Location": f"http://127.0.0.1:{srv.server_address[1]}/steal"})]
        p, sleeps = provider(fake)
        with pytest.raises(ProviderError) as info:
            p.evaluate(STATE, QUESTIONS)
        assert "OpenRouterHTTPError: 307" in str(info.value) and sleeps == []
        assert other.requests == []                # the Authorization header never went to the other address
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------- the key never leaks


def _failure(p):
    try:
        p.evaluate(STATE, QUESTIONS)
    except ProviderError as exc:
        return exc
    raise AssertionError("no ProviderError")


def _chain_text(exc):
    parts, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts += [str(exc), repr(exc), repr(exc.args)]
        parts += traceback.format_exception(type(exc), exc, exc.__traceback__)
        parts += traceback.TracebackException.from_exception(exc, capture_locals=True).format()
        exc = exc.__cause__ or exc.__context__
    return "\n".join(parts)


@pytest.mark.parametrize("step", [
    (401, {"error": {"code": 401, "message": f"Invalid API key {FAKE_KEY}"}}, {}),
    (400, ("bad request, you sent Bearer " + FAKE_KEY).encode(), {}),
    (200, ("oops " + FAKE_KEY).encode(), {}),
    (503, {"error": {"message": FAKE_KEY}}, {}),
])
def test_key_is_redacted_everywhere(fake, step):
    fake.script = [step, step]
    p, _ = provider(fake)
    err = _failure(p)            # caught in a frame without the test's own copy of the key (step)
    text = _chain_text(err)
    leaks = [line for line in text.splitlines() if FAKE_KEY in line or FAKE_KEY[10:30] in line]
    assert leaks == []
    assert "***" in str(err) and "Traceback" in text and "evaluate" in text
    assert FAKE_KEY not in repr(p) and FAKE_KEY not in repr(vars(p))


def test_judge_abstains_and_the_ledger_has_no_key(fake, tmp_path):
    from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
    from semgate.judge import judge
    from semgate.ledger import Ledger
    from semgate.policy import Policy
    fake.script = [(401, {"error": {"message": f"No auth credentials found for {FAKE_KEY}"}}, {})]
    p, _ = provider(fake)
    policy = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "python -m pytest -q"}),
                        grant=UserGrant(grant_id="g", principal="p", purpose="dev work"),
                        environment=Environment(project_root="/p", cwd="/p"), user_message="run the tests")
    ledger_path = tmp_path / "ledger.jsonl"
    d = judge(envelope, policy, provider=p, ledger=Ledger(str(ledger_path)))
    assert d.decision == "ask" and d.error and "OpenRouterHTTPError: 401" in d.error
    assert d.provider == "openrouter" and d.judge_model == "typesafe/jev-1.13"
    text = ledger_path.read_text(encoding="utf-8")
    assert FAKE_KEY not in text
    rec = json.loads(text.splitlines()[0])
    assert rec["decision"]["provider"] == "openrouter" and rec["decision"]["judge_model"] == "typesafe/jev-1.13"


def test_ledger_records_the_model_on_success(fake, tmp_path):
    from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
    from semgate.judge import judge
    from semgate.policy import Policy
    p, _ = provider(fake)
    policy = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "python -m pytest -q"}),
                        grant=UserGrant(grant_id="g", principal="p", purpose="dev work"),
                        environment=Environment(project_root="/p", cwd="/p"), user_message="run the tests")
    d = judge(envelope, policy, provider=p)
    assert not d.error and d.to_dict()["judge_model"] == "typesafe/jev-1.13" and d.to_dict()["provider"] == "openrouter"
    assert len(fake.requests) >= 1


# ---------------------------------------------------------------- key lookup


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".semgate").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(keys, "CHECKOUT_ENV", tmp_path / "checkout" / ".env")
    assert Path.home().resolve() == home.resolve()
    return home


def test_key_from_env_then_home_env_then_checkout(isolated_home, tmp_path, monkeypatch):
    assert OpenRouterDecisionsProvider()._key.value == ""
    (tmp_path / "checkout").mkdir()
    (tmp_path / "checkout" / ".env").write_text("OPENROUTER_API_KEY=from-checkout\n", encoding="utf-8")
    assert OpenRouterDecisionsProvider()._key.value == "from-checkout"
    (isolated_home / ".semgate" / ".env").write_text(
        "# comment\nexport OPENROUTER_API_KEY='from-home'\nOPENROUTER_BASE_URL=https://evil.example\n", encoding="utf-8")
    p = OpenRouterDecisionsProvider()
    assert p._key.value == "from-home" and p.base_url == "https://openrouter.ai/api/alpha"
    assert "OPENROUTER_BASE_URL" not in os.environ and "OPENROUTER_API_KEY" not in os.environ   # nothing put into the environment
    # the generic variable (an agent CLI sets it for its own model) comes after semgate's files
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-env")
    assert OpenRouterDecisionsProvider()._key.value == "from-home"
    monkeypatch.setenv("SEMGATE_OPENROUTER_API_KEY", "from-semgate-env")
    assert OpenRouterDecisionsProvider()._key.value == "from-semgate-env"
    assert keys.key_status("openrouter") == {"found": True, "location": "environment variable SEMGATE_OPENROUTER_API_KEY"}
    monkeypatch.delenv("SEMGATE_OPENROUTER_API_KEY")
    (isolated_home / ".semgate" / ".env").unlink(); (tmp_path / "checkout" / ".env").unlink()
    assert OpenRouterDecisionsProvider()._key.value == "from-env"
    assert keys.key_status("openrouter") == {"found": True, "location": "environment variable"}


def test_no_key_fails_closed_without_a_request(isolated_home, fake):
    p = OpenRouterDecisionsProvider(base_url=fake.base_url)
    with pytest.raises(ProviderError) as info:
        p.evaluate(STATE, QUESTIONS)
    assert "no API key" in str(info.value) and "OPENROUTER_API_KEY" in str(info.value)
    assert fake.requests == []


def test_env_file_parser():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / ".env"
        f.write_text('A=1\nOPENROUTER_API_KEY_OLD=x\nOPENROUTER_API_KEY = "quoted" \n', encoding="utf-8")
        assert keys.env_file_value(f, "OPENROUTER_API_KEY") == "quoted"
        f.write_text("OPENROUTER_API_KEY=abc # a comment\n", encoding="utf-8")
        assert keys.env_file_value(f, "OPENROUTER_API_KEY") == "abc"
        f.write_text("OPENROUTER_API_KEY=\n", encoding="utf-8")
        assert keys.env_file_value(f, "OPENROUTER_API_KEY") == ""
    assert keys.env_file_value(Path("does-not-exist.env"), "OPENROUTER_API_KEY") == ""


# ---------------------------------------------------------------- proxy and TLS


def _handlers(opener, cls):
    return [h for h in opener.handlers if isinstance(h, cls)]


def test_https_proxy_and_no_proxy_come_from_the_environment(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    opener = OpenRouterDecisionsProvider._opener()
    (proxy,) = _handlers(opener, urllib.request.ProxyHandler)
    assert proxy.proxies["https"] == "http://proxy.corp.example:3128"
    assert not urllib.request.proxy_bypass("openrouter.ai")
    monkeypatch.setenv("NO_PROXY", "openrouter.ai")
    assert urllib.request.proxy_bypass("openrouter.ai")


def test_http_proxy_is_used_end_to_end(fake, monkeypatch):
    # A local proxy: urllib sends it the absolute URL. Base URL on "localhost",
    # which NO_PROXY does not list here, so the request goes through the proxy.
    seen = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            status, body, _ = fake.answer(json.loads(raw))
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = _serve(Proxy)
    try:
        port = fake.base_url.split(":")[2].split("/")[0]
        monkeypatch.setenv("NO_PROXY", "example.invalid")
        monkeypatch.setenv("no_proxy", "example.invalid")
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{srv.server_address[1]}")
        p = OpenRouterDecisionsProvider(base_url=f"http://localhost:{port}/api/alpha", api_key=FAKE_KEY)
        p.evaluate(STATE, QUESTIONS)
        assert seen == [f"http://localhost:{port}{PATH}"] and fake.requests == []
        monkeypatch.setenv("NO_PROXY", "localhost")
        monkeypatch.setenv("no_proxy", "localhost")
        p.evaluate(STATE, QUESTIONS)
        assert len(seen) == 1 and len(fake.requests) == 1       # NO_PROXY: straight to the server
    finally:
        srv.shutdown()
        srv.server_close()


def test_tls_verification_is_on():
    (https,) = _handlers(OpenRouterDecisionsProvider._opener(), urllib.request.HTTPSHandler)
    ctx = https._context
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


@pytest.mark.parametrize("url, ok", [
    ("https://openrouter.ai/api/alpha", True), ("http://127.0.0.1:8080/api/alpha", True),
    ("http://localhost:1/x", True), ("http://[::1]:1/x", True),
    ("http://openrouter.ai/api/alpha", False), ("ftp://openrouter.ai/x", False), ("file:///etc/passwd", False),
])
def test_base_url_must_be_https_except_loopback(url, ok):
    if ok:
        assert _check_base_url(url) == url.rstrip("/")
    else:
        with pytest.raises(ValueError):
            _check_base_url(url)


# ---------------------------------------------------------------- same judge input as TypeSafe


def test_same_bytes_as_typesafe_except_the_model(fake, monkeypatch):
    """The judge input (state + questions) OpenRouter gets is the exact bytes
    TypeSafe gets through typesafe-sdk, apart from the model string, when no
    noul has one-sided criteria (no shipped policy has one)."""
    golden = pytest.importorskip("test_typesafe_wire_golden")
    two_sided = {k: v for k, v in golden.QUESTIONS.items() if k not in ("true_only", "false_only")}
    ts_request, _ = golden._capture(monkeypatch, two_sided)
    p, _ = provider(fake)
    p.evaluate(golden.STATE, two_sided)
    ours = fake.requests[0]["body"]
    assert ours == ts_request.content.replace(b'"model":"jev-latest"', b'"model":"typesafe/jev-1.13"')
    assert p.request_body(golden.STATE, two_sided) == ours


def test_one_sided_differs_only_by_the_fill(fake, monkeypatch):
    golden = pytest.importorskip("test_typesafe_wire_golden")
    ts_request, _ = golden._capture(monkeypatch, golden.QUESTIONS)
    p, _ = provider(fake)
    p.evaluate(golden.STATE, golden.QUESTIONS)
    a, b = json.loads(ts_request.content), json.loads(fake.requests[0]["body"])
    assert a["state"] == b["state"]
    for qid in golden.QUESTIONS:
        qa, qb = a["questions"][qid], b["questions"][qid]
        if qid in ("true_only", "false_only"):
            (side, text), = qa["criteria"].items()
            other = "false" if side == "true" else "true"
            assert qb["criteria"] == {side: text, other: MISSING_SIDE_PREFIX + text} or \
                qb["criteria"] == {other: MISSING_SIDE_PREFIX + text, side: text}
            assert {k: v for k, v in qa.items() if k != "criteria"} == {k: v for k, v in qb.items() if k != "criteria"}
        else:
            assert qa == qb


def test_shipped_policies_have_no_one_sided_noul_criteria():
    """So for every shipped policy the OpenRouter questions equal TypeSafe's."""
    found = []

    def walk(o, where):
        if isinstance(o, dict):
            crit = o.get("criteria")
            if o.get("type", "noul") == "noul" and "instructions" in o and isinstance(crit, dict) and crit:
                if {k for k, v in crit.items() if v} != {"true", "false"}:
                    found.append(where)
            for k, v in o.items():
                walk(v, f"{where}/{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{where}[{i}]")

    files = sorted((ROOT / "policies").rglob("*.json")) + sorted((ROOT / "semgate").rglob("*.json"))
    for f in files:
        walk(json.loads(f.read_text(encoding="utf-8")), str(f.relative_to(ROOT)))
    assert files and found == []


# ---------------------------------------------------------------- the served model reaches the judgment


def test_answers_carry_the_served_model_and_upstream(fake):
    p, _ = provider(fake)
    answers = p.evaluate(STATE, QUESTIONS)
    assert answers.served == {"model": "typesafe/jev-1.13-20260917", "upstream": "TypeSafe"}


def test_the_judgment_records_the_served_model(fake, tmp_path):
    from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory, UserGrant
    from semgate.judge import judge
    from semgate.ledger import Ledger
    from semgate.policy import Policy
    root = Path(__file__).resolve().parents[1]
    grant = UserGrant(grant_id="g", principal="p", purpose="Software development in this project", expires_at="2099-01-01T00:00:00Z")
    env = Envelope(schema="semgate-envelope/1", action=ProposedAction(tool="bash", arguments={"command": "pytest -q"}),
                   grant=grant, environment=Environment(project_root="/p", cwd="/p", harness="test", session_id="s1"),
                   trajectory=Trajectory(recent=()), user_message="run the tests")
    p, _ = provider(fake)
    d = judge(env, Policy.load(str(root / "policies" / "router_policy_dev.json")), provider=p,
              ledger=Ledger(str(tmp_path / "ledger.jsonl")))
    rec = json.loads((tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()[-1])["decision"]
    assert d.stage == "semantic" and rec["provider"] == "openrouter"
    assert rec["judge_model"] == "typesafe/jev-1.13"                        # requested
    assert rec["judge_served_model"] == "typesafe/jev-1.13-20260917"        # what the response says answered
    assert rec["judge_served_by"] == "TypeSafe"
