"""F5: the TypeSafe provider retries exactly once, after a short backoff, on
transient failures only. Auth / WAF (401, 403) and validation (4xx) errors
are never retried. The error text and the fail-closed behavior are unchanged."""
import sys
import types

import pytest

from semgate.providers.base import ProviderError


class _Api(Exception):
    def __init__(self, status, text):
        super().__init__(text)
        self.status = status


class _Answer:
    def __init__(self, p):
        self.noul = p


class _Response:
    answers = {"q": _Answer(0.2)}


def _sdk(script, calls, policies):
    """A stub SDK whose client raises the scripted exceptions in order, then answers."""
    class Client:
        def __init__(self, retry=None, **kwargs):
            policies.append(retry)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def system_one(self, state, questions, model):
            calls.append(1)
            if script:
                raise script.pop(0)
            return _Response()

    class RetryPolicy:
        def __init__(self, max_retries=2):
            self.max_retries = max_retries

    mod = types.ModuleType("typesafe_sdk")
    mod.TypeSafeClient = Client
    mod.RetryPolicy = RetryPolicy
    for name in ("Noul", "Choice", "Score"):
        setattr(mod, name, lambda **kw: kw)
    return mod


def _provider(monkeypatch, script):
    calls, policies, sleeps = [], [], []
    monkeypatch.setenv("TYPESAFE_API_KEY", "apikey_TESTSECRET123")
    monkeypatch.setitem(sys.modules, "typesafe_sdk", _sdk(list(script), calls, policies))
    from semgate.providers.typesafe import TypeSafeProvider
    return TypeSafeProvider(sleep=sleeps.append), calls, policies, sleeps


Q = {"q": {"type": "noul", "instructions": "x"}}


@pytest.mark.parametrize("exc", [
    TimeoutError("read timed out"),
    ConnectionError("connection reset"),
    _Api(503, "503 Service Unavailable"),
    _Api(500, "500 Internal Server Error"),
    _Api(429, "429 Too Many Requests"),
    _Api(408, "408 Request Timeout"),
])
def test_one_transient_failure_is_retried_once(monkeypatch, exc):
    provider, calls, policies, sleeps = _provider(monkeypatch, [exc])
    answers = provider.evaluate({"command": "ls"}, Q)
    assert answers["q"].probability == 0.2
    assert len(calls) == 2 and provider.retries == 1
    assert sleeps == [0.5]
    assert all(p is not None and p.max_retries == 0 for p in policies)   # the SDK's own retry is off


@pytest.mark.parametrize("exc", [
    _Api(401, "401 Unauthorized"),
    _Api(403, "403 <html><title>Attention Required! | Cloudflare</title></html>"),
    _Api(400, "400 Bad Request"),
    _Api(422, "422 Unprocessable Entity"),
    RuntimeError("unexpected"),
])
def test_auth_waf_and_validation_errors_are_not_retried(monkeypatch, exc):
    provider, calls, _, sleeps = _provider(monkeypatch, [exc])
    with pytest.raises(ProviderError) as info:
        provider.evaluate({"command": "ls"}, Q)
    assert len(calls) == 1 and sleeps == [] and provider.retries == 0
    assert str(info.value).startswith(f"typesafe call failed: {type(exc).__name__}: ")


def test_two_transient_failures_fail_closed_with_the_same_message(monkeypatch):
    provider, calls, _, sleeps = _provider(monkeypatch, [TimeoutError("t1"), TimeoutError("t2 key apikey_TESTSECRET123")])
    with pytest.raises(ProviderError) as info:
        provider.evaluate({"command": "ls"}, Q)
    assert len(calls) == 2 and len(sleeps) == 1
    assert str(info.value) == "typesafe call failed: TimeoutError: t2 key ***"


def test_retry_after_is_honored_only_when_short(monkeypatch):
    short = _Api(429, "429"); short.retry_after_ms = 1500
    long = _Api(429, "429"); long.retry_after_ms = 60000
    provider, _, _, sleeps = _provider(monkeypatch, [short])
    provider.evaluate({"command": "ls"}, Q)
    assert sleeps == [1.5]
    provider, _, _, sleeps = _provider(monkeypatch, [long])
    provider.evaluate({"command": "ls"}, Q)
    assert sleeps == [0.5]


def test_judge_still_abstains_to_ask_after_a_failed_retry(monkeypatch):
    from pathlib import Path
    from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
    from semgate.judge import judge
    from semgate.policy import Policy
    provider, calls, _, _ = _provider(monkeypatch, [_Api(502, "bad gateway"), _Api(502, "bad gateway")])
    policy = Policy.load(str(Path(__file__).parents[1] / "policies" / "router_policy_dev.json"))
    envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": "python -m pytest -q"}),
                        grant=UserGrant(grant_id="g", principal="p", purpose="dev work"),
                        environment=Environment(project_root="/p", cwd="/p"), user_message="run the tests")
    d = judge(envelope, policy, provider=provider)
    assert d.decision == "ask" and d.error and len(calls) == 2
