"""The TypeSafe provider adapter: SDK failures abstain (ProviderError) and never
leak the API key into the error text that reaches the ledger."""
import sys
import types

import pytest

from semgate.providers.base import ProviderError


class _Client:
    last_kwargs: dict = {}

    def __init__(self, **kwargs):
        _Client.last_kwargs = dict(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def system_one(self, state, questions, model):
        raise RuntimeError("401 Unauthorized for key apikey_TESTSECRET123 (model jev-latest)")


def _stub_sdk():
    mod = types.ModuleType("typesafe_sdk")
    mod.TypeSafeClient = _Client
    for name in ("Noul", "Choice", "Score"):
        setattr(mod, name, lambda **kw: kw)
    return mod


def test_sdk_exception_is_abstain_and_key_is_redacted(monkeypatch):
    monkeypatch.setenv("TYPESAFE_API_KEY", "apikey_TESTSECRET123")
    monkeypatch.setitem(sys.modules, "typesafe_sdk", _stub_sdk())
    from semgate.providers.typesafe import TypeSafeProvider
    provider = TypeSafeProvider()
    with pytest.raises(ProviderError) as info:
        provider.evaluate({"command": "ls"}, {"q": {"type": "noul", "instructions": "x"}})
    text = str(info.value)
    assert "apikey_TESTSECRET123" not in text
    assert "RuntimeError" in text and "401" in text   # the useful part of the message survives


def test_html_block_page_is_shortened_and_drops_the_ip():
    from semgate.providers.typesafe import _short
    page = ("POST https://api.typesafe.ai/v1/systemone: 403 <!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title>"
            "</head><body><h1 data-translate=\"block_headline\">Sorry, you have been blocked</h1>"
            "<span>Cloudflare Ray ID: <strong class=\"x\">a3f54e766c18744f</strong></span><span id=\"cf-footer-ip\">203.0.113.7</span></body></html>")
    s = _short(page)
    assert "403" in s and "Sorry, you have been blocked" in s and "a3f54e766c18744f" in s
    assert "203.0.113.7" not in s and "<" not in s and len(s) <= 400
    assert _short("plain error") == "plain error"


def test_only_the_api_key_is_read_from_env_files(monkeypatch, tmp_path):
    # A .env must never be able to set TYPESAFE_BASE_URL (redirecting the judge)
    # or any other variable; only TYPESAFE_API_KEY, only from ~/.semgate/.env.
    home = tmp_path / "home"
    (home / ".semgate").mkdir(parents=True)
    (home / ".semgate" / ".env").write_text("TYPESAFE_API_KEY=apikey_FROM_HOME\nTYPESAFE_BASE_URL=https://evil.example\nOTHER=1\n")
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("USERPROFILE", str(home))
    assert __import__("pathlib").Path.home().resolve() == home.resolve()
    for var in ("TYPESAFE_API_KEY", "TYPESAFE_BASE_URL", "OTHER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setitem(sys.modules, "typesafe_sdk", _stub_sdk())
    import semgate.providers.keys as keys
    import semgate.providers.typesafe as ts
    # make the checkout-.env candidate point somewhere empty so only the home file counts
    monkeypatch.setattr(keys, "CHECKOUT_ENV", tmp_path / "pkg" / ".env")
    provider = ts.TypeSafeProvider()
    import os
    # the key goes to the SDK client, never into os.environ (child processes
    # would inherit it); no other variable from the file is used at all
    assert provider._client() is not None and _Client.last_kwargs.get("api_key") == "apikey_FROM_HOME"
    assert "TYPESAFE_API_KEY" not in os.environ
    assert "TYPESAFE_BASE_URL" not in os.environ and "OTHER" not in os.environ


def test_semgate_sources_win_over_the_generic_env_variable(monkeypatch, tmp_path):
    # An agent CLI sets TYPESAFE_API_KEY / OPENROUTER_API_KEY for its own model;
    # the hook runs with that environment. semgate's own .env must win.
    home = tmp_path / "home"
    (home / ".semgate").mkdir(parents=True)
    (home / ".semgate" / ".env").write_text("TYPESAFE_API_KEY=apikey_SEMGATE\n")
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("TYPESAFE_API_KEY", "apikey_AGENT_STALE")
    monkeypatch.delenv("SEMGATE_TYPESAFE_API_KEY", raising=False)
    import semgate.providers.keys as keys
    monkeypatch.setattr(keys, "CHECKOUT_ENV", tmp_path / "pkg" / ".env")
    assert keys.find_key("TYPESAFE_API_KEY")[0] == "apikey_SEMGATE"
    monkeypatch.setenv("SEMGATE_TYPESAFE_API_KEY", "apikey_EXPLICIT")
    assert keys.find_key("TYPESAFE_API_KEY") == ("apikey_EXPLICIT", "environment variable SEMGATE_TYPESAFE_API_KEY")


def test_answers_carry_the_served_model(monkeypatch):
    class Answer:
        noul = 0.1

    class Response:
        model = "jev-1.13-20260917"
        answers = {"q": Answer()}
        usage = None

    class Client(_Client):
        def system_one(self, state, questions, model):
            return Response()

    mod = _stub_sdk()
    mod.TypeSafeClient = Client
    monkeypatch.setenv("TYPESAFE_API_KEY", "apikey_TESTSECRET123")
    monkeypatch.setitem(sys.modules, "typesafe_sdk", mod)
    from semgate.providers.typesafe import TypeSafeProvider
    answers = TypeSafeProvider().evaluate({"command": "ls"}, {"q": {"type": "noul", "instructions": "x"}})
    assert answers.served == {"model": "jev-1.13-20260917"} and answers["q"].probability == 0.1
