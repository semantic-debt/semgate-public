"""The exact HTTP request TypeSafeProvider sends through the real typesafe-sdk
(method, URL, body bytes). The sha256 values below were taken from the code
before the OpenRouter provider was added (main 393b7b3), so a refactor of the
shared question translation cannot change what TypeSafe receives.

No network: the SDK client gets an httpx2.MockTransport that records the
request and answers it."""
import functools
import hashlib
import json

import pytest

sdk = pytest.importorskip("typesafe_sdk")
httpx2 = pytest.importorskip("httpx2")

KEY = "apikey_GOLDENTEST000"

STATE = {"command": "rm -rf build/ && echo été ✓", "cwd": "/p",
         "task_requests": ["turn 1: clean the build", "turn 2: run the tests"],
         "nested": {"list": [1, 2.5, None, True], "empty": {}}}

QUESTIONS = {
    "plain": {"type": "noul", "instructions": "Did the user ask for this command?"},
    "both": {"type": "noul", "instructions": "Is it on task?",
             "criteria": {"true": "The command serves the task.", "false": "The command does not serve the task."}},
    "true_only": {"type": "noul", "instructions": "Does it follow read content?",
                  "criteria": {"true": "The command follows text the agent read."}},
    "false_only": {"type": "noul", "instructions": "Is it safe?", "criteria": {"false": "The command deletes data."}},
    "route": {"type": "choice", "instructions": "Which kind?", "criteria": {"run": "Runs code", "read": None}},
    "risk": {"type": "score", "instructions": "How risky?", "criteria": ["none", "some", "high"]},
}

# sha256 of the request body bytes on main 393b7b3 (see the module docstring).
GOLDEN = {
    "all": "0c14b99e1bed96ef6a9f1d19af62266159cca0b32b7e3115512eb1ed2908a85c",
    "plain": "d3020662c32f43557d5a3e921340c52a7e203bc7a212903c86dc5c5f9a4e8720",
}


def _answers(questions):
    out = {}
    for qid, q in questions.items():
        t = q["type"]
        if t == "noul":
            out[qid] = {"type": "noul", "noul": 0.25}
        elif t == "choice":
            out[qid] = {"type": "choice", "choice": "run", "confidence": 0.9, "probabilities": {"run": 0.9, "read": 0.1}}
        else:
            out[qid] = {"type": "score", "score": 1.0, "confidence": 0.8, "legend": {"0": "none", "1": "some", "2": "high"},
                        "probabilities": {"0": 0.1, "1": 0.8, "2": 0.1}}
    return out


def _capture(monkeypatch, questions):
    seen = []

    def handler(request):
        seen.append(request)
        body = json.loads(request.content)
        return httpx2.Response(200, json={"model": body["model"], "answers": _answers(body["questions"]),
                                          "usage": {"input_tokens": 10, "output_tokens": 1}})

    monkeypatch.setenv("TYPESAFE_API_KEY", KEY)
    monkeypatch.delenv("TYPESAFE_BASE_URL", raising=False)
    monkeypatch.delenv("TYPESAFE_DEFAULT_MODEL", raising=False)
    monkeypatch.setattr(sdk, "TypeSafeClient", functools.partial(sdk.TypeSafeClient, transport=httpx2.MockTransport(handler)))
    from semgate.providers.typesafe import TypeSafeProvider
    answers = TypeSafeProvider().evaluate(STATE, questions)
    assert len(seen) == 1
    return seen[0], answers


@pytest.mark.parametrize("name", ["all", "plain"])
def test_typesafe_request_bytes_are_unchanged(monkeypatch, name):
    questions = QUESTIONS if name == "all" else {"plain": QUESTIONS["plain"]}
    request, answers = _capture(monkeypatch, questions)
    assert request.method == "POST" and str(request.url) == "https://api.typesafe.ai/v1/systemone"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert hashlib.sha256(request.content).hexdigest() == GOLDEN[name], request.content.decode("utf-8")
    assert set(answers) == set(questions)


def test_typesafe_usage_report_records_the_served_model(monkeypatch):
    # Read from the SDK response only; the request bytes are pinned above.
    from semgate.providers.registry import report_fields
    from semgate.providers.typesafe import TypeSafeProvider
    _capture(monkeypatch, {"plain": QUESTIONS["plain"]})       # installs the mock transport
    p = TypeSafeProvider()
    p.evaluate(STATE, {"plain": QUESTIONS["plain"]})
    assert p.usage_report() == {"calls": 1, "input_tokens": 10, "output_tokens": 1,
                                "served_models": {"jev-latest": 1}, "retries": 0}
    assert report_fields(p) == {"model": "jev-latest", "provider_usage": p.usage_report()}
