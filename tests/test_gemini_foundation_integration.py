"""Real-engine tests. Run in a complete, installed checkout (also in CI).

The unit-only local export intentionally does not stand in for these tests.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from semgate import gemini_gate as gate


@pytest.fixture
def request_data(tmp_path):
    root = tmp_path / "project with \u00f1"; root.mkdir()
    return {"arguments": {"command": "pytest -q"},
            "context": {"harness": "gemini-cli", "harness_version": "v0.60.0",
                        "session_id": "s1", "cwd": str(root), "project_root": str(root),
                        "shell": "powershell", "reported_cwd": str(root)},
            "grant": {"grant_id": "g1", "principal": "operator", "purpose": "run project tests",
                      "allowed_tools": ["bash"], "allowed_path_prefixes": [str(root)],
                      "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                      "provenance": "unit-test operator fixture"},
            "policy_file": str(Path(__file__).resolve().parents[1] / "policies" / "default_policy.json"),
            "provider": "none", "model": ""}


def test_real_judge_asks_without_provider(request_data):
    result = gate.evaluate_request(request_data)
    assert result["decision"] == "ask" and result["stage"] == "semantic"
    assert gate.map_result(result, True)["decision"] == "ask"


@pytest.mark.parametrize("command", ["rm -rf /", "shutdown", "semgate feedback allow pytest -q"])
def test_real_hard_denial_is_never_reviewable(request_data, command):
    request_data["arguments"] = {"command": command}
    result = gate.evaluate_request(request_data)
    assert result["stage"] == "hard_rules" and result["decision"] == "deny"
    assert gate.map_result(result, True)["decision"] == "deny"


def test_real_gate_keeps_human_review_without_calling_provider(request_data, monkeypatch):
    from semgate.providers.fake import FakeProvider
    from semgate.providers import typesafe
    fake = FakeProvider(fail=True)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setattr(typesafe, "TypeSafeProvider", lambda **kwargs: fake)
    request_data.update(provider="typesafe", model="contract-test")
    request_data["arguments"] = {"command": "git push origin branch"}
    result = gate.evaluate_request(request_data)
    assert result["stage"] == "human_gate" and fake.calls == 0
    assert gate.map_result(result, True)["decision"] == "ask"


def test_real_provider_error_maps_to_deny(request_data, monkeypatch):
    from semgate.providers.fake import FakeProvider
    from semgate.providers import typesafe
    fake = FakeProvider(fail=True)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setattr(typesafe, "TypeSafeProvider", lambda **kwargs: fake)
    request_data.update(provider="typesafe", model="contract-test")
    result = gate.evaluate_request(request_data)
    assert fake.calls == 1 and result["failed"] is True
    assert gate.map_result(result, True)["decision"] == "deny"


def test_no_legacy_feedback_or_learned_history_passed(request_data, monkeypatch):
    import importlib
    module = importlib.import_module("semgate.judge")
    original = module.judge; calls = []
    def spy(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)
    monkeypatch.setattr(module, "judge", spy)
    gate.evaluate_request(request_data)
    assert len(calls) == 1
    assert calls[0]["feedback"] is None and calls[0]["history"] is None


def test_real_requests_rejudge_instead_of_reusing_clearance(request_data, monkeypatch):
    from semgate.providers.fake import FakeProvider
    from semgate.providers import typesafe
    fake = FakeProvider()
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setattr(typesafe, "TypeSafeProvider", lambda **kwargs: fake)
    request_data.update(provider="typesafe", model="contract-test")
    gate.evaluate_request(request_data); gate.evaluate_request(request_data)
    assert fake.calls == 2


def test_real_working_directory_changes_identity(request_data):
    first = gate.evaluate_request(request_data)
    second = deepcopy(request_data)
    sub = Path(second["context"]["cwd"]) / "sub"; sub.mkdir()
    second["context"]["cwd"] = str(sub)
    assert first["request_identity"] != gate.evaluate_request(second)["request_identity"]


def test_installed_isolated_worker_round_trip(request_data):
    result = gate.run_worker(request_data, 10)
    assert result["decision"] == "ask" and result["stage"] == "semantic"
    assert gate.map_result(result, True)["decision"] == "ask"
