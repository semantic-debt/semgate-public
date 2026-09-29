"""OpenCode permission.asked event -> envelope mapping."""
from semgate.adapters.opencode import envelope_from_permission_event, grant_from_config

from conftest import make_grant


def test_bash_event_maps_command():
    event = {
        "type": "permission.asked",
        "properties": {
            "id": "per-1",
            "sessionID": "ses-abc",
            "permission": "bash",
            "patterns": ["pytest tests/payments/ -q"],
            "metadata": {"command": "pytest tests/payments/ -q"},
            "tool": {"messageID": "msg-1", "callID": "call-1"},
        },
    }
    env = envelope_from_permission_event(event, grant=make_grant(), directory="/home/me/proj")
    assert env.action.tool == "bash"
    assert env.action.arguments["command"] == "pytest tests/payments/ -q"
    assert env.environment.project_root == "/home/me/proj"
    assert env.environment.harness == "opencode"
    assert env.environment.session_id == "ses-abc"


def test_read_event_maps_path_and_tolerates_missing_fields():
    event = {"type": "permission.asked", "properties": {"permission": "read", "patterns": ["/home/me/proj/src/app.py"]}}
    env = envelope_from_permission_event(event, grant=make_grant(), directory="/home/me/proj")
    assert env.action.tool == "read"
    assert env.action.arguments["path"] == "/home/me/proj/src/app.py"


def test_unknown_fields_fall_back_to_patterns():
    event = {"type": "permission.asked", "properties": {"permission": "webfetch", "patterns": ["https://example.com"]}}
    env = envelope_from_permission_event(event, grant=make_grant())
    assert env.action.tool == "webfetch"
    assert env.action.arguments["url"] == "https://example.com"


def test_grant_from_config():
    grant = grant_from_config({
        "grant_id": "g1",
        "principal": "me",
        "purpose": "triage the failing tests",
        "allowed_tools": ["read", "bash"],
        "allowed_path_prefixes": ["/home/me/proj"],
        "expires_at": "2026-09-19T00:00:00Z",
    })
    assert grant.grant_id == "g1"
    assert grant.allowed_tools == ("read", "bash")
