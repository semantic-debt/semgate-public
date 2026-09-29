"""Clean telemetry export: redaction removes personal data and secrets while
keeping the command's shape and the classifier signal."""
from __future__ import annotations

import json

from semgate import telemetry


def _judgment(command, decision="deny", stage="hard_rules", tool="bash",
              votes=None, gate_hits=None, ts="2026-09-21T10:11:12Z", policy="dev@abc123"):
    return {
        "record_type": "judgment",
        "judgment_id": "digest",
        "ts": ts,
        "decision": {
            "decision": decision,
            "stage": stage,
            "gate_hits": gate_hits or [],
            "predicate_votes": votes or [],
            "policy_version": policy,
        },
        "envelope": {
            "action": {"tool": tool, "arguments": {"command": command}},
            "environment": {"cwd": r"C:\Users\me\Desktop\semgate", "session_id": "s-secret"},
            "user_message": "please read my private notes at C:/Users/me/notes.txt",
        },
    }


# --- redaction ---

def test_home_path_username_stripped():
    out = telemetry.redact_command(r"cat C:\Users\me\.ssh\config")
    assert r"Users\me" not in out
    assert out == r"cat C:\Users\<user>\.ssh\config"


def test_unix_home_stripped():
    out = telemetry.redact_command("cat /home/me/.env")
    assert "/home/me/" not in out
    assert out == "cat /home/<user>/.env"


def test_email_local_part_stripped_host_kept():
    out = telemetry.redact_command("git config user.email me@gmail.com")
    assert " me@" not in out
    assert "<user>@gmail.com" in out


def test_key_value_secret_redacted_key_kept():
    out = telemetry.redact_command("curl -H 'authorization: Bearer sk-abcdefghijklmnopqrstuvwx' https://api.example.com")
    assert "sk-abcdefghijklmnopqrstuvwx" not in out
    assert "<redacted>" in out or "<token>" in out
    assert "api.example.com" in out  # host shape kept


def test_url_embedded_credentials_redacted():
    out = telemetry.redact_command("git clone https://user:p4ssw0rd@github.com/org/repo.git")
    assert "p4ssw0rd" not in out
    assert "user:" not in out
    assert "github.com/org/repo.git" in out


def test_known_token_shapes_redacted():
    for secret in ("ghp_0123456789abcdefghijklmnopqrstuvwx", "AKIAIOSFODNN7EXAMPLE"):
        out = telemetry.redact_command(f"echo {secret}")
        assert secret not in out


def test_extra_literal_stripped():
    out = telemetry.redact_command('git commit -m "by Example Person"', extra=["Example Person"])
    assert "Example Person" not in out
    assert "<redacted>" in out


def test_shape_preserved_for_benign_command():
    out = telemetry.redact_command("pytest -q tests/test_router.py")
    assert out == "pytest -q tests/test_router.py"


# --- record extraction ---

def test_record_drops_personal_fields_keeps_signal():
    votes = [
        {"predicate": "route", "vote": "deny", "value": "block", "confidence": 0.91,
         "probabilities": {"run": 0.05, "block": 0.9}},
        {"predicate": "effect", "vote": "uncertain", "value": 2.5, "confidence": 0.8},
        {"predicate": "user_asked", "vote": "uncertain", "p": 0.1},
        {"predicate": "executes", "vote": "blocks_allow", "value": 1.7, "confidence": 0.7},
    ]
    rec = telemetry.telemetry_record(
        _judgment("rm -rf /home/me/project", decision="deny", stage="hard_rules", votes=votes)
    )
    blob = json.dumps(rec)
    # no personal data
    assert "/home/me/" not in blob and "Users/me/" not in blob and "Users\\\\me" not in blob
    assert "s-secret" not in blob          # session id dropped
    assert "private notes" not in blob     # user_message dropped
    assert "cwd" not in rec                 # environment dropped
    # signal kept
    assert rec["decision"] == "deny"
    assert rec["stage"] == "hard_rules"
    assert rec["router"]["route"] == "block"
    assert rec["router"]["effect"] == 2.5
    assert rec["router"]["user_asked"] == 0.1
    assert rec["router"]["executes"] == 1.7
    assert rec["day"] == "2026-09-21"
    assert rec["policy_version"] == "dev@abc123"


def test_gate_class_kept_matched_text_dropped():
    rec = telemetry.telemetry_record(
        _judgment("cat .env", decision="ask", stage="human_gate",
                  gate_hits=[{"gate_class": "credentials_secrets", "matched": "/home/me/.env"}])
    )
    assert rec["gate_classes"] == ["credentials_secrets"]
    assert "/home/me/" not in json.dumps(rec)


def test_non_judgment_records_skipped():
    assert telemetry.telemetry_record({"record_type": "host_response"}) is None
    assert telemetry.telemetry_record({"record_type": "override"}) is None


def test_export_and_summary_roundtrip():
    records = [
        _judgment("rm -rf /", decision="deny", stage="hard_rules"),
        _judgment("cat .env", decision="ask", stage="human_gate"),
        _judgment("ls -la", decision="allow", stage="hard_rules"),
        {"record_type": "host_response"},
    ]
    clean = list(telemetry.export(records))
    assert len(clean) == 3  # host_response skipped
    report = telemetry.summarize(clean)
    assert report["total"] == 3
    assert report["by_decision"] == {"deny": 1, "ask": 1, "allow": 1}
    assert ("rm -rf /", 1) in report["top_denied"]
    assert ("cat .env", 1) in report["top_asked"]


# --- leak gate ---

def test_leak_gate_flags_real_home_path():
    hits = telemetry.find_leaks(r"cat C:\Users\me\.ssh\config")
    assert any("home" in h for h in hits)


def test_leak_gate_ignores_placeholder_home():
    assert telemetry.find_leaks(r"cat C:\Users\<user>\.ssh\config") == []
    assert telemetry.find_leaks(r"cat C:\Users\<redacted>\file") == []


def test_leak_gate_flags_real_email_not_placeholder():
    assert any("email" in h for h in telemetry.find_leaks("mail me@gmail.com"))
    assert telemetry.find_leaks("mail <user>@gmail.com") == []


def test_leak_gate_flags_token_and_literal():
    assert any("token" in h for h in telemetry.find_leaks("echo ghp_0123456789abcdefghijklmnopqrstuvwx"))
    assert any("literal" in h for h in telemetry.find_leaks("by Example Person", extra=["Example Person"]))


def test_scan_records_reports_index():
    clean = [{"command": "ls"}, {"command": r"cat /home/me/.env"}]
    issues = telemetry.scan_records(clean)
    assert issues and issues[0][0] == 1


def test_clean_export_passes_leak_gate():
    # A real ledger record, exported, must have zero leaks.
    rec = telemetry.telemetry_record(_judgment(r"cat C:\Users\me\.env", decision="ask"),
                                     extra=telemetry.default_extra_redactions())
    assert telemetry.scan_records([rec], telemetry.default_extra_redactions()) == []


def test_build_payload_header_is_minimal():
    payload = telemetry.build_payload([{"command": "ls"}], semgate_version="1.2.3", install_id="abc", sent_day="2026-09-21")
    assert payload["header"] == {"schema": telemetry.SCHEMA, "count": 1,
                                 "semgate_version": "1.2.3", "install_id": "abc", "sent_day": "2026-09-21"}
    # nothing personal
    assert "username" not in json.dumps(payload)


def test_load_ledger_skips_malformed_lines(tmp_path):
    p = tmp_path / "ledger.jsonl"
    p.write_text(
        json.dumps(_judgment("ls")) + "\n" + "not json\n" + "\n" + json.dumps(_judgment("pwd")) + "\n",
        encoding="utf-8",
    )
    recs = list(telemetry.load_ledger_records(str(p)))
    assert len(recs) == 2
