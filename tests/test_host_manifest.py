"""Host capability manifests (semgate/data/hosts) and the ask -> deny mapping."""
import json
from pathlib import Path

import pytest

from semgate.hosts import ADAPTERS, CAPABILITIES, fit_decision, get, load_manifest
from semgate.hosts.base import STATUSES, parse_manifest, unknown_manifest

DATA = Path(__file__).parents[1] / "semgate" / "data" / "hosts"
SEEDED = ("claude", "droid", "antigravity", "opencode-v1", "opencode-v2", "codex", "pi")


@pytest.mark.parametrize("name", SEEDED)
def test_seeded_manifest_is_complete_and_sourced(name):
    raw = json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))
    assert set(raw["capabilities"]) == set(CAPABILITIES), name
    m = load_manifest(name)
    assert m.loaded and m.host == name
    for cid, cap in m.capabilities.items():
        assert cap.status in STATUSES and cap.source, (name, cid)
        if cap.verified:
            assert "hookconf" in cap.source or "agy-1.2.8-live" in cap.source, (name, cid)


def test_kit_measured_cells_match_the_hookconf_matrix():
    # spot checks against hookconf's matrix.md (2026-09-23)
    assert load_manifest("codex").cap("C2").status == "no"            # A2 FAIL
    assert load_manifest("claude").cap("C2").status == "yes"          # A2 PASS
    assert load_manifest("opencode-v1").cap("C2").status == "no"      # A2 UNSUPPORTED
    assert load_manifest("opencode-v1").cap("C19").status == "yes"    # B5 PASS
    assert load_manifest("claude").cap("C19").status == "no"          # B5 UNSUPPORTED
    assert load_manifest("pi").cap("C3").status == "no"               # P1 UNSUPPORTED
    assert [load_manifest(h).core_level for h in ("claude", "codex", "opencode-v1", "opencode-v2", "pi")] == \
        ["L4*", "L1", "none", "none", "none"]


@pytest.mark.parametrize("host,expected", [
    ("claude", "ask"), ("droid", "ask"), ("antigravity", "ask"),
    ("codex", "deny"), ("opencode-v1", "deny"), ("opencode-v2", "deny"),
    ("pi", "deny"),                        # partial counts as unsupported
])
def test_ask_mapping_per_host(host, expected):
    decision, reason = fit_decision(host, "ask", "why")
    assert decision == expected
    if expected == "deny":
        assert reason.startswith("semgate: ") and "cannot show an ask prompt" in reason and reason.endswith("why")
    else:
        assert reason == "why"
    assert fit_decision(host, "allow", "r") == ("allow", "r")
    assert fit_decision(host, "deny", "r") == ("deny", "r")


def test_unknown_or_broken_manifest_fails_closed(tmp_path):
    assert fit_decision("some-new-host", "ask", "r")[0] == "deny"
    (tmp_path / "claude.json").write_text("{broken", encoding="utf-8")
    m = load_manifest("claude", directory=tmp_path)
    assert not m.loaded and m.ask_maps_to == "deny" and all(c.status == "unknown" for c in m.capabilities.values())
    assert fit_decision("claude", "ask", "r", manifest=m)[0] == "deny"
    # a cell with a made-up status, or a missing cell, is unknown
    raw = json.loads((DATA / "claude.json").read_text(encoding="utf-8"))
    raw["capabilities"]["C2"]["status"] = "sure"
    del raw["capabilities"]["C1"]
    m = parse_manifest(raw, "claude")
    assert m.cap("C2").status == "unknown" and m.cap("C1").status == "unknown" and m.ask_maps_to == "deny"
    assert unknown_manifest("x", "e").ask_maps_to == "deny"


def test_legacy_hosts_keep_their_rendering():
    for host in ("vscode", "copilot", "devin"):
        assert fit_decision(host, "ask", "r") == ("ask", "r")


def test_conformance_line_and_adapters():
    assert load_manifest("opencode-v1").conformance_line() == "OpenCode V1 1.18.31: core none, ask no -> ask maps to deny"
    assert load_manifest("claude").conformance_line() == "Claude Code 2.1.280: core L4*, ask supported"
    assert get("opencode").manifest("2.0.1").host == "opencode-v2" and get("opencode").manifest("1.18.31").host == "opencode-v1"
    for name in ("claude", "droid", "antigravity", "opencode", "codex", "pi"):
        assert name in ADAPTERS
    assert sorted(n for n, a in ADAPTERS.items() if a.installable) == ["antigravity", "claude", "codex", "copilot", "droid", "opencode", "pi"]


# ---------------------------------------------------------------- host_shows_ask (block_when_unsure rule)


def test_host_shows_ask_per_host_from_the_manifests():
    from semgate.hosts import host_shows_ask
    got = {h: host_shows_ask(h) for h in ADAPTERS}
    assert got == {"claude": True, "droid": False, "antigravity": False, "opencode": False, "codex": False,
                   "pi": False, "vscode": False, "copilot": False}
    assert host_shows_ask("devin") is False and host_shows_ask("") is False
    # the evidence the rule reads
    assert load_manifest("claude").cap("C2b").status == "yes" and load_manifest("claude").cap("C2b").verified
    assert load_manifest("antigravity").cap("C2b").status == "no"          # force_ask ran under YOLO
    assert load_manifest("droid").cap("C2b").status == "unknown"           # docs only, bypass not measured
    assert load_manifest("codex").cap("C2b").status == "no"                # hookconf A2b FAIL
    assert load_manifest("pi").cap("C2").status == "partial"               # A2b passes, C2 does not


def _claude_raw():
    return json.loads((DATA / "claude.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("c2,c2b,verified,expected", [
    ("yes", "yes", True, True),
    ("yes", "yes", False, False),        # a docs-only bypass claim does not loosen the default
    ("yes", "no", True, False),          # agy: ask ignored in YOLO mode
    ("yes", "unknown", False, False),    # droid
    ("partial", "yes", True, False),     # pi
    ("no", "yes", True, False),
    ("yes", None, False, False),         # cell missing
])
def test_shows_ask_needs_c2_and_a_measured_c2b(c2, c2b, verified, expected):
    raw = _claude_raw()
    raw["capabilities"]["C2"]["status"] = c2
    if c2b is None:
        del raw["capabilities"]["C2b"]
    else:
        raw["capabilities"]["C2b"].update(status=c2b, verified=verified)
    assert parse_manifest(raw, "claude").shows_ask is expected
    assert unknown_manifest("x", "e").shows_ask is False
