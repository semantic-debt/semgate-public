"""evals/25-clustered-bounds.py: statistics and base clustering. Offline: no
network, no model, no key. The last three tests read the committed reports
under evals/reports/; those are in the private repository only, so in the
public release the three tests skip."""
from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("clustered_bounds", ROOT / "evals" / "25-clustered-bounds.py")
cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cb)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


# ------------------------------------------------------------- statistics

def test_zero_failures_26_bases():
    # 1 - 0.05^(1/26)
    assert cb.zero_failure_upper(26) == pytest.approx(0.108830, abs=1e-6)
    assert cb.zero_failure_upper(26) < 0.11


def test_zero_failures_bound_is_where_all_pass_has_5_percent():
    for n in (1, 3, 23, 130):
        p = cb.zero_failure_upper(n)
        assert (1 - p) ** n == pytest.approx(0.05)


def test_zero_failures_needs_bases():
    with pytest.raises(ValueError):
        cb.zero_failure_upper(0)


def test_clopper_pearson_known_values():
    lo, hi = cb.clopper_pearson(3, 10)
    assert lo == pytest.approx(0.066740, abs=1e-5)
    assert hi == pytest.approx(0.652453, abs=1e-5)
    lo, hi = cb.clopper_pearson(0, 5)
    assert lo == 0.0
    assert hi == pytest.approx(1 - 0.025 ** (1 / 5), abs=1e-9)
    lo, hi = cb.clopper_pearson(5, 5)
    assert hi == 1.0
    assert lo == pytest.approx(0.025 ** (1 / 5), abs=1e-9)


def test_clopper_pearson_rejects_bad_input():
    with pytest.raises(ValueError):
        cb.clopper_pearson(4, 3)


def test_binom_cdf_sums_to_one():
    assert cb.binom_cdf(10, 10, 0.3) == 1.0
    total = sum(math.exp(cb._log_pmf(i, 10, 0.3)) for i in range(11))
    assert total == pytest.approx(1.0)


def test_bootstrap_is_deterministic_with_seed():
    groups = [(1, 1), (0, 1), (3, 4), (2, 2), (0, 3), (1, 2)]
    a = cb.cluster_bootstrap(groups, resamples=2000, seed=7)
    b = cb.cluster_bootstrap(groups, resamples=2000, seed=7)
    c = cb.cluster_bootstrap(groups, resamples=2000, seed=8)
    assert a == b
    assert a[0] == pytest.approx(7 / 13)
    assert a[1] <= a[0] <= a[2]
    assert c[0] == a[0]  # the point estimate does not depend on the seed


def test_bootstrap_resamples_bases_not_cases():
    # One base with 10 successes, one with 10 failures: a resample draws whole
    # bases, so the ratio can only be 0, 0.5 or 1.
    lo_hi = cb.cluster_bootstrap([(10, 10), (0, 10)], resamples=500, seed=1)
    assert lo_hi[0] == 0.5
    assert lo_hi[1] in (0.0, 0.5, 1.0) and lo_hi[2] in (0.0, 0.5, 1.0)


# ------------------------------------------------------------- clustering

def test_any_failing_variant_fails_the_base():
    units = [("t1", False), ("t1", True), ("t1", False), ("t2", False), ("t3", False), ("t3", False)]
    row = cb.safety_claim(units, runs=6, cases=6)
    assert row["bases"] == 3
    assert row["failed_bases"] == 1
    assert row["method"].startswith("Clopper-Pearson")
    assert row["point"] == pytest.approx(1 / 3)


def test_variants_collapse_to_bases_for_the_zero_failure_bound():
    # 130 runs on 26 bases (5 each), no failure: the bound uses 26, not 130.
    units = [(f"b{i}", False) for i in range(26) for _ in range(5)]
    row = cb.safety_claim(units, runs=130, cases=26)
    assert row["bases"] == 26 and row["failed_bases"] == 0
    assert row["upper_95"] == pytest.approx(cb.zero_failure_upper(26))
    assert row["upper_95_if_runs_independent"] == pytest.approx(cb.zero_failure_upper(130))
    assert row["upper_95"] > 4 * row["upper_95_if_runs_independent"]


def test_rate_at_zero_uses_clopper_pearson_on_bases():
    row = cb.rate_claim([("a", False), ("b", False), ("c", False), ("d", False), ("e", False)], runs=5, cases=5)
    assert row["point"] == 0.0
    assert row["upper_95"] == pytest.approx(cb.clopper_pearson(0, 5)[1])


def test_base_functions():
    assert cb.base_trajectory({"source_id": "chatcmpl-abc:inserted:none"}) == "chatcmpl-abc"
    assert cb.base_trajectory({"source_id": "chatcmpl-abc:56"}) == "chatcmpl-abc"
    assert cb.base_numbered({"case_id": "inj:2:injected"}) == "inj:2"
    assert cb.base_numbered({"case_id": "inj:2:asked-with-context"}) == "inj:2"
    assert cb.base_numbered({"case_id": "inj:steer:2"}) == "inj:steer:2"
    assert cb.base_numbered({"case_id": "inj:combined"}) == "inj:combined"
    assert cb.base_numbered({"case_id": "drift:3:aligned"}) == "drift:3"
    assert cb.base_355({"case_id": "redcode:13_4", "category": "redcode:index13"}) == "redcode:index13"
    assert cb.base_355({"case_id": "nl2sh:7", "category": "nl2sh:difficulty1"}) == "nl2sh:7"
    assert cb.base_margin({"set": "nonsense", "case_id": "nonsense:chatcmpl-x:inserted:false"}) == "nonsense:chatcmpl-x"
    assert cb.base_margin({"set": "355", "case_id": "redcode:9_2"}) == "355:redcode:index9"
    assert cb.base_margin({"set": "chat-approval", "case_id": "chat-approval:approve:yes:claude"}) == \
        "chat-approval:chat-approval:approve:yes"


def test_overrides_relabel_by_case_id():
    cases = [{"case_id": "nl2sh:1", "label": "ask", "decision": "allow"},
             {"case_id": "nl2sh:2", "label": "ask", "decision": "ask"}]
    out, changed = cb.apply_overrides(cases, {"_meta": {}, "nl2sh:1": {"old": "ask", "new": "allow"}})
    assert changed == 1
    assert out[0]["label"] == "allow" and out[1]["label"] == "ask"
    assert cases[0]["label"] == "ask"  # input not changed


def test_held_out_paths_are_refused(tmp_path):
    with pytest.raises(SystemExit):
        cb._check_public(ROOT / "evals" / "private" / "x.jsonl")
    with pytest.raises(SystemExit):
        cb._check_public(ROOT / "evals" / "agenttrust-heldout-v1-report.json")


# ------------------------------------------------------------- real reports

# The per-case Jev reports under evals/reports/ are in the private repository
# only (TypeSafe terms question; see .publish/exclude.txt). Skip only when NONE
# of the inputs is there (the public release). When some are there, the tests
# run, so one missing file in the private repository still fails.
_INPUT_REPORTS = ([cb.REPORTS / s[1] for s in cb.PRETOOL_SETS] + [cb.REPORTS / s[1] for s in cb.APPROVAL_SETS]
                  + [cb.REPORTS / n for n in cb.MARGIN_REPORTS] + [cb.REPORTS / n for n in cb.PROFILE_REPORTS])
needs_reports = pytest.mark.skipif(not any(p.is_file() for p in _INPUT_REPORTS),
                                   reason="per-case Jev reports are not in the public release")


@needs_reports
def test_committed_reports_give_the_documented_counts():
    report = cb.build_report()
    rows = {(r["set"], r["claim"].split(" (")[0]): r for r in report["rows"]}
    r355 = rows[("355", "harmful allows")]
    assert (r355["cases"], r355["bases"], r355["failed_bases"]) == (91, 47, 0)
    assert rows[("355", "correct allows")]["successes"] == 219
    margin = rows[("margin-study repeats (5 runs per case)", "harmful allows over all runs")]
    assert (margin["runs"], margin["cases"], margin["failed_bases"]) == (130, 26, 0)
    assert margin["bases"] == 23  # three nonsense trajectories each give two ask-labeled cases
    for r in report["rows"]:
        assert r["dropped_not_public"] == 0
    devops = rows[("work-kind check (30 requests x 27 commands)", "unrequested devops command not caught")]
    assert (devops["cases"], devops["bases"], devops["failed_bases"]) == (100, 4, 0)


@needs_reports
def test_markdown_table_has_one_line_per_row():
    report = cb.build_report()
    table = cb.markdown_table(report)
    assert len(table.strip().splitlines()) == len(report["rows"]) + 2


@needs_reports
def test_main_writes_json_and_markdown(tmp_path):
    assert cb.main(["--date", "20000101", "--out-dir", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "clustered-bounds-20000101.json").read_text(encoding="utf-8"))
    assert data["schema"] == "semgate-clustered-bounds/1"
    assert (tmp_path / "clustered-bounds-20000101.md").read_text(encoding="utf-8").startswith("| set |")
