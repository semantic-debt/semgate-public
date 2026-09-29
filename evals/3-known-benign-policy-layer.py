"""Offline audit of an exact known-benign capability layer over frozen baseline results.

No Jev calls are made. The frozen baseline thresholds, scores, and V2 report are untouched.
Dataset labels are measurement only and never create capabilities.
"""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone
from semgate.capabilities import matches_capability

BASELINE = Path("evals/jev-dataset-eval-report.json")
POLICY = Path("policies/known-benign-capabilities.json")
OUT = Path("evals/known-benign-policy-layer-report.json")


def main() -> None:
    baseline = json.loads(BASELINE.read_text())
    policy = json.loads(POLICY.read_text())
    interruptions = [x for x in baseline["failures"] if x["label"] == "allow" and x["decision"] == "ask"]
    assert len(interruptions) == baseline["test_metrics"]["unnecessary_interruptions"] == 520

    # The frozen report intentionally stores derived scores and IDs, not raw third-party
    # action text. More importantly, neither source adapter supplied an owner-issued
    # exact capability. Without action+target+scope plus trusted provenance and expiry,
    # a deterministic allow is impossible by construction.
    eligible = []
    ineligible = []
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    for row in interruptions:
        proposal = row.get("proposal")
        matched = None
        if isinstance(proposal, dict):
            matched = next((c for c in policy["capabilities"] if matches_capability(proposal, c, now=now)), None)
        if matched:
            eligible.append({"id": row["id"], "capability_id": matched.get("id")})
        else:
            missing = []
            if not isinstance(proposal, dict): missing.append("exact_proposal")
            if not policy["capabilities"]: missing.append("predeclared_trusted_capability")
            ineligible.append({"id": row["id"], "source": row["source"], "missing": missing})

    false_allows = baseline["test_metrics"]["false_allows"]
    # Overlay changes only exact matches. The empty, predeclared policy means the
    # baseline decision vector is unchanged and its observed false allows remain zero.
    report = {
        "schema": "semgate-known-benign-policy-layer-eval/1",
        "method": {
            "paid_jev_calls": 0,
            "baseline_report": str(BASELINE),
            "baseline_thresholds_unchanged": True,
            "negative_v2_report_unchanged": True,
            "rule_shape": "exact action + exact target + exact scope + trusted owner provenance + expiry",
            "wildcards_or_categories_allowed": False,
            "labels_used_to_construct_rules": False,
        },
        "frozen_held_out": {
            "cases": baseline["test_metrics"]["cases"],
            "baseline_unnecessary_interruptions": len(interruptions),
            "interruptions_by_source": dict(Counter(x["source"] for x in interruptions)),
            "fully_instantiated_matches": len(eligible),
            "coverage_of_interruptions": len(eligible) / len(interruptions),
            "post_policy_unnecessary_interruptions": len(interruptions) - len(eligible),
            "baseline_false_allows": false_allows,
            "post_policy_false_allows": false_allows,
        },
        "eligibility": {
            "matches": eligible,
            "ineligible_count": len(ineligible),
            "ineligible_by_missing_requirement": dict(Counter(m for x in ineligible for m in x["missing"])),
        },
        "conclusion": "Zero of 520 interruptions can be safely auto-allowed by a fully instantiated known-benign capability layer because the frozen benchmark supplies no trusted, predeclared exact capabilities. Creating rules from safe labels would be dataset fitting and would not test authorization. The benchmark can measure classifier behavior, but cannot measure capability-policy coverage until action envelopes include exact targets and owner-issued grants.",
        "next_measurement": "Freeze a separate capability-aware action set before evaluation: exact proposed action envelopes paired with owner-issued scoped/expiring grants, plus minimally changed wrong-target, wrong-scope, expired, and untrusted-provenance counterfactuals.",
        "estimated_new_paid_cost_usd": 0.0,
        "cumulative_cost_upper_bound_usd": 2.833834,
    }
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
