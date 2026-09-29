"""Provider execution, scoring, calibration, and replay artifacts."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
from ..judge import judge
from ..policy import Policy
from ..providers.base import JudgeProvider
from ..providers.fake import FakeProvider
from ..providers.registry import report_fields
from .case import BenchmarkCase
from .metrics import score, selective_curve
from ..gitstate import SyntheticFacts, SyntheticHistory
from ..scriptsource import SyntheticWorkspace

REPORT_SCHEMA = "semgate-eval-report/1"


class JudgeCallCounter(JudgeProvider):
    """Wraps a live provider and counts its calls: `asked` (evaluate called)
    and `answered` (it returned without an exception). `semgate eval` uses the
    counts to refuse a run where the judge answered nothing: during a
    provider outage every semantic case abstains to ask, which scores like a
    cautious model but measures nothing. Other attributes go to the wrapped
    provider (model, usage_report); report_fields finds it through .inner."""

    def __init__(self, inner: JudgeProvider):
        self.inner = inner
        self.asked = 0
        self.answered = 0

    @property
    def name(self) -> str:  # type: ignore[override]
        return self.inner.name

    def __getattr__(self, attr: str) -> Any:
        if attr == "inner":            # not set yet (copy, pickle): no recursion
            raise AttributeError(attr)
        return getattr(self.inner, attr)

    def evaluate(self, state, questions):
        self.asked += 1
        answers = self.inner.evaluate(state, questions)
        self.answered += 1
        return answers

    def counts(self) -> Dict[str, int]:
        return {"asked": self.asked, "answered": self.answered, "failed": self.asked - self.answered}


def validity_problems(report: Mapping[str, Any], judge_calls: Optional[Mapping[str, int]]) -> List[str]:
    """Why a live eval run does not measure the judge ([] = valid).
    judge_calls None means no judge was expected (--provider none or
    scripted): then there is nothing to check."""
    if judge_calls is None:
        return []
    problems: List[str] = []
    n = len(report.get("cases") or [])
    errors = int(report.get("provider_errors") or 0)
    if errors:
        problems.append(f"{errors} of {n} cases got no model answer (provider failure); those cases abstained to ask")
    if n and not judge_calls.get("answered"):
        if judge_calls.get("asked"):
            problems.append(f"the judge was asked {judge_calls['asked']} times and answered 0 times")
        else:
            problems.append(f"a live judge was selected but none of the {n} cases reached it (0 calls)")
    return problems

def load_cases(paths: Sequence[str]) -> List[BenchmarkCase]:
    cases: List[BenchmarkCase] = []
    for raw_path in paths:
        path = Path(raw_path)
        members = sorted(path.glob("*.json")) + sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
        for member in members:
            text = member.read_text(encoding="utf-8")
            values = [json.loads(line) for line in text.splitlines() if line.strip()] if member.suffix == ".jsonl" else json.loads(text)
            if isinstance(values, dict): values = values.get("cases", [values])
            for value in values: cases.append(BenchmarkCase.from_dict(value))
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)): raise ValueError("duplicate benchmark case_id")
    return cases

def evaluate_cases(cases: Sequence[BenchmarkCase], policy: Policy, *, provider: Optional[JudgeProvider] = None, scripted: bool = False) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    for case in cases:
        active = FakeProvider(case.fake_answers, fail=case.provider_fail) if scripted else provider
        # Synthetic workspace facts (F4 files, F6 agent-created paths) replace
        # the filesystem and the ledger, which an eval does not have. Cases
        # without them are judged exactly as before (no facts, no workspace).
        ws = case.workspace or {}
        workspace = (SyntheticWorkspace(ws.get("files") or {}, ws.get("dirs") or ())
                     if (ws.get("files") or ws.get("dirs")) else None)
        facts = (SyntheticFacts(ws.get("agent_created") or {}, case.envelope.environment.project_root)
                 if ws.get("agent_created") else None)
        # G2/S1: eval-only fact envelope.environment.git_head_predates_session.
        predates = case.envelope.environment.git_head_predates_session
        history = SyntheticHistory(predates) if predates is not None else None
        # Session drift: eval-only synthetic earlier on_task values (slow-drift set).
        prior = case.envelope.environment.prior_on_task_p
        # persistence_link: the PATH folders come from the case (workspace.path_env,
        # a fixed fake PATH) or from the fixed list only; never this machine's PATH.
        path_env = ws.get("path_env")
        decision = judge(case.envelope, policy, provider=active, facts=facts, workspace=workspace, git_history=history,
                         prior_on_task=list(prior) if prior is not None else None,
                         path_env=str(path_env) if path_env else None)
        script_ev = decision.evidence.get("script_source") or {}
        fired = [s.get("id", "") for s in (decision.evidence.get("code_signals") or {}).get("fired", [])]
        # Prove the provider never owns absolute categories: a deterministic
        # category reaching semantic evaluation is a benchmark construction error.
        boundary_ok = not case.deterministic_only or decision.stage != "semantic"
        records.append({
            "case_id": case.case_id, "source": case.source, "source_id": case.source_id,
            "label": case.label, "category": case.category,
            "decision": decision.decision, "stage": decision.stage,
            "predicate_votes": decision.predicate_votes,
            "match": case.label == decision.decision, "boundary_ok": boundary_ok,
            "envelope_digest": decision.envelope_digest,
            "provider_error": bool(decision.error),
            **({"script_source_sent": bool(script_ev.get("sent"))} if script_ev else {}),
            **({"test_run_sent": bool(decision.evidence["test_run"].get("sent"))} if decision.evidence.get("test_run") else {}),
            **({"workspace_synthetic": True} if ws else {}),
            **({"code_signals": fired} if fired else {}),
        })
    metrics = score(records)
    return {
        "schema": REPORT_SCHEMA, "policy_version": policy.version,
        "provider": provider.name if provider is not None else ("per-case-script" if scripted else "none"),
        # model id and usage (calls, tokens, cost) of a live provider: results compare only for the same model
        **(report_fields(provider) if provider is not None and not scripted else {}),
        "metrics": metrics, "selective_risk_curve": selective_curve(records),
        "boundary_violations": [r["case_id"] for r in records if not r["boundary_ok"]],
        # A run where the model never answered measures nothing: every semantic
        # case abstains to ask. Report it loudly instead of looking like data.
        "provider_errors": sum(1 for r in records if r["provider_error"]),
        # F4: provider failures on cases whose request carried a script source
        # (e.g. the TypeSafe WAF 403 on some file contents). They fail closed.
        "script_source_sent": sum(1 for r in records if r.get("script_source_sent")),
        "script_source_provider_errors": sum(1 for r in records if r.get("script_source_sent") and r["provider_error"]),
        # Test-run facts (testrun.py) sent with script_source, and provider failures on them.
        "test_run_sent": sum(1 for r in records if r.get("test_run_sent")),
        "test_run_provider_errors": sum(1 for r in records if r.get("test_run_sent") and r["provider_error"]),
        "cases": records,
        "warning": "Benchmark labels and source conversions require review. Deterministic gates remain authoritative; model scores cover semantic residue only.",
    }
