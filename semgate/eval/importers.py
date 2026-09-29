"""Explicit conversion from benchmark records to canonical eval cases.

Dataset text is untrusted data. It may supply an action stimulus and label, but
never a grant. The operator must provide the immutable grant template.
"""
from __future__ import annotations
import hashlib
from typing import Any, Dict, Mapping
from ..envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, Trajectory, UserGrant
from .case import BenchmarkCase

SOURCES = {
    "r-judge": "https://github.com/Lordog/R-Judge",
    "agentharm": "https://huggingface.co/datasets/ai-safety-institute/AgentHarm",
    "injecagent": "https://github.com/uiuc-kang-lab/InjecAgent",
    "tool-sandbox": "https://github.com/apple/ToolSandbox",
    "abstentionbench": "https://github.com/facebookresearch/AbstentionBench",
    "toolemu": "https://github.com/ryoungj/ToolEmu",
}

def _text(record: Mapping[str, Any]) -> str:
    for key in ("action", "prompt", "instruction", "query", "goal", "text", "risk_description"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""

def _id(record: Mapping[str, Any], source: str) -> str:
    for key in ("id", "case_id", "behavior_id", "sample_id", "task_id"):
        if record.get(key) not in (None, ""):
            return str(record[key])
    return hashlib.sha256((source + repr(sorted(record.items()))).encode()).hexdigest()[:16]

def _label(record: Mapping[str, Any], source: str) -> str:
    # Source-family defaults are intentionally conservative. Explicit tri-state
    # labels win; import output should still receive human review before claims.
    value = str(record.get("semgate_label", record.get("decision", ""))).lower()
    if value in ("allow", "ask", "deny"):
        return value
    if source in ("agentharm", "injecagent", "toolemu"):
        return "deny"
    if source in ("tool-sandbox", "abstentionbench"):
        return "ask"
    unsafe = record.get("unsafe", record.get("risk", record.get("label")))
    if unsafe is True or str(unsafe).lower() in ("unsafe", "harmful", "risk", "1"):
        return "deny"
    if unsafe is False or str(unsafe).lower() in ("safe", "benign", "0"):
        return "allow"
    return "ask"

def _category(record: Mapping[str, Any], source: str) -> str:
    explicit = str(record.get("semgate_category", ""))
    if explicit:
        return explicit
    return {
        "agentharm": "harm", "injecagent": "prompt_injection",
        "tool-sandbox": "ambiguity", "abstentionbench": "missing_evidence",
        "toolemu": "tool_risk", "r-judge": "trajectory_risk",
    }.get(source, "semantic_residue")

def import_record(record: Mapping[str, Any], source: str, grant: UserGrant, *, project_root: str = "") -> BenchmarkCase:
    if source not in SOURCES:
        raise ValueError(f"unsupported benchmark source: {source}")
    action_text = _text(record)
    if not action_text:
        raise ValueError("record has no supported action/prompt text field")
    source_id = _id(record, source)
    envelope = Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool="benchmark_action", arguments={"description": action_text}),
        grant=grant,
        environment=Environment(project_root=project_root, cwd=project_root, harness="benchmark", session_id=f"{source}:{source_id}"),
        trajectory=Trajectory(),
        evaluated_at=str(record.get("evaluated_at", "2090-01-01T00:00:00Z")),
    )
    label = _label(record, source)
    return BenchmarkCase(
        case_id=f"{source}:{source_id}", source=source, source_id=source_id,
        label=label, category=_category(record, source), envelope=envelope,
        tags=("imported", source),
        rationale="Imported label mapping; review against source annotation before reporting benchmark results.",
    )
