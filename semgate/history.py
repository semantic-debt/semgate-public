"""Append-only JSONL store of tool executions, used for learned auto-allow.

Two record types share one file, distinguished by `record_type`:
  - pending:  written by the PreToolUse hook. Holds the tool, its normalized
              arguments and the decision semgate produced for that step.
  - executed: written by the PostToolUse hook. Antigravity's PostToolUse
              payload carries only `conversationId`, `stepIdx` and `error`
              (no tool name, no args), so the record is built by joining the
              payload with the pending record of the same conversation and
              step.

An action counts toward auto-allow only when its pending decision was "ask"
and an executed record without `error` exists for the same step: semgate
asked, and the tool still ran, so a human approved it.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional

from . import filelock
from .envelope import canonical_json, utcnow_iso

# Free text the model writes to describe its own call. It changes between
# identical calls, so it is not part of the action identity.
NARRATION_KEYS = frozenset({"toolAction", "toolSummary"})

_WHITESPACE = re.compile(r"\s+")


def normalize_args(arguments: Mapping[str, Any]) -> str:
    """Normalization v1: lowercase and collapsed whitespace. Nothing else."""
    kept = {k: v for k, v in arguments.items() if k not in NARRATION_KEYS}
    return _WHITESPACE.sub(" ", canonical_json(kept).lower()).strip()


def action_key(tool: str, arguments: Mapping[str, Any]) -> str:
    text = tool.strip().lower() + "\n" + normalize_args(arguments)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ToolHistory:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, record: Dict[str, Any]) -> None:
        """One line, one write, under the cross-process lock (filelock).
        Raises filelock.LockTimeout (the record is kept in a spill file)."""
        filelock.append_record(self.path, record)

    def records(self) -> Iterator[Dict[str, Any]]:
        """Well-formed records only. A malformed line is skipped and gets one
        `store_warning` record; it never counts (no tolerant parsing: a partial
        line must never add to a learned-allow count). One bad line no longer
        makes every later read raise (formal/REPORT.md S2)."""
        result = filelock.read_jsonl(self.path)
        filelock.warn_malformed(self.path, result, "tool_history")
        yield from result.records

    def record_pending(
        self,
        conversation_id: str,
        step_idx: Any,
        tool: str,
        arguments: Mapping[str, Any],
        decision: str,
        stage: str,
        judgment_id: str = "",
    ) -> None:
        self._append({
            "record_type": "pending",
            "conversation_id": conversation_id,
            "step_idx": step_idx,
            "tool": tool,
            "args_normalized": normalize_args(arguments),
            "action_key": action_key(tool, arguments),
            "decision": decision,
            "stage": stage,
            "judgment_id": judgment_id,
            "ts": utcnow_iso(),
        })

    def record_executed(self, conversation_id: str, step_idx: Any, error: str = "") -> Optional[Dict[str, Any]]:
        """Join a PostToolUse payload with its pending record. Returns the
        executed record, or None when no pending record matches (an
        `executed_unmatched` record is written so the mismatch is visible)."""
        pending: Optional[Dict[str, Any]] = None
        if conversation_id and step_idx is not None:
            for record in self.records():
                if (
                    record.get("record_type") == "pending"
                    and record.get("conversation_id") == conversation_id
                    and record.get("step_idx") == step_idx
                ):
                    pending = record
        if pending is None:
            self._append({
                "record_type": "executed_unmatched",
                "conversation_id": conversation_id,
                "step_idx": step_idx,
                "error": error,
                "ts": utcnow_iso(),
            })
            return None
        executed = {
            "record_type": "executed",
            "conversation_id": conversation_id,
            "step_idx": step_idx,
            "tool": pending.get("tool"),
            "args_normalized": pending.get("args_normalized"),
            "action_key": pending.get("action_key"),
            "prior_decision": pending.get("decision"),
            "prior_stage": pending.get("stage"),
            "judgment_id": pending.get("judgment_id"),
            "error": error,
            "ts": utcnow_iso(),
        }
        self._append(executed)
        return executed

    def count_executed_after_ask(self, tool: str, arguments: Mapping[str, Any]) -> int:
        key = action_key(tool, arguments)
        return sum(
            1
            for record in self.records()
            if record.get("record_type") == "executed"
            and record.get("action_key") == key
            and record.get("prior_decision") == "ask"
            and not record.get("error")
        )
