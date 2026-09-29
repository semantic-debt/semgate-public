"""Payload size as evidence (owner decision 2026-09-23: observe, do not cap).

Every decision records, in the ledger judgment under
`decision.evidence.payload`:

  hook_payload_bytes   size of the raw hook payload (stdin, or the serve line)
  tool_input_bytes     size of the tool input as compact JSON (UTF-8)
  model                the model id from the payload or transcript ("" unknown)
  max_output_tokens    from semgate/data/model_limits.json (null: unknown model)
  expected_max_bytes   max_output_tokens x bytes_per_token x safety_factor (null: unknown)
  anomaly              tool_input_bytes > expected_max_bytes

An anomaly also writes a ledger incident `payload_anomaly`. It never blocks.
With the policy switch router.code_signals containing "S5_payload_size" (off
in dev), the model also gets the fact line

  checked by code: this tool input is N KB, larger than the model can write
  in one response (about M KB)

A tool input larger than one model response can hold was not written by the
model in that response: the host, a plugin or something the agent pasted in
built it. That is a fact for the model to weigh, not a decision.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

S5_ID = "S5_payload_size"
_LIMITS_FILE = Path(__file__).resolve().parent / "data" / "model_limits.json"
_TABLE: Optional[Dict[str, Any]] = None
_SNAPSHOT = re.compile(r"^(?:-\d{8}|-\d{4}-\d{2}-\d{2}|@\d{8})$")


def limits_table() -> Dict[str, Any]:
    global _TABLE
    if _TABLE is None:
        try:
            raw = json.loads(_LIMITS_FILE.read_text(encoding="utf-8"))
            models = {str(m["id"]).lower(): m for m in raw.get("models", []) if isinstance(m, dict) and m.get("id")}
            _TABLE = {"bytes_per_token": int(raw.get("bytes_per_token", 4)), "safety_factor": int(raw.get("safety_factor", 4)),
                      "models": models}
        except (OSError, ValueError, KeyError, TypeError):
            _TABLE = {"bytes_per_token": 4, "safety_factor": 4, "models": {}}
    return _TABLE


def normalize_model(model: str) -> str:
    m = (model or "").strip().lower()
    m = m.split("[", 1)[0]                     # claude-opus-5-5[1m]
    m = m.rsplit("/", 1)[-1]                   # openai/gpt-5.5, anthropic/claude-...
    for prefix in ("global.", "us.", "eu.", "apac.", "anthropic."):
        if m.startswith(prefix):
            m = m[len(prefix):]
    m = re.sub(r"-v\d+(?::\d+)?$", "", m)      # bedrock -v1:0
    return m


def lookup(model: str) -> Optional[Mapping[str, Any]]:
    """The model_limits.json entry for `model`, or None (no expectation)."""
    m = normalize_model(model)
    if not m:
        return None
    models = limits_table()["models"]
    if m in models:
        return models[m]
    for key in sorted(models, key=len, reverse=True):
        if m.startswith(key) and _SNAPSHOT.match(m[len(key):]):
            return models[key]
    return None


def tool_input_bytes(tool_input: Any) -> int:
    if tool_input is None:
        return 0
    if isinstance(tool_input, str):
        return len(tool_input.encode("utf-8", "replace"))
    try:
        return len(json.dumps(tool_input, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8", "replace"))
    except (TypeError, ValueError):
        return 0


def describe(hook_payload_bytes: int, tool_input: Any, model: str = "") -> Dict[str, Any]:
    """The `payload` evidence for one decision."""
    t = limits_table()
    entry = lookup(model)
    size = tool_input_bytes(tool_input)
    out: Dict[str, Any] = {"hook_payload_bytes": int(hook_payload_bytes or 0), "tool_input_bytes": size,
                           "model": str(model or "")[:200], "max_output_tokens": None, "expected_max_bytes": None,
                           "anomaly": False}
    if entry is not None:
        tokens = int(entry["max_output_tokens"])
        expected = tokens * t["bytes_per_token"] * t["safety_factor"]
        out.update(max_output_tokens=tokens, expected_max_bytes=expected, anomaly=size > expected)
    return out


def signal_text(ev: Mapping[str, Any]) -> str:
    return (f"checked by code: this tool input is {round(ev['tool_input_bytes'] / 1024):,} KB, larger than the model "
            f"can write in one response (about {round(ev['expected_max_bytes'] / 1024):,} KB for {ev.get('model') or 'this model'})")


def signals(ev: Optional[Mapping[str, Any]], enabled: Any) -> List[Any]:
    """The S5 code signal when it is switched on and the input is an anomaly."""
    if not ev or not ev.get("anomaly") or S5_ID not in (enabled or ()):
        return []
    from .codesignals import Signal
    return [Signal(S5_ID, signal_text(ev), {"tool_input_bytes": ev["tool_input_bytes"],
                                            "expected_max_bytes": ev["expected_max_bytes"], "model": ev.get("model", "")})]
