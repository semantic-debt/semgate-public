"""Clean telemetry export.

The ledger already records every judgment, but a raw ledger record is not safe
to share: it holds absolute paths with the operator's username, the user's own
message, grant details, and the full command text, which can carry secrets.

This module reads a ledger and emits one clean record per judgment. A clean
record keeps only what improves the classifier:

  - the tool, the redacted command text, the decision and the stage,
  - the router's numeric votes (route/effect/user_asked/executes) and the
    gate classes that fired -- numbers and enums, never matched text,
  - the policy version and the day (not the exact time).

It drops the envelope's paths, session id, user_message and grant, and it
redacts the command: home directories, email local parts, URL credentials,
`key=value` secrets, bearer tokens and known token shapes become placeholders.
Nothing is uploaded. The operator runs the export locally and decides what to
send. This reuses the redaction approach from the Gemini shadow observer.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

SCHEMA = "semgate.telemetry.v1"

# --- redaction -------------------------------------------------------------

# `C:\Users\<name>\`, `/home/<name>/`, `/Users/<name>/` -> keep the prefix,
# drop the username. The path shape (that it is under a home dir, and the file
# name after it) is signal; the username is not.
_HOME_PATH = re.compile(r"(?i)([A-Za-z]:\\Users\\|/home/|/Users/)([^\\/\s\"'<>|]+)")
# An email: keep the host (exfil signal), drop the local part.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# `scheme://user:pass@host` -> drop the embedded credentials, keep the scheme.
_URL_CRED = re.compile(r"(?i)\b(https?|ftp|ssh)://[^\s/@:]+:[^\s/@]+@")
# `bearer <token>` in a header or URL.
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")
# `token=...`, `password: ...`, `api_key=...` -> keep the key, drop the value.
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|secret[_-]?key"
    r"|authorization|cookie|credential|client[_-]?secret|private[_-]?key)\b(\s*[:=]\s*)(\S+)"
)
# Well-known credential shapes, matched on their own so they are caught even
# without a `key=` prefix.
_TOKENS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),          # AWS access key id
    re.compile(r"\bgh[posru]_[0-9A-Za-z]{20,}\b"),          # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                 # OpenAI-style keys
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),        # Slack tokens
    re.compile(r"\beyJ[A-Za-z0-9._-]{20,}\b"),              # JWTs
]
# A long opaque base64/hex blob (e.g. an inlined key or payload). Runs last so
# it never eats a placeholder we already wrote.
_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def redact_command(text: str, extra: Sequence[str] = ()) -> str:
    """Strip personal data and secrets from a command string, keeping its shape.

    `extra` is a list of literal strings the operator wants removed too (their
    real name, a company, a hostname) -- matched case-insensitively.
    """
    if not isinstance(text, str) or not text:
        return "" if not isinstance(text, str) else text
    s = text
    for literal in extra:
        if literal:
            s = re.sub(re.escape(literal), "<redacted>", s, flags=re.IGNORECASE)
    s = _URL_CRED.sub(lambda m: f"{m.group(1)}://<redacted>@", s)
    s = _BEARER.sub("bearer <redacted>", s)
    s = _SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", s)
    for rule in _TOKENS:
        s = rule.sub("<token>", s)
    s = _HOME_PATH.sub(lambda m: f"{m.group(1)}<user>", s)
    s = _EMAIL.sub(lambda m: f"<user>@{m.group(1)}", s)
    s = _BLOB.sub("<blob>", s)
    return s


def default_extra_redactions() -> List[str]:
    """Literals from the local environment worth stripping automatically: the
    OS login name and the home-directory leaf. The operator can add more."""
    out: List[str] = []
    for value in (os.environ.get("USERNAME"), os.environ.get("USER")):
        if value and len(value) >= 3:
            out.append(value)
    home = os.path.expanduser("~")
    leaf = os.path.basename(home.rstrip("\\/"))
    if leaf and len(leaf) >= 3:
        out.append(leaf)
    return sorted(set(out))


# --- record extraction -----------------------------------------------------

_COMMAND_KEYS = ("command", "commandline", "CommandLine", "cmd", "script")
_PATH_KEYS = ("file_path", "filePath", "path", "url", "target_file", "AbsolutePath")


def _primary_arg(arguments: Dict[str, Any]) -> str:
    """The one string that best describes the action: the shell command, else a
    path/url, else the first string argument."""
    if not isinstance(arguments, dict):
        return ""
    for k in _COMMAND_KEYS:
        if isinstance(arguments.get(k), str) and arguments[k].strip():
            return arguments[k]
    for k in _PATH_KEYS:
        if isinstance(arguments.get(k), str) and arguments[k].strip():
            return arguments[k]
    for v in arguments.values():
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _router_votes(decision: Dict[str, Any]) -> Dict[str, Any]:
    """The router's numeric/enum votes only. No text, no matched strings."""
    out: Dict[str, Any] = {}
    for vote in decision.get("predicate_votes") or []:
        if not isinstance(vote, dict):
            continue
        p = vote.get("predicate")
        if p == "route":
            out["route"] = vote.get("value")
            out["route_confidence"] = vote.get("confidence")
            probs = vote.get("probabilities") or {}
            if isinstance(probs, dict):
                out["run_p"] = probs.get("run")
                out["block_p"] = probs.get("block")
        elif p == "effect":
            out["effect"] = vote.get("value")
            out["effect_confidence"] = vote.get("confidence")
        elif p == "user_asked":
            out["user_asked"] = vote.get("p")
        elif p == "executes":
            out["executes"] = vote.get("value")
    return out


def telemetry_record(record: Dict[str, Any], extra: Sequence[str] = ()) -> Optional[Dict[str, Any]]:
    """Turn one ledger judgment into a clean, shareable record. Returns None for
    any record that is not a judgment."""
    if not isinstance(record, dict) or record.get("record_type") != "judgment":
        return None
    decision = record.get("decision") or {}
    envelope = record.get("envelope") or {}
    action = envelope.get("action") or {}
    tool = str(action.get("tool", ""))
    command = redact_command(_primary_arg(action.get("arguments") or {}), extra)
    ts = str(record.get("ts", ""))
    clean = {
        "schema": SCHEMA,
        "day": ts[:10],
        "tool": tool,
        "command": command,
        "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()[:16],
        "decision": decision.get("decision"),
        "stage": decision.get("stage"),
        # gate classes only -- never the matched text, which can be a secret path
        "gate_classes": sorted({h.get("gate_class", "") for h in (decision.get("gate_hits") or []) if isinstance(h, dict)}),
        "router": _router_votes(decision),
        "policy_version": decision.get("policy_version"),
    }
    if decision.get("error"):
        clean["errored"] = True
    payload = (decision.get("evidence") or {}).get("payload")
    if isinstance(payload, dict):
        # sizes and the model id only; never the content
        clean["payload"] = {k: payload.get(k) for k in ("hook_payload_bytes", "tool_input_bytes", "model",
                                                         "expected_max_bytes", "anomaly")}
    return clean


def export(records: Iterable[Dict[str, Any]], extra: Sequence[str] = ()) -> Iterator[Dict[str, Any]]:
    for record in records:
        clean = telemetry_record(record, extra)
        if clean is not None:
            yield clean


# --- summary ---------------------------------------------------------------

def summarize(clean_records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate clean records into counts an operator can act on: how many of
    each decision, which stages decided, and the redacted commands that were
    denied or sent to a human -- the candidates to review for the classifier."""
    by_decision: Counter = Counter()
    by_stage: Counter = Counter()
    by_gate: Counter = Counter()
    denied: Counter = Counter()
    asked: Counter = Counter()
    for r in clean_records:
        by_decision[r.get("decision")] += 1
        by_stage[f"{r.get('stage')}/{r.get('decision')}"] += 1
        for gc in r.get("gate_classes") or []:
            by_gate[gc] += 1
        cmd = r.get("command") or ""
        if r.get("decision") == "deny":
            denied[cmd] += 1
        elif r.get("decision") == "ask":
            asked[cmd] += 1
    return {
        "schema": SCHEMA,
        "total": len(clean_records),
        "by_decision": dict(by_decision),
        "by_stage": dict(sorted(by_stage.items())),
        "by_gate_class": dict(by_gate),
        "top_denied": denied.most_common(25),
        "top_asked": asked.most_common(25),
    }


# --- leak gate (independent of the redactor) -------------------------------
#
# The exporter redacts. This scans the *already clean* payload one more time,
# just before it leaves the machine, and refuses to send if anything still
# looks like real personal data or a secret. It never trusts the exporter.

# A real home path is `Users\X` / `/home/X` where X is not a placeholder.
_LEAK_HOME = re.compile(r"(?i)(?:[A-Za-z]:\\Users\\|/home/|/Users/)([^\\/\s\"'<>|]+)")
# A real email: local@host, where the local part is not preceded by `<`
# (so the `<user>@host` placeholder is not flagged).
_LEAK_EMAIL = re.compile(r"(?<![<\w])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PLACEHOLDERS = {"<user>", "<redacted>", "<token>", "<blob>"}


def find_leaks(text: str, extra: Sequence[str] = ()) -> List[str]:
    """Return a list of leak descriptions found in `text`, empty when clean."""
    if not isinstance(text, str) or not text:
        return []
    hits: List[str] = []
    for m in _LEAK_HOME.finditer(text):
        seg = m.group(1)
        if seg not in _PLACEHOLDERS:
            hits.append(f"unredacted home segment: {m.group(0)!r}")
    for m in _LEAK_EMAIL.finditer(text):
        hits.append(f"email address: {m.group(0)!r}")
    for rule in _TOKENS:
        for m in rule.finditer(text):
            hits.append(f"token shape: {m.group(0)[:8]!r}…")
    for literal in extra:
        if literal and re.search(re.escape(literal), text, re.IGNORECASE):
            hits.append(f"forbidden literal: {literal!r}")
    return hits


def scan_records(records: Sequence[Dict[str, Any]], extra: Sequence[str] = ()) -> List[Tuple[int, str]]:
    """Scan clean records for leaks. Returns (index, description) for each hit."""
    out: List[Tuple[int, str]] = []
    for i, rec in enumerate(records):
        for issue in find_leaks(json.dumps(rec, ensure_ascii=False), extra):
            out.append((i, issue))
    return out


# --- payload + transport (human-run, opt-in) -------------------------------

def build_payload(records: Sequence[Dict[str, Any]], semgate_version: str = "",
                  install_id: Optional[str] = None, sent_day: str = "") -> Dict[str, Any]:
    """The exact object sent to an endpoint: the clean records plus a minimal,
    non-identifying header. No hostname, no username, no path."""
    header: Dict[str, Any] = {"schema": SCHEMA, "count": len(records)}
    if semgate_version:
        header["semgate_version"] = semgate_version
    if install_id:  # opt-in random id for dedup, not derived from anything personal
        header["install_id"] = install_id
    if sent_day:
        header["sent_day"] = sent_day
    return {"header": header, "records": list(records)}


def post_json(endpoint: str, payload: Dict[str, Any], timeout: float = 10.0) -> Tuple[int, str]:
    """POST a JSON payload. Uses only the stdlib. Returns (status, body)."""
    import urllib.request

    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "semgate-telemetry"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-provided endpoint)
        return resp.status, resp.read().decode("utf-8", "replace")


def load_ledger_records(path: str) -> Iterator[Dict[str, Any]]:
    """Yield ledger records, skipping blank or malformed lines rather than failing."""
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj
