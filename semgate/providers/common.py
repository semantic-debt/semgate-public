"""Parts every live Jev transport shares (TypeSafe SDK, OpenRouter Decisions).

- question translation: one semgate question -> (type, fields) as the wire
  form carries them. TypeSafe passes the fields to the SDK's Noul/Choice/Score;
  OpenRouter sends {"type": type, **fields}. So both transports send the same
  judge input (state + questions).
- the retry rule: which failures get the one retry (is_transient)
- error text: shorten HTML block pages (shorten) and remove the API key (redact)

Moved here from providers/typesafe.py without a change in behavior; typesafe.py
still exports the old names (_short, is_transient, noul_criteria, ...).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Tuple

from .base import ProviderError

RETRY_BACKOFF_S = 0.5          # wait before the single retry
RETRY_AFTER_CAP_S = 2.0        # a server Retry-After above this is not waited for; the backoff is used

QUESTION_TYPES = ("noul", "choice", "score")


def shorten(text: str) -> str:
    """Keep provider errors readable in the ledger and the host's reason field.
    A proxy/WAF block returns a full HTML page (with the client's IP address);
    keep the status line, the page title / headline and any ray id only."""
    if "<html" not in text.lower() and "<!doctype" not in text.lower():
        return text[:400]
    head = text.split("<", 1)[0].strip()
    title = re.search(r"<title>(.*?)</title>", text, re.S | re.I)
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", text, re.S | re.I)
    ray = re.search(r"Ray ID:\s*(?:<[^>]+>)?\s*([0-9a-f]{8,})", text, re.I)
    parts = [head] + [" ".join(re.sub(r"<[^>]+>", " ", m.group(1)).split()) for m in (title, h1) if m]
    if ray:
        parts.append(f"ray id {ray.group(1)}")
    return " | ".join(p for p in parts if p)[:400]


def redact(text: str, secret: str) -> str:
    """`text` with every copy of `secret` replaced by ***."""
    return text.replace(secret, "***") if secret else text


def status_of(exc: BaseException) -> "int | None":
    for obj in (exc, getattr(exc, "response", None)):
        for attr in ("status", "status_code"):
            value = getattr(obj, attr, None) if obj is not None else None
            if isinstance(value, int):
                return value
    return None


def is_transient(exc: BaseException) -> bool:
    """True for failures a second attempt can fix: timeouts, connection errors,
    HTTP 408 / 429 / 5xx. False for 401/403 (auth or WAF block), other 4xx,
    and anything unrecognised (fail closed without a retry)."""
    status = status_of(exc)
    if status is not None:
        return status in (408, 429) or 500 <= status <= 599
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    name = type(exc).__name__.lower()
    return "timeout" in name or "connecterror" in name or "connectionerror" in name


def backoff_seconds(exc: BaseException, retry_backoff: float) -> float:
    """The wait before the retry: a short server Retry-After (retry_after_ms,
    at most RETRY_AFTER_CAP_S) when it is longer than the backoff, else the backoff."""
    after_ms = getattr(exc, "retry_after_ms", None)
    if isinstance(after_ms, (int, float)) and 0 <= after_ms / 1000.0 <= RETRY_AFTER_CAP_S:
        return max(retry_backoff, after_ms / 1000.0)
    return retry_backoff


def noul_criteria(question: Mapping[str, Any]) -> Dict[str, str]:
    """The `criteria` of a noul question as {"true": text, "false": text}
    (either may be absent), or {} when the question has none. Any other key
    is an error: the SDK's NoulCriteria accepts only true and false."""
    raw = question.get("criteria")
    if raw is None or raw == {}:
        return {}
    if not isinstance(raw, Mapping):
        raise ProviderError("noul criteria must be an object with the keys true and/or false")
    unknown = [k for k in raw if k not in ("true", "false")]
    if unknown:
        raise ProviderError(f"noul criteria accepts only the keys true and false, not {', '.join(map(str, unknown))}")
    return {k: str(v) for k, v in raw.items() if v is not None and str(v).strip()}


def question_fields(question: Mapping[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """(type, fields) of one semgate question, in wire order (instructions,
    then criteria). A noul carries criteria only when the policy sets them, so
    other questions are unchanged. Choice and score always carry criteria."""
    qtype = question.get("type", "noul")
    instructions = question["instructions"]
    if qtype == "noul":
        crit = noul_criteria(question)
        return qtype, ({"instructions": instructions, "criteria": crit} if crit else {"instructions": instructions})
    if qtype == "choice":
        return qtype, {"instructions": instructions, "criteria": question.get("criteria") or {}}
    if qtype == "score":
        return qtype, {"instructions": instructions, "criteria": question.get("criteria") or []}
    raise ProviderError(f"unsupported question type: {qtype}")


# OpenRouter's Decisions endpoint rejects a noul whose criteria has one side
# only (HTTP 400). The missing side is filled with the complement of the given
# side: this fixed prefix, then the given text word for word. Complement, not
# antonym: noul "false" means "the true description does not apply". A fixed
# prefix keeps the fill deterministic (the same policy gives the same bytes in
# every run) and never rewrites the policy author's text; an automatic
# negation of free text could turn its meaning around.
MISSING_SIDE_PREFIX = "This does not apply: "


def both_sides(criteria: Mapping[str, str]) -> Dict[str, str]:
    """Noul criteria with both keys, true first. A missing side is
    MISSING_SIDE_PREFIX + the given side's text. {} stays {}."""
    if not criteria:
        return {}
    true, false = criteria.get("true"), criteria.get("false")
    if true is None:
        true = MISSING_SIDE_PREFIX + str(false)
    if false is None:
        false = MISSING_SIDE_PREFIX + str(true)
    return {"true": true, "false": false}
