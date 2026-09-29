"""Thin adapter over the vendor's public Python SDK (typesafe-sdk).

We deliberately do NOT reimplement transport, model selection or question
batching: TypeSafe already supplies those layers. This file translates
semgate questions into SDK calls and answers back.

Retries are the one exception. typesafe-sdk 0.7.0 retries by default (up to 2
retries, 30 s budget per call). A hook runs inside the host's own hook
timeout, and a hook that times out is not a decision, so semgate owns the
retry instead: the SDK's retry is switched off (RetryPolicy(max_retries=0)
when the SDK has it) and `evaluate` retries exactly once, after a short
backoff, and only on a transient failure (timeout, connection error, HTTP 408,
429 or 5xx). 401/403 (auth, or the Cloudflare WAF block) and other 4xx are
never retried. Worst case: two attempts instead of the SDK's three.

`pip install semgate` installs the SDK (pinned in pyproject.toml). It is
imported lazily, so the deterministic layers and the fake provider run with
no key and no network. Set TYPESAFE_API_KEY to use this.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Mapping

from . import keys
from .base import Answers, JudgeProvider, PredicateAnswer, ProviderError
from .common import (RETRY_AFTER_CAP_S, RETRY_BACKOFF_S, backoff_seconds, is_transient, noul_criteria,  # noqa: F401
                     question_fields, redact, shorten, status_of)


# The TypeSafe API root (typesafe_sdk.constants.DEFAULT_BASE_URL in 0.7.1).
# Passed to the SDK explicitly, so TYPESAFE_BASE_URL in the environment is
# not used (_key_kwargs).
BASE_URL = "https://api.typesafe.ai"

# Shared with the OpenRouter transport (providers/common.py); the old names stay.
_short = shorten
_status = status_of


class TypeSafeProvider(JudgeProvider):
    name = "typesafe"

    def __init__(self, model: str = "jev-latest", *, retry_backoff: float = RETRY_BACKOFF_S, sleep=time.sleep):
        self.model = model
        self.retry_backoff = float(retry_backoff)
        self._sleep = sleep
        self.retries = 0               # count of retries this provider made (for telemetry and tests)
        # Usage over this provider's life (eval reports: provider_usage). Read
        # from the SDK response only; the request is not changed.
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.served_models: Dict[str, int] = {}
        self._key_hint = ""
        # One lookup for every provider (keys.find_key): SEMGATE_TYPESAFE_API_KEY,
        # ~/.semgate/.env, the checkout .env, then TYPESAFE_API_KEY from the
        # environment. The key goes to the SDK client as api_key=...; it is
        # never copied into os.environ, so child processes do not inherit it.
        self._api_key, self._key_source = keys.find_key("TYPESAFE_API_KEY")
        try:
            import typesafe_sdk  # noqa: F401
        except ImportError as exc:
            raise ProviderError(
                "typesafe-sdk cannot be imported; the semgate install is incomplete. "
                "Run: pip install --force-reinstall semgate"
            ) from exc
        self._sdk = typesafe_sdk
        # typesafe-sdk < 0.7.1 can echo the API key inside exception text (fixed
        # upstream in 0.7.1: "exclude the value from logged exceptions"). Our
        # ProviderError text reaches the ledger and telemetry, so strip it here
        # regardless of SDK version.
        self._secret = os.environ.get("TYPESAFE_API_KEY", "")

    def _redact(self, text: str) -> str:
        return redact(text, self._secret)

    def _client(self):
        """A client with the SDK's own retry off, so the one retry in
        `evaluate` is the only one. Older or stub SDKs without RetryPolicy
        get a plain client."""
        policy_cls = getattr(self._sdk, "RetryPolicy", None)
        if policy_cls is not None:
            try:
                return self._sdk.TypeSafeClient(retry=policy_cls(max_retries=0), **self._key_kwargs())
            except TypeError:
                pass
        return self._sdk.TypeSafeClient(**self._key_kwargs())

    def _key_kwargs(self) -> Dict[str, str]:
        """api_key for the SDK client when semgate found one (else nothing, so
        the SDK raises its own "no API key" error: fail closed), and the API
        root always. The SDK reads TYPESAFE_BASE_URL from the environment when
        no base_url is given: a variable of the agent host's environment
        could then send every question, and the key, to another server that
        answers "allow". semgate passes the SDK's own default explicitly."""
        consts = getattr(self._sdk, "constants", None)
        out = {"base_url": str(getattr(consts, "DEFAULT_BASE_URL", "") or BASE_URL)}
        if self._api_key:
            out["api_key"] = self._api_key
        return out

    def _backoff(self, exc: BaseException) -> float:
        return backoff_seconds(exc, self.retry_backoff)

    def _note_usage(self, response: Any) -> None:
        self.calls += 1
        usage = getattr(response, "usage", None)
        for attr in ("input_tokens", "output_tokens"):
            value = getattr(usage, attr, None)
            if isinstance(value, int) and not isinstance(value, bool):
                setattr(self, attr, getattr(self, attr) + value)
        served = getattr(response, "model", None)
        if isinstance(served, str) and served:
            self.served_models[served] = self.served_models.get(served, 0) + 1

    def usage_report(self) -> Dict[str, Any]:
        """Totals for an eval report: calls, tokens and the model ids that
        answered (TypeSafe reports no cost per call)."""
        return {"calls": self.calls, "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "served_models": dict(sorted(self.served_models.items())), "retries": self.retries}

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        sdk = self._sdk
        sdk_questions: Dict[str, Any] = {}
        builders = {"noul": sdk.Noul, "choice": sdk.Choice, "score": sdk.Score}
        for qid, q in questions.items():
            # The same fields the OpenRouter transport sends (common.question_fields).
            # A noul carries criteria (typesafe-sdk 0.7.0: Noul(criteria={"true":
            # ..., "false": ...})) only when the policy sets them.
            qtype, fields = question_fields(q)
            sdk_questions[qid] = builders[qtype](**fields)
        response = None
        for attempt in (1, 2):
            try:
                with self._client() as client:
                    response = client.system_one(state=dict(state), questions=sdk_questions, model=self.model)
                break
            except Exception as exc:  # transport, auth, timeout, rate limit: all abstain upstream
                if attempt == 1 and is_transient(exc):
                    self.retries += 1
                    self._sleep(self._backoff(exc))
                    continue
                hint = self._key_hint if "API key" in str(exc) else ""
                raise ProviderError(f"typesafe call failed: {type(exc).__name__}: {_short(self._redact(str(exc)))}{hint}") from exc

        self._note_usage(response)
        # The model id the response names (TypeSafe answers with the model that
        # served the call); the judge records it on the judgment.
        served_model = getattr(response, "model", None)
        answers: Dict[str, PredicateAnswer] = Answers(served={"model": served_model} if isinstance(served_model, str) else {})
        for qid, q in questions.items():
            answer = response.answers.get(qid)
            if answer is None:
                raise ProviderError(f"missing answer for question '{qid}'")
            if q.get("type", "noul") == "noul":
                probability = float(answer.noul)
                answers[qid] = PredicateAnswer(
                    predicate_id=qid,
                    probability=probability,
                    confidence=abs(probability - 0.5) * 2.0,
                    raw={"source": "typesafe"},
                )
            else:
                answers[qid] = PredicateAnswer(
                    predicate_id=qid,
                    value=getattr(answer, "choice", getattr(answer, "score", None)),
                    confidence=getattr(answer, "confidence", None),
                    raw={"source": "typesafe", "probabilities": {str(k): float(v) for k, v in dict(getattr(answer, "probabilities", None) or {}).items()}},
                )
        return answers
