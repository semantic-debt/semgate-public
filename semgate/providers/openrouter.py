"""Jev through OpenRouter's Decisions endpoint (alpha).

POST https://openrouter.ai/api/alpha/decisions with the same body TypeSafe's
/v1/systemone takes, {"state", "model", "questions"}, and the same answer
shapes (noul, choice, score). Auth: `Authorization: Bearer <OpenRouter key>`.
The response adds `id`, `provider` and `usage.cost` (USD).

Same behavior as TypeSafeProvider (providers/typesafe.py):
- the same question fields (common.question_fields), so the judge input is
  the same, with one difference: OpenRouter answers HTTP 400 when a noul's
  criteria has one side only, so the missing side is filled
  (common.both_sides). No shipped policy has a one-sided noul, so for them
  the questions are identical.
- one retry after a short backoff, only on a transient failure (timeout,
  connection error, HTTP 408, 429, 5xx); 401, 402, 403, other 4xx and
  malformed answers are never retried. Two attempts at most.
- 10 s timeout per attempt (the typesafe-sdk default).
- every failure is a ProviderError (the judge abstains -> ask). The API key
  is removed from every error text, and a ProviderError's cause chain holds
  only semgate's own error objects (no urllib error, no request headers).

Standard library only (urllib.request): no new dependency. HTTPS_PROXY /
NO_PROXY work through urllib's default ProxyHandler; TLS certificates and the
host name are verified (ssl.create_default_context). Redirects are not
followed: a redirect is an error, so the Authorization header never goes to
another address.

The key: OPENROUTER_API_KEY from the environment, else from ~/.semgate/.env or
the source checkout's .env (providers/keys.py, the same places as
TYPESAFE_API_KEY). The provider does not put the key into os.environ.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Mapping, Optional

from . import keys
from .base import Answers, JudgeProvider, PredicateAnswer, ProviderError
from .common import RETRY_BACKOFF_S, backoff_seconds, both_sides, is_transient, question_fields, redact, shorten

DEFAULT_BASE_URL = "https://openrouter.ai/api/alpha"
DECISIONS_PATH = "/decisions"
# Pinned snapshot family, so eval runs are reproducible. "~typesafe/jev-latest"
# follows the newest Jev; "typesafe/jev-1.13-20260917" is the dated snapshot.
DEFAULT_MODEL = "typesafe/jev-1.13"
DEFAULT_TIMEOUT_S = 10.0          # = typesafe-sdk DEFAULT_TIMEOUT, per attempt
MAX_RESPONSE_BYTES = 1 << 20      # a Decisions answer is a few hundred bytes
KEY_ENV = keys.KEY_ENV["openrouter"]


class _Secret:
    """Holds the key. repr/str never show it (tracebacks with locals, debuggers)."""

    __slots__ = ("value",)

    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return "<secret>" if self.value else "<no key>"

    __str__ = __repr__


class OpenRouterError(Exception):
    """A failed Decisions call. The text never holds the key."""


class OpenRouterHTTPError(OpenRouterError):
    def __init__(self, status: int, text: str, retry_after_ms: Optional[float] = None) -> None:
        super().__init__(text)
        self.status = status
        self.retry_after_ms = retry_after_ms


class OpenRouterConnectionError(OpenRouterError, ConnectionError):
    """No HTTP response (refused, reset, DNS, proxy): transient."""


class OpenRouterTimeoutError(OpenRouterError, TimeoutError):
    """No answer within the timeout: transient."""


class OpenRouterTLSError(OpenRouterError):
    """The server certificate failed verification: never retried."""


class OpenRouterResponseError(OpenRouterError):
    """HTTP 2xx with a body that is not a valid Decisions answer: never retried."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None        # urllib then raises HTTPError(3xx): not transient, not followed


def _check_base_url(base_url: str) -> str:
    """https, or http to this machine only (the tests' local server)."""
    url = base_url.rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname:
        host = parts.hostname
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if loopback:
            return url
    raise ValueError("the OpenRouter base URL must be https (http only for localhost)")


def _retry_after_ms(headers: Any) -> Optional[float]:
    for name, factor in (("retry-after-ms", 1.0), ("retry-after", 1000.0)):
        raw = headers.get(name) if headers is not None else None
        if raw is None:
            continue
        try:
            value = float(str(raw).strip())
        except ValueError:
            continue           # an HTTP date: not a short wait, use the backoff
        if math.isfinite(value) and value >= 0:
            return value * factor
    return None


def _error_message(body: bytes) -> str:
    """The server's message: {"error": {"message": ...}} (OpenRouter), else
    {"error": str} / {"message": str} / {"detail": str}, else the text."""
    text = body.decode("utf-8", errors="replace").strip()
    try:
        doc = json.loads(text)
    except ValueError:
        return text
    if isinstance(doc, dict):
        err = doc.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return err["message"]
        for k in ("error", "message", "detail"):
            if isinstance(doc.get(k), str):
                return doc[k]
    return text


def _number(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


class OpenRouterDecisionsProvider(JudgeProvider):
    name = "openrouter"

    def __init__(self, model: str = DEFAULT_MODEL, *, api_key: Optional[str] = None,
                 base_url: str = DEFAULT_BASE_URL, timeout: float = DEFAULT_TIMEOUT_S,
                 retry_backoff: float = RETRY_BACKOFF_S, sleep=time.sleep) -> None:
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty OpenRouter model id, e.g. typesafe/jev-1.13")
        if not (_number(timeout) and timeout > 0):
            raise ValueError("timeout must be a positive number of seconds")
        self.model = model.strip()
        self.base_url = _check_base_url(base_url)
        self.timeout = float(timeout)
        self.retry_backoff = float(retry_backoff)
        self._sleep = sleep
        self.retries = 0               # count of retries this provider made (for telemetry and tests)
        if api_key is None:
            api_key, _ = keys.find_key(KEY_ENV)
        self._key = _Secret(str(api_key or "").strip())
        # Usage over this provider's life (eval reports: provider_usage).
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.cost = 0.0
        self.served_models: Dict[str, int] = {}
        self.last_response: Dict[str, Any] = {}

    # ---------------------------------------------------------------- request

    @property
    def url(self) -> str:
        return self.base_url + DECISIONS_PATH

    @staticmethod
    def wire_questions(questions: Mapping[str, Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """{"type", "instructions", "criteria"?} per question: the fields TypeSafe
        gets (common.question_fields), a one-sided noul criteria filled."""
        out: Dict[str, Dict[str, Any]] = {}
        for qid, q in questions.items():
            qtype, fields = question_fields(q)
            if qtype == "noul" and "criteria" in fields:
                fields = {**fields, "criteria": both_sides(fields["criteria"])}
            out[qid] = {"type": qtype, **fields}
        return out

    def request_body(self, state: Mapping[str, Any], questions: Mapping[str, Mapping[str, Any]]) -> bytes:
        """The exact bytes sent: {"state", "model", "questions"} in the order and
        compact form typesafe-sdk uses, UTF-8, no ASCII escaping."""
        body = {"state": dict(state), "model": self.model, "questions": self.wire_questions(questions)}
        try:
            return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ProviderError(f"openrouter request could not be encoded as JSON: {type(exc).__name__}") from None

    def _headers(self) -> Dict[str, str]:
        from .. import __version__
        return {"Authorization": "Bearer " + self._key.value, "Content-Type": "application/json",
                "Accept": "application/json", "User-Agent": f"semgate/{__version__}"}

    @staticmethod
    def _opener() -> urllib.request.OpenerDirector:
        # Built per call: the ProxyHandler reads HTTPS_PROXY / NO_PROXY when it is made.
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                                           _NoRedirect())

    def _post(self, body: bytes) -> Dict[str, Any]:
        """One attempt. Raises only OpenRouterError subclasses, raised outside
        any `except` block, so they carry no urllib error as context."""
        request = urllib.request.Request(self.url, data=body, headers=self._headers(), method="POST")
        err: Optional[OpenRouterError] = None
        raw = b""
        try:
            with self._opener().open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            try:
                detail = _error_message(exc.read(64 * 1024) or b"") or (exc.reason or "")
            except Exception:
                detail = str(exc.reason or "")
            finally:
                exc.close()
            err = OpenRouterHTTPError(exc.code, self._clean(f"{exc.code} {detail}".strip()), _retry_after_ms(exc.headers))
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError):
                err = OpenRouterTimeoutError(f"request timed out (timeout={self.timeout:g})")
            elif isinstance(reason, ssl.SSLCertVerificationError):
                err = OpenRouterTLSError(self._clean(f"TLS certificate verification failed: {reason}"))
            else:
                err = OpenRouterConnectionError(self._clean(f"connection error: {reason}"))
        except TimeoutError:
            err = OpenRouterTimeoutError(f"request timed out (timeout={self.timeout:g})")
        except ssl.SSLCertVerificationError as exc:
            err = OpenRouterTLSError(self._clean(f"TLS certificate verification failed: {exc}"))
        except (OSError, http.client.HTTPException) as exc:
            err = OpenRouterConnectionError(self._clean(f"connection error: {type(exc).__name__}: {exc}"))
        if err is not None:
            raise err
        if len(raw) > MAX_RESPONSE_BYTES:
            raise OpenRouterResponseError(f"response larger than {MAX_RESPONSE_BYTES} bytes")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except ValueError:
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("answers"), dict):
            raise OpenRouterResponseError(self._clean("response is not a Decisions answer: " + raw[:200].decode("utf-8", "replace")))
        return doc

    def _key_problem(self) -> str:
        value = self._key.value
        if not value:
            return f"no API key: set {KEY_ENV} or put {KEY_ENV}=... in ~/.semgate/.env"
        if not value.isascii() or not value.isprintable() or " " in value:
            return f"{KEY_ENV} must contain only printable ASCII characters without whitespace"
        return ""

    def _clean(self, text: str) -> str:
        return shorten(redact(text, self._key.value))

    # ---------------------------------------------------------------- evaluate

    def _fail(self, exc: BaseException) -> ProviderError:
        err = ProviderError(f"openrouter call failed: {type(exc).__name__}: {self._clean(str(exc))}")
        err.__cause__ = exc.with_traceback(None)
        err.__suppress_context__ = True
        return err

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        body = self.request_body(state, questions)
        problem = self._key_problem()      # no local holds the key: this frame is in the ProviderError traceback
        if problem:
            raise ProviderError(f"openrouter call failed: {problem}")
        doc: Dict[str, Any] = {}
        failure: Optional[ProviderError] = None
        for attempt in (1, 2):
            try:
                doc = self._post(body)
                break
            except OpenRouterError as exc:  # transport, auth, credits, timeout, rate limit: all abstain upstream
                if attempt == 1 and is_transient(exc):
                    self.retries += 1
                    self._sleep(backoff_seconds(exc, self.retry_backoff))
                    continue
                failure = self._fail(exc)
                break
        if failure is not None:
            raise failure
        self._note_usage(doc)
        return self._answers(questions, doc)

    def _note_usage(self, doc: Mapping[str, Any]) -> None:
        usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
        self.calls += 1
        for attr, field in (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")):
            if _number(usage.get(field)):
                setattr(self, attr, getattr(self, attr) + int(usage[field]))
        if _number(usage.get("cost")):
            self.cost += float(usage["cost"])
        served = doc.get("model")
        if isinstance(served, str) and served:
            self.served_models[served] = self.served_models.get(served, 0) + 1
        self.last_response = {"id": doc.get("id") if isinstance(doc.get("id"), str) else "",
                              "provider": doc.get("provider") if isinstance(doc.get("provider"), str) else "",
                              "model": served if isinstance(served, str) else "",
                              "usage": {k: usage[k] for k in ("input_tokens", "output_tokens", "cost") if _number(usage.get(k))}}

    def usage_report(self) -> Dict[str, Any]:
        """Totals for an eval report: calls, tokens, cost (USD, as OpenRouter
        reports it) and the model ids that answered."""
        return {"calls": self.calls, "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cost": round(self.cost, 8), "served_models": dict(sorted(self.served_models.items())),
                "retries": self.retries}

    def _answers(self, questions: Mapping[str, Mapping[str, Any]], doc: Mapping[str, Any]) -> Dict[str, PredicateAnswer]:
        got = doc["answers"]
        # Who answered, as the response says: the served model id (a dated id
        # such as typesafe/jev-1.13-20260917, not always the requested one) and
        # the upstream provider. The judge records both on the judgment.
        served = {"model": doc.get("model"), "upstream": doc.get("provider")}
        answers: Dict[str, PredicateAnswer] = Answers(served={k: v for k, v in served.items() if isinstance(v, str)})
        for qid, q in questions.items():
            answer = got.get(qid)
            if answer is None:
                raise ProviderError(f"missing answer for question '{qid}'")
            qtype = q.get("type", "noul")
            if not isinstance(answer, dict) or answer.get("type") != qtype:
                raise ProviderError(f"openrouter answer for question '{qid}' is not a {qtype} answer")
            if qtype == "noul":
                p = answer.get("noul")
                if not _number(p) or not 0.0 <= p <= 1.0:
                    raise ProviderError(f"openrouter answer for question '{qid}' has no noul probability in [0, 1]")
                probability = float(p)
                answers[qid] = PredicateAnswer(predicate_id=qid, probability=probability,
                                               confidence=abs(probability - 0.5) * 2.0, raw={"source": "openrouter"})
                continue
            value = answer.get("choice") if qtype == "choice" else answer.get("score")
            if (qtype == "choice" and not isinstance(value, str)) or (qtype == "score" and not _number(value)):
                raise ProviderError(f"openrouter answer for question '{qid}' has no {qtype} value")
            confidence = answer.get("confidence")
            probs = answer.get("probabilities") or {}
            if (confidence is not None and not _number(confidence)) or not isinstance(probs, dict) \
                    or not all(_number(v) for v in probs.values()):
                raise ProviderError(f"openrouter answer for question '{qid}' is malformed")
            answers[qid] = PredicateAnswer(
                predicate_id=qid, value=value,
                confidence=float(confidence) if confidence is not None else None,
                raw={"source": "openrouter", "probabilities": {str(k): float(v) for k, v in probs.items()}})
        return answers
