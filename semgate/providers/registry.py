"""The live Jev providers by name, for every entry point (CLI, hooks, serve,
HTTP gate, Python API, exposure check): one place that maps a name to a
provider, so a new transport is added once.

  typesafe    TypeSafe 1P API through typesafe-sdk (TYPESAFE_API_KEY), model jev-latest
  openrouter  OpenRouter Decisions API, stdlib HTTP (OPENROUTER_API_KEY), model typesafe/jev-1.13

`model` None (or "") means the provider's own default. semgate.json may set
`judge_model`; without it a hook uses the default above.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .base import JudgeProvider

LIVE = ("typesafe", "openrouter")
DEFAULT_MODELS = {"typesafe": "jev-latest", "openrouter": "typesafe/jev-1.13"}


def live_provider(name: str, model: Optional[str] = None) -> JudgeProvider:
    """A live provider. Raises ValueError for another name and ProviderError
    when the provider cannot start (e.g. typesafe-sdk not installed)."""
    if name == "typesafe":
        from .typesafe import TypeSafeProvider
        return TypeSafeProvider(model=model) if model else TypeSafeProvider()
    if name == "openrouter":
        from .openrouter import OpenRouterDecisionsProvider
        return OpenRouterDecisionsProvider(model=model) if model else OpenRouterDecisionsProvider()
    raise ValueError(f"unknown live provider {name!r}; use one of {', '.join(LIVE)}")


def _unwrap(provider: Any) -> Any:
    seen = 0
    while provider is not None and getattr(provider, "inner", None) is not None and seen < 5:
        provider, seen = provider.inner, seen + 1     # eval wrappers (_Recorder, _Guarded) keep the real one in .inner
    return provider


def provider_model(provider: Any) -> str:
    """The model id a provider sends ("" for fake, recorded, none)."""
    for p in (provider, _unwrap(provider)):
        model = getattr(p, "model", None) if p is not None else None
        if isinstance(model, str) and model:
            return model
    return ""


def report_fields(provider: Any) -> Dict[str, Any]:
    """Fields an eval report adds for its provider: the model id, and the
    usage totals (calls, tokens, cost) when the provider counts them."""
    out: Dict[str, Any] = {"model": provider_model(provider)}
    real = _unwrap(provider)
    usage = getattr(real, "usage_report", None)
    if callable(usage):
        out["provider_usage"] = usage()
    return out
