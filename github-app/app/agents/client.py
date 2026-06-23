"""Bounded Gemini calls with sanitized, product-safe failure reporting."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TypeVar

from google import genai
from google.genai import types as genai_types
from pydantic import BaseModel, ValidationError

from app.config import get_settings

logger = logging.getLogger(__name__)
OutputT = TypeVar("OutputT", bound=BaseModel)


class AIProviderError(RuntimeError):
    """Sanitized provider error safe to persist and show to users."""

    def __init__(self, code: str, *, model: str | None = None, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.model = model
        self.retryable = retryable


@dataclass
class AIBudget:
    total_seconds: float
    started_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.started_at:
            self.started_at = time.monotonic()

    def remaining(self) -> float:
        return max(0.0, self.total_seconds - (time.monotonic() - self.started_at))


def _classify_error(exc: Exception, model: str) -> AIProviderError:
    if isinstance(exc, AIProviderError):
        return exc
    if isinstance(exc, ValidationError):
        return AIProviderError("AI_INVALID_OUTPUT", model=model, retryable=True)

    status = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if status == 429 or "resource_exhausted" in message or "rate limit" in message:
        return AIProviderError("AI_RATE_LIMIT", model=model, retryable=True)
    if status in (401, 403) or "permission_denied" in message or "api key" in message:
        return AIProviderError("AI_AUTH", model=model, retryable=False)
    if status == 404 or "not_found" in message:
        return AIProviderError("AI_MODEL_UNAVAILABLE", model=model, retryable=True)
    if status in (500, 502, 503, 504) or "unavailable" in message:
        return AIProviderError("AI_UNAVAILABLE", model=model, retryable=True)
    if "timeout" in name or "timeout" in message or "deadline" in message:
        return AIProviderError("AI_TIMEOUT", model=model, retryable=True)
    if isinstance(exc, RuntimeError):
        return AIProviderError("AI_INVALID_OUTPUT", model=model, retryable=True)
    return AIProviderError("AI_PROVIDER_ERROR", model=model, retryable=False)


def get_client(timeout_seconds: float | None = None) -> genai.Client:
    settings = get_settings()
    timeout = timeout_seconds or settings.gemini_timeout_seconds
    return genai.Client(
        api_key=settings.gemini_api_key,
        http_options=genai_types.HttpOptions(timeout=max(1, int(timeout * 1000))),
    )


def generate_structured(
    *,
    response_model: type[OutputT],
    system_instruction: str,
    user_message: str,
    thinking_level: str,
    max_output_tokens: int,
    budget: AIBudget,
) -> tuple[OutputT, str]:
    """Call the primary model, then a bounded fallback for retryable failures."""
    settings = get_settings()
    models = [settings.gemini_model]
    if settings.gemini_fallback_model and settings.gemini_fallback_model not in models:
        models.append(settings.gemini_fallback_model)

    last_error: AIProviderError | None = None
    for model in models:
        remaining = budget.remaining()
        if remaining <= 0:
            raise AIProviderError("AI_TIMEOUT", model=model, retryable=True)
        timeout = min(float(settings.gemini_timeout_seconds), remaining)
        try:
            thinking_config = (
                genai_types.ThinkingConfig(thinking_level=thinking_level)
                if model.startswith("gemini-3")
                else genai_types.ThinkingConfig(thinking_budget=0)
            )
            client = get_client(timeout)
            response = client.models.generate_content(
                model=model,
                contents=[
                    genai_types.Content(
                        role="user",
                        parts=[genai_types.Part(text=user_message)],
                    ),
                ],
                config=genai_types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    response_json_schema=response_model.model_json_schema(),
                    thinking_config=thinking_config,
                    max_output_tokens=max_output_tokens,
                ),
            )
            try:
                raw = response.text or ""
            except RuntimeError as exc:
                raise AIProviderError("AI_INVALID_OUTPUT", model=model, retryable=True) from exc
            if not raw:
                raise AIProviderError("AI_INVALID_OUTPUT", model=model, retryable=True)
            return response_model.model_validate_json(raw), model
        except Exception as exc:
            error = _classify_error(exc, model)
            last_error = error
            logger.warning(
                "Gemini call failed code=%s model=%s type=%s retryable=%s",
                error.code,
                model,
                type(exc).__name__,
                error.retryable,
            )
            if not error.retryable:
                break

    raise last_error or AIProviderError("AI_PROVIDER_ERROR")
