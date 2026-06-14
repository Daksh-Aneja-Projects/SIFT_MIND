"""LLM provider abstraction.

The forensic pipeline never depends on a specific model vendor. Local Ollama is
the default for development; a cloud provider can implement this same interface.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from .contracts import ModelConfig


class ModelProviderError(RuntimeError):
    pass


class ModelResponse(dict):
    """JSON response with model/provider metadata attached."""

    @property
    def metadata(self) -> dict[str, Any]:
        return self.get("_metadata", {})


class ModelClient(ABC):
    @abstractmethod
    def generate_json(self, prompt: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def summarize(self, prompt: str) -> str:
        result = self.generate_json(
            "Respond as JSON with a single key named summary.\n\n" + prompt,
            {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
        )
        return str(result.get("summary", ""))


class OllamaClient(ModelClient):
    def __init__(self, config: ModelConfig):
        self.config = config

    def generate_json(self, prompt: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
        errors: list[str] = []
        for model in self._candidate_models():
            try:
                return self._generate_with_model(model, prompt, schema)
            except ModelProviderError as exc:
                errors.append(f"{model}: {exc}")
        raise ModelProviderError("All Ollama model attempts failed: " + " | ".join(errors))

    def _candidate_models(self) -> list[str]:
        models = [self.config.model]
        if self.config.fallback_model and self.config.fallback_model not in models:
            models.append(self.config.fallback_model)
        return models

    def _generate_with_model(self, model: str, prompt: str, schema: dict[str, Any] | None = None) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt + "\n\nReturn only valid JSON.",
            "stream": False,
            "format": schema or "json",
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.max_context_tokens,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.config.host.rstrip('/')}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelProviderError(f"Ollama request failed: {exc}") from exc
        try:
            parsed = json.loads(body.get("response", "{}"))
        except json.JSONDecodeError as exc:
            raise ModelProviderError("Ollama returned non-JSON content") from exc
        result = ModelResponse(parsed)
        result["_metadata"] = {
            "provider": "ollama",
            "model": model,
            "fallback_used": model != self.config.model,
            "total_duration_ns": body.get("total_duration", 0),
            "load_duration_ns": body.get("load_duration", 0),
            "prompt_eval_count": body.get("prompt_eval_count", 0),
            "eval_count": body.get("eval_count", 0),
        }
        return result


class OpenAICompatibleClient(ModelClient):
    """Cloud client for OpenAI-compatible chat-completions APIs."""

    def __init__(self, config: ModelConfig):
        self.config = config

    def generate_json(self, prompt: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
        api_key = os.environ.get(self.config.api_key_env, "")
        if not api_key:
            raise ModelProviderError(
                f"Cloud API key is not set. Configure env var {self.config.api_key_env} "
                "or use SIFT_MIND_MODEL_PROVIDER=ollama."
            )
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are SIFT-MIND's bounded JSON reasoning component. Return only valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
        }
        if schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "sift_mind_response",
                    "schema": schema,
                    "strict": False,
                },
            }
        else:
            payload["response_format"] = {"type": "json_object"}

        request = urllib.request.Request(
            f"{self.config.host.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = _safe_http_error(exc)
            raise ModelProviderError(f"Cloud model request failed: HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise ModelProviderError(f"Cloud model request failed: {exc}") from exc

        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelProviderError("Cloud model response did not include choices[0].message.content") from exc
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ModelProviderError("Cloud model returned non-JSON content") from exc
        result = ModelResponse(parsed)
        usage = body.get("usage", {})
        result["_metadata"] = {
            "provider": self.config.provider,
            "model": body.get("model", self.config.model),
            "fallback_used": False,
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        }
        return result


CloudModelClient = OpenAICompatibleClient


def _safe_http_error(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    return body[:500]


def build_model_client(config: ModelConfig) -> ModelClient:
    provider = config.provider.lower()
    if provider == "ollama":
        return OllamaClient(config)
    if provider in {"openai-compatible", "openai", "cloud"}:
        return OpenAICompatibleClient(config)
    raise ModelProviderError(f"Unknown model provider: {config.provider}")
