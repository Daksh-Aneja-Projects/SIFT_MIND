from __future__ import annotations

import json
import urllib.error
import unittest
from unittest.mock import patch

from sift_mind.contracts import ModelConfig
from sift_mind.model_provider import ModelProviderError, OllamaClient, OpenAICompatibleClient, build_model_client


class _FakeResponse:
    def __init__(self, body: dict):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.body


class ModelProviderTests(unittest.TestCase):
    def test_ollama_response_includes_metadata(self) -> None:
        body = {
            "response": json.dumps({"status": "ok"}),
            "total_duration": 10,
            "eval_count": 3,
        }
        with patch("urllib.request.urlopen", return_value=_FakeResponse(body)):
            result = OllamaClient(ModelConfig(model="primary", fallback_model="fallback")).generate_json("hi")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["_metadata"]["model"], "primary")
        self.assertFalse(result["_metadata"]["fallback_used"])

    def test_ollama_uses_fallback_after_primary_failure(self) -> None:
        body = {"response": json.dumps({"status": "ok"})}
        calls = [urllib.error.URLError("primary failed"), _FakeResponse(body)]

        def fake_urlopen(*args, **kwargs):
            item = calls.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = OllamaClient(ModelConfig(model="primary", fallback_model="fallback")).generate_json("hi")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["_metadata"]["model"], "fallback")
        self.assertTrue(result["_metadata"]["fallback_used"])

    def test_ollama_raises_when_all_models_fail(self) -> None:
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(ModelProviderError):
                OllamaClient(ModelConfig(model="primary", fallback_model="fallback")).generate_json("hi")

    def test_openai_compatible_requires_api_key(self) -> None:
        config = ModelConfig(provider="openai-compatible", model="cloud-model", host="https://example.test/v1", api_key_env="SIFT_TEST_KEY")
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ModelProviderError):
                OpenAICompatibleClient(config).generate_json("hi")

    def test_openai_compatible_parses_json_and_metadata(self) -> None:
        body = {
            "model": "cloud-model",
            "choices": [{"message": {"content": json.dumps({"status": "ok"})}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            return _FakeResponse(body)

        config = ModelConfig(provider="openai-compatible", model="cloud-model", host="https://example.test/v1", api_key_env="SIFT_TEST_KEY")
        secret_value = "secret" + "-value"
        with patch.dict("os.environ", {"SIFT_TEST_KEY": secret_value}, clear=True):
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                result = OpenAICompatibleClient(config).generate_json("hi")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["_metadata"]["provider"], "openai-compatible")
        self.assertEqual(result["_metadata"]["total_tokens"], 7)
        self.assertEqual(captured["url"], "https://example.test/v1/chat/completions")
        self.assertEqual(captured["authorization"], "Bearer " + secret_value)

    def test_build_model_client_rejects_unknown_provider(self) -> None:
        with self.assertRaises(ModelProviderError):
            build_model_client(ModelConfig(provider="mystery"))


if __name__ == "__main__":
    unittest.main()
