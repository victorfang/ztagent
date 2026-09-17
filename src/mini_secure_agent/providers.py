# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Small provider abstraction for hosted and OpenAI-compatible model APIs."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from .config import ProviderConfig
from .models import Message


class ProviderError(RuntimeError):
    pass


class ModelProvider(Protocol):
    name: str

    async def generate(self, messages: list[Message], model: str | None = None) -> tuple[str, str]:
        """Return output text and effective model."""
        ...


class HTTPModelProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.name: str = config.kind

    async def generate(self, messages: list[Message], model: str | None = None) -> tuple[str, str]:
        effective_model = model or self.config.model
        allowed = self.config.allowed_models or [self.config.model]
        if effective_model not in allowed:
            raise ProviderError(f"Model {effective_model!r} is not allowed")
        try:
            if any(message.role == "tool" for message in messages):
                raise ProviderError(
                    "Tool-result messages require provider-specific call identifiers"
                )
            key = self.config.api_key().get_secret_value()
            headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
            if self.config.kind == "anthropic":
                headers = {
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                }
                url, payload = self._anthropic_request(messages, effective_model)
            elif self.config.kind == "openai-compatible":
                url, payload = self._chat_request(messages, effective_model)
            else:
                url, payload = self._openai_request(messages, effective_model)
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
            output = self._extract(data)
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, RuntimeError) as exc:
            raise ProviderError(f"Provider request failed: {type(exc).__name__}") from exc
        if not output:
            raise ProviderError("Provider returned no text output")
        return output, effective_model

    def _openai_request(self, messages: list[Message], model: str) -> tuple[str, dict[str, Any]]:
        base = self.config.base_url or "https://api.openai.com/v1"
        return f"{base.rstrip('/')}/responses", {
            "model": model,
            "input": [message.model_dump() for message in messages],
            "max_output_tokens": self.config.max_output_tokens,
            "store": False,
        }

    def _chat_request(self, messages: list[Message], model: str) -> tuple[str, dict[str, Any]]:
        if not self.config.base_url:
            raise ProviderError("base_url is required for an OpenAI-compatible provider")
        return f"{self.config.base_url.rstrip('/')}/chat/completions", {
            "model": model,
            "messages": [message.model_dump() for message in messages],
            "max_tokens": self.config.max_output_tokens,
        }

    def _anthropic_request(self, messages: list[Message], model: str) -> tuple[str, dict[str, Any]]:
        base = self.config.base_url or "https://api.anthropic.com/v1"
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in {"user", "assistant"}
        ]
        payload: dict[str, Any] = {
            "model": model,
            "messages": turns,
            "max_tokens": self.config.max_output_tokens,
        }
        if system:
            payload["system"] = system
        return f"{base.rstrip('/')}/messages", payload

    def _extract(self, data: dict[str, Any]) -> str:
        if self.config.kind == "anthropic":
            return "".join(
                str(block.get("text", ""))
                for block in data["content"]
                if block.get("type") == "text"
            )
        if self.config.kind == "openai-compatible":
            content = data["choices"][0]["message"]["content"]
            if not isinstance(content, str):
                raise TypeError("Provider returned non-text content")
            return content
        chunks: list[str] = []
        for item in data["output"]:
            if item.get("type") != "message":
                continue
            for block in item.get("content", []):
                if block.get("type") in {"output_text", "text"}:
                    chunks.append(str(block.get("text", "")))
        return "".join(chunks)
