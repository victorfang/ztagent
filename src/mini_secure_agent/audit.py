"""Append-only, HMAC-chained JSONL audit trail with secret redaction."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .models import SecurityEvent

_SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "password",
    "prompt",
    "token",
    "access_token",
    "refresh_token",
}


def redact(value: Any, log_prompt_content: bool = False) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = key.lower()
            if normalized in _SENSITIVE_KEYS and not (
                normalized == "prompt" and log_prompt_content
            ):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(item, log_prompt_content)
        return result
    if isinstance(value, list):
        return [redact(item, log_prompt_content) for item in value]
    return value


class AuditLog:
    def __init__(self, path: Path, key: bytes, log_prompt_content: bool = False) -> None:
        if len(key) < 32:
            raise ValueError("Audit HMAC key must be at least 32 bytes")
        self.path = path
        self.key = key
        self.log_prompt_content = log_prompt_content
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._tail_digest = self._load_tail_digest()

    @classmethod
    def from_env(cls, path: Path, key_env: str, log_prompt_content: bool = False) -> AuditLog:
        value = os.getenv(key_env)
        if not value:
            raise RuntimeError(
                f"{key_env} is required; generate one with `msa secret` and store it securely"
            )
        return cls(path, value.encode(), log_prompt_content)

    def append(self, event: SecurityEvent) -> None:
        record = redact(event.model_dump(mode="json"), self.log_prompt_content)
        with self._lock:
            previous = self._tail_digest
            body = json.dumps(record, sort_keys=True, separators=(",", ":"))
            digest = hmac.new(self.key, f"{previous}.{body}".encode(), hashlib.sha256).hexdigest()
            envelope = {"previous": previous, "event": record, "digest": digest}
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(envelope, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._tail_digest = digest

    def read(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as stream:
            lines = deque((line for line in stream if line.strip()), maxlen=limit)
        return [json.loads(line) for line in lines]

    def verify(self) -> tuple[bool, int]:
        previous = "GENESIS"
        count = 0
        for envelope in self._records():
            body = json.dumps(envelope["event"], sort_keys=True, separators=(",", ":"))
            expected = hmac.new(self.key, f"{previous}.{body}".encode(), hashlib.sha256).hexdigest()
            if (
                not hmac.compare_digest(expected, str(envelope.get("digest", "")))
                or envelope.get("previous") != previous
            ):
                return False, count
            previous = expected
            count += 1
        return True, count

    def _load_tail_digest(self) -> str:
        last = "GENESIS"
        for envelope in self._records():
            last = str(envelope.get("digest", ""))
        return last

    def _records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line)
