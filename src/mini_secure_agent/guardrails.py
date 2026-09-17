# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Deterministic signature guardrails for prompts and tool arguments."""

from __future__ import annotations

import unicodedata
from pathlib import Path
from typing import Literal

import regex
import yaml
from pydantic import BaseModel, Field

from .models import Detection


class Signature(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    description: str
    pattern: str
    category: str = "prompt-injection"
    severity: Literal["low", "medium", "high", "critical"] = "high"
    action: Literal["log", "block", "contain"] = "block"
    score: int = Field(default=80, ge=0, le=100)
    enabled: bool = True


class SignatureFile(BaseModel):
    version: int = 1
    signatures: list[Signature]


class SignatureScanner:
    def __init__(self, signatures: list[Signature], timeout_ms: int = 50) -> None:
        self.timeout_seconds = timeout_ms / 1000
        self._signatures = [
            (rule, regex.compile(rule.pattern, regex.IGNORECASE | regex.MULTILINE))
            for rule in signatures
            if rule.enabled
        ]

    @property
    def rule_count(self) -> int:
        return len(self._signatures)

    @classmethod
    def from_file(cls, path: Path, timeout_ms: int = 50) -> SignatureScanner:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules = SignatureFile.model_validate(raw)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise ValueError(f"Cannot load signature rules from {path}: {exc}") from exc
        return cls(rules.signatures, timeout_ms)

    def scan(self, text: str) -> list[Detection]:
        normalized = unicodedata.normalize("NFKC", text)
        findings: list[Detection] = []
        for rule, pattern in self._signatures:
            try:
                matched = pattern.search(normalized, timeout=self.timeout_seconds)
            except TimeoutError:
                findings.append(
                    Detection(
                        rule_id=rule.id,
                        category="guardrail-error",
                        severity="high",
                        action="block",
                        score=100,
                        detail="Signature evaluation timed out; fail-closed",
                    )
                )
                continue
            if matched:
                findings.append(
                    Detection(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        action=rule.action,
                        score=rule.score,
                        detail=rule.description,
                    )
                )
        return findings
