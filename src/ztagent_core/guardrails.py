# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Backward-compatible signatures backed by the canonical staged Rule IR."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from .config import GuardrailConfig
from .models import Detection
from .rules.engine import GuardrailSet
from .rules.models import (
    GuardrailContext,
    GuardrailStage,
    LoadedPack,
    PackContent,
    PackManifest,
    RuleDefinition,
)
from .rules.packs import RulePackLoader


class Signature(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    description: str
    pattern: str
    category: str = "prompt-injection"
    severity: Literal["low", "medium", "high", "critical"] = "high"
    action: Literal["log", "block", "contain"] = "block"
    score: int = Field(default=80, ge=0, le=100)
    enabled: bool = True
    stages: tuple[GuardrailStage, ...] = (
        "model_input",
        "tool_input",
        "tool_output",
    )


class SignatureFile(BaseModel):
    version: int = 1
    signatures: list[Signature]


class SignatureScanner:
    def __init__(
        self,
        signatures: list[Signature],
        timeout_ms: int = 50,
        *,
        additional_packs: list[LoadedPack] | None = None,
        legacy_digest: str | None = None,
        evaluation_budget_ms: int = 200,
        max_active_rules: int = 2_000,
    ) -> None:
        rules = tuple(
            RuleDefinition(
                id=rule.id,
                description=rule.description,
                stages=rule.stages,
                engine="regex",
                pattern=rule.pattern,
                category=rule.category,
                severity=rule.severity,
                action=rule.action,
                score=rule.score,
                enabled=rule.enabled,
            )
            for rule in signatures
        )
        digest = legacy_digest or hashlib.sha256(
            "\n".join(rule.model_dump_json() for rule in rules).encode()
        ).hexdigest()
        legacy_pack = LoadedPack(
            manifest=PackManifest(
                name="local.legacy-signatures",
                version="1.0.0",
                publisher="local",
                description="Backward-compatible signatures.yaml rules",
                license="project-local",
                contents=(
                    PackContent(path="signatures.yaml", sha256="0" * 64, kind="rules"),
                ),
            ),
            digest=digest,
            signed=False,
            rules=rules,
        )
        self._guardrails = GuardrailSet.compile(
            [legacy_pack, *(additional_packs or [])],
            default_timeout_ms=timeout_ms,
            evaluation_budget_ms=evaluation_budget_ms,
            max_active_rules=max_active_rules,
        )

    @property
    def rule_count(self) -> int:
        return self._guardrails.rule_count

    @property
    def packs(self) -> tuple[LoadedPack, ...]:
        return self._guardrails.packs

    @classmethod
    def from_file(cls, path: Path, timeout_ms: int = 50) -> SignatureScanner:
        return cls.from_sources(path, timeout_ms=timeout_ms)

    @classmethod
    def from_sources(
        cls,
        path: Path,
        *,
        timeout_ms: int = 50,
        packs: list[LoadedPack] | None = None,
        evaluation_budget_ms: int = 200,
        max_active_rules: int = 2_000,
    ) -> SignatureScanner:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            rules = SignatureFile.model_validate(raw)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise ValueError(f"Cannot load signature rules from {path}: {exc}") from exc
        return cls(
            rules.signatures,
            timeout_ms,
            additional_packs=packs,
            legacy_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
            evaluation_budget_ms=evaluation_budget_ms,
            max_active_rules=max_active_rules,
        )

    def scan(self, text: str) -> list[Detection]:
        return self.inspect("model_input", text)

    def inspect(
        self,
        stage: GuardrailStage,
        text: str,
        *,
        request_id: str | None = None,
        subject: str | None = None,
        resource: dict[str, object] | None = None,
    ) -> list[Detection]:
        return self._guardrails.inspect(
            GuardrailContext(
                stage=stage,
                content=text,
                request_id=request_id,
                subject=subject,
                resource=resource or {},
            )
        )


def load_guardrail_scanner(config: GuardrailConfig) -> SignatureScanner:
    """Load one immutable legacy-plus-pack rule snapshot from configuration."""
    packs: list[LoadedPack] = []
    for source in config.packs:
        if not source.path.exists() and not source.required:
            continue
        packs.append(
            RulePackLoader(
                trust_store=config.trust_store,
                require_signature=config.require_signed_packs or source.require_signature,
            ).load(source.path, source.signature)
        )
    return SignatureScanner.from_sources(
        config.signatures_file,
        timeout_ms=config.regex_timeout_ms,
        packs=packs,
        evaluation_budget_ms=config.evaluation_budget_ms,
        max_active_rules=config.max_active_rules,
    )
