# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Immutable staged evaluator for canonical ZTAgent rules."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from time import monotonic

import regex

from ..models import Detection
from .models import GuardrailContext, LoadedPack, RuleDefinition


@dataclass(frozen=True)
class _CompiledRule:
    definition: RuleDefinition
    expression: regex.Pattern[str]
    pack: str
    pack_version: str
    pack_digest: str
    default_timeout_seconds: float


class GuardrailSet:
    """A request-safe immutable snapshot of compiled rules and provenance."""

    def __init__(
        self,
        rules: tuple[_CompiledRule, ...],
        packs: tuple[LoadedPack, ...],
        evaluation_budget_ms: int,
    ) -> None:
        self._rules = rules
        self.packs = packs
        self._evaluation_budget_seconds = evaluation_budget_ms / 1_000

    @classmethod
    def compile(
        cls,
        packs: list[LoadedPack],
        *,
        default_timeout_ms: int = 50,
        evaluation_budget_ms: int = 200,
        max_active_rules: int = 2_000,
    ) -> GuardrailSet:
        seen: dict[str, str] = {}
        compiled: list[_CompiledRule] = []
        for pack in packs:
            for rule in pack.rules:
                if rule.id in seen:
                    raise ValueError(
                        f"Duplicate rule ID {rule.id!r} in packs "
                        f"{seen[rule.id]!r} and {pack.manifest.name!r}"
                    )
                seen[rule.id] = pack.manifest.name
                if not rule.enabled:
                    continue
                source = regex.escape(rule.pattern) if rule.engine == "phrase" else rule.pattern
                flags = regex.MULTILINE
                if not rule.case_sensitive:
                    flags |= regex.IGNORECASE
                try:
                    expression = regex.compile(source, flags)
                except regex.error as exc:
                    raise ValueError(f"Invalid rule regex {rule.id!r}: {exc}") from exc
                compiled.append(
                    _CompiledRule(
                        definition=rule,
                        expression=expression,
                        pack=pack.manifest.name,
                        pack_version=pack.manifest.version,
                        pack_digest=pack.digest,
                        default_timeout_seconds=default_timeout_ms / 1_000,
                    )
                )
                if len(compiled) > max_active_rules:
                    raise ValueError(
                        f"Active guardrail count exceeds configured limit of {max_active_rules}"
                    )
        return cls(tuple(compiled), tuple(packs), evaluation_budget_ms)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def inspect(self, context: GuardrailContext) -> list[Detection]:
        normalized = unicodedata.normalize("NFKC", context.content)
        findings: list[Detection] = []
        deadline = monotonic() + self._evaluation_budget_seconds
        for compiled in self._rules:
            rule = compiled.definition
            if context.stage not in rule.stages:
                continue
            remaining = deadline - monotonic()
            if remaining <= 0:
                findings.append(self._budget_finding(context))
                break
            timeout = (
                rule.timeout_ms / 1_000
                if rule.timeout_ms is not None
                else compiled.default_timeout_seconds
            )
            timeout = min(timeout, remaining)
            try:
                matched = compiled.expression.search(normalized, timeout=timeout)
            except TimeoutError:
                findings.append(
                    self._finding(
                        compiled,
                        context,
                        category="guardrail-error",
                        severity="high",
                        action="block",
                        score=100,
                        detail="Rule evaluation timed out; fail-closed",
                    )
                )
                if monotonic() >= deadline:
                    break
                continue
            if matched:
                findings.append(
                    self._finding(
                        compiled,
                        context,
                        category=rule.category,
                        severity=rule.severity,
                        action=rule.action,
                        score=rule.score,
                        detail=rule.description,
                    )
                )
        return findings

    def scan(self, text: str) -> list[Detection]:
        """Backward-compatible shorthand for model-input inspection."""
        return self.inspect(GuardrailContext(stage="model_input", content=text))

    @staticmethod
    def _finding(
        compiled: _CompiledRule,
        context: GuardrailContext,
        *,
        category: str,
        severity: str,
        action: str,
        score: int,
        detail: str,
    ) -> Detection:
        return Detection.model_validate(
            {
                "rule_id": compiled.definition.id,
                "category": category,
                "severity": severity,
                "action": action,
                "score": score,
                "detail": detail,
                "stage": context.stage,
                "pack": compiled.pack,
                "pack_version": compiled.pack_version,
                "pack_digest": compiled.pack_digest,
            }
        )

    @staticmethod
    def _budget_finding(context: GuardrailContext) -> Detection:
        return Detection(
            rule_id="ztagent.guardrail-evaluation-budget",
            category="guardrail-error",
            severity="high",
            action="block",
            score=100,
            detail="Aggregate guardrail evaluation budget exhausted; fail-closed",
            stage=context.stage,
            pack="ztagent-core",
        )
