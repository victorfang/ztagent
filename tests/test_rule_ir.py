# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import pytest
from pydantic import ValidationError

from ztagent_core.rules import GuardrailContext, GuardrailSet, LoadedPack
from ztagent_core.rules.models import PackContent, PackManifest, RuleDefinition


def pack_with(rule: RuleDefinition) -> LoadedPack:
    return LoadedPack(
        manifest=PackManifest(
            name="security",
            version="1.0.0",
            publisher="test",
            description="Rule IR test pack",
            license="Apache-2.0",
            contents=(PackContent(path="rules.yaml", sha256="0" * 64),),
        ),
        digest="1" * 64,
        signed=False,
        rules=(rule,),
    )


def test_rule_ir_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        RuleDefinition.model_validate(
            {
                "id": "test.security.rule",
                "description": "Test",
                "stages": ["model_input"],
                "pattern": "unsafe",
                "script": "execute-me",
            }
        )


def test_rule_ir_rejects_duplicate_stages() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        RuleDefinition(
            id="test.security.rule",
            description="Test",
            stages=("tool_input", "tool_input"),
            pattern="unsafe",
        )


def test_rule_only_runs_at_declared_stage() -> None:
    guardrails = GuardrailSet.compile(
        [
            pack_with(
                RuleDefinition(
                    id="test.security.rule",
                    description="Tool-only test",
                    stages=("tool_input",),
                    engine="phrase",
                    pattern="unsafe",
                )
            )
        ]
    )

    assert (
        guardrails.inspect(GuardrailContext(stage="model_input", content="unsafe"))
        == []
    )
    assert guardrails.inspect(GuardrailContext(stage="tool_input", content="unsafe"))


def test_regex_timeout_fails_closed() -> None:
    guardrails = GuardrailSet.compile(
        [
            pack_with(
                RuleDefinition(
                    id="test.security.regex-timeout",
                    description="Expensive expression",
                    stages=("model_input",),
                    pattern=r"(?:a|aa)+$",
                    timeout_ms=1,
                )
            )
        ]
    )

    findings = guardrails.inspect(
        GuardrailContext(stage="model_input", content=("a" * 20_000) + "!")
    )

    assert findings[0].category == "guardrail-error"
    assert findings[0].action == "block"
