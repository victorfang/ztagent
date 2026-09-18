# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import pytest
from pydantic import BaseModel, Field, ValidationError

from ztagent_core.tools import ToolRegistry, ToolSpec


class AddArguments(BaseModel):
    left: int = Field(ge=0, le=10)
    right: int = Field(ge=0, le=10)


class OtherArguments(BaseModel):
    pass


@pytest.mark.asyncio
async def test_tool_arguments_are_schema_validated() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="add",
            description="Add bounded numbers",
            arguments=AddArguments,
            handler=lambda args: args.left + args.right,  # type: ignore[attr-defined]
            risk="low",
        )
    )

    assert await registry.execute("add", {"left": 2, "right": 3}) == 5
    with pytest.raises(ValidationError):
        await registry.execute("add", {"left": 200, "right": 3})


def test_policy_context_is_derived_from_validated_arguments() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="add",
            description="Add bounded numbers",
            arguments=AddArguments,
            handler=lambda args: args.left + args.right,  # type: ignore[attr-defined]
            risk="low",
            policy_context=lambda args: {  # type: ignore[attr-defined]
                "total": args.left + args.right,
                "classification": "non-sensitive",
            },
        )
    )

    validated = registry.validate("add", {"left": 2, "right": 3})

    assert registry.policy_context("add", validated) == {
        "total": 5,
        "classification": "non-sensitive",
    }


@pytest.mark.asyncio
async def test_execute_validated_rejects_wrong_argument_model() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="add",
            description="Add bounded numbers",
            arguments=AddArguments,
            handler=lambda args: args.left + args.right,  # type: ignore[attr-defined]
        )
    )

    with pytest.raises(TypeError, match="must be AddArguments"):
        await registry.execute_validated("add", OtherArguments())
