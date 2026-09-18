# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

import pytest
from pydantic import BaseModel, Field, ValidationError

from ztagent_core.tools import ToolRegistry, ToolSpec


class AddArguments(BaseModel):
    left: int = Field(ge=0, le=10)
    right: int = Field(ge=0, le=10)


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
