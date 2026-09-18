# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""Explicitly registered, schema-validated tools for use by any orchestrator."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel

ToolHandler = Callable[[BaseModel], Any | Awaitable[Any]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments: type[BaseModel]
    handler: ToolHandler
    risk: Literal["low", "medium", "high"] = "medium"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.arguments.model_json_schema(),
            "risk": self.risk,
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ValueError(f"Unknown or disabled tool {name!r}") from exc

    def schemas(self, allowed: list[str] | None = None) -> list[dict[str, Any]]:
        names = allowed if allowed is not None else list(self._tools)
        return [self.get(name).schema() for name in names]

    async def execute(self, name: str, raw_arguments: dict[str, Any]) -> Any:
        spec = self.get(name)
        arguments = spec.arguments.model_validate(raw_arguments)
        result = spec.handler(arguments)
        if inspect.isawaitable(result):
            return await result
        return result
