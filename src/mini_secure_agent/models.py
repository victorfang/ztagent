# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Shared, provider-neutral data models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

Role = Literal["system", "user", "assistant", "tool"]


class Message(BaseModel):
    role: Role
    content: str = Field(min_length=1, max_length=100_000)


class Principal(BaseModel):
    subject: str
    roles: frozenset[str] = frozenset()
    claims: dict[str, Any] = Field(default_factory=dict)


class AgentRequest(BaseModel):
    messages: list[Message] = Field(min_length=1, max_length=100)
    model: str | None = None
    tools: list[str] = Field(default_factory=list, max_length=32)
    metadata: dict[str, str] = Field(default_factory=dict)


class AgentResponse(BaseModel):
    request_id: str
    output: str
    model: str
    provider: str


class Detection(BaseModel):
    rule_id: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    action: Literal["log", "block", "contain"]
    score: int = Field(default=0, ge=0, le=100)
    detail: str


class Decision(BaseModel):
    allowed: bool
    reason: str
    decision_id: str | None = None


class SecurityEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    outcome: str
    subject: str | None = None
    request_id: str | None = None
    source_ip: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
