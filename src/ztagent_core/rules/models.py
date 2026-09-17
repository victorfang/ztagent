# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Canonical, vendor-neutral ZTAgent Rule IR and pack metadata."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

GuardrailStage = Literal["model_input", "model_output", "tool_input", "tool_output"]
RuleAction = Literal["log", "block", "contain"]
RuleSeverity = Literal["low", "medium", "high", "critical"]
RuleEngine = Literal["regex", "phrase"]


class RuleDefinition(BaseModel):
    """One declarative rule in the canonical ZTAgent Rule IR."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,127}$")
    description: str = Field(min_length=1, max_length=500)
    stages: tuple[GuardrailStage, ...] = Field(min_length=1, max_length=4)
    engine: RuleEngine = "regex"
    pattern: str = Field(min_length=1, max_length=2_000)
    category: str = Field(default="prompt-injection", min_length=1, max_length=100)
    severity: RuleSeverity = "high"
    action: RuleAction = "block"
    score: StrictInt = Field(default=80, ge=0, le=100)
    enabled: StrictBool = True
    case_sensitive: StrictBool = False
    timeout_ms: StrictInt | None = Field(default=None, ge=1, le=1_000)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("stages")
    @classmethod
    def unique_stages(
        cls, stages: tuple[GuardrailStage, ...]
    ) -> tuple[GuardrailStage, ...]:
        if len(stages) != len(set(stages)):
            raise ValueError("rule stages must be unique")
        return stages

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, metadata: dict[str, str]) -> dict[str, str]:
        if len(metadata) > 20:
            raise ValueError("rule metadata is limited to 20 entries")
        if any(len(key) > 100 or len(value) > 500 for key, value in metadata.items()):
            raise ValueError("rule metadata key or value is too long")
        return metadata


class RuleDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    rules: tuple[RuleDefinition, ...] = Field(min_length=1, max_length=500)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_schema_version(cls, version: object) -> object:
        if type(version) is not int:
            raise ValueError("schema_version must be integer 1")
        return version

    @field_validator("rules")
    @classmethod
    def unique_rule_ids(cls, rules: tuple[RuleDefinition, ...]) -> tuple[RuleDefinition, ...]:
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule IDs must be unique within a document")
        return rules


class PackCompatibility(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    core: str = Field(default=">=0.1,<1", min_length=1, max_length=100)
    rule_ir: Literal[1] = 1

    @field_validator("rule_ir", mode="before")
    @classmethod
    def exact_rule_ir_version(cls, version: object) -> object:
        if type(version) is not int:
            raise ValueError("rule_ir must be integer 1")
        return version


class PackContent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["rules", "tests", "documentation"] = "rules"


class PackManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?$")
    publisher: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,63}$")
    description: str = Field(min_length=1, max_length=500)
    license: str = Field(min_length=1, max_length=100)
    compatibility: PackCompatibility = PackCompatibility()
    contents: tuple[PackContent, ...] = Field(min_length=1, max_length=100)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_schema_version(cls, version: object) -> object:
        if type(version) is not int:
            raise ValueError("schema_version must be integer 1")
        return version

    @field_validator("contents")
    @classmethod
    def unique_content_paths(cls, contents: tuple[PackContent, ...]) -> tuple[PackContent, ...]:
        paths = [item.path for item in contents]
        if len(paths) != len(set(paths)):
            raise ValueError("pack content paths must be unique")
        if len(paths) != len({path.casefold() for path in paths}):
            raise ValueError("pack content paths must be case-insensitively unique")
        return contents


class PackSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["ztagent-pack-signature-v1"]
    key_id: str = Field(pattern=r"^[a-zA-Z0-9._-]{1,100}$")
    algorithm: Literal["ed25519"]
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature: str = Field(min_length=40, max_length=200)


class TrustStore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    keys: dict[str, str] = Field(min_length=1, max_length=50)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_schema_version(cls, version: object) -> object:
        if type(version) is not int:
            raise ValueError("schema_version must be integer 1")
        return version


class GuardrailContext(BaseModel):
    """Trusted execution context supplied to guardrail engines."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: GuardrailStage
    content: str
    request_id: str | None = None
    subject: str | None = None
    resource: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)


class LoadedPack(BaseModel):
    """Validated pack provenance and canonical rules."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: PackManifest
    digest: str
    signed: StrictBool
    signer_key_id: str | None = None
    rules: tuple[RuleDefinition, ...]
