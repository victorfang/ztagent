"""Configuration loader with secure defaults and environment overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, SecretStr, ValidationError


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    environment: Literal["development", "test", "production"] = "development"
    max_body_bytes: int = Field(default=262_144, ge=1024)
    admin_roles: list[str] = ["msa-admin"]


class AuthConfig(BaseModel):
    enabled: bool = True
    issuer: str = "https://identity.example/realms/agents"
    audience: str = "mini-secure-agent"
    jwks_url: str = "https://identity.example/realms/agents/protocol/openid-connect/certs"
    algorithms: list[str] = ["RS256"]
    role_claim: str = "realm_access.roles"
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    max_token_chars: int = Field(default=16_384, ge=256, le=65_536)


class ProviderConfig(BaseModel):
    kind: Literal["openai", "anthropic", "openai-compatible"] = "openai"
    model: str = "gpt-5-mini"
    allowed_models: list[str] = []
    base_url: str | None = None
    api_key_env: str | None = None
    timeout_seconds: float = Field(default=60, gt=0, le=300)
    max_output_tokens: int = Field(default=1024, ge=1, le=32_768)

    def api_key(self) -> SecretStr:
        variable = (
            self.api_key_env
            or {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "openai-compatible": "OPENAI_API_KEY",
            }[self.kind]
        )
        value = os.getenv(variable)
        if not value:
            raise RuntimeError(f"Required environment variable {variable} is not set")
        return SecretStr(value)


class PolicyConfig(BaseModel):
    opa_url: str = "http://127.0.0.1:8181"
    decision_path: str = "mini_secure_agent/authz/allow"
    timeout_seconds: float = Field(default=2, gt=0, le=30)
    fail_open: bool = False
    development_allow_without_opa: bool = False


class GuardrailConfig(BaseModel):
    signatures_file: Path = Path("config/signatures.yaml")
    regex_timeout_ms: int = Field(default=50, ge=1, le=1000)
    max_prompt_chars: int = Field(default=100_000, ge=100)
    block_score: int = Field(default=80, ge=1)


class AuditConfig(BaseModel):
    path: Path = Path("data/audit.jsonl")
    hmac_key_env: str = "MSA_AUDIT_HMAC_KEY"
    log_prompt_content: bool = False


class AnomalyConfig(BaseModel):
    enabled: bool = True
    state_backend: Literal["memory", "sqlite"] = "sqlite"
    sqlite_path: Path = Path("data/state.db")
    requests_per_24h: int = Field(default=1000, ge=1)
    blocked_events_per_24h: int = Field(default=5, ge=1)


class ContainmentConfig(BaseModel):
    enabled: bool = True
    blocklist_path: Path = Path("data/blocked_identities.json")
    webhook_url: str | None = None
    keycloak_admin_url: str | None = None
    keycloak_realm: str | None = None
    keycloak_token_env: str = "KEYCLOAK_ADMIN_TOKEN"


class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    auth: AuthConfig = AuthConfig()
    provider: ProviderConfig = ProviderConfig()
    policy: PolicyConfig = PolicyConfig()
    guardrails: GuardrailConfig = GuardrailConfig()
    audit: AuditConfig = AuditConfig()
    anomaly: AnomalyConfig = AnomalyConfig()
    containment: ContainmentConfig = ContainmentConfig()

    def validate_security(self) -> None:
        if self.server.environment == "production":
            errors: list[str] = []
            if not self.auth.enabled:
                errors.append("authentication cannot be disabled")
            if not self.auth.algorithms or any(
                algorithm.startswith("HS") or algorithm.lower() == "none"
                for algorithm in self.auth.algorithms
            ):
                errors.append("JWT algorithms must be asymmetric and explicitly configured")
            if urlparse(self.auth.issuer).scheme != "https":
                errors.append("OIDC issuer must use HTTPS")
            if urlparse(self.auth.jwks_url).scheme != "https":
                errors.append("OIDC JWKS URL must use HTTPS")
            if self.policy.fail_open or self.policy.development_allow_without_opa:
                errors.append("OPA must fail closed")
            if self.server.host == "0.0.0.0" and not self.auth.enabled:
                errors.append("public binding requires authentication")
            if errors:
                raise ValueError("Unsafe production configuration: " + "; ".join(errors))


def _env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply MSA_SECTION__FIELD values without putting secrets in YAML."""
    for key, value in os.environ.items():
        if not key.startswith("MSA_") or "__" not in key:
            continue
        section, field = key[4:].lower().split("__", 1)
        if section not in AppConfig.model_fields:
            continue
        parsed: Any
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError:
            parsed = value
        data.setdefault(section, {})[field] = parsed
    return data


def load_config(path: str | Path | None = None) -> AppConfig:
    selected_path = path if path is not None else os.getenv("MSA_CONFIG") or "config/agent.yaml"
    config_path = Path(selected_path)
    raw: dict[str, Any] = {}
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if loaded is not None and not isinstance(loaded, dict):
            raise ValueError("Configuration root must be a mapping")
        raw = loaded or {}
    try:
        config = AppConfig.model_validate(_env_overrides(raw))
    except ValidationError as exc:
        raise ValueError(f"Invalid configuration: {exc}") from exc
    config.validate_security()
    return config
