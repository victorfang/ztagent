from pathlib import Path

import pytest

from mini_secure_agent.config import AppConfig, load_config


def test_production_rejects_disabled_authentication() -> None:
    config = AppConfig()
    config.server.environment = "production"
    config.auth.enabled = False

    with pytest.raises(ValueError, match="authentication cannot be disabled"):
        config.validate_security()


def test_environment_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text("server:\n  port: 8000\n")
    monkeypatch.setenv("MSA_SERVER__PORT", "9000")

    assert load_config(path).server.port == 9000
