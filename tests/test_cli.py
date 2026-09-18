# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

import os
from pathlib import Path

import pytest
import uvicorn
from typer.testing import CliRunner

from ztagent_core.cli import app


def test_serve_propagates_selected_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "custom.yaml"
    config.write_text(
        "server:\n  host: 127.0.0.1\n  port: 9123\n"
        "auth:\n  enabled: false\n"
        "policy:\n  development_allow_without_opa: true\n"
        f"guardrails:\n  signatures_file: {Path('config/signatures.yaml').resolve()}\n"
    )
    called: dict[str, object] = {}

    def fake_run(*args: object, **kwargs: object) -> None:
        called.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    result = CliRunner().invoke(app, ["serve", "--config", str(config)])

    assert result.exit_code == 0
    assert os.environ["ZTAGENT_CONFIG"] == str(config.resolve())
    assert called["port"] == 9123


def test_live_demo_rejects_opa_development_bypass() -> None:
    result = CliRunner().invoke(
        app,
        ["demo", "article-only", "--live", "--config", "config/agent.yaml"],
    )

    assert result.exit_code != 0
    assert "require fail-closed OPA" in result.output
