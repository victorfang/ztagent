import os
from pathlib import Path

import pytest
import uvicorn
from typer.testing import CliRunner

from mini_secure_agent.cli import app


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
    assert os.environ["MSA_CONFIG"] == str(config.resolve())
    assert called["port"] == 9123
