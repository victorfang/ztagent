"""Friendly command-line setup and operations."""

from __future__ import annotations

import secrets
from pathlib import Path

import typer

from .config import load_config
from .guardrails import SignatureScanner
from .templates import (
    APP_TEMPLATE,
    COMPOSE_TEMPLATE,
    CONFIG_TEMPLATE,
    ENV_TEMPLATE,
    REGO_TEMPLATE,
    SIGNATURES_TEMPLATE,
)

app = typer.Typer(
    name="msa",
    help="Set up and operate a lean secure AI agent gateway.",
    no_args_is_help=True,
)


@app.command()
def init(
    directory: Path = typer.Argument(Path("."), help="Project directory"),
    force: bool = typer.Option(False, "--force", help="Replace generated files"),
) -> None:
    """Create a ready-to-customize secure agent project."""
    files = {
        "config/agent.yaml": CONFIG_TEMPLATE,
        "config/signatures.yaml": SIGNATURES_TEMPLATE,
        "policies/authz.rego": REGO_TEMPLATE,
        "app.py": APP_TEMPLATE,
        ".env.example": ENV_TEMPLATE,
        "compose.yaml": COMPOSE_TEMPLATE,
    }
    directory.mkdir(parents=True, exist_ok=True)
    conflicts = [name for name in files if (directory / name).exists() and not force]
    if conflicts:
        typer.echo("Setup stopped; files already exist:")
        for name in conflicts:
            typer.echo(f"  - {name}")
        raise typer.Exit(1)
    for name, content in files.items():
        destination = directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        typer.echo(f"  created {destination}")
    typer.secho("\nMini Secure Agent is ready.", fg=typer.colors.GREEN, bold=True)
    typer.echo("1. Copy .env.example to .env and set provider credentials.")
    typer.echo("2. Replace its audit key with the output of: msa secret")
    typer.echo("3. Start OPA: docker compose up -d")
    typer.echo("4. Run: msa serve")
    typer.echo("5. Open: http://127.0.0.1:8000/admin")


@app.command()
def secret() -> None:
    """Generate a strong audit-chain HMAC key."""
    typer.echo(secrets.token_urlsafe(48))


@app.command()
def check(
    config: Path = typer.Option(Path("config/agent.yaml"), "--config", "-c"),
) -> None:
    """Validate configuration and security signature rules."""
    loaded = load_config(config)
    rules = SignatureScanner.from_file(
        loaded.guardrails.signatures_file, loaded.guardrails.regex_timeout_ms
    )
    rule_count = rules.rule_count
    warnings: list[str] = []
    if not loaded.auth.enabled:
        warnings.append("authentication is disabled")
    if loaded.policy.development_allow_without_opa:
        warnings.append("OPA development bypass is enabled")
    typer.secho(f"Configuration valid; {rule_count} signatures loaded.", fg=typer.colors.GREEN)
    for warning in warnings:
        typer.secho(f"WARNING: {warning}", fg=typer.colors.YELLOW)


@app.command()
def serve(
    config: Path = typer.Option(Path("config/agent.yaml"), "--config", "-c"),
    reload: bool = typer.Option(False, help="Reload on source changes (development only)"),
) -> None:
    """Run the API gateway and administration portal."""
    import uvicorn

    loaded = load_config(config)
    if reload:
        typer.echo("Reload mode uses app:create_app only when MSA_CONFIG points to your config.")
    uvicorn.run(
        "mini_secure_agent.api:create_app",
        factory=True,
        host=loaded.server.host,
        port=loaded.server.port,
        reload=reload,
    )
