# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""Friendly command-line setup and operations."""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path
from typing import cast

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
    name="ztagent",
    help="Set up and operate ZTAgent Core. Never trust an agent action. Verify before execution.",
    no_args_is_help=True,
)


@app.command()
def init(
    directory: Path = typer.Argument(Path("."), help="Project directory"),
    force: bool = typer.Option(False, "--force", help="Replace generated files"),
) -> None:
    """Create a ready-to-customize ZTAgent project."""
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
    typer.secho("\nZTAgent Core is ready.", fg=typer.colors.GREEN, bold=True)
    typer.echo("1. Copy .env.example to .env and set provider credentials.")
    typer.echo("2. Replace its audit key with the output of: ztagent secret")
    typer.echo("3. Start OPA: docker compose up -d")
    typer.echo("4. Run: ztagent serve")
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
def demo(
    scenario: str = typer.Argument(
        "stock-injection",
        help="stock-injection, unauthorized-publish, or article-only",
    ),
    mode: str = typer.Option("both", help="before, after, or both"),
    config: Path = typer.Option(Path("config/agent.yaml"), "--config", "-c"),
    data_dir: Path = typer.Option(Path("data/demos"), help="Sandbox output directory"),
    live: bool = typer.Option(False, help="Use the configured OpenAI API instead of fixtures"),
    privileged: bool = typer.Option(
        False, help="Simulate the role mapping required for publishing"
    ),
) -> None:
    """Contrast an intentionally vulnerable LangChain agent with the secured version."""
    from .demos.runner import DemoMode, DemoScenario, create_demo_runner

    scenarios = {"stock-injection", "unauthorized-publish", "article-only"}
    modes = {"before", "after", "both"}
    if scenario not in scenarios:
        raise typer.BadParameter(f"scenario must be one of: {', '.join(sorted(scenarios))}")
    if mode not in modes:
        raise typer.BadParameter("mode must be before, after, or both")
    loaded = load_config(config)
    if live and loaded.provider.kind != "openai":
        raise typer.BadParameter("live demos currently require provider.kind: openai")
    if live and (loaded.policy.fail_open or loaded.policy.development_allow_without_opa):
        raise typer.BadParameter(
            "live demos require fail-closed OPA; disable policy development bypasses"
        )
    selected_modes = ["before", "after"] if mode == "both" else [mode]
    typer.secho(
        "DEMO SAFETY: all email, DM, and social delivery stays in a local JSONL sandbox.",
        fg=typer.colors.YELLOW,
    )
    for selected in selected_modes:
        runner = create_demo_runner(
            loaded,
            data_dir / selected,
            offline=not live,
            privileged=privileged,
        )
        result = asyncio.run(
            runner.run(
                cast("DemoMode", selected),
                cast("DemoScenario", scenario),
            )
        )
        color = (
            typer.colors.RED
            if result.status == "completed" and selected == "before"
            else (typer.colors.GREEN)
        )
        typer.secho(f"\n{selected.upper()}: {result.status.upper()}", fg=color, bold=True)
        typer.echo(result.explanation)
        if result.model_output:
            typer.echo(f"Model output: {result.model_output}")
        typer.echo(f"Sandbox deliveries: {len(result.outbox)}")
        if selected == "after":
            typer.echo("Controls: " + ", ".join(result.controls))


@app.command()
def serve(
    config: Path = typer.Option(Path("config/agent.yaml"), "--config", "-c"),
    reload: bool = typer.Option(False, help="Reload on source changes (development only)"),
) -> None:
    """Run the API gateway and administration portal."""
    import uvicorn

    resolved_config = config.resolve()
    loaded = load_config(resolved_config)
    os.environ["ZTAGENT_CONFIG"] = str(resolved_config)
    uvicorn.run(
        "ztagent_core.api:create_app",
        factory=True,
        host=loaded.server.host,
        port=loaded.server.port,
        reload=reload,
    )
