# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Friendly command-line setup and operations."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from pathlib import Path
from typing import cast

import typer
from pydantic import BaseModel

from .config import load_config
from .guardrails import load_guardrail_scanner
from .rules import RulePackLoader, build_pack_archive, install_pack
from .rules.models import PackManifest, PackSignature, RuleDocument
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
    help="Set up and operate ztagent-core, the open-source security gateway from ztagent.ai.",
    no_args_is_help=True,
)
pack_app = typer.Typer(help="Build, verify, and install declarative Rule Packs.")
app.add_typer(pack_app, name="pack")


@app.command()
def init(
    directory: Path = typer.Argument(Path("."), help="Project directory"),
    force: bool = typer.Option(False, "--force", help="Replace generated files"),
) -> None:
    """Create a ready-to-customize ztagent-core project."""
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
    typer.secho("\nztagent-core is ready.", fg=typer.colors.GREEN, bold=True)
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
    rules = load_guardrail_scanner(loaded.guardrails)
    rule_count = rules.rule_count
    warnings: list[str] = []
    if not loaded.auth.enabled:
        warnings.append("authentication is disabled")
    if loaded.policy.development_allow_without_opa:
        warnings.append("OPA development bypass is enabled")
    if any(
        not pack.signed and pack.manifest.name != "local.legacy-signatures"
        for pack in rules.packs
    ):
        warnings.append("one or more configured Rule Packs are unsigned")
    typer.secho(
        f"Configuration valid; {rule_count} guardrail rules loaded "
        f"from {len(rules.packs)} packs.",
        fg=typer.colors.GREEN,
    )
    for pack in rules.packs:
        trust = f"signed:{pack.signer_key_id}" if pack.signed else "unsigned"
        typer.echo(
            f"  {pack.manifest.publisher}.{pack.manifest.name} "
            f"{pack.manifest.version} {pack.digest} {trust}"
        )
    for warning in warnings:
        typer.secho(f"WARNING: {warning}", fg=typer.colors.YELLOW)


@pack_app.command("validate")
def pack_validate(
    source: Path = typer.Argument(..., exists=True, readable=True),
    signature: Path | None = typer.Option(None, "--signature"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
    require_signature: bool = typer.Option(False, "--require-signature"),
    expected_pack_id: str | None = typer.Option(None, "--expected-pack-id"),
    allowed_key_id: list[str] | None = typer.Option(None, "--allowed-key-id"),
    version_spec: str | None = typer.Option(None, "--version-spec"),
    expected_digest: str | None = typer.Option(None, "--expected-digest"),
) -> None:
    """Fail-closed validation of a directory or .ztpack artifact."""
    loaded = RulePackLoader(
        trust_store=trust_store,
        require_signature=require_signature,
        expected_pack_id=expected_pack_id,
        allowed_key_ids=allowed_key_id,
        version_spec=version_spec,
        expected_digest=expected_digest,
    ).load(source, signature)
    trust = f"signed by {loaded.signer_key_id}" if loaded.signed else "unsigned"
    typer.secho(
        f"Valid: {loaded.manifest.name} {loaded.manifest.version}; "
        f"{len(loaded.rules)} rules; digest {loaded.digest}; {trust}",
        fg=typer.colors.GREEN,
    )


@pack_app.command("schema")
def pack_schema(
    kind: str = typer.Argument("rules", help="rules, manifest, or signature"),
) -> None:
    """Print the canonical JSON Schema for Rule IR or pack metadata."""
    models: dict[str, type[BaseModel]] = {
        "rules": RuleDocument,
        "manifest": PackManifest,
        "signature": PackSignature,
    }
    if kind not in models:
        raise typer.BadParameter("kind must be rules, manifest, or signature")
    typer.echo(json.dumps(models[kind].model_json_schema(), indent=2, sort_keys=True))


@pack_app.command("build")
def pack_build(
    source: Path = typer.Argument(..., exists=True, file_okay=False, readable=True),
    output: Path = typer.Option(..., "--output", "-o"),
) -> None:
    """Build a deterministic .ztpack from a validated source directory."""
    digest = build_pack_archive(source, output)
    typer.secho(f"Built {output}; digest {digest}", fg=typer.colors.GREEN)


@pack_app.command("install")
def pack_install(
    source: Path = typer.Argument(..., exists=True, readable=True),
    store: Path = typer.Option(Path("data/rule-packs"), "--store"),
    signature: Path | None = typer.Option(None, "--signature"),
    trust_store: Path | None = typer.Option(None, "--trust-store"),
    require_signature: bool = typer.Option(False, "--require-signature"),
    expected_pack_id: str | None = typer.Option(None, "--expected-pack-id"),
    allowed_key_id: list[str] | None = typer.Option(None, "--allowed-key-id"),
    version_spec: str | None = typer.Option(None, "--version-spec"),
    expected_digest: str | None = typer.Option(None, "--expected-digest"),
) -> None:
    """Verify and install a pack without activating it."""
    installed = install_pack(
        source,
        store,
        signature_path=signature,
        trust_store=trust_store,
        require_signature=require_signature,
        expected_pack_id=expected_pack_id,
        allowed_key_ids=allowed_key_id,
        version_spec=version_spec,
        expected_digest=expected_digest,
    )
    typer.secho(f"Installed at {installed}", fg=typer.colors.GREEN)
    typer.echo("Activation is explicit: add pack.ztpack to guardrails.packs in agent.yaml.")


@app.command()
def demo(
    scenario: str = typer.Argument(
        "stock-injection",
        help=(
            "stock-injection, unauthorized-publish, article-only, fintech-refund, "
            "or rogue-agent-egress"
        ),
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

    scenarios = {
        "stock-injection",
        "unauthorized-publish",
        "article-only",
        "fintech-refund",
        "rogue-agent-egress",
    }
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
        "DEMO SAFETY: simulated funds, demo web tools, email, DM, and social delivery "
        "stay local. --live may contact the configured model provider and OPA.",
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
        typer.echo(f"Sandbox refunds: {len(result.transactions)}")
        typer.echo(f"Sandbox network writes: {len(result.network_events)}")
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
