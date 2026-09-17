from pathlib import Path

import pytest

from mini_secure_agent.config import AppConfig
from mini_secure_agent.demos.runner import create_demo_runner


@pytest.mark.asyncio
async def test_stock_injection_contrasts_before_and_after(tmp_path: Path) -> None:
    config = AppConfig()

    before = await create_demo_runner(config, tmp_path / "before").run("before", "stock-injection")
    after = await create_demo_runner(config, tmp_path / "after").run("after", "stock-injection")

    assert before.status == "completed"
    assert before.outbox[0]["recipient"] == "attacker@example.test"
    assert after.status == "blocked"
    assert after.outbox == []
    assert "Untrusted tool output" in after.explanation


@pytest.mark.asyncio
async def test_policy_blocks_unauthorized_social_publish(tmp_path: Path) -> None:
    config = AppConfig()

    before = await create_demo_runner(config, tmp_path / "before").run(
        "before", "unauthorized-publish"
    )
    after = await create_demo_runner(config, tmp_path / "after").run(
        "after", "unauthorized-publish"
    )

    assert len(before.outbox) == 1
    assert after.status == "blocked"
    assert after.outbox == []
    assert "requires msa-tool-admin" in after.explanation


@pytest.mark.asyncio
async def test_authorized_publish_stays_in_sandbox(tmp_path: Path) -> None:
    config = AppConfig()
    runner = create_demo_runner(config, tmp_path, privileged=True)

    result = await runner.run("after", "unauthorized-publish")

    assert result.status == "completed"
    assert result.outbox[0]["transport"] == "sandbox"
    assert result.outbox[0]["channel"] == "social"


@pytest.mark.asyncio
async def test_article_only_never_delivers(tmp_path: Path) -> None:
    config = AppConfig()
    runner = create_demo_runner(config, tmp_path)

    result = await runner.run("after", "article-only")

    assert result.status == "completed"
    assert result.model_output
    assert result.outbox == []


@pytest.mark.asyncio
async def test_blocked_rerun_does_not_report_old_deliveries(tmp_path: Path) -> None:
    config = AppConfig()
    privileged = create_demo_runner(config, tmp_path, privileged=True)
    delivered = await privileged.run("after", "unauthorized-publish")
    unprivileged = create_demo_runner(config, tmp_path)

    blocked = await unprivileged.run("after", "unauthorized-publish")

    assert len(delivered.outbox) == 1
    assert blocked.status == "blocked"
    assert blocked.outbox == []


def test_demo_disables_external_containment_integrations(tmp_path: Path) -> None:
    config = AppConfig()
    config.containment.webhook_url = "https://security.example.test/hook"
    config.containment.keycloak_admin_url = "https://identity.example.test"
    config.containment.keycloak_realm = "agents"

    runner = create_demo_runner(config, tmp_path)

    assert runner.gateway.containment.config.webhook_url is None
    assert runner.gateway.containment.config.keycloak_admin_url is None
    assert runner.gateway.containment.config.keycloak_realm is None
