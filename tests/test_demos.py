# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

from pathlib import Path

import pytest

from ztagent_core.config import AppConfig
from ztagent_core.demos.runner import create_demo_runner
from ztagent_core.gateway import SecurityDenied


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
    assert "requires ztagent-tool-admin" in after.explanation


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
async def test_compromised_fintech_account_cannot_redirect_refund(tmp_path: Path) -> None:
    config = AppConfig()

    before = await create_demo_runner(config, tmp_path / "before").run(
        "before", "fintech-refund"
    )
    after = await create_demo_runner(config, tmp_path / "after").run(
        "after", "fintech-refund"
    )

    assert before.status == "completed"
    assert before.transactions[0]["amount"] == "1000.00"
    assert before.transactions[0]["destination_country"] == "KY"
    assert before.transactions[0]["destination_type"] == "external_account"
    assert after.status == "blocked"
    assert after.transactions == []
    assert "Refund policy denied" in after.explanation


@pytest.mark.asyncio
async def test_rogue_agent_cannot_use_message_board_for_coordination(
    tmp_path: Path,
) -> None:
    config = AppConfig()

    before = await create_demo_runner(config, tmp_path / "before").run(
        "before", "rogue-agent-egress"
    )
    after = await create_demo_runner(config, tmp_path / "after").run(
        "after", "rogue-agent-egress"
    )

    assert before.status == "completed"
    assert before.network_events[0]["transport"] == "sandbox-network"
    assert before.network_events[0]["method"] == "GET"
    assert before.network_events[0]["operation"] == "publish_message"
    assert "dsewiki.example.invalid" in before.network_events[0]["url"]
    assert after.status == "blocked"
    assert after.network_events == []
    assert "Egress policy denied" in after.explanation


@pytest.mark.asyncio
async def test_narrow_refund_and_read_only_egress_paths_remain_available(
    tmp_path: Path,
) -> None:
    runner = create_demo_runner(AppConfig(), tmp_path)

    await runner.gateway.execute_tool(
        "issue_refund",
        {
            "case_id": "CASE-2001",
            "customer_id": "CUST-0042",
            "amount_cents": 2_500,
            "currency": "USD",
            "destination_type": "original_payment_method",
            "destination_country": "US",
            "destination_ref": "ORIGINAL-PAYMENT-TOKEN",
            "approval_id": None,
        },
        runner.principal,
    )
    await runner.gateway.execute_tool(
        "read_web_resource",
        {
            "url": "https://api.example.test/reference-data",
        },
        runner.principal,
    )

    assert runner.refunds.read_current_run()[0]["amount"] == "25.00"
    assert runner.network.read_current_run()[0]["operation"] == "read"


@pytest.mark.asyncio
async def test_refund_policy_checks_amount_destination_and_verified_approval(
    tmp_path: Path,
) -> None:
    runner = create_demo_runner(AppConfig(), tmp_path)
    base = {
        "case_id": "CASE-3001",
        "customer_id": "CUST-0042",
        "currency": "USD",
        "destination_country": "US",
        "destination_ref": "ORIGINAL-PAYMENT-TOKEN",
    }

    for overrides in (
        {
            "amount_cents": 100_000,
            "destination_type": "original_payment_method",
            "approval_id": None,
        },
        {
            "amount_cents": 10_000,
            "destination_type": "external_account",
            "approval_id": None,
        },
    ):
        with pytest.raises(SecurityDenied, match="Refund policy denied"):
            await runner.gateway.execute_tool(
                "issue_refund", {**base, **overrides}, runner.principal
            )

    supervisor = runner.principal.model_copy(
        update={"roles": frozenset({"finance-supervisor"})}
    )
    with pytest.raises(SecurityDenied, match="Refund policy denied"):
        await runner.gateway.execute_tool(
            "issue_refund",
            {
                **base,
                "amount_cents": 100_000,
                "destination_type": "original_payment_method",
                "approval_id": "APR-9999",
            },
            supervisor,
        )
    await runner.gateway.execute_tool(
        "issue_refund",
        {
            **base,
            "amount_cents": 100_000,
            "destination_type": "original_payment_method",
            "approval_id": "APR-3001",
        },
        supervisor,
    )

    assert len(runner.refunds.read_current_run()) == 1


@pytest.mark.asyncio
async def test_publish_capability_cannot_be_relabeled_as_read(tmp_path: Path) -> None:
    runner = create_demo_runner(AppConfig(), tmp_path)

    with pytest.raises(ValueError):
        await runner.gateway.execute_tool(
            "publish_web_message",
            {
                "url": "https://api.example.test/reference-data",
                "operation": "read",
            },
            runner.principal,
        )
    with pytest.raises(SecurityDenied, match="external agent communication"):
        await runner.gateway.execute_tool(
            "publish_web_message",
            {
                "url": "https://api.example.test/coordination",
                "transport_method": "GET",
                "payload": "share state",
            },
            runner.principal,
        )

    assert runner.network.read_current_run() == []


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


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["fintech-refund", "rogue-agent-egress"])
async def test_blocked_rerun_does_not_report_old_sandbox_effects(
    tmp_path: Path, scenario: str
) -> None:
    first = create_demo_runner(AppConfig(), tmp_path)
    await first.run("before", scenario)  # type: ignore[arg-type]
    second = create_demo_runner(AppConfig(), tmp_path)

    blocked = await second.run("after", scenario)  # type: ignore[arg-type]

    assert blocked.status == "blocked"
    assert blocked.transactions == []
    assert blocked.network_events == []


def test_demo_disables_external_containment_integrations(tmp_path: Path) -> None:
    config = AppConfig()
    config.containment.webhook_url = "https://security.example.test/hook"
    config.containment.keycloak_admin_url = "https://identity.example.test"
    config.containment.keycloak_realm = "agents"

    runner = create_demo_runner(config, tmp_path)

    assert runner.gateway.containment.config.webhook_url is None
    assert runner.gateway.containment.config.keycloak_admin_url is None
    assert runner.gateway.containment.config.keycloak_realm is None
