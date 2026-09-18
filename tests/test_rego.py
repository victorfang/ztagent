# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

OPA = shutil.which("opa")
POLICY = Path("policies/authz.rego")
EXPECTED_OPA_VERSION = "1.20.2"


def require_opa() -> str:
    if OPA is not None:
        return OPA
    if os.getenv("CI"):
        pytest.fail("OPA must be installed in CI")
    pytest.skip("OPA binary is not installed")


def evaluate(policy_input: dict[str, object]) -> bool:
    opa = require_opa()
    result = subprocess.run(  # noqa: S603 - test intentionally executes installed OPA
        [
            opa,
            "eval",
            "--data",
            str(POLICY),
            "--stdin-input",
            "--format",
            "raw",
            "data.ztagent_core.authz.allow",
        ],
        input=json.dumps(policy_input),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() == "true"


def tool_input(
    tool: str,
    roles: list[str],
    authorization_context: dict[str, object],
) -> dict[str, object]:
    return {
        "action": "tool.execute",
        "subject": "demo-user",
        "roles": roles,
        "resource": {
            "tool": tool,
            "risk": "high",
            "authorization_context": authorization_context,
        },
    }


def test_rego_policy_compiles() -> None:
    opa = require_opa()
    subprocess.run(  # noqa: S603 - test intentionally executes installed OPA
        [opa, "check", str(POLICY)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_opa_test_version_is_pinned() -> None:
    opa = require_opa()
    result = subprocess.run(  # noqa: S603 - test intentionally executes installed OPA
        [opa, "version"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert f"Version: {EXPECTED_OPA_VERSION}" in result.stdout


@pytest.mark.parametrize(
    ("policy_input", "allowed"),
    [
        (
            tool_input(
                "issue_refund",
                ["customer-service-agent"],
                {
                    "amount_cents": 25_000,
                    "destination_type": "original_payment_method",
                    "approval_verified": False,
                },
            ),
            True,
        ),
        (
            tool_input(
                "issue_refund",
                ["customer-service-agent"],
                {
                    "amount_cents": 100_000,
                    "destination_type": "external_account",
                    "approval_verified": False,
                },
            ),
            False,
        ),
        (
            tool_input(
                "issue_refund",
                ["finance-supervisor"],
                {
                    "amount_cents": 100_000,
                    "destination_type": "original_payment_method",
                    "approval_verified": True,
                },
            ),
            True,
        ),
        (
            tool_input(
                "read_web_resource",
                [],
                {"destination_class": "approved_business_service"},
            ),
            True,
        ),
        (
            tool_input(
                "publish_web_message",
                ["ztagent-tool-admin"],
                {"destination_class": "approved_business_service"},
            ),
            False,
        ),
    ],
)
def test_rego_policy_boundaries(
    policy_input: dict[str, object], allowed: bool
) -> None:
    assert evaluate(policy_input) is allowed
