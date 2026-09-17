# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

from pathlib import Path

import pytest

from ztagent_core.config import AppConfig, load_config


def test_production_rejects_disabled_authentication() -> None:
    config = AppConfig()
    config.server.environment = "production"
    config.auth.enabled = False

    with pytest.raises(ValueError, match="authentication cannot be disabled"):
        config.validate_security()


def test_environment_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text("server:\n  port: 8000\n")
    monkeypatch.setenv("ZTAGENT_SERVER__PORT", "9000")

    assert load_config(path).server.port == 9000


def test_production_rejects_symmetric_jwt_algorithm() -> None:
    config = AppConfig()
    config.server.environment = "production"
    config.auth.algorithms = ["HS256"]

    with pytest.raises(ValueError, match="asymmetric"):
        config.validate_security()


def test_rule_pack_configuration_is_explicit(tmp_path: Path) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text(
        """
guardrails:
  trust_store: config/trusted-publishers.yaml
  require_signed_packs: true
  packs:
    - path: packs/commercial.ztpack
      signature: packs/commercial.signature.json
      required: true
      require_signature: true
      expected_pack_id: ztagent/commercial
      allowed_key_ids: [ztagent-commercial-2026]
      version_spec: '>=1,<2'
      expected_digest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.guardrails.require_signed_packs is True
    assert config.guardrails.packs[0].path == Path("packs/commercial.ztpack")
    assert config.guardrails.packs[0].require_signature is True
    assert config.guardrails.packs[0].expected_pack_id == "ztagent/commercial"
    assert config.guardrails.packs[0].allowed_key_ids == ["ztagent-commercial-2026"]


@pytest.mark.parametrize(
    "pack_fields,error",
    [
        ("      unknown_policy: true\n", "extra_forbidden"),
        ("      require_signature: 'false'\n", "bool_type"),
        ("      expected_pack_id: acme.foo.bar\n", "string_pattern_mismatch"),
    ],
)
def test_rule_pack_configuration_rejects_unsafe_values(
    tmp_path: Path, pack_fields: str, error: str
) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text(
        "guardrails:\n"
        "  packs:\n"
        "    - path: pack.ztpack\n"
        f"{pack_fields}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=error):
        load_config(path)


def test_configuration_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = tmp_path / "agent.yaml"
    path.write_text(
        "guardrails:\n"
        "  packs:\n"
        "    - path: pack.ztpack\n"
        "      allowed_key_ids: [trusted]\n"
        "      allowed_key_ids: [attacker]\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate key"):
        load_config(path)
