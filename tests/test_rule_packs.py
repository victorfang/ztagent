# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ztagent_core.rules import (
    GuardrailContext,
    GuardrailSet,
    PackError,
    RulePackLoader,
    build_pack_archive,
    install_pack,
)
from ztagent_core.rules.packs import compute_pack_digest


def write_pack(
    root: Path,
    *,
    rule_id: str = "acme.secure-baseline.block-injection",
    compatibility: str = ">=0.1,<1",
) -> Path:
    root.mkdir()
    rules = {
        "schema_version": 1,
        "rules": [
            {
                "id": rule_id,
                "description": "Block instruction override language",
                "stages": ["model_input", "model_output"],
                "engine": "phrase",
                "pattern": "ignore prior policy",
                "category": "prompt-injection",
                "severity": "high",
                "action": "block",
                "score": 90,
            }
        ],
    }
    rules_path = root / "rules.yaml"
    rules_path.write_text(yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "name": "secure-baseline",
        "version": "1.2.3",
        "publisher": "acme",
        "description": "Test security rules",
        "license": "Apache-2.0",
        "compatibility": {"core": compatibility, "rule_ir": 1},
        "contents": [
            {
                "path": "rules.yaml",
                "sha256": hashlib.sha256(rules_path.read_bytes()).hexdigest(),
                "kind": "rules",
            }
        ],
    }
    (root / "pack.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    return root


def sign_pack(pack: Path, tmp_path: Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trust_store = tmp_path / "trusted.yaml"
    trust_store.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "keys": {"ztagent-commercial-2026": public_key.decode()},
            }
        ),
        encoding="utf-8",
    )
    digest = compute_pack_digest(pack)
    signature = tmp_path / "pack.signature.json"
    signature.write_text(
        json.dumps(
            {
                "format": "ztagent-pack-signature-v1",
                "key_id": "ztagent-commercial-2026",
                "algorithm": "ed25519",
                "digest": digest,
                "signature": base64.b64encode(
                    private_key.sign(bytes.fromhex(digest))
                ).decode(),
            }
        ),
        encoding="utf-8",
    )
    return signature, trust_store


def test_loads_staged_rules_with_pack_provenance(tmp_path: Path) -> None:
    loaded = RulePackLoader().load(write_pack(tmp_path / "pack"))
    guardrails = GuardrailSet.compile([loaded])

    findings = guardrails.inspect(
        GuardrailContext(stage="model_output", content="Please ignore prior policy now")
    )

    assert findings[0].rule_id == "acme.secure-baseline.block-injection"
    assert findings[0].stage == "model_output"
    assert findings[0].pack == "secure-baseline"
    assert findings[0].pack_digest == loaded.digest


def test_rejects_tampered_content(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    (pack / "rules.yaml").write_text("schema_version: 1\nrules: []\n", encoding="utf-8")

    with pytest.raises(PackError, match="Hash mismatch"):
        RulePackLoader().load(pack)


def test_rejects_undeclared_files(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    (pack / "payload.py").write_text("raise RuntimeError()\n", encoding="utf-8")

    with pytest.raises(PackError, match="undeclared files"):
        RulePackLoader().load(pack)


def test_verifies_commercial_pack_signature(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    signature, trust_store = sign_pack(pack, tmp_path)

    loaded = RulePackLoader(
        trust_store=trust_store, require_signature=True
    ).load(pack, signature)

    assert loaded.signed is True
    assert loaded.signer_key_id == "ztagent-commercial-2026"


def test_rejects_forged_commercial_pack_signature(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    signature, trust_store = sign_pack(pack, tmp_path)
    payload = json.loads(signature.read_text(encoding="utf-8"))
    payload["signature"] = base64.b64encode(b"x" * 64).decode()
    signature.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PackError, match="signature verification failed"):
        RulePackLoader(trust_store=trust_store).load(pack, signature)


def test_rejects_unsigned_pack_when_signature_is_required(tmp_path: Path) -> None:
    with pytest.raises(PackError, match="detached signature is required"):
        RulePackLoader(require_signature=True).load(write_pack(tmp_path / "pack"))


def test_rejects_archive_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "malicious.ztpack"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("../outside.yaml", "rules: []")

    with pytest.raises(PackError, match="Unsafe Rule Pack path"):
        RulePackLoader().load(archive)

    assert not (tmp_path / "outside.yaml").exists()


def test_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    manifest = (pack / "pack.yaml").read_text(encoding="utf-8")
    (pack / "pack.yaml").write_text(manifest + "\nname: second-name\n", encoding="utf-8")

    with pytest.raises(PackError, match="duplicate key"):
        RulePackLoader().load(pack)


def test_rejects_incompatible_core_version(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack", compatibility=">=9")

    with pytest.raises(PackError, match="requires ztagent-core"):
        RulePackLoader().load(pack)


def test_rejects_duplicate_rule_ids_across_packs(tmp_path: Path) -> None:
    first = RulePackLoader().load(write_pack(tmp_path / "first"))
    second = RulePackLoader().load(write_pack(tmp_path / "second"))

    with pytest.raises(ValueError, match="Duplicate rule ID"):
        GuardrailSet.compile([first, second])


def test_build_and_install_preserve_verified_digest(tmp_path: Path) -> None:
    pack = write_pack(tmp_path / "pack")
    archive = tmp_path / "baseline.ztpack"
    expected_digest = build_pack_archive(pack, archive)

    loaded = RulePackLoader().load(archive)
    installed = install_pack(archive, tmp_path / "installed")

    assert loaded.digest == expected_digest
    assert (installed / "pack.ztpack").is_file()
    metadata = json.loads((installed / "installed.json").read_text(encoding="utf-8"))
    assert metadata["digest"] == expected_digest

    with pytest.raises(PackError, match="already installed"):
        install_pack(archive, tmp_path / "installed")
