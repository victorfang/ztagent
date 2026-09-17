# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

"""Secure loading, verification, and composition of declarative Rule Packs."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import stat
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError
from yaml.tokens import AliasToken

from ..version import __version__
from .models import (
    LoadedPack,
    PackManifest,
    PackSignature,
    RuleDefinition,
    RuleDocument,
    TrustStore,
)

MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_EXPANDED_BYTES = 25 * 1024 * 1024
MAX_FILES = 200
MAX_YAML_BYTES = 2 * 1024 * 1024
MAX_ALIASES = 20
ALLOWED_SUFFIXES = {".yaml", ".yml", ".json", ".md", ".txt"}


class PackError(ValueError):
    """A Rule Pack failed closed during validation or verification."""


class RulePackLoader:
    def __init__(
        self,
        *,
        trust_store: Path | None = None,
        require_signature: bool = False,
        core_version: str = __version__,
    ) -> None:
        self.require_signature = require_signature
        self.core_version = core_version
        self.trust_store = self._load_trust_store(trust_store) if trust_store else None

    def load(self, source: Path, signature_path: Path | None = None) -> LoadedPack:
        with materialize_pack(source) as root:
            manifest = self._load_manifest(root)
            self._check_compatibility(manifest)
            self._verify_contents(root, manifest)
            digest = compute_pack_digest(root, manifest)
            signer = self._verify_signature(digest, signature_path)
            rules = self._load_rules(root, manifest)
        return LoadedPack(
            manifest=manifest,
            digest=digest,
            signed=signer is not None,
            signer_key_id=signer,
            rules=tuple(rules),
        )

    def _load_manifest(self, root: Path) -> PackManifest:
        path = root / "pack.yaml"
        if not path.is_file():
            raise PackError("Rule Pack must contain pack.yaml")
        try:
            return PackManifest.model_validate(_safe_yaml(path))
        except (ValidationError, yaml.YAMLError, OSError, UnicodeError) as exc:
            raise PackError(f"Invalid pack manifest: {exc}") from exc

    def _check_compatibility(self, manifest: PackManifest) -> None:
        try:
            compatible = Version(self.core_version) in SpecifierSet(manifest.compatibility.core)
        except (InvalidSpecifier, InvalidVersion) as exc:
            raise PackError(f"Invalid pack compatibility range: {exc}") from exc
        if not compatible:
            raise PackError(
                f"Pack {manifest.name} {manifest.version} requires ztagent-core "
                f"{manifest.compatibility.core}; running {self.core_version}"
            )

    def _verify_contents(self, root: Path, manifest: PackManifest) -> None:
        expected = {"pack.yaml"}
        for item in manifest.contents:
            relative = _safe_relative_path(item.path)
            if relative.as_posix().casefold() == "pack.yaml":
                raise PackError("pack.yaml is reserved and cannot be declared as content")
            expected.add(relative.as_posix())
            path = root.joinpath(*relative.parts)
            current = root
            unsafe_link = False
            for part in relative.parts:
                current /= part
                if current.is_symlink():
                    unsafe_link = True
                    break
            if not path.is_file() or unsafe_link:
                raise PackError(f"Missing or unsafe pack content: {item.path}")
            digest = _sha256_file(path)
            if digest != item.sha256:
                raise PackError(f"Hash mismatch for pack content: {item.path}")
        total_size = sum(
            path.stat().st_size
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        if total_size > MAX_EXPANDED_BYTES:
            raise PackError("Rule Pack directory exceeds expanded size limit")
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        undeclared = actual - expected
        if undeclared:
            raise PackError(f"Pack contains undeclared files: {sorted(undeclared)}")

    def _load_rules(self, root: Path, manifest: PackManifest) -> list[RuleDefinition]:
        rules: list[RuleDefinition] = []
        for item in manifest.contents:
            if item.kind != "rules":
                continue
            path = root.joinpath(*_safe_relative_path(item.path).parts)
            try:
                document = RuleDocument.model_validate(_safe_yaml(path))
            except (ValidationError, yaml.YAMLError, OSError, UnicodeError) as exc:
                raise PackError(f"Invalid rule document {item.path}: {exc}") from exc
            rules.extend(document.rules)
        if not rules:
            raise PackError("Rule Pack contains no rules")
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise PackError("Rule IDs must be unique across the pack")
        prefix = f"{manifest.publisher}.{manifest.name}."
        for rule in rules:
            if not rule.id.startswith(prefix):
                raise PackError(f"Rule ID {rule.id!r} must start with {prefix!r}")
        return rules

    def _verify_signature(self, digest: str, signature_path: Path | None) -> str | None:
        if signature_path is None:
            if self.require_signature:
                raise PackError("A detached signature is required for this Rule Pack")
            return None
        if self.trust_store is None:
            raise PackError("A trust store is required to verify a Rule Pack signature")
        try:
            signature = PackSignature.model_validate(_safe_json(signature_path))
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as exc:
            raise PackError(f"Invalid detached signature: {exc}") from exc
        if signature.digest != digest:
            raise PackError("Detached signature digest does not match the Rule Pack")
        pem = self.trust_store.keys.get(signature.key_id)
        if pem is None:
            raise PackError(f"Untrusted Rule Pack signing key: {signature.key_id}")
        try:
            key = serialization.load_pem_public_key(pem.encode())
        except ValueError as exc:
            raise PackError(f"Invalid public key for {signature.key_id}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise PackError("Rule Pack signing key must be Ed25519")
        try:
            encoded_signature = base64.b64decode(signature.signature, validate=True)
            key.verify(encoded_signature, bytes.fromhex(digest))
        except (InvalidSignature, ValueError) as exc:
            raise PackError("Rule Pack signature verification failed") from exc
        return signature.key_id

    @staticmethod
    def _load_trust_store(path: Path) -> TrustStore:
        try:
            return TrustStore.model_validate(_safe_yaml(path))
        except (ValidationError, yaml.YAMLError, OSError, UnicodeError) as exc:
            raise PackError(f"Invalid Rule Pack trust store: {exc}") from exc


def compose_packs(packs: list[LoadedPack], default_timeout_ms: int = 50) -> Any:
    from .engine import GuardrailSet

    return GuardrailSet.compile(packs, default_timeout_ms=default_timeout_ms)


def compute_pack_digest(root: Path, manifest: PackManifest | None = None) -> str:
    active_manifest = manifest or PackManifest.model_validate(_safe_yaml(root / "pack.yaml"))
    digest = hashlib.sha256()
    paths = ["pack.yaml", *(item.path for item in active_manifest.contents)]
    for name in sorted(paths):
        relative = _safe_relative_path(name)
        path = root.joinpath(*relative.parts)
        size = path.stat().st_size
        if size > MAX_EXPANDED_BYTES:
            raise PackError(f"Rule Pack file exceeds size limit: {name}")
        encoded_name = relative.as_posix().encode()
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def build_pack_archive(source: Path, output: Path) -> str:
    """Validate an unsigned source directory and create a deterministic .ztpack ZIP."""
    loaded = RulePackLoader().load(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        with materialize_pack(source) as root:
            names = ["pack.yaml", *(item.path for item in loaded.manifest.contents)]
            for name in sorted(names):
                info = zipfile.ZipInfo(name)
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, root.joinpath(*PurePosixPath(name).parts).read_bytes())
    verified = RulePackLoader().load(temporary)
    temporary.replace(output)
    return verified.digest


def install_pack(
    source: Path,
    store: Path,
    *,
    signature_path: Path | None = None,
    trust_store: Path | None = None,
    require_signature: bool = False,
) -> Path:
    """Verify and immutably install a pack; activation remains explicit in config."""
    loader = RulePackLoader(
        trust_store=trust_store,
        require_signature=require_signature,
    )
    loaded = loader.load(source, signature_path)
    store.mkdir(parents=True, exist_ok=True)
    destination = store / loaded.manifest.name / loaded.manifest.version
    if destination.exists():
        raise PackError(f"Rule Pack version is already installed: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".install-", dir=destination.parent))
    try:
        archive_path = staging / "pack.ztpack"
        if source.is_dir():
            build_pack_archive(source, archive_path)
        else:
            shutil.copy2(source, archive_path)
        if signature_path:
            shutil.copy2(signature_path, staging / "pack.signature.json")
        verified = loader.load(
            archive_path,
            staging / "pack.signature.json" if signature_path else None,
        )
        if (
            verified.manifest.name != loaded.manifest.name
            or verified.manifest.version != loaded.manifest.version
            or verified.digest != loaded.digest
        ):
            raise PackError("Rule Pack source changed during installation")
        (staging / "installed.json").write_text(
            json.dumps(
                {
                    "name": loaded.manifest.name,
                    "version": loaded.manifest.version,
                    "digest": verified.digest,
                    "signed": verified.signed,
                    "signer_key_id": verified.signer_key_id,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        staging.replace(destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination


@contextmanager
def materialize_pack(source: Path) -> Iterator[Path]:
    if source.is_dir():
        yield source
        return
    if not source.is_file():
        raise PackError(f"Rule Pack source does not exist: {source}")
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackError("Rule Pack archive exceeds compressed size limit")
    temporary = tempfile.TemporaryDirectory(prefix="ztagent-pack-")
    root = Path(temporary.name)
    try:
        with zipfile.ZipFile(source) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES:
                raise PackError("Rule Pack archive contains too many files")
            if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
                raise PackError("Rule Pack archive exceeds expanded size limit")
            seen: set[str] = set()
            for info in infos:
                if info.is_dir():
                    continue
                relative = _safe_relative_path(info.filename)
                normalized = relative.as_posix().casefold()
                if normalized in seen:
                    raise PackError(f"Duplicate Rule Pack archive path: {info.filename}")
                seen.add(normalized)
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise PackError(f"Rule Pack archive contains a symlink: {info.filename}")
                if info.flag_bits & 0x1:
                    raise PackError("Encrypted Rule Pack archives are not supported")
                destination = root.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as source_stream, destination.open("wb") as target:
                    while chunk := source_stream.read(64 * 1024):
                        written += len(chunk)
                        if written > info.file_size or written > MAX_EXPANDED_BYTES:
                            raise PackError("Rule Pack file exceeds declared size")
                        target.write(chunk)
        yield root
    except (zipfile.BadZipFile, OSError) as exc:
        raise PackError(f"Invalid Rule Pack archive: {exc}") from exc
    finally:
        temporary.cleanup()


def _safe_relative_path(value: str) -> PurePosixPath:
    if "\\" in value or "\x00" in value or ":" in value:
        raise PackError(f"Unsafe Rule Pack path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackError(f"Unsafe Rule Pack path: {value!r}")
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        raise PackError(f"Unsupported Rule Pack file type: {value!r}")
    return path


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _safe_yaml(path: Path) -> Any:
    content = path.read_bytes()
    if len(content) > MAX_YAML_BYTES:
        raise PackError(f"YAML file exceeds size limit: {path.name}")
    text = content.decode("utf-8")
    aliases = sum(1 for token in yaml.scan(text) if isinstance(token, AliasToken))
    if aliases > MAX_ALIASES:
        raise PackError(f"YAML file contains too many aliases: {path.name}")
    # _UniqueKeyLoader subclasses SafeLoader; it only adds duplicate-key rejection.
    return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506


def _safe_json(path: Path) -> Any:
    content = path.read_bytes()
    if len(content) > 16_384:
        raise PackError("Detached signature exceeds size limit")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PackError(f"Detached signature contains duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            size += len(chunk)
            if size > MAX_EXPANDED_BYTES:
                raise PackError(f"Rule Pack file exceeds size limit: {path.name}")
            digest.update(chunk)
    return digest.hexdigest()
