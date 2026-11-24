"""AFP-KDC v1.0.3 domain-tag reference.

Field domain separators and fixed-width byte tags are different classes. The
former use the deployed ZKA/ZKC/ZKM Blake2b-512 reduction; the latter retain
the direct 32-byte encoding used by KDC's HKDF salt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
FIELD_TAG_PREFIX = b"ZKA-Domain-"

_DOMAIN_TAG_CONTRACT = {
    **{
        tag: ("KDC", "derivation")
        for tag in {
            "zka/spending",
            "zka/viewing",
            "zka/proof",
            "zka/address",
            "zkc/credential",
            "zkc/binding",
        }
    },
    **{
        tag: ("ZKA", "operational")
        for tag in {
            "zka/nullifier",
            "zka/note",
            "zka/asset",
            "zka/commitment",
        }
    },
    **{
        tag: ("ZKC", "operational")
        for tag in {
            "zkc/claim",
            "zkc/context",
            "zkc/purpose",
            "zkc/apr",
            "zkc/receipt",
            "zkc/presentation-scope:v1",
            "zkc/scope:v1",
            "zkc/verifier-id:v1",
        }
    },
    **{
        tag: ("ZKM", "operational")
        for tag in {
            "zkm/mandate_commitment/v1",
            "zkm/mandate_nullifier/v1",
            "zkm/mandate_nullifier_key/v1",
            "zkm/mandate_root_id/v1",
            "zkm/holder_key/v1",
            "zkm/issuance_key/v1",
            "zkm/control_attestation/v1",
            "zkm/disclosure_binding/v1",
            "zkm/policy/v1",
        }
    },
}

_EXPECTED_EXTERNAL_OPERATIONAL_TAG_CLASS = {
    "authority": "ZKA",
    "class": "active_fixed_byte",
    "registry_path": "protocol-family/poseidon2-operational-domains-v1.json",
    "encoding": (
        "right-aligned UTF-8 in a 32-byte word, consumed directly as a field element"
    ),
    "included_in_kdc_tags": False,
    "uses_derive_field_tag": False,
    "publication_requirement": (
        "collision-check against the KDC field registry and the ZKA fixed-byte registry"
    ),
}


class DomainTagError(ValueError):
    """A KDC domain tag or family-registry record is invalid."""


def derive_entity_subseed(master_seed: bytes, entity_name: str) -> bytes:
    """Derive an AFP-KDC §A.5 entity sub-seed with HKDF-SHA256.

    Entity names are encoded exactly as supplied; in particular, this function
    intentionally performs no Unicode normalization.
    """
    if not isinstance(master_seed, bytes) or len(master_seed) != 32:
        raise DomainTagError("tenant master seed must be exactly 32 bytes")
    if not isinstance(entity_name, str) or not entity_name:
        raise DomainTagError("entity name must be a non-empty string")
    try:
        info = ("entity/" + entity_name).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DomainTagError("entity name must be valid UTF-8") from exc

    # RFC 5869 extract and its single 32-byte SHA-256 expand block.
    pseudorandom_key = hmac.digest(
        encode_fixed_tag("kdc/entity-subseed"), master_seed, "sha256"
    )
    return hmac.digest(pseudorandom_key, info + b"\x01", "sha256")


def derive_keys(seed: bytes, profile: dict[str, object]) -> dict[str, int]:
    """Derive AFP-KDC §A.6 keys via the canonical Poseidon2 implementation."""
    # poseidon2 imports this module's field-domain helpers, so importing it at
    # the public entry point avoids a module-initialization cycle.
    from .poseidon2 import derive_kdc_keys

    return derive_kdc_keys(seed, profile)


def derive_field_tag(tag: str) -> int:
    """Derive a circuit field tag using AFP-KDC v1.0.2 §A.3."""
    if not isinstance(tag, str) or not tag:
        raise DomainTagError("field tag must be a non-empty string")
    try:
        encoded = tag.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DomainTagError("field tag must be valid UTF-8") from exc
    digest = hashlib.blake2b(FIELD_TAG_PREFIX + encoded, digest_size=64).digest()
    return int.from_bytes(digest, "little") % BN254_SCALAR_MODULUS


def encode_fixed_tag(tag: str) -> bytes:
    """Encode a non-circuit tag injectively as a padded 32-byte string."""
    if not isinstance(tag, str) or not tag:
        raise DomainTagError("fixed byte tag must be a non-empty string")
    encoded = tag.encode("utf-8")
    if len(encoded) > 32:
        raise DomainTagError("fixed byte tag must fit in 32 bytes")
    if encoded[0] == 0:
        raise DomainTagError("fixed byte tag must not contain a leading NUL byte")
    return encoded.rjust(32, b"\x00")


@dataclass(frozen=True)
class DomainTagRecord:
    tag: str
    owner: str
    tag_class: str
    field_value: int


def validate_domain_registry(
    records: Iterable[DomainTagRecord], *, rederive: bool = True
) -> None:
    """Reject malformed, drifted, duplicate, zero, or colliding tag records."""
    seen_tags: set[str] = set()
    seen_fields: dict[int, str] = {}
    for record in records:
        if record.owner not in {"KDC", "ZKA", "ZKC", "ZKM"}:
            raise DomainTagError(f"unknown owner for {record.tag!r}: {record.owner!r}")
        if record.tag_class not in {"derivation", "operational"}:
            raise DomainTagError(
                f"unknown tag class for {record.tag!r}: {record.tag_class!r}"
            )
        if record.tag in seen_tags:
            raise DomainTagError(f"duplicate domain tag {record.tag!r}")
        seen_tags.add(record.tag)
        if not 0 < record.field_value < BN254_SCALAR_MODULUS:
            raise DomainTagError(f"domain tag {record.tag!r} is not a non-zero field value")
        if rederive and record.field_value != derive_field_tag(record.tag):
            raise DomainTagError(f"domain tag KAT mismatch for {record.tag!r}")
        colliding_tag = seen_fields.get(record.field_value)
        if colliding_tag is not None:
            raise DomainTagError(
                f"field collision between {colliding_tag!r} and {record.tag!r}"
            )
        seen_fields[record.field_value] = record.tag


def validate_external_operational_tag_classes(document: object) -> None:
    """Enforce AFP-KDC's exact delegation of ZKA fixed-byte tag authority."""
    if not isinstance(document, dict):
        raise DomainTagError("external operational tag classes require an object")
    classes = document.get("external_operational_tag_classes")
    if (
        not isinstance(classes, list)
        or len(classes) != 1
        or not isinstance(classes[0], dict)
    ):
        raise DomainTagError(
            "external operational tag classes must contain exactly one object"
        )
    actual = classes[0]
    expected = _EXPECTED_EXTERNAL_OPERATIONAL_TAG_CLASS
    if set(actual) != set(expected) or any(
        type(actual[key]) is not type(value) or actual[key] != value
        for key, value in expected.items()
    ):
        raise DomainTagError(
            "external operational tag classes violate the AFP-KDC v1.0.3 contract"
        )


def validate_complete_domain_registry(
    records: Iterable[DomainTagRecord], *, rederive: bool = True
) -> None:
    """Enforce the exact AFP-KDC v1.0.3 tag, owner, and class contract."""
    materialized = list(records)
    validate_domain_registry(materialized, rederive=rederive)
    actual_tags = {record.tag for record in materialized}
    expected_tags = set(_DOMAIN_TAG_CONTRACT)
    if actual_tags != expected_tags:
        missing = sorted(expected_tags - actual_tags)
        extra = sorted(actual_tags - expected_tags)
        raise DomainTagError(
            "domain registry violates the complete 27-tag contract: "
            f"missing={missing!r}, extra={extra!r}"
        )
    for record in materialized:
        expected = _DOMAIN_TAG_CONTRACT[record.tag]
        if (record.owner, record.tag_class) != expected:
            raise DomainTagError(
                f"owner/class mismatch for {record.tag!r}: "
                f"expected {expected!r}, got {(record.owner, record.tag_class)!r}"
            )


def load_domain_registry(path: str | Path) -> list[DomainTagRecord]:
    """Load and validate the AFP-KDC v1.0.3 family registry JSON."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DomainTagError("domain registry must contain valid JSON") from exc
    if not isinstance(data, dict):
        raise DomainTagError("domain registry root must be a JSON object")
    if data.get("kdc_version") != "1.0.3":
        raise DomainTagError("domain registry must identify AFP-KDC v1.0.3")
    validate_external_operational_tag_classes(data)
    raw_tags = data.get("tags", [])
    if not isinstance(raw_tags, list):
        raise DomainTagError("domain registry tags must be a list")
    records: list[DomainTagRecord] = []
    for item in raw_tags:
        try:
            field_hex = item["field_hex"]
            if not isinstance(field_hex, str) or not field_hex.startswith("0x"):
                raise ValueError("field_hex must be 0x-prefixed")
            records.append(
                DomainTagRecord(
                    tag=item["tag"],
                    owner=item["owner"],
                    tag_class=item["class"],
                    field_value=int(field_hex, 16),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DomainTagError(f"malformed domain registry entry: {item!r}") from exc
    validate_complete_domain_registry(records)
    return records


__all__ = [
    "BN254_SCALAR_MODULUS",
    "FIELD_TAG_PREFIX",
    "DomainTagError",
    "DomainTagRecord",
    "derive_entity_subseed",
    "derive_field_tag",
    "derive_keys",
    "encode_fixed_tag",
    "load_domain_registry",
    "validate_complete_domain_registry",
    "validate_domain_registry",
    "validate_external_operational_tag_classes",
]
