"""``zka:bundle:v1`` — the ZKA-owned cryptographic bundle (opaque to AFP).

Per §12.7: **ZKA owns the cryptographic bundle; AFP owns the session envelope.**
AFP carries a ``zka:bundle:v1`` (ZKA §5.4) verbatim inside an ``afp:envelope:v1``
and never authors a bundle wire format. AFP's only job at the bundle layer is to
*frame and bind* it; ZKA *proves* it.

This module therefore models the bundle as a structured-but-opaque payload.
It can retain the canonical ZKA v1 JSON object verbatim while exposing the
context and proof discriminators AFP needs at its ownership boundary.  For
Coord v2, the ZKA metadata context is the BN254 field reading of AFP's signed
session digest (§12.7.1), not a second replay domain.

``verify_bundle`` here performs the AFP-side structural checks the spec assigns
to the envelope/bundle boundary (kind, version, context match, non-empty proof
set, pure-attestation rule) and takes a ``bundle_verifier`` seam through which a
real ZKA verifier performs the §12.7 second layer.

That seam is **required**, not optional: §12.7 verification is two-layer, so a
structural pass alone is not a verified bundle. A caller that has no ZKA verifier
to supply states so explicitly at each call site rather than inheriting a default
that silently skips every proof.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import math
import re
from typing import Any, Callable, List, Mapping, Optional

from .canonical import canonical_bytes, digest, qb64

__all__ = [
    "BUNDLE_VERSION",
    "ZkaBundle",
    "BundleError",
    "session_context_field",
    "verify_bundle",
    "BundleVerificationResult",
    "BundleVerifier",
]

BUNDLE_VERSION = "zka:bundle:v1"
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)

_BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
_SESSION_CONTEXT = re.compile(r"X_[0-9a-f]{64}\Z")
_ZKA_FIELD_CONTEXT = re.compile(r"0x[0-9a-f]{64}\Z")


class BundleError(ValueError):
    """Structural failure of the AFP-side bundle checks (§12.7)."""


def _rfc3339_timestamp(value: object) -> float:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise ValueError("canonical ZKA bundle timestamp is not RFC 3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("canonical ZKA bundle timestamp is not RFC 3339") from exc
    if parsed.utcoffset() is None:
        raise ValueError("canonical ZKA bundle timestamp requires an offset")
    return parsed.timestamp()


def session_context_field(session_context: str) -> str:
    """Project one canonical AFP session digest into ZKA's BN254 field.

    The AFP envelope and session atom retain the exact §5.2 wire value:
    ``X_`` followed by the 32-byte SHA-256 digest in lowercase hexadecimal.
    ZKA's bundle, transaction, binding, and Coord context slots are scalar-field
    inputs, so §12.7 reads those same digest bytes as an unsigned big-endian
    integer and reduces them modulo the BN254 scalar modulus, matching the
    already-published §15.4 digest-to-field seam.

    Zero is ZKA's missing-context sentinel and is rejected.  This function has
    no alternate prefix, normalization, retry, rehash, or substitution path.
    """
    if type(session_context) is not str or _SESSION_CONTEXT.fullmatch(
        session_context
    ) is None:
        raise BundleError(
            "session_context must be canonical X_ followed by 64 lowercase "
            "hexadecimal digits"
        )
    field = int(session_context[2:], 16) % _BN254_SCALAR_MODULUS
    if field == 0:
        raise BundleError(
            "session_context projects to ZKA's zero BN254 context sentinel"
        )
    return f"0x{field:064x}"


def _require_canonical_zka_field_context(context: object) -> str:
    """Validate a bundle context without normalizing untrusted wire input."""
    if type(context) is not str or _ZKA_FIELD_CONTEXT.fullmatch(context) is None:
        raise BundleError(
            "bundle context must be lowercase 0x followed by 64 hexadecimal digits"
        )
    value = int(context[2:], 16)
    if not 1 <= value < _BN254_SCALAR_MODULUS:
        raise BundleError("bundle context must be a nonzero canonical BN254 scalar")
    return context


@dataclass
class ZkaBundle:
    """A ZKA Compliance/Coordination bundle (ZKA §5.4), opaque payload to AFP.

    AFP carries this verbatim. The proof members are opaque blobs to AFP; ZKA
    verifies them. The one field AFP reads is ``context`` (the canonical BN254
    projection of the envelope ``session_context``, §12.7) plus the
    discriminators of which proofs are present, so AFP can apply the pure-work-
    attestation rule (§12.7: a bundle where ``coord_proof`` is present and
    ``transaction`` is absent is valid).
    """

    kind: str  # always 'zka:bundle:v1'
    context: str  # 0x field projection of envelope.session_context's X_ digest
    transaction: Optional[Any] = None  # ZKA/Pay transaction proof (opaque)
    coord_proof: Optional[Any] = None  # ZKA/Coord final proof (opaque to AFP)
    compliance_proofs: List[Any] = field(default_factory=list)  # ZKC v1/v2 (opaque)
    binding_proof: Optional[Any] = None  # identity-binding proof (opaque)
    _canonical_payload: Optional[dict] = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def is_canonical_payload(self) -> bool:
        """Whether this object carries the ZKA-owned v1 JSON shape verbatim."""
        return self._canonical_payload is not None

    @property
    def is_pure_coord_payload(self) -> bool:
        """Whether this is the minimal canonical Coord-only bundle profile."""
        if self._canonical_payload is None:
            return False
        payload = self._canonical_payload
        return (
            set(payload) == {"compliance", "coord_proof", "metadata"}
            and payload.get("coord_proof") is not None
            and payload.get("compliance") == {"proofs": []}
        )

    @property
    def present_proofs(self) -> List[str]:
        if self._canonical_payload is not None:
            payload = self._canonical_payload
            present = []
            if payload.get("transaction") is not None:
                present.append("transaction")
            if payload.get("coord_proof") is not None:
                present.append("coord_proof")
            compliance = payload.get("compliance", {})
            if isinstance(compliance, dict) and compliance.get("proofs"):
                present.append("compliance")
            if payload.get("binding") is not None:
                present.append("binding")
            return present
        present = []
        if self.transaction is not None:
            present.append("transaction")
        if self.coord_proof is not None:
            present.append("coord_proof")
        if self.compliance_proofs:
            present.append("compliance")
        if self.binding_proof is not None:
            present.append("binding")
        return present

    def to_dict(self) -> dict:
        if self._canonical_payload is not None:
            return deepcopy(self._canonical_payload)
        return {
            "kind": self.kind,
            "context": self.context,
            "transaction": self.transaction,
            "coord_proof": self.coord_proof,
            "compliance_proofs": list(self.compliance_proofs),
            "binding_proof": self.binding_proof,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ZkaBundle":
        if not isinstance(data, dict):
            raise ValueError("ZKA bundle must be a JSON object")
        if "metadata" in data or "compliance" in data:
            return cls.from_canonical_payload(data)
        return cls(
            kind=data["kind"],
            context=data["context"],
            transaction=data.get("transaction"),
            coord_proof=data.get("coord_proof"),
            compliance_proofs=list(data.get("compliance_proofs", [])),
            binding_proof=data.get("binding_proof"),
        )

    @classmethod
    def from_canonical_payload(cls, payload: Mapping[str, Any]) -> "ZkaBundle":
        """Carry one canonical ZKA ``zka:bundle:v1`` object verbatim.

        This validates only the outer ownership boundary AFP needs in order to
        frame the object.  Coord receipt/proof validation remains the ZKA
        verifier's job; :mod:`afp_session.coord` validates the consumer-facing
        integration projection before completion is recorded.
        """
        if not isinstance(payload, Mapping):
            raise ValueError("canonical ZKA bundle must be a JSON object")
        allowed = {"transaction", "compliance", "binding", "coord_proof", "metadata"}
        if set(payload) - allowed:
            raise ValueError("canonical ZKA bundle has unknown top-level members")
        metadata = payload.get("metadata")
        compliance = payload.get("compliance")
        if not isinstance(metadata, Mapping) or not isinstance(compliance, Mapping):
            raise ValueError("canonical ZKA bundle requires metadata and compliance")
        if set(metadata) != {"version", "generatedAt", "expiresAt", "context"}:
            raise ValueError("canonical ZKA bundle metadata shape is invalid")
        if metadata.get("version") != BUNDLE_VERSION:
            raise ValueError(f"canonical ZKA bundle version must be {BUNDLE_VERSION}")
        generated_at = _rfc3339_timestamp(metadata.get("generatedAt"))
        expires_at = _rfc3339_timestamp(metadata.get("expiresAt"))
        if expires_at < generated_at:
            raise ValueError("canonical ZKA bundle expiry must not precede generation")
        context = _require_canonical_zka_field_context(metadata.get("context"))
        if set(compliance) - {"proofs", "aggregation"}:
            raise ValueError("canonical ZKA bundle compliance shape is invalid")
        proofs = compliance.get("proofs")
        if not isinstance(proofs, list):
            raise ValueError("canonical ZKA bundle compliance.proofs must be an array")
        copied = deepcopy(dict(payload))
        copied_compliance = copied["compliance"]
        bundle = cls(
            kind=BUNDLE_VERSION,
            context=context,
            transaction=copied.get("transaction"),
            coord_proof=copied.get("coord_proof"),
            compliance_proofs=copied_compliance["proofs"],
            binding_proof=copied.get("binding"),
        )
        bundle._canonical_payload = copied
        return bundle

    @property
    def content_hash(self) -> str:
        return qb64("D", digest(self.to_dict()))


@dataclass(frozen=True)
class BundleVerificationResult:
    """Exact ZKA verifier result bound to the bundle bytes it checked.

    A boolean cannot say *which* mutable bundle a verifier accepted.  The
    content hash makes that binding explicit while ``verified`` preserves a
    verifier's ordinary accept/reject result.  ``verify_bundle`` accepts this
    exact type only; truthy substitutes and subclasses fail closed.
    """

    bundle_content_hash: str
    verified: bool

    def __post_init__(self) -> None:
        if type(self.bundle_content_hash) is not str:
            raise TypeError("bundle_content_hash must be an exact str")
        if type(self.verified) is not bool:
            raise TypeError("verified must be an exact bool")

    @classmethod
    def accepted(cls, bundle: ZkaBundle) -> "BundleVerificationResult":
        """Build an acceptance result for the exact bundle presented."""
        return cls(bundle_content_hash=bundle.content_hash, verified=True)

    @classmethod
    def rejected(cls, bundle: ZkaBundle) -> "BundleVerificationResult":
        """Build a rejection result for the exact bundle presented."""
        return cls(bundle_content_hash=bundle.content_hash, verified=False)


# A pluggable ZKA verifier: takes a bundle and returns an exact, content-bound
# result after checking all its proofs. AFP never implements the proof checks;
# a real deployment supplies them.
BundleVerifier = Callable[[ZkaBundle], BundleVerificationResult]


def verify_bundle(
    bundle: ZkaBundle,
    *,
    expected_session_context: str,
    bundle_verifier: BundleVerifier,
    now: Optional[float] = None,
) -> None:
    """AFP-side structural verification of a ``zka:bundle:v1`` (§12.7).

    Checks the boundary AFP owns:
      * the kind/version is ``zka:bundle:v1``;
      * the bundle context is the canonical nonzero BN254 projection of the
        envelope's authenticated ``X_`` ``session_context`` (§12.7);
      * at least one proof is present (an empty bundle is not a bundle);
      * the pure-work-attestation rule: a transaction-less bundle is valid only
        if it carries a ``coord_proof`` (§12.7 resolved interface).

    The cryptographic verification of the proofs themselves is ZKA's, and
    ``bundle_verifier`` is how it runs: it is invoked last and unconditionally,
    completing §12.7's second layer. It is a required argument and ``None`` fails
    closed — an absent verifier means the proofs were never checked, which is not
    a weaker pass but no pass at all.
    """
    if type(bundle) is not ZkaBundle:
        raise BundleError("bundle must be an exact ZkaBundle")
    if type(bundle.kind) is not str or bundle.kind != BUNDLE_VERSION:
        raise BundleError(f"bundle kind must be {BUNDLE_VERSION}, got {bundle.kind!r}")
    projected_context = session_context_field(expected_session_context)
    _require_canonical_zka_field_context(bundle.context)
    if bundle.context != projected_context:
        raise BundleError(
            "bundle context does not equal the canonical BN254 projection of "
            "the envelope session_context (§12.7)"
        )
    if now is not None:
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise BundleError("bundle verification clock is invalid")
        if bundle.is_canonical_payload:
            # The pinned ZKA v0.9 verifier defines bundle freshness by expiry;
            # generatedAt is parsed and ordered above but has no independent
            # clock-skew limit. The full deployment verifier still receives the
            # unchanged metadata and may apply its pinned profile policy.
            try:
                expires_at = _rfc3339_timestamp(
                    bundle.to_dict()["metadata"]["expiresAt"]
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise BundleError("canonical ZKA bundle expiry is invalid") from exc
            if expires_at <= now:
                raise BundleError("canonical ZKA bundle has expired")
    present = bundle.present_proofs
    if not present:
        raise BundleError("EMPTY_BUNDLE: bundle carries no proofs")
    if "transaction" not in present and "coord_proof" not in present:
        raise BundleError(
            "EMPTY_BUNDLE: a transaction-less bundle MUST carry a coord_proof (§12.7 pure "
            "work-attestation rule)"
        )
    if bundle_verifier is None:
        raise BundleError(
            "no ZKA bundle verifier supplied; §12.7 verification is two-layer and "
            "the proof layer cannot be skipped"
        )
    bundle_snapshot = canonical_bytes(bundle.to_dict())
    bundle_content_hash = bundle.content_hash
    result = bundle_verifier(bundle)
    try:
        current_snapshot = canonical_bytes(bundle.to_dict())
        current_content_hash = bundle.content_hash
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise BundleError(
            "ZKA bundle verifier left the bundle malformed after verification"
        ) from exc
    if current_snapshot != bundle_snapshot or current_content_hash != bundle_content_hash:
        raise BundleError("ZKA bundle verifier mutated the bundle during verification")
    if type(result) is not BundleVerificationResult:
        raise BundleError(
            "ZKA bundle verifier must return an exact BundleVerificationResult"
        )
    if (
        type(result.bundle_content_hash) is not str
        or type(result.verified) is not bool
    ):
        raise BundleError("ZKA bundle verifier returned malformed verification fields")
    if result.bundle_content_hash != bundle_content_hash:
        raise BundleError("ZKA bundle verifier result is bound to a different bundle")
    if result.verified is not True:
        raise BundleError("ZKA bundle verifier rejected the bundle proofs")
