"""AFP §15 USD-obligation / WETH-settlement quote value objects.

The wire representation deliberately uses decimal strings and exact integer
arithmetic.  Validation is fail-closed: Base launch-profile constants,
addresses, timestamps, nonces, BN254 fields, settlement arithmetic, and policy
bindings must already be canonical; this module never normalizes signed input.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import re
from typing import Any, Optional

from afp_session.atoms import AfpCommitSignature
from afp_session.canonical import canonical_json as _canonical_json
from afp_session.canonical import jcs_digest, qb64
from afp_session.poseidon2 import Poseidon2ProfileError, hash_fields, load_profile

__all__ = [
    "PAYMENT_QUOTE_KIND",
    "PAYMENT_POLICY_KIND",
    "BASE_CHAIN_ID",
    "BASE_WETH9",
    "HARD_S3_RISK_PROFILE",
    "MAX_NOTE_VALUE_WEI",
    "BN254_SCALAR_MODULUS",
    "PaymentQuoteError",
    "Obligation",
    "Settlement",
    "Rate",
    "PaymentDeployment",
    "AfpPaymentPolicyV1",
    "AfpPaymentQuoteV1",
    "settlement_amount_wei",
    "within_slippage",
    "INTERACTION_CONTEXT_TAG",
    "field_from_digest",
    "fold_interaction_context",
    "derive_interaction_context",
]

PAYMENT_QUOTE_KIND = "afp:payment-quote:v1"
PAYMENT_POLICY_KIND = "afp:payment-policy:v1"
BASE_CHAIN_ID = 8453
BASE_WETH9 = "0x4200000000000000000000000000000000000006"
HARD_S3_RISK_PROFILE = "zka:asset-risk:s3-hard:v1"
MAX_NOTE_VALUE_WEI = 2**120 - 1
BN254_SCALAR_MODULUS = int(
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    16,
)

_POSITIVE_DECIMAL_RE = re.compile(r"[1-9][0-9]*\Z")
_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}\Z")
_QUOTE_HASH_RE = re.compile(r"D_[0-9a-f]{64}\Z")
_SESSION_CONTEXT_RE = re.compile(r"X_[0-9a-f]{64}\Z")
_BYTES32_RE = re.compile(r"0x[0-9a-f]{64}\Z")
_UTC_SECONDS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class PaymentQuoteError(ValueError):
    """A §15 quote, policy, or derived value is not canonical or valid."""


def _signature_from_wire(data: object, field: str) -> AfpCommitSignature:
    signature_data = _require_wire_keys(
        data,
        required=frozenset({"signed_by", "kel_event_dig", "signature", "signed_at"}),
        field=field,
    )
    try:
        return AfpCommitSignature.from_dict(signature_data)
    except (KeyError, TypeError, ValueError) as exc:
        raise PaymentQuoteError(f"{field} is malformed") from exc


def _require_wire_keys(
    data: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    field: str,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise PaymentQuoteError(f"{field} must be an object")
    keys = set(data)
    missing = required - keys
    unknown = keys - required - optional
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown {sorted(unknown)!r}")
        raise PaymentQuoteError(f"{field} has noncanonical keys: {', '.join(details)}")
    return data


def _positive_decimal(value: object, field: str) -> int:
    if not isinstance(value, str) or _POSITIVE_DECIMAL_RE.fullmatch(value) is None:
        raise PaymentQuoteError(f"{field} must be a positive canonical decimal string")
    return int(value)


def _settlement_amount(value: object) -> int:
    amount = _positive_decimal(value, "settlement.amount_wei")
    if amount > MAX_NOTE_VALUE_WEI:
        raise PaymentQuoteError(
            "settlement.amount_wei must be at most the ZKA note bound 2^120 - 1"
        )
    return amount


def _bounded_bps(value: object, field: str = "max_slippage_bps") -> int:
    if type(value) is not int or not 0 <= value <= 10_000:
        raise PaymentQuoteError(f"{field} must be an integer in 0..10000")
    return value


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentQuoteError(f"{field} must be a non-empty string")
    return value


def _canonical_address(value: object, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            f"{field} must be lowercase 0x followed by 40 hexadecimal digits"
        )
    return value


def _canonical_field(value: object, field: str) -> str:
    if not isinstance(value, str) or _BYTES32_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            f"{field} must be lowercase 0x followed by 64 hexadecimal digits"
        )
    integer = int(value[2:], 16)
    if not 1 <= integer < BN254_SCALAR_MODULUS:
        raise PaymentQuoteError(f"{field} must be a nonzero canonical BN254 scalar")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECONDS_RE.fullmatch(value) is None:
        raise PaymentQuoteError(f"{field} must use whole-second RFC 3339 UTC form")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PaymentQuoteError(f"{field} must represent a valid UTC instant") from exc


def settlement_amount_wei(
    obligation_amount_minor: str,
    rate_usd_minor: str,
    rate_weth_wei: str,
) -> str:
    """Return ``ceil(obligation * weth_wei / usd_minor)`` exactly (§15.2)."""
    obligation = _positive_decimal(obligation_amount_minor, "obligation.amount_minor")
    usd_minor = _positive_decimal(rate_usd_minor, "rate.usd_minor")
    weth_wei = _positive_decimal(rate_weth_wei, "rate.weth_wei")
    amount = str((obligation * weth_wei + usd_minor - 1) // usd_minor)
    _settlement_amount(amount)
    return amount


def within_slippage(
    usd_minor: str,
    weth_wei: str,
    reference_usd_minor: str,
    reference_weth_wei: str,
    max_slippage_bps: int,
) -> bool:
    """Evaluate the normative §15.2 cross-multiplied slippage inequality."""
    usd = _positive_decimal(usd_minor, "rate.usd_minor")
    weth = _positive_decimal(weth_wei, "rate.weth_wei")
    reference_usd = _positive_decimal(
        reference_usd_minor, "rate.reference_usd_minor"
    )
    reference_weth = _positive_decimal(
        reference_weth_wei, "rate.reference_weth_wei"
    )
    bps = _bounded_bps(max_slippage_bps)
    deviation = abs(usd * reference_weth - reference_usd * weth)
    return deviation * 10_000 <= bps * weth * reference_usd


# The UTF-8 bytes "zka/pay/interaction-context/v1", right-aligned in a
# 32-byte word (ZKA sdd_pay_interaction_binding.md §2; profile v1 frozen).
INTERACTION_CONTEXT_TAG = int.from_bytes(
    b"zka/pay/interaction-context/v1".rjust(32, b"\x00"), "big"
)

_POSEIDON2_PROFILE_PATH = Path(
    os.environ.get("AFP_KDC_POSEIDON2_PROFILE")
    or Path(__file__).resolve().parents[2]
    / "docs"
    / "kdc_v1_0_2_poseidon2_parameters.json"
)
_poseidon2_profile: dict[str, Any] | None = None


def _poseidon2() -> dict[str, Any]:
    # Idempotent lazy load; a concurrent double-load is harmless (same
    # digest-validated artifact, atomic rebind).
    global _poseidon2_profile
    if _poseidon2_profile is None:
        try:
            _poseidon2_profile = load_profile(_POSEIDON2_PROFILE_PATH)
        except Poseidon2ProfileError as exc:
            raise PaymentQuoteError(
                "AFP-KDC Poseidon2 profile unavailable at "
                f"{_POSEIDON2_PROFILE_PATH} (set AFP_KDC_POSEIDON2_PROFILE to "
                "override)"
            ) from exc
    return _poseidon2_profile


def field_from_digest(digest_bytes: bytes) -> int:
    """Reduce one 32-byte digest into the BN254 scalar field (§15.4, SDD §3.3).

    Plain big-endian reduction modulo ``r`` — not the retired
    ``1 + (x mod (r - 1))`` mapping.  A zero result is rejected fail-closed,
    never substituted; producers derive at quote-construction time, so
    rejection there costs only a reissue with a fresh nonce.
    """
    if not isinstance(digest_bytes, bytes) or len(digest_bytes) != 32:
        raise PaymentQuoteError("field reduction input must be exactly 32 bytes")
    value = int.from_bytes(digest_bytes, "big") % BN254_SCALAR_MODULUS
    if value == 0:
        raise PaymentQuoteError("digest reduces to zero in the BN254 scalar field")
    return value


def fold_interaction_context(
    afp_quote_hash_field: int, session_context_field: int
) -> int:
    """ZKA/Pay interaction-context fold v1 over two canonical field elements.

    ``state = Poseidon2(tag, 2); state = Poseidon2(state, afp_quote_hash);
    state = Poseidon2(state, session_context)`` — input order is normative
    (§15.4; ZKA sdd_pay_interaction_binding.md §2, pinned at revision db39afd).
    """
    for label, value in (
        ("afp_quote_hash", afp_quote_hash_field),
        ("session_context", session_context_field),
    ):
        if type(value) is not int or not 1 <= value < BN254_SCALAR_MODULUS:
            raise PaymentQuoteError(
                f"{label} must be a canonical nonzero BN254 field element"
            )
    profile = _poseidon2()
    state = hash_fields([INTERACTION_CONTEXT_TAG, 2], profile)
    state = hash_fields([state, afp_quote_hash_field], profile)
    state = hash_fields([state, session_context_field], profile)
    if state == 0:
        raise PaymentQuoteError("interaction_context fold output is zero")
    return state


def derive_interaction_context(quote_hash: str, session_context: str) -> str:
    """Derive the ZKA payment interaction context (§15.4).

    ``quote_hash`` must be the §15.3 ``D_`` digest and ``session_context`` the
    §5.2 ``X_`` digest; any other derivation code is out of profile and is
    rejected, never mapped. The fold consumes their 32-byte payloads reduced
    into the field, and the wire form of the quote digest stays unreduced
    (recomputing parties reduce first).
    """
    fields = []
    for label, value, pattern, code in (
        ("quote_hash", quote_hash, _QUOTE_HASH_RE, "D_"),
        ("session_context", session_context, _SESSION_CONTEXT_RE, "X_"),
    ):
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise PaymentQuoteError(f"{label} must be a canonical {code} digest")
        fields.append(field_from_digest(bytes.fromhex(value[2:])))
    return f"0x{fold_interaction_context(fields[0], fields[1]):064x}"


@dataclass(frozen=True)
class Obligation:
    currency: str
    amount_minor: str

    def __post_init__(self) -> None:
        if self.currency != "USD":
            raise PaymentQuoteError("obligation.currency must be USD")
        _positive_decimal(self.amount_minor, "obligation.amount_minor")

    def to_dict(self) -> dict[str, Any]:
        return {"currency": self.currency, "amount_minor": self.amount_minor}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Obligation":
        _require_wire_keys(
            data,
            required=frozenset({"currency", "amount_minor"}),
            field="obligation",
        )
        return cls(currency=data["currency"], amount_minor=data["amount_minor"])


@dataclass(frozen=True)
class Settlement:
    chain_id: int
    asset: str
    pool: str
    amount_wei: str
    pool_context: str
    asset_risk_profile: str

    def __post_init__(self) -> None:
        if type(self.chain_id) is not int or self.chain_id != BASE_CHAIN_ID:
            raise PaymentQuoteError(f"settlement.chain_id must be {BASE_CHAIN_ID}")
        _canonical_address(self.asset, "settlement.asset")
        if self.asset != BASE_WETH9:
            raise PaymentQuoteError("settlement.asset must be the Base WETH9 address")
        _canonical_address(self.pool, "settlement.pool")
        _settlement_amount(self.amount_wei)
        _canonical_field(self.pool_context, "settlement.pool_context")
        if self.asset_risk_profile != HARD_S3_RISK_PROFILE:
            raise PaymentQuoteError(
                f"settlement.asset_risk_profile must be {HARD_S3_RISK_PROFILE}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "asset": self.asset,
            "pool": self.pool,
            "amount_wei": self.amount_wei,
            "pool_context": self.pool_context,
            "asset_risk_profile": self.asset_risk_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settlement":
        _require_wire_keys(
            data,
            required=frozenset(
                {
                    "chain_id",
                    "asset",
                    "pool",
                    "amount_wei",
                    "pool_context",
                    "asset_risk_profile",
                }
            ),
            field="settlement",
        )
        return cls(**data)


@dataclass(frozen=True)
class Rate:
    source: str
    usd_minor: str
    weth_wei: str
    reference_usd_minor: str
    reference_weth_wei: str

    def __post_init__(self) -> None:
        _nonempty(self.source, "rate.source")
        _positive_decimal(self.usd_minor, "rate.usd_minor")
        _positive_decimal(self.weth_wei, "rate.weth_wei")
        _positive_decimal(self.reference_usd_minor, "rate.reference_usd_minor")
        _positive_decimal(self.reference_weth_wei, "rate.reference_weth_wei")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "usd_minor": self.usd_minor,
            "weth_wei": self.weth_wei,
            "reference_usd_minor": self.reference_usd_minor,
            "reference_weth_wei": self.reference_weth_wei,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rate":
        _require_wire_keys(
            data,
            required=frozenset(
                {
                    "source",
                    "usd_minor",
                    "weth_wei",
                    "reference_usd_minor",
                    "reference_weth_wei",
                }
            ),
            field="rate",
        )
        return cls(**data)


@dataclass(frozen=True)
class PaymentDeployment:
    chain_id: int
    asset: str
    pool: str
    pool_context: str
    asset_risk_profile: str

    def __post_init__(self) -> None:
        # Reuse Settlement's launch-profile validation with a harmless amount.
        Settlement(
            chain_id=self.chain_id,
            asset=self.asset,
            pool=self.pool,
            amount_wei="1",
            pool_context=self.pool_context,
            asset_risk_profile=self.asset_risk_profile,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "asset": self.asset,
            "pool": self.pool,
            "pool_context": self.pool_context,
            "asset_risk_profile": self.asset_risk_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PaymentDeployment":
        _require_wire_keys(
            data,
            required=frozenset(
                {"chain_id", "asset", "pool", "pool_context", "asset_risk_profile"}
            ),
            field="payment policy deployment",
        )
        return cls(**data)


@dataclass(frozen=True)
class AfpPaymentPolicyV1:
    deployment: PaymentDeployment
    accepted_rate_sources: tuple[str, ...]
    max_quote_lifetime_seconds: int
    max_slippage_bps: int
    required_finality: str
    kind: str = PAYMENT_POLICY_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_POLICY_KIND:
            raise PaymentQuoteError(f"policy kind must be {PAYMENT_POLICY_KIND}")
        if not isinstance(self.deployment, PaymentDeployment):
            raise PaymentQuoteError("deployment must be a PaymentDeployment")
        sources = self.accepted_rate_sources
        if not isinstance(sources, tuple) or not sources:
            raise PaymentQuoteError("accepted_rate_sources must be a non-empty tuple")
        if any(not isinstance(source, str) or not source for source in sources):
            raise PaymentQuoteError("accepted_rate_sources must contain non-empty names")
        if len(set(sources)) != len(sources):
            raise PaymentQuoteError("accepted_rate_sources must be unique")
        if type(self.max_quote_lifetime_seconds) is not int or self.max_quote_lifetime_seconds <= 0:
            raise PaymentQuoteError("max_quote_lifetime_seconds must be a positive integer")
        _bounded_bps(self.max_slippage_bps)
        if self.required_finality not in ("safe", "finalized"):
            raise PaymentQuoteError("required_finality must be safe or finalized")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "deployment": self.deployment.to_dict(),
            "accepted_rate_sources": list(self.accepted_rate_sources),
            "max_quote_lifetime_seconds": self.max_quote_lifetime_seconds,
            "max_slippage_bps": self.max_slippage_bps,
            "required_finality": self.required_finality,
        }

    @property
    def policy_hash(self) -> str:
        """Canonical §12 session ``profile_policy_hash`` for this policy."""
        return qb64("D", jcs_digest(self.to_dict()))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AfpPaymentPolicyV1":
        _require_wire_keys(
            data,
            required=frozenset(
                {
                    "kind",
                    "deployment",
                    "accepted_rate_sources",
                    "max_quote_lifetime_seconds",
                    "max_slippage_bps",
                    "required_finality",
                }
            ),
            field="payment policy",
        )
        sources = data["accepted_rate_sources"]
        if not isinstance(sources, list):
            raise PaymentQuoteError(
                "payment policy accepted_rate_sources must be a JSON array"
            )
        return cls(
            deployment=PaymentDeployment.from_dict(data["deployment"]),
            accepted_rate_sources=tuple(sources),
            max_quote_lifetime_seconds=data["max_quote_lifetime_seconds"],
            max_slippage_bps=data["max_slippage_bps"],
            required_finality=data["required_finality"],
            kind=data["kind"],
        )


@dataclass(frozen=True)
class AfpPaymentQuoteV1:
    quote_id: str
    session_ref: str
    session_context: str
    obligation: Obligation
    settlement: Settlement
    rate: Rate
    quoted_at: str
    expires_at: str
    max_slippage_bps: int
    quote_nonce: str
    initiator_signature: Optional[AfpCommitSignature] = None
    responder_signature: Optional[AfpCommitSignature] = None
    kind: str = PAYMENT_QUOTE_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_QUOTE_KIND:
            raise PaymentQuoteError(f"quote kind must be {PAYMENT_QUOTE_KIND}")
        _nonempty(self.quote_id, "quote_id")
        _nonempty(self.session_ref, "session_ref")
        if not isinstance(self.session_context, str) or _SESSION_CONTEXT_RE.fullmatch(
            self.session_context
        ) is None:
            raise PaymentQuoteError("session_context must be a canonical X_ digest")
        if not isinstance(self.obligation, Obligation):
            raise PaymentQuoteError("obligation must be an Obligation")
        if not isinstance(self.settlement, Settlement):
            raise PaymentQuoteError("settlement must be a Settlement")
        if not isinstance(self.rate, Rate):
            raise PaymentQuoteError("rate must be a Rate")
        quoted = _timestamp(self.quoted_at, "quoted_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= quoted:
            raise PaymentQuoteError("expires_at must be strictly later than quoted_at")
        _bounded_bps(self.max_slippage_bps)
        if not isinstance(self.quote_nonce, str) or _BYTES32_RE.fullmatch(self.quote_nonce) is None:
            raise PaymentQuoteError(
                "quote_nonce must be lowercase 0x followed by 64 hexadecimal digits"
            )
        expected = settlement_amount_wei(
            self.obligation.amount_minor,
            self.rate.usd_minor,
            self.rate.weth_wei,
        )
        if self.settlement.amount_wei != expected:
            raise PaymentQuoteError(
                f"settlement amount must equal deterministic ceiling result {expected}"
            )
        if not within_slippage(
            self.rate.usd_minor,
            self.rate.weth_wei,
            self.rate.reference_usd_minor,
            self.rate.reference_weth_wei,
            self.max_slippage_bps,
        ):
            raise PaymentQuoteError("rate exceeds the signed reference slippage bound")
        for field, signature in (
            ("initiator_signature", self.initiator_signature),
            ("responder_signature", self.responder_signature),
        ):
            if signature is not None and not isinstance(signature, AfpCommitSignature):
                raise PaymentQuoteError(f"{field} must be an AfpCommitSignature")
        # §15.4: the producer MUST perform the full derivation at
        # quote-construction time, before signature exchange and nonce
        # reservation — an out-of-profile session context or zero field
        # reduction rejects here, costing only a reissue with a fresh nonce.
        object.__setattr__(
            self,
            "_interaction_context",
            derive_interaction_context(self.quote_hash, self.session_context),
        )

    def quote_content(self) -> dict[str, Any]:
        """Return the canonical content both principals sign (§15.3)."""
        return {
            "kind": self.kind,
            "quote_id": self.quote_id,
            "session_ref": self.session_ref,
            "session_context": self.session_context,
            "obligation": self.obligation.to_dict(),
            "settlement": self.settlement.to_dict(),
            "rate": self.rate.to_dict(),
            "quoted_at": self.quoted_at,
            "expires_at": self.expires_at,
            "max_slippage_bps": self.max_slippage_bps,
            "quote_nonce": self.quote_nonce,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.quote_content()
        if self.initiator_signature is not None:
            data["initiator_signature"] = self.initiator_signature.to_dict()
        if self.responder_signature is not None:
            data["responder_signature"] = self.responder_signature.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AfpPaymentQuoteV1":
        _require_wire_keys(
            data,
            required=frozenset(
                {
                    "kind",
                    "quote_id",
                    "session_ref",
                    "session_context",
                    "obligation",
                    "settlement",
                    "rate",
                    "quoted_at",
                    "expires_at",
                    "max_slippage_bps",
                    "quote_nonce",
                }
            ),
            optional=frozenset({"initiator_signature", "responder_signature"}),
            field="payment quote",
        )
        return cls(
            quote_id=data["quote_id"],
            session_ref=data["session_ref"],
            session_context=data["session_context"],
            obligation=Obligation.from_dict(data["obligation"]),
            settlement=Settlement.from_dict(data["settlement"]),
            rate=Rate.from_dict(data["rate"]),
            quoted_at=data["quoted_at"],
            expires_at=data["expires_at"],
            max_slippage_bps=data["max_slippage_bps"],
            quote_nonce=data["quote_nonce"],
            initiator_signature=_signature_from_wire(
                data["initiator_signature"], "initiator_signature"
            )
            if "initiator_signature" in data
            else None,
            responder_signature=_signature_from_wire(
                data["responder_signature"], "responder_signature"
            )
            if "responder_signature" in data
            else None,
            kind=data["kind"],
        )

    @property
    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def quote_hash(self) -> str:
        return qb64("D", jcs_digest(self.quote_content()))

    @property
    def acceptance_record_hash(self) -> str:
        """§15.3 hash of the full signed quote, both signatures included."""
        return qb64("D", jcs_digest(self.to_dict(), floats=True))

    @property
    def interaction_context(self) -> str:
        # Derived once, fail-closed, in __post_init__ (§15.4).
        return self._interaction_context

    def validate(self, policy: AfpPaymentPolicyV1) -> None:
        """Validate the quote against one bilateral payment policy (§15.1)."""
        if not isinstance(policy, AfpPaymentPolicyV1):
            raise PaymentQuoteError("policy must be an AfpPaymentPolicyV1")
        expected_deployment = PaymentDeployment(
            chain_id=self.settlement.chain_id,
            asset=self.settlement.asset,
            pool=self.settlement.pool,
            pool_context=self.settlement.pool_context,
            asset_risk_profile=self.settlement.asset_risk_profile,
        )
        if expected_deployment != policy.deployment:
            raise PaymentQuoteError("quote deployment does not match payment policy")
        if self.rate.source not in policy.accepted_rate_sources:
            raise PaymentQuoteError("quote rate source is not accepted by payment policy")
        lifetime = (_timestamp(self.expires_at, "expires_at") - _timestamp(
            self.quoted_at, "quoted_at"
        )).total_seconds()
        if lifetime > policy.max_quote_lifetime_seconds:
            raise PaymentQuoteError("quote lifetime exceeds payment policy")
        if self.max_slippage_bps > policy.max_slippage_bps:
            raise PaymentQuoteError("quote slippage bound exceeds payment policy")
