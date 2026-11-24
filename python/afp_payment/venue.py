"""Venue-neutral AFP payment quote value objects.

The opt-in version-2 profile uses separate value objects from the published
Base-specific version-1 objects.  A quote signs the exact target and payment identities; the
bilateral policy carries the larger trusted deployment descriptor against
which those identities are checked.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Optional

from afp_session.atoms import AfpCommitSignature
from afp_session.profiles import AfpProfileDescriptor
from afp_session.canonical import canonical_json as _canonical_json
from afp_session.canonical import jcs_digest, qb64

from .quote import (
    HARD_S3_RISK_PROFILE,
    BN254_SCALAR_MODULUS,
    Obligation,
    PaymentQuoteError,
    _bounded_bps,
    _nonempty,
    _positive_decimal,
    _require_wire_keys,
    _signature_from_wire,
    _timestamp,
    derive_interaction_context,
    within_slippage,
)

__all__ = [
    "PAYMENT_QUOTE_V2_KIND",
    "PAYMENT_POLICY_V2_KIND",
    "AZTEC_NATIVE_PAY_VENUE",
    "AZTEC_PAY_RECEIPT_PROFILE",
    "AZTEC_PROTOCOL_FEE_ROUTE",
    "AZTEC_NULLIFIER_SEMANTICS",
    "MAX_U128",
    "VenueDeployment",
    "VenueSettlement",
    "VenueRate",
    "AfpPaymentPolicyV2",
    "AfpPaymentQuoteV2",
    "settlement_amount_atomic",
    "venue_profile_descriptor",
]

PAYMENT_QUOTE_V2_KIND = "afp:payment-quote:v2"
PAYMENT_POLICY_V2_KIND = "afp:payment-policy:v2"
AZTEC_NATIVE_PAY_VENUE = "zka:aztec:native-pay:v1"
AZTEC_PAY_RECEIPT_PROFILE = "zka:aztec:pay-receipt:v1"
AZTEC_PROTOCOL_FEE_ROUTE = "aztec-protocol-fee-v1"
AZTEC_NULLIFIER_SEMANTICS = "aztec-app-siloed-v1"
MAX_U128 = 2**128 - 1

_CHAIN_ID_RE = re.compile(r"[a-z0-9]{3,8}:[a-z0-9][a-z0-9._-]{0,31}\Z")
_ASSET_ID_RE = re.compile(
    r"([a-z0-9]{3,8}:[a-z0-9][a-z0-9._-]{0,31})/"
    r"([a-z0-9]{3,8}):([a-z0-9][a-z0-9._-]*)\Z"
)
_FIELD_RE = re.compile(r"0x[0-9a-f]{64}\Z")
_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"D_[0-9a-f]{64}\Z")


def _chain_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _CHAIN_ID_RE.fullmatch(value) is None:
        raise PaymentQuoteError(f"{field} must be a canonical CAIP-2 identifier")
    if value.startswith("eip155:") and re.fullmatch(r"eip155:[1-9][0-9]*", value) is None:
        raise PaymentQuoteError(f"{field} requires a positive canonical chain number")
    return value


def _asset_id(value: object, anchor_chain_id: str, field: str) -> str:
    if not isinstance(value, str):
        raise PaymentQuoteError(f"{field} must be a canonical CAIP-19 identifier")
    match = _ASSET_ID_RE.fullmatch(value)
    if match is None or match.group(1) != anchor_chain_id:
        raise PaymentQuoteError(
            f"{field} must be a canonical CAIP-19 identifier on anchor_chain_id"
        )
    if match.group(2) != "erc20" or _ADDRESS_RE.fullmatch(match.group(3)) is None:
        raise PaymentQuoteError(f"{field} erc20 reference must be a canonical address")
    _address(match.group(3), field)
    return value


def _field(value: object, field: str) -> str:
    if not isinstance(value, str) or _FIELD_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            f"{field} must be lowercase 0x followed by 64 hexadecimal digits"
        )
    if not 1 <= int(value[2:], 16) < BN254_SCALAR_MODULUS:
        raise PaymentQuoteError(f"{field} must be a canonical nonzero BN254 scalar")
    return value


def _address(value: object, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            f"{field} must be lowercase 0x followed by 40 hexadecimal digits"
        )
    if int(value[2:], 16) == 0:
        raise PaymentQuoteError(f"{field} must be a nonzero address")
    return value


def _manifest_hash(value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            "manifest_hash must be sha256: followed by 64 lowercase hexadecimal digits"
        )
    return value


def settlement_amount_atomic(
    obligation_amount_minor: str,
    rate_usd_minor: str,
    rate_asset_atomic: str,
) -> str:
    """Return ``ceil(obligation * asset_atomic / usd_minor)`` exactly."""
    obligation = _positive_decimal(obligation_amount_minor, "obligation.amount_minor")
    usd_minor = _positive_decimal(rate_usd_minor, "rate.usd_minor")
    asset_atomic = _positive_decimal(rate_asset_atomic, "rate.asset_atomic")
    amount = (obligation * asset_atomic + usd_minor - 1) // usd_minor
    if amount > MAX_U128:
        raise PaymentQuoteError("settlement.amount_atomic must be at most u128::MAX")
    return str(amount)


@dataclass(frozen=True)
class VenueDeployment:
    """Trusted immutable deployment tuple selected by bilateral policy."""

    venue_profile: str
    network_id: str
    anchor_chain_id: str
    asset_id: str
    asset_commitment: str
    contract_class_id: str
    contract_instance_id: str
    settlement_portal_id: str
    manifest_hash: str
    fee_route: str
    receipt_profile: str
    nullifier_semantics: str
    max_note_value: str
    asset_risk_profile: str

    def __post_init__(self) -> None:
        if self.venue_profile != AZTEC_NATIVE_PAY_VENUE:
            raise PaymentQuoteError(
                f"venue_profile must be {AZTEC_NATIVE_PAY_VENUE}"
            )
        network_id = _chain_id(self.network_id, "network_id")
        if not network_id.startswith("aztec:"):
            raise PaymentQuoteError("network_id must identify an Aztec network")
        anchor = _chain_id(self.anchor_chain_id, "anchor_chain_id")
        if not anchor.startswith("eip155:"):
            raise PaymentQuoteError("anchor_chain_id must identify an EVM L1")
        _asset_id(self.asset_id, anchor, "asset_id")
        _field(self.asset_commitment, "asset_commitment")
        _field(self.contract_class_id, "contract_class_id")
        _field(self.contract_instance_id, "contract_instance_id")
        _address(self.settlement_portal_id, "settlement_portal_id")
        _manifest_hash(self.manifest_hash)
        if self.fee_route != AZTEC_PROTOCOL_FEE_ROUTE:
            raise PaymentQuoteError(f"fee_route must be {AZTEC_PROTOCOL_FEE_ROUTE}")
        if self.receipt_profile != AZTEC_PAY_RECEIPT_PROFILE:
            raise PaymentQuoteError(
                f"receipt_profile must be {AZTEC_PAY_RECEIPT_PROFILE}"
            )
        if self.nullifier_semantics != AZTEC_NULLIFIER_SEMANTICS:
            raise PaymentQuoteError(
                f"nullifier_semantics must be {AZTEC_NULLIFIER_SEMANTICS}"
            )
        maximum = _positive_decimal(self.max_note_value, "max_note_value")
        if maximum != MAX_U128:
            raise PaymentQuoteError("max_note_value must equal u128::MAX")
        if self.asset_risk_profile != HARD_S3_RISK_PROFILE:
            raise PaymentQuoteError(
                f"asset_risk_profile must be {HARD_S3_RISK_PROFILE}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "venue_profile": self.venue_profile,
            "network_id": self.network_id,
            "anchor_chain_id": self.anchor_chain_id,
            "asset_id": self.asset_id,
            "asset_commitment": self.asset_commitment,
            "contract_class_id": self.contract_class_id,
            "contract_instance_id": self.contract_instance_id,
            "settlement_portal_id": self.settlement_portal_id,
            "manifest_hash": self.manifest_hash,
            "fee_route": self.fee_route,
            "receipt_profile": self.receipt_profile,
            "nullifier_semantics": self.nullifier_semantics,
            "max_note_value": self.max_note_value,
            "asset_risk_profile": self.asset_risk_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VenueDeployment":
        wire = _require_wire_keys(
            data, required=frozenset(cls.__dataclass_fields__), field="venue deployment"
        )
        return cls(**wire)


@dataclass(frozen=True)
class VenueSettlement:
    """The exact venue identities and value authenticated by a V2 quote."""

    venue_profile: str
    network_id: str
    anchor_chain_id: str
    asset_id: str
    contract_instance_id: str
    settlement_portal_id: str
    manifest_hash: str
    recipient_id: str
    amount_atomic: str
    asset_risk_profile: str

    def __post_init__(self) -> None:
        if self.venue_profile != AZTEC_NATIVE_PAY_VENUE:
            raise PaymentQuoteError(
                f"venue_profile must be {AZTEC_NATIVE_PAY_VENUE}"
            )
        network = _chain_id(self.network_id, "settlement.network_id")
        if not network.startswith("aztec:"):
            raise PaymentQuoteError("settlement.network_id must identify Aztec")
        anchor = _chain_id(self.anchor_chain_id, "settlement.anchor_chain_id")
        if not anchor.startswith("eip155:"):
            raise PaymentQuoteError("settlement.anchor_chain_id must identify an EVM L1")
        _asset_id(self.asset_id, anchor, "settlement.asset_id")
        _field(self.contract_instance_id, "settlement.contract_instance_id")
        _address(self.settlement_portal_id, "settlement.settlement_portal_id")
        _manifest_hash(self.manifest_hash)
        _field(self.recipient_id, "settlement.recipient_id")
        amount = _positive_decimal(self.amount_atomic, "settlement.amount_atomic")
        if amount > MAX_U128:
            raise PaymentQuoteError("settlement.amount_atomic must be at most u128::MAX")
        if self.asset_risk_profile != HARD_S3_RISK_PROFILE:
            raise PaymentQuoteError(
                f"settlement.asset_risk_profile must be {HARD_S3_RISK_PROFILE}"
            )

    def deployment_identity(self) -> tuple[str, ...]:
        return (
            self.venue_profile,
            self.network_id,
            self.anchor_chain_id,
            self.asset_id,
            self.contract_instance_id,
            self.settlement_portal_id,
            self.manifest_hash,
            self.asset_risk_profile,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "venue_profile": self.venue_profile,
            "network_id": self.network_id,
            "anchor_chain_id": self.anchor_chain_id,
            "asset_id": self.asset_id,
            "contract_instance_id": self.contract_instance_id,
            "settlement_portal_id": self.settlement_portal_id,
            "manifest_hash": self.manifest_hash,
            "recipient_id": self.recipient_id,
            "amount_atomic": self.amount_atomic,
            "asset_risk_profile": self.asset_risk_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VenueSettlement":
        wire = _require_wire_keys(
            data, required=frozenset(cls.__dataclass_fields__), field="venue settlement"
        )
        return cls(**wire)


@dataclass(frozen=True)
class VenueRate:
    source: str
    usd_minor: str
    asset_atomic: str
    reference_usd_minor: str
    reference_asset_atomic: str

    def __post_init__(self) -> None:
        _nonempty(self.source, "rate.source")
        for name in (
            "usd_minor",
            "asset_atomic",
            "reference_usd_minor",
            "reference_asset_atomic",
        ):
            _positive_decimal(getattr(self, name), f"rate.{name}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "usd_minor": self.usd_minor,
            "asset_atomic": self.asset_atomic,
            "reference_usd_minor": self.reference_usd_minor,
            "reference_asset_atomic": self.reference_asset_atomic,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VenueRate":
        wire = _require_wire_keys(
            data, required=frozenset(cls.__dataclass_fields__), field="venue rate"
        )
        return cls(**wire)


@dataclass(frozen=True)
class AfpPaymentPolicyV2:
    deployment: VenueDeployment
    accepted_rate_sources: tuple[str, ...]
    max_quote_lifetime_seconds: int
    max_slippage_bps: int
    required_finality: str
    kind: str = PAYMENT_POLICY_V2_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_POLICY_V2_KIND:
            raise PaymentQuoteError(f"policy kind must be {PAYMENT_POLICY_V2_KIND}")
        if not isinstance(self.deployment, VenueDeployment):
            raise PaymentQuoteError("deployment must be a VenueDeployment")
        sources = self.accepted_rate_sources
        if not isinstance(sources, tuple) or not sources:
            raise PaymentQuoteError("accepted_rate_sources must be a non-empty tuple")
        if any(not isinstance(source, str) or not source for source in sources):
            raise PaymentQuoteError("accepted_rate_sources must contain non-empty names")
        if len(set(sources)) != len(sources):
            raise PaymentQuoteError("accepted_rate_sources must be unique")
        if (
            type(self.max_quote_lifetime_seconds) is not int
            or self.max_quote_lifetime_seconds <= 0
        ):
            raise PaymentQuoteError(
                "max_quote_lifetime_seconds must be a positive integer"
            )
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
        return qb64("D", jcs_digest(self.to_dict()))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AfpPaymentPolicyV2":
        wire = _require_wire_keys(
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
            field="venue payment policy",
        )
        sources = wire["accepted_rate_sources"]
        if not isinstance(sources, list):
            raise PaymentQuoteError(
                "payment policy accepted_rate_sources must be a JSON array"
            )
        return cls(
            deployment=VenueDeployment.from_dict(wire["deployment"]),
            accepted_rate_sources=tuple(sources),
            max_quote_lifetime_seconds=wire["max_quote_lifetime_seconds"],
            max_slippage_bps=wire["max_slippage_bps"],
            required_finality=wire["required_finality"],
            kind=wire["kind"],
        )


@dataclass(frozen=True)
class AfpPaymentQuoteV2:
    quote_id: str
    session_ref: str
    session_context: str
    policy_hash: str
    obligation: Obligation
    settlement: VenueSettlement
    rate: VenueRate
    quoted_at: str
    expires_at: str
    max_slippage_bps: int
    quote_nonce: str
    initiator_signature: Optional[AfpCommitSignature] = None
    responder_signature: Optional[AfpCommitSignature] = None
    kind: str = PAYMENT_QUOTE_V2_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_QUOTE_V2_KIND:
            raise PaymentQuoteError(f"quote kind must be {PAYMENT_QUOTE_V2_KIND}")
        _nonempty(self.quote_id, "quote_id")
        _nonempty(self.session_ref, "session_ref")
        if not isinstance(self.session_context, str) or re.fullmatch(
            r"X_[0-9a-f]{64}", self.session_context
        ) is None:
            raise PaymentQuoteError("session_context must be a canonical X_ digest")
        if not isinstance(self.policy_hash, str) or _DIGEST_RE.fullmatch(
            self.policy_hash
        ) is None:
            raise PaymentQuoteError("policy_hash must be a canonical D_ digest")
        if not isinstance(self.obligation, Obligation):
            raise PaymentQuoteError("obligation must be an Obligation")
        if not isinstance(self.settlement, VenueSettlement):
            raise PaymentQuoteError("settlement must be a VenueSettlement")
        if not isinstance(self.rate, VenueRate):
            raise PaymentQuoteError("rate must be a VenueRate")
        quoted = _timestamp(self.quoted_at, "quoted_at")
        expires = _timestamp(self.expires_at, "expires_at")
        if expires <= quoted:
            raise PaymentQuoteError("expires_at must be strictly later than quoted_at")
        _bounded_bps(self.max_slippage_bps)
        if not isinstance(self.quote_nonce, str) or _FIELD_RE.fullmatch(self.quote_nonce) is None:
            raise PaymentQuoteError("quote_nonce must be canonical 32-byte hexadecimal")
        expected = settlement_amount_atomic(
            self.obligation.amount_minor,
            self.rate.usd_minor,
            self.rate.asset_atomic,
        )
        if self.settlement.amount_atomic != expected:
            raise PaymentQuoteError(
                f"settlement amount must equal deterministic ceiling result {expected}"
            )
        if not within_slippage(
            self.rate.usd_minor,
            self.rate.asset_atomic,
            self.rate.reference_usd_minor,
            self.rate.reference_asset_atomic,
            self.max_slippage_bps,
        ):
            raise PaymentQuoteError("rate exceeds the signed reference slippage bound")
        for field, signature in (
            ("initiator_signature", self.initiator_signature),
            ("responder_signature", self.responder_signature),
        ):
            if signature is not None and not isinstance(signature, AfpCommitSignature):
                raise PaymentQuoteError(f"{field} must be an AfpCommitSignature")
        object.__setattr__(
            self,
            "_interaction_context",
            derive_interaction_context(self.quote_hash, self.session_context),
        )

    def quote_content(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "quote_id": self.quote_id,
            "session_ref": self.session_ref,
            "session_context": self.session_context,
            "policy_hash": self.policy_hash,
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
    def from_dict(cls, data: dict[str, Any]) -> "AfpPaymentQuoteV2":
        wire = _require_wire_keys(
            data,
            required=frozenset(
                {
                    "kind",
                    "quote_id",
                    "session_ref",
                    "session_context",
                    "policy_hash",
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
            field="venue payment quote",
        )
        return cls(
            quote_id=wire["quote_id"],
            session_ref=wire["session_ref"],
            session_context=wire["session_context"],
            policy_hash=wire["policy_hash"],
            obligation=Obligation.from_dict(wire["obligation"]),
            settlement=VenueSettlement.from_dict(wire["settlement"]),
            rate=VenueRate.from_dict(wire["rate"]),
            quoted_at=wire["quoted_at"],
            expires_at=wire["expires_at"],
            max_slippage_bps=wire["max_slippage_bps"],
            quote_nonce=wire["quote_nonce"],
            initiator_signature=_signature_from_wire(
                wire["initiator_signature"], "initiator_signature"
            )
            if "initiator_signature" in wire
            else None,
            responder_signature=_signature_from_wire(
                wire["responder_signature"], "responder_signature"
            )
            if "responder_signature" in wire
            else None,
            kind=wire["kind"],
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
        return self._interaction_context

    def validate(self, policy: AfpPaymentPolicyV2) -> None:
        if not isinstance(policy, AfpPaymentPolicyV2):
            raise PaymentQuoteError("policy must be an AfpPaymentPolicyV2")
        if self.policy_hash != policy.policy_hash:
            raise PaymentQuoteError("quote policy_hash does not match payment policy")
        deployment = policy.deployment
        expected_identity = (
            deployment.venue_profile,
            deployment.network_id,
            deployment.anchor_chain_id,
            deployment.asset_id,
            deployment.contract_instance_id,
            deployment.settlement_portal_id,
            deployment.manifest_hash,
            deployment.asset_risk_profile,
        )
        if self.settlement.deployment_identity() != expected_identity:
            raise PaymentQuoteError("quote deployment does not match payment policy")
        if int(self.settlement.amount_atomic) > int(deployment.max_note_value):
            raise PaymentQuoteError("settlement amount exceeds deployment value bound")
        if self.rate.source not in policy.accepted_rate_sources:
            raise PaymentQuoteError("quote rate source is not accepted by payment policy")
        lifetime = (
            _timestamp(self.expires_at, "expires_at")
            - _timestamp(self.quoted_at, "quoted_at")
        ).total_seconds()
        if lifetime > policy.max_quote_lifetime_seconds:
            raise PaymentQuoteError("quote lifetime exceeds payment policy")
        if self.max_slippage_bps > policy.max_slippage_bps:
            raise PaymentQuoteError("quote slippage bound exceeds payment policy")




def venue_profile_descriptor() -> AfpProfileDescriptor:
    """Return the published descriptor for bilateral negotiation.

    Registration does not supply a qualified manifest or enable a live route.
    """
    return AfpProfileDescriptor(
        name="pay_venue",
        version="2.0",
        spec_ref="AFP 0.3.12-draft §15.9",
        atom_kinds=[PAYMENT_QUOTE_V2_KIND, "afp:payment-receipt:v2"],
        policy_schema_ref=PAYMENT_POLICY_V2_KIND,
        status="experimental",
    )
