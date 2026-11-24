"""Observational settlement receipts and monotonic finality for AFP §15.6."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import copy
import re
from types import MappingProxyType
from threading import Lock
from typing import Any, Callable, Mapping, Optional, Protocol

from afp_session import SessionError, VerifiedLiveSession, session_datetime_to_unix
from afp_session.atoms import AfpSessionStatus

from .authentication import AcceptedPaymentQuote
from .replay import (
    AcceptanceEvidenceVerifier,
    _AcceptanceVerifierView,
)
from .quote import (
    BASE_CHAIN_ID,
    BASE_WETH9,
    BN254_SCALAR_MODULUS,
    AfpPaymentPolicyV1,
    PaymentQuoteError,
)

from .venue import AfpPaymentPolicyV2, AfpPaymentQuoteV2, VenueSettlement

__all__ = [
    "PAYMENT_RECEIPT_KIND",
    "PAYMENT_RECEIPT_V2_KIND",
    "PaymentRouteEvidenceV2",
    "AfpPaymentReceiptV2",
    "PaymentRouteEvidence",
    "AfpPaymentReceiptV1",
    "FinalityEvidenceVerifier",
    "PaymentReceiptVerificationContext",
    "ReceiptFinalityTracker",
]

PAYMENT_RECEIPT_KIND = "afp:payment-receipt:v1"
PAYMENT_RECEIPT_V2_KIND = "afp:payment-receipt:v2"

_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}\Z")
_BN254_RE = re.compile(r"0x[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"D_[0-9a-f]{64}\Z")
_POSITIVE_DECIMAL_RE = re.compile(r"[1-9][0-9]*\Z")
_UTC_SECONDS_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_FINALITY_RANK = {"pending": 0, "safe": 1, "finalized": 2}


def _verify_accepted_quote(
    accepted: AcceptedPaymentQuote,
    acceptance_verifier: AcceptanceEvidenceVerifier,
):
    if not isinstance(accepted, AcceptedPaymentQuote):
        raise PaymentQuoteError("accepted quote capability is malformed")
    if acceptance_verifier is None or not callable(
        getattr(acceptance_verifier, "verify_reservation", None)
    ):
        raise PaymentQuoteError("acceptance ledger verifier is required")
    quote = accepted.to_quote()
    try:
        verified = acceptance_verifier.verify_reservation(
            accepted.quote_id,
            accepted.quote_hash,
            accepted.quote_nonce,
            accepted.acceptance_record_hash,
        )
    except Exception as exc:
        raise PaymentQuoteError("acceptance ledger verification failed closed") from exc
    if verified is not True:
        raise PaymentQuoteError("accepted quote tuple is absent from acceptance ledger")
    return quote


def _quote_instant(value: str, field: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError) as exc:
        raise PaymentQuoteError(f"quote {field} is malformed") from exc


def _trusted_now(clock: Callable[[], datetime]) -> datetime:
    try:
        now = clock()
    except Exception as exc:
        raise PaymentQuoteError("deployment clock failed closed") from exc
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PaymentQuoteError("deployment clock must return a timezone-aware datetime")
    return now.astimezone(timezone.utc)


def _require_dispatch_window(
    accepted: AcceptedPaymentQuote, quote, live_session: object, now: datetime
) -> None:
    """Fail closed unless dispatch is inside the quote window and live session."""
    if now < _quote_instant(quote.quoted_at, "quoted_at"):
        raise PaymentQuoteError("payment quote is not yet valid at quoted_at")
    if now >= _quote_instant(quote.expires_at, "expires_at"):
        raise PaymentQuoteError("payment quote has expired; route dispatch refused")
    if not isinstance(live_session, VerifiedLiveSession):
        raise PaymentQuoteError(
            "route dispatch requires a VerifiedLiveSession capability"
        )
    try:
        session = live_session.to_atom()
        session_expires_at = session_datetime_to_unix(session.expires_at, "expires_at")
    except (SessionError, ValueError) as exc:
        raise PaymentQuoteError(
            f"live-session capability is invalid: {exc}"
        ) from exc
    if session.status is not AfpSessionStatus.ACTIVE:
        raise PaymentQuoteError("route dispatch requires a live ACTIVE session")
    if now.timestamp() >= session_expires_at:
        raise PaymentQuoteError("live session has expired; route dispatch refused")
    expected_profile = "pay_venue" if isinstance(quote, AfpPaymentQuoteV2) else "pay"
    if session.profile != expected_profile:
        raise PaymentQuoteError(
            f"route dispatch requires a {expected_profile} profile session"
        )
    if quote.session_ref != session.id:
        raise PaymentQuoteError("quote session_ref does not match the live session")
    if quote.session_context != session.session_context:
        raise PaymentQuoteError("quote session_context does not match the live session")
    if session.profile_policy_hash != accepted.profile_policy_hash:
        raise PaymentQuoteError(
            "live session profile_policy_hash does not match the accepted quote"
        )


def _require_accepted_policy(accepted: AcceptedPaymentQuote, quote, policy) -> None:
    if not isinstance(policy, (AfpPaymentPolicyV1, AfpPaymentPolicyV2)):
        raise PaymentQuoteError("payment policy must be an AfpPaymentPolicyV1 or V2")
    if policy.policy_hash != accepted.profile_policy_hash:
        raise PaymentQuoteError(
            "policy_hash does not match the accepted session profile_policy_hash"
        )
    quote.validate(policy)


def _require_verified_receipt(
    verifier, receipt, route, policy, expires_at: datetime
) -> None:
    """Fail closed unless the receipt echoes the route and its evidence verifies."""
    receipt_fields = receipt.to_dict()
    for field, expected in route.to_dict().items():
        if receipt_fields.get(field) != expected:
            raise PaymentQuoteError(f"receipt {field} does not match route evidence")
    try:
        verified = verifier.verify(
            receipt=receipt, route=route, policy=policy, expires_at=expires_at
        )
    except Exception as exc:
        raise PaymentQuoteError("finality evidence verification failed closed") from exc
    if verified is not True:
        raise PaymentQuoteError(
            "finality evidence does not verify for deployment and level"
        )


def _route_authority_call(accepted, authority, method, transaction_id):
    try:
        result = getattr(authority, method)(
            accepted.quote_id,
            accepted.quote_hash,
            accepted.quote_nonce,
            accepted.acceptance_record_hash,
            transaction_id,
        )
    except Exception as exc:
        raise PaymentQuoteError("acceptance route authority failed closed") from exc
    if result is not True:
        raise PaymentQuoteError("transaction is not claimed by accepted quote")


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PaymentQuoteError(f"{field} must be a non-empty string")
    return value


def _strict_object(
    value: object, *, required: frozenset[str], field: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PaymentQuoteError(f"{field} must be an object")
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        unknown = sorted(keys - required)
        raise PaymentQuoteError(
            f"{field} has noncanonical keys: missing {missing!r}, unknown {unknown!r}"
        )
    return value


def _canonical_address(value: object, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS_RE.fullmatch(value) is None:
        raise PaymentQuoteError(
            f"{field} must be lowercase 0x followed by 40 hexadecimal digits"
        )
    return value


def _canonical_context(value: object) -> str:
    if not isinstance(value, str) or _BN254_RE.fullmatch(value) is None:
        raise PaymentQuoteError("interaction_context is not canonical BN254 hex")
    integer = int(value[2:], 16)
    if not 1 <= integer < BN254_SCALAR_MODULUS:
        raise PaymentQuoteError("interaction_context must be a nonzero BN254 scalar")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _UTC_SECONDS_RE.fullmatch(value) is None:
        raise PaymentQuoteError("observed_at must use whole-second RFC 3339 UTC form")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PaymentQuoteError("observed_at must represent a valid UTC instant") from exc
    return value


def _freeze_json(value: object, field: str) -> object:
    if value is None or isinstance(value, (str, bool)):
        return value
    if type(value) is int:
        return value
    if isinstance(value, list):
        return tuple(_freeze_json(item, field) for item in value)
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise PaymentQuoteError(f"{field} object keys must be strings")
        return MappingProxyType(
            {key: _freeze_json(item, field) for key, item in value.items()}
        )
    raise PaymentQuoteError(f"{field} must contain only canonical JSON values")


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _evidence(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not value:
        raise PaymentQuoteError("finality_evidence must be a non-empty object")
    detached = _freeze_json(copy.deepcopy(value), "finality_evidence")
    assert isinstance(detached, Mapping)
    return detached


@dataclass(frozen=True)
class PaymentRouteEvidence:
    """Immutable APL route evidence matched to one accepted quote."""

    quote_ref: str
    quote_hash: str
    interaction_context: str
    chain_id: int
    pool: str
    asset: str
    amount_wei: str
    transaction_id: str

    def __post_init__(self) -> None:
        _nonempty(self.quote_ref, "quote_ref")
        if not isinstance(self.quote_hash, str) or _DIGEST_RE.fullmatch(self.quote_hash) is None:
            raise PaymentQuoteError("quote_hash must be canonical digest qb64")
        _canonical_context(self.interaction_context)
        if type(self.chain_id) is not int or self.chain_id != BASE_CHAIN_ID:
            raise PaymentQuoteError(f"chain_id must be {BASE_CHAIN_ID}")
        _canonical_address(self.pool, "pool")
        if _canonical_address(self.asset, "asset") != BASE_WETH9:
            raise PaymentQuoteError("asset must be the Base WETH9 address")
        if not isinstance(self.amount_wei, str) or _POSITIVE_DECIMAL_RE.fullmatch(
            self.amount_wei
        ) is None:
            raise PaymentQuoteError("amount_wei must be a positive canonical decimal string")
        _nonempty(self.transaction_id, "transaction_id")

    @classmethod
    def _from_accepted(
        cls,
        accepted: AcceptedPaymentQuote,
        *,
        transaction_id: str,
        acceptance_verifier: AcceptanceEvidenceVerifier,
    ) -> "PaymentRouteEvidence":
        quote = _verify_accepted_quote(accepted, acceptance_verifier)
        return cls(
            quote_ref=accepted.quote_id,
            quote_hash=accepted.quote_hash,
            interaction_context=accepted.interaction_context,
            chain_id=quote.settlement.chain_id,
            pool=quote.settlement.pool,
            asset=quote.settlement.asset,
            amount_wei=quote.settlement.amount_wei,
            transaction_id=transaction_id,
        )

    @classmethod
    def _from_dict(
        cls,
        data: object,
        *,
        accepted: AcceptedPaymentQuote,
        acceptance_verifier: AcceptanceEvidenceVerifier,
    ) -> "PaymentRouteEvidence":
        wire = _strict_object(
            data,
            required=frozenset(
                {
                    "quote_ref",
                    "quote_hash",
                    "interaction_context",
                    "chain_id",
                    "pool",
                    "asset",
                    "amount_wei",
                    "transaction_id",
                }
            ),
            field="route evidence",
        )
        route = cls(**wire)
        expected = cls._from_accepted(
            accepted,
            transaction_id=route.transaction_id,
            acceptance_verifier=acceptance_verifier,
        )
        if route != expected:
            raise PaymentQuoteError("route evidence does not exactly match accepted quote")
        return route

    def to_dict(self) -> dict[str, object]:
        return {
            "quote_ref": self.quote_ref,
            "quote_hash": self.quote_hash,
            "interaction_context": self.interaction_context,
            "chain_id": self.chain_id,
            "pool": self.pool,
            "asset": self.asset,
            "amount_wei": self.amount_wei,
            "transaction_id": self.transaction_id,
        }


@dataclass(frozen=True)
class AfpPaymentReceiptV1:
    quote_ref: str
    quote_hash: str
    interaction_context: str
    chain_id: int
    pool: str
    asset: str
    amount_wei: str
    transaction_id: str
    observed_at: str
    finality: str
    finality_evidence: Mapping[str, object]
    kind: str = PAYMENT_RECEIPT_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_RECEIPT_KIND:
            raise PaymentQuoteError(f"receipt kind must be {PAYMENT_RECEIPT_KIND}")
        # Route construction centralizes all canonical binding encodings.
        PaymentRouteEvidence(
            quote_ref=self.quote_ref,
            quote_hash=self.quote_hash,
            interaction_context=self.interaction_context,
            chain_id=self.chain_id,
            pool=self.pool,
            asset=self.asset,
            amount_wei=self.amount_wei,
            transaction_id=self.transaction_id,
        )
        _timestamp(self.observed_at)
        if self.finality not in _FINALITY_RANK:
            raise PaymentQuoteError("finality must be pending, safe, or finalized")
        object.__setattr__(self, "finality_evidence", _evidence(self.finality_evidence))

    @classmethod
    def from_dict(cls, data: object) -> "AfpPaymentReceiptV1":
        wire = _strict_object(
            data,
            required=frozenset(
                {
                    "kind",
                    "quote_ref",
                    "quote_hash",
                    "interaction_context",
                    "chain_id",
                    "pool",
                    "asset",
                    "amount_wei",
                    "transaction_id",
                    "observed_at",
                    "finality",
                    "finality_evidence",
                }
            ),
            field="payment receipt",
        )
        return cls(**wire)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "quote_ref": self.quote_ref,
            "quote_hash": self.quote_hash,
            "interaction_context": self.interaction_context,
            "chain_id": self.chain_id,
            "pool": self.pool,
            "asset": self.asset,
            "amount_wei": self.amount_wei,
            "transaction_id": self.transaction_id,
            "observed_at": self.observed_at,
            "finality": self.finality,
            "finality_evidence": _thaw_json(self.finality_evidence),
        }


@dataclass(frozen=True)
class PaymentRouteEvidenceV2:
    """An exact accepted venue settlement, echoed by the selected adapter."""

    quote_ref: str
    quote_hash: str
    interaction_context: str
    settlement: VenueSettlement
    transaction_id: str

    def __post_init__(self) -> None:
        _nonempty(self.quote_ref, "quote_ref")
        if not isinstance(self.quote_hash, str) or _DIGEST_RE.fullmatch(self.quote_hash) is None:
            raise PaymentQuoteError("quote_hash must be canonical digest qb64")
        _canonical_context(self.interaction_context)
        if not isinstance(self.settlement, VenueSettlement):
            raise PaymentQuoteError("route settlement must be a VenueSettlement")
        _nonempty(self.transaction_id, "transaction_id")

    @classmethod
    def _from_accepted(
        cls,
        accepted: AcceptedPaymentQuote,
        *,
        transaction_id: str,
        acceptance_verifier: AcceptanceEvidenceVerifier,
    ) -> "PaymentRouteEvidenceV2":
        quote = _verify_accepted_quote(accepted, acceptance_verifier)
        if not isinstance(quote, AfpPaymentQuoteV2):
            raise PaymentQuoteError("venue route requires an accepted v2 quote")
        return cls(
            quote_ref=accepted.quote_id,
            quote_hash=accepted.quote_hash,
            interaction_context=accepted.interaction_context,
            settlement=quote.settlement,
            transaction_id=transaction_id,
        )

    @classmethod
    def _from_dict(
        cls,
        data: object,
        *,
        accepted: AcceptedPaymentQuote,
        acceptance_verifier: AcceptanceEvidenceVerifier,
    ) -> "PaymentRouteEvidenceV2":
        wire = _strict_object(
            data,
            required=frozenset({
                "quote_ref", "quote_hash", "interaction_context",
                "settlement", "transaction_id",
            }),
            field="venue route evidence",
        )
        route = cls(**{**wire, "settlement": VenueSettlement.from_dict(wire["settlement"])})
        expected = cls._from_accepted(
            accepted, transaction_id=route.transaction_id,
            acceptance_verifier=acceptance_verifier,
        )
        if route != expected:
            raise PaymentQuoteError("route evidence does not exactly match accepted quote")
        return route

    def to_dict(self) -> dict[str, object]:
        return {
            "quote_ref": self.quote_ref,
            "quote_hash": self.quote_hash,
            "interaction_context": self.interaction_context,
            "settlement": self.settlement.to_dict(),
            "transaction_id": self.transaction_id,
        }


@dataclass(frozen=True)
class AfpPaymentReceiptV2:
    """Holder-disclosed venue observation; never a public Base batch receipt."""

    quote_ref: str
    quote_hash: str
    interaction_context: str
    settlement: VenueSettlement
    transaction_id: str
    output_note_hash: str
    private_event_log_position: int
    observed_at: str
    finality: str
    finality_evidence: Mapping[str, object]
    kind: str = PAYMENT_RECEIPT_V2_KIND

    def __post_init__(self) -> None:
        if self.kind != PAYMENT_RECEIPT_V2_KIND:
            raise PaymentQuoteError(f"receipt kind must be {PAYMENT_RECEIPT_V2_KIND}")
        PaymentRouteEvidenceV2(
            self.quote_ref, self.quote_hash, self.interaction_context,
            self.settlement, self.transaction_id,
        )
        if (not isinstance(self.output_note_hash, str)
                or _BN254_RE.fullmatch(self.output_note_hash) is None
                or int(self.output_note_hash[2:], 16) >= BN254_SCALAR_MODULUS):
            raise PaymentQuoteError("output_note_hash must be a canonical BN254 scalar")
        if (type(self.private_event_log_position) is not int
                or not 0 <= self.private_event_log_position <= (1 << 53) - 1):
            raise PaymentQuoteError("private_event_log_position must be a nonnegative JSON-safe integer")
        _timestamp(self.observed_at)
        if not isinstance(self.finality, str) or self.finality not in _FINALITY_RANK:
            raise PaymentQuoteError("finality must be pending, safe, or finalized")
        object.__setattr__(self, "finality_evidence", _evidence(self.finality_evidence))

    @classmethod
    def from_dict(cls, data: object) -> "AfpPaymentReceiptV2":
        wire = _strict_object(
            data,
            required=frozenset({
                "kind", "quote_ref", "quote_hash", "interaction_context",
                "settlement", "transaction_id", "observed_at", "finality",
                "finality_evidence", "output_note_hash", "private_event_log_position",
            }),
            field="venue payment receipt",
        )
        return cls(**{**wire, "settlement": VenueSettlement.from_dict(wire["settlement"])})

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "quote_ref": self.quote_ref,
            "quote_hash": self.quote_hash,
            "interaction_context": self.interaction_context,
            "settlement": self.settlement.to_dict(),
            "transaction_id": self.transaction_id,
            "output_note_hash": self.output_note_hash,
            "private_event_log_position": self.private_event_log_position,
            "observed_at": self.observed_at,
            "finality": self.finality,
            "finality_evidence": _thaw_json(self.finality_evidence),
        }


PaymentRoute = PaymentRouteEvidence | PaymentRouteEvidenceV2
PaymentReceipt = AfpPaymentReceiptV1 | AfpPaymentReceiptV2
PaymentPolicy = AfpPaymentPolicyV1 | AfpPaymentPolicyV2


class FinalityEvidenceVerifier(Protocol):
    """Deployment-specific verifier for one receipt's claimed finality level."""

    def verify(
        self,
        *,
        receipt: PaymentReceipt,
        route: PaymentRoute,
        policy: PaymentPolicy,
        expires_at: datetime,
    ) -> bool:
        """Return exactly ``True`` only for valid evidence under this policy.

        ``safe`` or ``finalized`` evidence must prove that the transaction was
        included strictly before the accepted quote's ``expires_at``. For v1 it
        must also prove from the chain that the transaction carries one payment
        whose public inputs hold the receipt's ``interaction_context`` and the
        configured ``pool_context``, and hold the payee's disclosure of the
        slot-0 note for ``amount_wei``; echoed receipt fields are not evidence.
        The same verdict admits a claim outside dispatch through
        ``route_from_observation``. Only the payee's tracker may represent a
        v1 interaction as settled. The other principal's tracker reports
        dispatch and inclusion only.
        """


class PaymentReceiptVerificationContext:
    """Deployment-owned verifier composition; never selected by request data."""

    def __init__(
        self,
        *,
        acceptance_verifier: AcceptanceEvidenceVerifier,
        finality_verifier: FinalityEvidenceVerifier,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(acceptance_verifier, _AcceptanceVerifierView) or not (
            acceptance_verifier._is_issued()
        ):
            raise PaymentQuoteError(
                "acceptance authority must be a registered store-issued view"
            )
        if finality_verifier is None or not callable(
            getattr(finality_verifier, "verify", None)
        ):
            raise PaymentQuoteError(
                "verification context requires a finality evidence verifier"
            )
        if not callable(clock):
            raise PaymentQuoteError("verification context requires a trusted clock")
        self._acceptance_verifier = acceptance_verifier
        self._finality_verifier = finality_verifier
        self._clock = clock

    def route_from_accepted(
        self,
        accepted: AcceptedPaymentQuote,
        *,
        live_session: VerifiedLiveSession,
        transaction_id: str,
    ) -> PaymentRoute:
        """Claim the dispatched transaction inside the quote window and session."""
        _nonempty(transaction_id, "transaction_id")
        quote = _verify_accepted_quote(accepted, self._acceptance_verifier)
        _require_dispatch_window(
            accepted, quote, live_session, _trusted_now(self._clock)
        )
        _route_authority_call(
            accepted,
            self._acceptance_verifier,
            "claim_route",
            transaction_id,
        )
        route_type = PaymentRouteEvidenceV2 if isinstance(quote, AfpPaymentQuoteV2) else PaymentRouteEvidence
        return route_type._from_accepted(
            accepted,
            transaction_id=transaction_id,
            acceptance_verifier=self._acceptance_verifier,
        )

    def route_from_observation(
        self,
        accepted: AcceptedPaymentQuote,
        *,
        receipt: PaymentReceipt,
        policy: PaymentPolicy,
    ) -> PaymentRoute:
        """Claim an observed transaction on verified inclusion before expiry.

        This path needs no live session and reads no clock: the claim follows
        the chain fact that the transaction was included strictly before the
        quote's ``expires_at``, at the policy's required finality, not the time
        a party learns of it. Every check precedes the atomic claim, so a
        rejected observation does not consume the route claim.
        """
        quote = _verify_accepted_quote(accepted, self._acceptance_verifier)
        if isinstance(quote, AfpPaymentQuoteV2):
            route_type, receipt_type = PaymentRouteEvidenceV2, AfpPaymentReceiptV2
        else:
            route_type, receipt_type = PaymentRouteEvidence, AfpPaymentReceiptV1
        if not isinstance(receipt, receipt_type):
            raise PaymentQuoteError(f"observation must be an {receipt_type.__name__}")
        _require_accepted_policy(accepted, quote, policy)
        receipt = receipt_type.from_dict(receipt.to_dict())
        if _FINALITY_RANK[receipt.finality] < _FINALITY_RANK[policy.required_finality]:
            raise PaymentQuoteError(
                "a claim outside dispatch requires inclusion evidence at the "
                "policy's required finality"
            )
        route = route_type._from_accepted(
            accepted,
            transaction_id=receipt.transaction_id,
            acceptance_verifier=self._acceptance_verifier,
        )
        _require_verified_receipt(
            self._finality_verifier,
            receipt,
            route,
            policy,
            _quote_instant(quote.expires_at, "expires_at"),
        )
        _route_authority_call(
            accepted,
            self._acceptance_verifier,
            "claim_route",
            receipt.transaction_id,
        )
        return route

    def route_from_dict(
        self, data: object, *, accepted: AcceptedPaymentQuote
    ) -> PaymentRoute:
        quote = _verify_accepted_quote(accepted, self._acceptance_verifier)
        route_type = PaymentRouteEvidenceV2 if isinstance(quote, AfpPaymentQuoteV2) else PaymentRouteEvidence
        route = route_type._from_dict(
            data,
            accepted=accepted,
            acceptance_verifier=self._acceptance_verifier,
        )
        _route_authority_call(
            accepted,
            self._acceptance_verifier,
            "verify_route",
            route.transaction_id,
        )
        return route

    def tracker(
        self,
        *,
        accepted: AcceptedPaymentQuote,
        route: PaymentRoute,
        policy: PaymentPolicy,
    ) -> "ReceiptFinalityTracker":
        return ReceiptFinalityTracker(
            accepted=accepted,
            route=route,
            policy=policy,
            _context=self,
        )


class ReceiptFinalityTracker:
    """Validate exact bindings and retain one monotonic receipt observation."""

    def __init__(
        self,
        *,
        accepted: AcceptedPaymentQuote,
        route: PaymentRoute,
        policy: PaymentPolicy,
        _context: PaymentReceiptVerificationContext,
    ) -> None:
        if not isinstance(accepted, AcceptedPaymentQuote):
            raise PaymentQuoteError("tracker requires an AcceptedPaymentQuote")
        if not isinstance(route, (PaymentRouteEvidence, PaymentRouteEvidenceV2)):
            raise PaymentQuoteError("tracker requires PaymentRouteEvidence")
        if not isinstance(policy, (AfpPaymentPolicyV1, AfpPaymentPolicyV2)):
            raise PaymentQuoteError("tracker requires AfpPaymentPolicyV1")
        if not isinstance(_context, PaymentReceiptVerificationContext):
            raise PaymentQuoteError(
                "tracker must be created by PaymentReceiptVerificationContext"
            )
        # Reparse route evidence against the accepted snapshot before retaining it.
        self._route = _context.route_from_dict(route.to_dict(), accepted=accepted)
        quote = _verify_accepted_quote(accepted, _context._acceptance_verifier)
        _require_accepted_policy(accepted, quote, policy)
        self._expires_at = _quote_instant(quote.expires_at, "expires_at")
        self._required_finality = policy.required_finality
        self._policy = policy
        self._finality_verifier = _context._finality_verifier
        self._lock = Lock()
        self._current: Optional[PaymentReceipt] = None

    @property
    def current(self) -> Optional[PaymentReceipt]:
        with self._lock:
            return self._current

    @property
    def is_settled(self) -> bool:
        with self._lock:
            return self._current is not None and _FINALITY_RANK[
                self._current.finality
            ] >= _FINALITY_RANK[self._required_finality]

    def observe(self, receipt: PaymentReceipt) -> None:
        if not isinstance(receipt, (AfpPaymentReceiptV1, AfpPaymentReceiptV2)):
            raise PaymentQuoteError("observation must be an AfpPaymentReceiptV1")
        receipt_type = AfpPaymentReceiptV2 if isinstance(receipt, AfpPaymentReceiptV2) else AfpPaymentReceiptV1
        # Check, verify and retain one detached snapshot of the observation.
        candidate = receipt_type.from_dict(receipt.to_dict())
        _require_verified_receipt(
            self._finality_verifier, candidate, self._route, self._policy, self._expires_at
        )
        with self._lock:
            if self._current is not None:
                if isinstance(candidate, AfpPaymentReceiptV2) and (
                    candidate.output_note_hash != self._current.output_note_hash
                    or candidate.private_event_log_position != self._current.private_event_log_position
                ):
                    raise PaymentQuoteError("receipt occurrence must remain unchanged")
                if _FINALITY_RANK[candidate.finality] <= _FINALITY_RANK[
                    self._current.finality
                ]:
                    raise PaymentQuoteError(
                        "receipt finality must advance without rewrite or regression"
                    )
                if candidate.observed_at <= self._current.observed_at:
                    raise PaymentQuoteError(
                        "receipt observed_at must advance with finality"
                    )
            self._current = candidate
