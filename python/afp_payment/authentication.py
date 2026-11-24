"""Bilateral KEL-current quote authentication for AFP §15.3/§15.5."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import copy
import hmac
import json
import re
import secrets
import time
from typing import Optional

from afp_session import (
    IdentityBindingError,
    RemoteParty,
    SessionError,
    VerifiedLiveSession,
    compute_session_context,
    session_datetime_to_unix,
    validate_opened_at,
    ed25519,
    keri,
    verify_party_ref,
)
from afp_session.atoms import (
    AfpCommitSignature,
    AfpSessionAtom,
    AfpSessionStatus,
    validate_signed_at,
    validate_signed_at_number,
)
from afp_session.canonical import canonical_json

from .quote import (
    AfpPaymentPolicyV1,
    AfpPaymentQuoteV1,
    PaymentQuoteError,
    derive_interaction_context,
)
from .venue import (
    PAYMENT_QUOTE_V2_KIND,
    PAYMENT_POLICY_V2_KIND,
    AfpPaymentPolicyV2,
    AfpPaymentQuoteV2,
)
from .replay import ReplayStore

PaymentQuote = AfpPaymentQuoteV1 | AfpPaymentQuoteV2
PaymentPolicy = AfpPaymentPolicyV1 | AfpPaymentPolicyV2


def _quote_from_wire(wire: object) -> PaymentQuote:
    if isinstance(wire, dict) and wire.get("kind") == PAYMENT_QUOTE_V2_KIND:
        return AfpPaymentQuoteV2.from_dict(wire)
    return AfpPaymentQuoteV1.from_dict(wire)


def _policy_from_wire(wire: object) -> PaymentPolicy:
    if isinstance(wire, dict) and wire.get("kind") == PAYMENT_POLICY_V2_KIND:
        return AfpPaymentPolicyV2.from_dict(wire)
    return AfpPaymentPolicyV1.from_dict(wire)


__all__ = [
    "AcceptedPaymentQuote",
    "sign_payment_quote",
    "accept_payment_quote",
]

_AID_RE = re.compile(r"E_[0-9a-f]{64}\Z")
_DIGEST_RE = re.compile(r"D_[0-9a-f]{64}\Z")
_QB64_RE = re.compile(r"[A-Z]_[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")


def _define_accepted_quote_capability():
    authority = object()
    seal_key = secrets.token_bytes(32)

    def seal(canonical_wire: str, profile_policy_hash: str) -> bytes:
        # The digest form has no newline, so the separator is unambiguous.
        message = f"{profile_policy_hash}\n{canonical_wire}".encode("utf-8")
        return hmac.digest(seal_key, message, "sha256")

    @dataclass(frozen=True, init=False)
    class AcceptedPaymentQuote:
        """Proof that one quote crossed the authenticated acceptance boundary."""

        quote_hash: str
        quote_id: str
        quote_nonce: str
        acceptance_record_hash: str
        interaction_context: str
        profile_policy_hash: str
        _canonical_wire: str
        _acceptance_seal: bytes

        def __new__(cls, supplied_authority: object = None):
            if supplied_authority is not authority:
                raise TypeError(
                    "AcceptedPaymentQuote is issued only by accept_payment_quote"
                )
            return super().__new__(cls)

        def to_quote(self) -> PaymentQuote:
            """Verify process-local authority and return a detached quote."""
            try:
                if (
                    not isinstance(self._canonical_wire, str)
                    or not isinstance(self._acceptance_seal, bytes)
                    or not isinstance(self.profile_policy_hash, str)
                    or _DIGEST_RE.fullmatch(self.profile_policy_hash) is None
                ):
                    raise PaymentQuoteError("accepted quote authority is malformed")
                expected_seal = seal(self._canonical_wire, self.profile_policy_hash)
                if not hmac.compare_digest(self._acceptance_seal, expected_seal):
                    raise PaymentQuoteError("accepted quote authority seal is invalid")
                wire = json.loads(self._canonical_wire)
                quote = _quote_from_wire(wire)
                quote_hash = quote.quote_hash
                acceptance_record_hash = quote.acceptance_record_hash
                expected_context = derive_interaction_context(
                    quote_hash, quote.session_context
                )
                if (
                    self.quote_hash != quote_hash
                    or self.quote_id != quote.quote_id
                    or self.quote_nonce != quote.quote_nonce
                    or self.acceptance_record_hash != acceptance_record_hash
                    or self.interaction_context != expected_context
                ):
                    raise PaymentQuoteError(
                        "accepted quote authority fields do not match sealed wire"
                    )
                if (
                    isinstance(quote, AfpPaymentQuoteV2)
                    and quote.policy_hash != self.profile_policy_hash
                ):
                    raise PaymentQuoteError(
                        "accepted quote policy_hash does not match sealed profile_policy_hash"
                    )
                return quote
            except PaymentQuoteError:
                raise
            except (AttributeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                raise PaymentQuoteError(
                    "accepted quote snapshot is malformed"
                ) from exc

        def __reduce__(self):
            raise TypeError("AcceptedPaymentQuote is process-local authority")

        def __reduce_ex__(self, _protocol):
            raise TypeError("AcceptedPaymentQuote is process-local authority")

    AcceptedPaymentQuote.__name__ = "AcceptedPaymentQuote"
    AcceptedPaymentQuote.__qualname__ = "AcceptedPaymentQuote"

    def issue(quote: PaymentQuote, profile_policy_hash: str) -> AcceptedPaymentQuote:
        try:
            if (
                not isinstance(profile_policy_hash, str)
                or _DIGEST_RE.fullmatch(profile_policy_hash) is None
            ):
                raise PaymentQuoteError("accepted profile_policy_hash is malformed")
            canonical_wire = canonical_json(quote.to_dict())
            reconstructed = _quote_from_wire(json.loads(canonical_wire))
            quote_hash = reconstructed.quote_hash
            acceptance_record_hash = reconstructed.acceptance_record_hash
            if quote_hash != quote.quote_hash:
                raise PaymentQuoteError("accepted quote hash does not verify")
            instance = AcceptedPaymentQuote(authority)
            object.__setattr__(instance, "quote_hash", quote_hash)
            object.__setattr__(instance, "quote_id", reconstructed.quote_id)
            object.__setattr__(instance, "quote_nonce", reconstructed.quote_nonce)
            object.__setattr__(
                instance, "acceptance_record_hash", acceptance_record_hash
            )
            object.__setattr__(
                instance,
                "interaction_context",
                derive_interaction_context(quote_hash, reconstructed.session_context),
            )
            object.__setattr__(instance, "profile_policy_hash", profile_policy_hash)
            object.__setattr__(instance, "_canonical_wire", canonical_wire)
            object.__setattr__(
                instance, "_acceptance_seal", seal(canonical_wire, profile_policy_hash)
            )
            return instance
        except PaymentQuoteError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise PaymentQuoteError("accepted quote cannot be issued") from exc

    return AcceptedPaymentQuote, issue


AcceptedPaymentQuote, _issue_accepted_quote = _define_accepted_quote_capability()
del _define_accepted_quote_capability


def _signed_at_seconds(value: Optional[datetime | float]) -> int | float:
    """Turn a signer's ``signed_at`` input into its §1.6.1 JSON number.

    ``None`` (the local clock) and an aware ``datetime`` are authoring
    conveniences. A caller's number is validated as given, before any float
    conversion, so an integer that binary64 cannot hold exactly is rejected,
    never rounded on the way to the wire.
    """
    if value is None:
        value = time.time()
    elif isinstance(value, datetime):
        # A tzinfo can return an unusable offset, and an extreme instant can
        # overflow; both are the signer's error, never a bare ValueError.
        try:
            offset = value.utcoffset()
        except (ArithmeticError, TypeError, ValueError) as exc:
            raise PaymentQuoteError(
                f"signed_at datetime has an unusable UTC offset: {exc}"
            ) from exc
        if value.tzinfo is None or offset is None:
            raise PaymentQuoteError("signed_at datetime must be timezone-aware")
        try:
            value = value.timestamp()
        except (ArithmeticError, TypeError, ValueError) as exc:
            raise PaymentQuoteError(
                f"signed_at datetime cannot be converted to Unix seconds: {exc}"
            ) from exc
    try:
        return validate_signed_at_number(value)
    except ValueError as exc:
        raise PaymentQuoteError(f"signed_at is not a finite JSON number: {exc}") from exc


def sign_payment_quote(
    quote: PaymentQuote,
    identity: keri.Identity,
    *,
    role: str,
    signed_at: Optional[datetime | float] = None,
) -> PaymentQuote:
    """Return one KEL-pinned signature over the exact quote hash.

    ``signed_at`` is retained only as untrusted observational metadata. It is
    intentionally outside the signed payload and never establishes freshness.
    """
    if not isinstance(quote, (AfpPaymentQuoteV1, AfpPaymentQuoteV2)):
        raise PaymentQuoteError("quote must be an AfpPaymentQuoteV1 or AfpPaymentQuoteV2")
    if role not in ("initiator", "responder"):
        raise PaymentQuoteError("payment signature role must be initiator or responder")
    signature = AfpCommitSignature(
        signed_by=identity.aid,
        kel_event_dig=keri.current_key_event_digest(identity.kel),
        signature=identity.sign(quote.quote_hash.encode("utf-8")).hex(),
        signed_at=_signed_at_seconds(signed_at),
    )
    return replace(quote, **{f"{role}_signature": signature})


def _now(value: Optional[datetime]) -> datetime:
    result = value or datetime.now(timezone.utc)
    if not isinstance(result, datetime) or result.tzinfo is None or result.utcoffset() is None:
        raise PaymentQuoteError("verification time must be a timezone-aware datetime")
    return result.astimezone(timezone.utc)


def _quote_time(value: str, field: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError) as exc:
        raise PaymentQuoteError(f"quote {field} is malformed") from exc


def _verify_signature(
    quote_hash: str,
    signature: AfpCommitSignature,
    *,
    expected_entity_aid: str,
    expected_tenant_aid: str,
    entity_kel: keri.Kel,
    tenant_kel: keri.Kel,
    witness_keys: dict[str, bytes],
    role: str,
    first_seen: object = None,
) -> None:
    try:
        if _AID_RE.fullmatch(signature.signed_by) is None:
            raise PaymentQuoteError(f"{role} signed_by is not canonical AID qb64")
        if _DIGEST_RE.fullmatch(signature.kel_event_dig) is None:
            raise PaymentQuoteError(f"{role} kel_event_dig is not canonical digest qb64")
        if not isinstance(signature.signature, str) or _SIGNATURE_RE.fullmatch(
            signature.signature
        ) is None:
            raise PaymentQuoteError(f"{role} signature is not canonical Ed25519 hex")
        # ``signed_at`` is observational metadata outside the Ed25519 payload.
        # Validate only its §1.6.1 wire shape; a missing value is rejected, never
        # replaced by the local clock, and it never decides freshness or authority.
        try:
            validate_signed_at(signature.signed_at)
        except ValueError as exc:
            raise PaymentQuoteError(f"{role} signed_at is not a finite JSON number") from exc
        if signature.signed_by != expected_entity_aid or entity_kel.aid != expected_entity_aid:
            raise PaymentQuoteError(f"{role} signature principal does not match live session")
        if tenant_kel.aid != expected_tenant_aid:
            raise PaymentQuoteError(f"{role} tenant principal does not match live session")
        keri.verify_kel(
            entity_kel,
            tenant_kel=tenant_kel,
            witness_keys=witness_keys,
            first_seen=first_seen,
        )
        keri.assert_keystate_current(entity_kel, signature.kel_event_dig)
        public_key = keri.resolve_current_key(entity_kel)
        ed25519.validate_public_key(public_key)
        if not ed25519.verify_strict(
            quote_hash.encode("utf-8"),
            bytes.fromhex(signature.signature),
            public_key,
        ):
            raise PaymentQuoteError(f"invalid {role} payment quote signature")
    except PaymentQuoteError:
        raise
    except (
        keri.KeriError,
        AttributeError,
        OSError,
        OverflowError,
        TypeError,
        ValueError,
    ) as exc:
        raise PaymentQuoteError(f"{role} signature is not KEL-current or valid") from exc


def _snapshot_inputs(
    quote: PaymentQuote,
    policy: PaymentPolicy,
    live_session: VerifiedLiveSession,
    initiator_remote: RemoteParty,
    responder_remote: RemoteParty,
) -> tuple[
    PaymentQuote,
    PaymentPolicy,
    AfpSessionAtom,
    RemoteParty,
    RemoteParty,
]:
    try:
        if not isinstance(quote, (AfpPaymentQuoteV1, AfpPaymentQuoteV2)):
            raise PaymentQuoteError("quote must be an AfpPaymentQuoteV1 or AfpPaymentQuoteV2")
        if not isinstance(policy, (AfpPaymentPolicyV1, AfpPaymentPolicyV2)):
            raise PaymentQuoteError("policy must be an AfpPaymentPolicyV1 or AfpPaymentPolicyV2")
        if not isinstance(live_session, VerifiedLiveSession):
            raise PaymentQuoteError(
                "payment acceptance requires a VerifiedLiveSession capability"
            )
        if not isinstance(initiator_remote, RemoteParty) or not isinstance(
            responder_remote, RemoteParty
        ):
            raise PaymentQuoteError("payment principals require RemoteParty material")
        for role, remote in (
            ("initiator", initiator_remote),
            ("responder", responder_remote),
        ):
            if remote.witness_keys is None:
                raise PaymentQuoteError(
                    f"{role} witness key material must be explicitly supplied"
                )
            if not isinstance(remote.witness_keys, dict):
                raise PaymentQuoteError(f"{role} witness key material is malformed")
        session = live_session.to_atom()
        try:
            validate_opened_at(session.opened_at)
        except ValueError as exc:
            raise PaymentQuoteError("live session opened_at is malformed") from exc
        quote_copy, policy_copy, session_copy, initiator_copy, responder_copy = (
            copy.deepcopy(
                (quote, policy, session, initiator_remote, responder_remote)
            )
        )
        return (
            _quote_from_wire(quote_copy.to_dict()),
            _policy_from_wire(policy_copy.to_dict()),
            AfpSessionAtom.from_dict(session_copy.to_dict()),
            initiator_copy,
            responder_copy,
        )
    except PaymentQuoteError:
        raise
    except SessionError as exc:
        raise PaymentQuoteError(
            f"live-session capability is invalid: {exc}"
        ) from exc
    except Exception as exc:
        raise PaymentQuoteError("payment acceptance input is malformed") from exc


def _accept_payment_quote_impl(
    *,
    quote: PaymentQuote,
    policy: PaymentPolicy,
    live_session: VerifiedLiveSession,
    initiator_remote: RemoteParty,
    responder_remote: RemoteParty,
    replay_store: ReplayStore,
    now: Optional[datetime] = None,
    issue_capability,
) -> AcceptedPaymentQuote:
    """Authenticate detached inputs, then atomically reserve both replay keys.

    Each ``RemoteParty`` must carry an explicit witness-key map. An empty map
    is valid for a threshold-zero KEL; ``None`` is rejected because it would
    silently disable witness verification at this value-transfer boundary.
    """
    quote, policy, session, initiator_remote, responder_remote = _snapshot_inputs(
        quote, policy, live_session, initiator_remote, responder_remote
    )
    verified_at = _now(now)
    quote_hash = quote.quote_hash
    quote.validate(policy)
    if session.kind != "afp:session:v1":
        raise PaymentQuoteError("live session kind is malformed")
    if not isinstance(session.id, str) or not session.id:
        raise PaymentQuoteError("live session id is malformed")
    expected_profile = "pay_venue" if isinstance(quote, AfpPaymentQuoteV2) else "pay"
    if session.profile != expected_profile:
        raise PaymentQuoteError(
            f"payment quote requires a {expected_profile} profile session"
        )
    if session.profile_policy_hash != policy.policy_hash:
        raise PaymentQuoteError(
            "payment policy does not match the live session profile_policy_hash"
        )
    if session.status is not AfpSessionStatus.ACTIVE:
        raise PaymentQuoteError("payment quote requires a live ACTIVE session")
    try:
        session_expires_at = session_datetime_to_unix(session.expires_at, "expires_at")
    except ValueError as exc:
        raise PaymentQuoteError("live session expiry is malformed") from exc
    if verified_at.timestamp() >= session_expires_at:
        raise PaymentQuoteError("live session has expired")
    if quote.session_ref != session.id:
        raise PaymentQuoteError("quote session_ref does not match the live session")
    if quote.session_context != session.session_context:
        raise PaymentQuoteError("quote session_context does not match the live session")
    if _QB64_RE.fullmatch(quote.session_context) is None:
        raise PaymentQuoteError("live payment session_context is not canonical qb64")
    if not isinstance(session.responder.signature, str) or not session.responder.signature:
        raise PaymentQuoteError("live session responder signature is missing")
    try:
        opened_at = validate_opened_at(session.opened_at)
    except ValueError as exc:
        raise PaymentQuoteError("live session opened_at is malformed") from exc
    if opened_at > verified_at.timestamp():
        raise PaymentQuoteError("live session opened_at is after verification time")
    if session_expires_at <= opened_at:
        raise PaymentQuoteError("live session expiry must be after opened_at")
    try:
        expected_session_context = compute_session_context(
            session.initiator.entity_aid,
            session.responder.entity_aid,
            session.id,
            opened_at,
        )
    except ValueError as exc:
        raise PaymentQuoteError("live session opened_at is malformed") from exc
    if session.session_context != expected_session_context:
        raise PaymentQuoteError("live session_context does not match session principals")
    retained = live_session.kel_state
    try:
        verify_party_ref(
            session.initiator, session.content_hash, initiator_remote, kel_state=retained
        )
        verify_party_ref(
            session.responder, session.content_hash, responder_remote, kel_state=retained
        )
    except IdentityBindingError as exc:
        raise PaymentQuoteError(
            f"live session identity authentication failed: {exc}"
        ) from exc

    quoted_at = _quote_time(quote.quoted_at, "quoted_at")
    expires_at = _quote_time(quote.expires_at, "expires_at")
    if verified_at < quoted_at:
        raise PaymentQuoteError("payment quote is not yet valid at quoted_at")
    if verified_at >= expires_at:
        raise PaymentQuoteError("payment quote has expired")
    if quote.initiator_signature is None or quote.responder_signature is None:
        raise PaymentQuoteError("payment quote requires both principal signatures")

    _verify_signature(
        quote_hash,
        quote.initiator_signature,
        expected_entity_aid=session.initiator.entity_aid,
        expected_tenant_aid=session.initiator.tenant_aid,
        entity_kel=initiator_remote.entity_kel,
        tenant_kel=initiator_remote.tenant_kel,
        witness_keys=initiator_remote.witness_keys,
        first_seen=(getattr(initiator_remote, "kel_state", None), retained),
        role="initiator",
    )
    _verify_signature(
        quote_hash,
        quote.responder_signature,
        expected_entity_aid=session.responder.entity_aid,
        expected_tenant_aid=session.responder.tenant_aid,
        entity_kel=responder_remote.entity_kel,
        tenant_kel=responder_remote.tenant_kel,
        witness_keys=responder_remote.witness_keys,
        first_seen=(getattr(responder_remote, "kel_state", None), retained),
        role="responder",
    )

    try:
        acceptance_record_hash = quote.acceptance_record_hash
        replay_store.reserve(
            quote.quote_id,
            quote_hash,
            quote.quote_nonce,
            acceptance_record_hash,
        )
    except PaymentQuoteError:
        raise
    except Exception as exc:
        raise PaymentQuoteError("payment replay store failed closed") from exc
    return issue_capability(quote, session.profile_policy_hash)


def _bind_acceptance(implementation, issue_capability):
    def accept_payment_quote(
        *,
        quote: PaymentQuote,
        policy: PaymentPolicy,
        live_session: VerifiedLiveSession,
        initiator_remote: RemoteParty,
        responder_remote: RemoteParty,
        replay_store: ReplayStore,
        now: Optional[datetime] = None,
    ) -> AcceptedPaymentQuote:
        return implementation(
            quote=quote,
            policy=policy,
            live_session=live_session,
            initiator_remote=initiator_remote,
            responder_remote=responder_remote,
            replay_store=replay_store,
            now=now,
            issue_capability=issue_capability,
        )

    return accept_payment_quote


accept_payment_quote = _bind_acceptance(
    _accept_payment_quote_impl, _issue_accepted_quote
)
del _accept_payment_quote_impl
del _bind_acceptance
del _issue_accepted_quote
