"""Integration: route AFP session envelopes through the mixnet (§8 + §12.7).

This module composes an ``afp_session`` bilateral session with the §8 Federation
Mixnet: a sealed ``afp:envelope:v1`` is carried through at least three relays with
mandatory cover traffic, and the receiving instance opens it before running the
unchanged §12.7 verification path. The two packages retain distinct roles:

  * ``afp_session`` owns the *envelope* (§12.7): build, sign, verify. AFP never
    sees the mixnet wire form (transport.py documents the §8 mixnet as a seam —
    this module is that seam *filled in*).
  * ``afp_mixnet`` owns the *route*: Sphinx-wrap the already sealed frame, push it
    through a stratified >= 3-hop path with per-hop mixing + replay rejection,
    and slot it into the mandatory constant-rate cover stream (§8.5). Sphinx's
    source-layered, per-relay onion protection is not the recipient's end-to-end
    channel encryption.

The flow:

  1. A builds and signs an envelope, then seals its canonical bytes with the §5.2
     entity-to-entity channel before handing anything to the mixnet.
  2. The mixnet delivers only the sealed frame to B (the final hop's
     ``delivered_payload``).
  3. B's ``Instance.receive_envelope_with_attestation`` opens the frame, mints
     authenticated-transit evidence, and runs the *normal* §12.7 two-layer
     verification: session context, KEL-anchored signature, and bundle checks.

Sealing composes outside the signed §12.7 content. The signature verification
remains end-to-end, while content confidentiality from the sender through the
terminal relay to the receiving ``Instance`` comes from the distinct
``afp:sealed:v1`` entity channel. The terminal relay peels its Sphinx layer but
recovers the opaque per-session destination handle plus the sealed frame; only
the receiving ``Instance`` opens the frame.
The result is a :class:`MixnetTransitResult` carrying the received envelope, its
receiver-minted sealed-channel attestation, and the
:class:`~afp_mixnet.network.TransitLog` for conformance assertions.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterable, Optional

from afp_session import (
    AfpEnvelope,
    ChannelError,
    DeploymentProfile,
    Instance,
    ObClaim,
    RemoteParty,
    SEALED_FRAME_OVERHEAD,
    SealedChannelAttestation,
    SessionChannel,
    SessionFSM,
    ZkaBundle,
    assess_ob_disclosure,
)
from afp_session.bundle import BundleVerifier
from afp_session.canonical import canonical_bytes, digest

from .conformance import RoutingConformance, assess_routing_layer
from .cover import CoverScheduler
from .directory import MixnetDirectory
from .network import Mixnet, TransitLog

__all__ = [
    "MixnetTransitError",
    "MixnetTransitResult",
    "rendezvous_handle",
    "send_envelope_via_mixnet",
    "deployment_profile_from_conformance",
    "ob_claim_for_mixnet",
]


class MixnetTransitError(Exception):
    """The envelope could not be carried through the mixnet (§8)."""


@dataclass
class MixnetTransitResult:
    """Outcome of routing an AFP envelope through the mixnet."""

    received_envelope: AfpEnvelope
    transit_log: TransitLog
    payload_bytes: int
    channel_attestation: SealedChannelAttestation | None = None


def rendezvous_handle(*, session_context: str, recipient_entity_aid: str) -> bytes:
    """A per-relationship, per-session rendezvous handle (§8.8).

    §8.8: rendezvous handles MUST NOT be stable cleartext identifiers of the tenant
    pair. We derive an opaque 32-byte handle from the per-session
    ``session_context`` and recipient entity AID, so the same pair gets a different
    handle each session and the value exposes neither AID in cleartext. Intermediate
    relays cannot see it through later Sphinx layers; the terminal relay necessarily
    sees it as that packet's destination address. Privacy comes from non-stability
    and the absence of a cleartext AID encoding, not secrecy from the terminal relay.
    This clean-room helper is intentionally unkeyed and does not resist offline
    testing of known candidate inputs. A deployment claiming that stronger property
    derives destination values with bilateral secret material.
    """
    return digest({"session_context": session_context, "recipient": recipient_entity_aid})


def send_envelope_via_mixnet(
    *,
    sender: Instance,
    fsm: SessionFSM,
    bundle: ZkaBundle,
    message_class: str,
    receiver: Instance,
    receiver_fsm: SessionFSM,
    sender_remote: RemoteParty,
    sender_channel: SessionChannel,
    receiver_channel: SessionChannel,
    mixnet: Mixnet,
    sender_cover: CoverScheduler,
    recipient_entity_aid: str,
    bundle_verifier: BundleVerifier,
    ttl_seconds: float = 600.0,
) -> MixnetTransitResult:
    """Send ``sender``'s envelope to ``receiver`` THROUGH the mixnet (>= 3 hops).

    The envelope is built and signed by the normal §12.7 path, sealed by the
    session-bound §5.2 channel, slotted into the sender's mandatory cover stream as
    a REAL emission (§8.5), Sphinx-routed to the receiver's rendezvous handle, then
    opened and verified by the receiving ``Instance``. Raises
    :class:`MixnetTransitError` if the mixnet fails to deliver the sealed frame.
    """
    if recipient_entity_aid != receiver.entity_aid:
        raise MixnetTransitError(
            "recipient_entity_aid does not match the receiving Instance"
        )

    # 1. Build + sign the envelope via the standard session path (§12.7), but do
    #    not publish on the in-memory transport — the mixnet IS the transport here.
    envelope = sender.build_envelope(
        fsm, bundle=bundle, message_class=message_class, ttl_seconds=ttl_seconds
    )
    raw = canonical_bytes(envelope.to_dict())
    sealed_size = len(raw) + SEALED_FRAME_OVERHEAD
    if sealed_size > mixnet.params.usable_payload_size:
        plaintext_limit = (
            mixnet.params.usable_payload_size - SEALED_FRAME_OVERHEAD
        )
        raise MixnetTransitError(
            f"sealed envelope ({sealed_size} B) exceeds the usable Sphinx payload "
            f"budget ({mixnet.params.usable_payload_size} B); the unfragmented "
            f"plaintext-envelope limit is {plaintext_limit} B after the "
            f"{SEALED_FRAME_OVERHEAD} B sealed-frame overhead; the fragmentation "
            f"seam is required "
            f"(§8.4 'larger AFP messages are fragmented')"
        )
    sealed = sender.seal_envelope(fsm, envelope, channel=sender_channel)
    if len(sealed) != sealed_size:  # Fixed v1 geometry is a protocol invariant.
        raise MixnetTransitError("sealed-frame size differs from the v1 geometry")

    # 2. Slot the REAL message into the sender's mandatory cover stream (§8.5).
    payload_ref = f"env:{envelope.session_ref}:{message_class}"
    sender_cover.enqueue_real(payload_ref)
    sender_cover.tick()  # emit the slot (REAL because a message is queued)

    # 3. Route through the stratified mixnet (>= 3 hops).
    handle = rendezvous_handle(
        session_context=fsm.atom.session_context,
        recipient_entity_aid=recipient_entity_aid,
    )
    route = mixnet.select_route()
    log = mixnet.send(route=route, destination_handle=handle, payload=sealed)
    if not log.delivered or log.delivered_payload is None:
        raise MixnetTransitError("mixnet did not deliver the envelope to the final hop")
    if len(route.node_aids) < mixnet.hop_count:
        raise MixnetTransitError(
            f"route had {len(route.node_aids)} hops, below the {mixnet.hop_count}-hop "
            f"OB-2 minimum"
        )

    # 4. Open only inside the receiving Instance, then verify via §12.7.
    received, channel_attestation = receiver.receive_envelope_with_attestation(
        receiver_fsm,
        log.delivered_payload,
        message_class=message_class,
        channel=receiver_channel,
        sender_remote=sender_remote,
        bundle_verifier=bundle_verifier,
    )
    return MixnetTransitResult(
        received_envelope=received,
        channel_attestation=channel_attestation,
        transit_log=log,
        payload_bytes=len(sealed),
    )


def deployment_profile_from_conformance(
    *,
    name: str,
    channel_encryption_operational: SealedChannelAttestation | None,
    channel_session_context: str,
    channel_kel_event_dig: str,
    directory: MixnetDirectory,
    conformance: RoutingConformance,
) -> DeploymentProfile:
    """Build the ``afp_session`` :class:`DeploymentProfile` from a LIVE mixnet's facts.

    This is the honest wiring: OB-1 receives channel-minted evidence bound to the
    expected signed session/KEL, while the OB-2-relevant fields are derived from
    *measured* conformance, never asserted. ``mixnet_operational`` is True only when the
    endpoint, cross-session identifier, and relay-trust properties are PROVEN
    (while the explicitly bounded correlation-resistance seam may remain PARTIAL);
    cover traffic and the mix-node count come from the live directory/scheduler. The
    ``afp_session.conformance`` guard then derives the OB level — and it will NOT
    permit OB-2 unless all three (operational, cover, sufficient set) hold.
    """
    return DeploymentProfile(
        name=name,
        channel_encryption_operational=channel_encryption_operational,
        mixnet_operational=conformance.routing_evidence_sufficient,
        channel_session_context=channel_session_context,
        channel_kel_event_dig=channel_kel_event_dig,
        mandatory_cover_traffic=conformance.cover_healthy,
        mix_node_count=directory.node_count,
        min_mix_nodes_for_ob2=conformance.min_mix_nodes,
    )


def ob_claim_for_mixnet(
    *,
    name: str,
    channel_encryption_operational: SealedChannelAttestation | None,
    channel_session_context: str,
    channel_kel_event_dig: str,
    directory: MixnetDirectory,
    transit_log: TransitLog,
    scheduler: CoverScheduler,
    originator: str,
    recipient_handle: str | bytes,
    comparison_logs: Optional[Iterable[TransitLog]] = None,
) -> ObClaim:
    """End-to-end: assess §8.2 over a real transit, then derive the honest OB claim.

    The single call that turns "the mixnet just carried an AFP envelope through
    >= 3 hops with cover traffic" into a §3.5-honest OB disclosure. The receive-
    minted channel attestation must name the exact final delivered frame. If that
    binding is valid, the §8.2 assessment is clean, cross-session comparison
    evidence is supplied, and cover/set preconditions hold, the returned
    :class:`~afp_session.conformance.ObClaim` legitimately reads OB-2; otherwise it
    reads OB-1 with the not-yet-met disclosure — the guard cannot be fooled.
    """
    conformance = assess_routing_layer(
        log=transit_log,
        directory=directory,
        scheduler=scheduler,
        originator=originator,
        recipient_handle=recipient_handle,
        comparison_logs=comparison_logs,
    )
    # A recent attestation from some other receive is insufficient: OB-2 may
    # compose only when the channel evidence names this exact mixnet delivery.
    transit_attestation = channel_encryption_operational
    if type(transit_attestation) is SealedChannelAttestation:
        try:
            delivered_payload = transit_log.delivered_payload
            if type(delivered_payload) is not bytes:
                transit_attestation = None
            else:
                expected_digest = hashlib.sha256(delivered_payload).hexdigest()
                observed_digest = (
                    transit_attestation.transit_evidence.frame_digest
                )
                if not isinstance(observed_digest, str) or not hmac.compare_digest(
                    observed_digest, expected_digest
                ):
                    transit_attestation = None
        except (AttributeError, ChannelError, TypeError, ValueError):
            transit_attestation = None

    profile = deployment_profile_from_conformance(
        name=name,
        channel_encryption_operational=transit_attestation,
        channel_session_context=channel_session_context,
        channel_kel_event_dig=channel_kel_event_dig,
        directory=directory,
        conformance=conformance,
    )
    return assess_ob_disclosure(profile)
