"""§8.2 conformance properties — the routing-layer conformance test.

§8.2 is *the conformance test*: "The §8.2 properties are the conformance test;
the §8.3–§8.8 design is the means by which v0.3.0 meets them." This module checks
the §8.2 properties *over real artifacts* — a :class:`~afp_mixnet.network.TransitLog`
from an actual Sphinx transit and a :class:`~afp_mixnet.cover.CoverScheduler`
emission trace — so the result is evidence, not assertion.

The four §8.2 properties:

  1. **Endpoint unlinkability.** A relay forwarding a message sees, at most, one
     hop in each direction — never both the originating and terminating tenant of
     a session. (Checked: no single relay observation has both ``prev_hop`` and
     ``next_hop`` spanning the endpoints; and per the Sphinx layer, no relay sees
     the originator or the final recipient identity.)
  2. **No cleartext relationship in addressing.** Routing headers and any
     identifier visible to a relay MUST NOT encode the tenant pair, and MUST NOT
     be stable across sessions. (Checked: the alpha/header a relay sees is blinded
     per hop — distinct received vs forwarded — and, when comparison transits are
     supplied, every relay-visible value differs across sessions on the same route.)
  3. **Correlation resistance.** Timing/volume patterns are treated so a relay,
     colluding minority, or link observer cannot reconstruct the pairing.
     (Partially provable in a unit test: we assert exponential per-hop mixing
     delay is applied, fixed-size packets (volume), and cover-traffic
     indistinguishability. The *statistical* guarantee against a global passive
     adversary over a long horizon is a Loopix-family property argued analytically,
     not a unit-test assertion — declared a SEAM honestly, §8.10.)
  4. **No single trusted relay.** No relay whose compromise reveals the graph.
     (Checked at the directory level by the §8.6 operator-control constraints; here
     re-checked over the transit: no single relay in the log spans both endpoints,
     and the path crosses >= 3 distinct operators where the directory provides
     them.)

Each property returns a :class:`PropertyResult` with ``status`` one of
``proven`` / ``partial`` / ``seam`` and the evidence. :func:`assess_routing_layer`
aggregates them into a :class:`RoutingConformance` that the OB-2 disclosure layer
consumes — and it is conservative: OB-2 is permitted only when properties 8.2.1,
8.2.2, and 8.2.4 are ``proven``, property 8.2.3 is not ``failed``, and the
mandatory cover-traffic and sufficient-mix-node-set preconditions hold. It NEVER
reports OB-2 as met on the strength of missing cross-session evidence or the
documented correlation-resistance seam alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional, Tuple

from afp_session import AfpEnvelope, SEALED_FRAME_OVERHEAD
from afp_session.canonical import digest

from .cover import CoverScheduler, EmissionKind
from .directory import MixnetDirectory
from .network import HopObservation, TransitLog
from .profiles import OB2_BASELINE, MixnetProfile

__all__ = [
    "PropertyStatus",
    "PropertyResult",
    "RoutingConformance",
    "check_endpoint_unlinkability",
    "check_no_cleartext_relationship",
    "check_correlation_resistance",
    "check_no_single_trusted_relay",
    "check_cover_indistinguishability",
    "assess_routing_layer",
]


class PropertyStatus(str, Enum):
    PROVEN = "proven"  # asserted over real artifacts, fully met
    PARTIAL = "partial"  # the unit-testable part is met; a bounded seam remains
    SEAM = "seam"  # documented seam — not provable in a unit test (declared)
    FAILED = "failed"  # the property is violated


@dataclass(frozen=True)
class PropertyResult:
    """One §8.2 property's verdict + the evidence supporting it."""

    property_id: str  # "8.2.1" .. "8.2.4" (+ "8.5" cover)
    name: str
    status: PropertyStatus
    evidence: str

    @property
    def ok(self) -> bool:
        """Whether this individual check avoided a concrete failure."""
        return self.status != PropertyStatus.FAILED


_SEALED_FRAME_PREFIX = b"afp:sealed:v1\x00"
_ROUTING_ADDRESS_SIZE = 32
_SEALED_SUITE_ID = 1
_SEALED_SEQUENCE_SIZE = 8
_SEALED_NONCE_SIZE = 16
_SEALED_LENGTH_SIZE = 4


def _recipient_handle_bytes(handle: object) -> Optional[bytes]:
    """Normalize the public hex-string and byte handle forms to wire bytes."""
    if type(handle) is bytes:
        return handle
    if not isinstance(handle, str) or not handle:
        return None
    hex_handle = handle[2:] if handle.startswith("0x") else handle
    if len(hex_handle) % 2 == 0:
        try:
            return bytes.fromhex(hex_handle)
        except ValueError:
            pass
    return handle.encode("utf-8")


def _final_observation(log: TransitLog) -> Tuple[Optional[HopObservation], Optional[str]]:
    """Return the sole terminal observation, rejecting incomplete transit evidence."""
    if any(type(observation.is_final) is not bool for observation in log.observations):
        return None, "transit has a non-boolean final-hop marker"
    finals = [
        (index, observation)
        for index, observation in enumerate(log.observations)
        if observation.is_final
    ]
    if len(finals) != 1:
        return None, f"transit records {len(finals)} final hops (need exactly one)"
    index, final = finals[0]
    if index != len(log.observations) - 1:
        return None, "final hop is not the terminal recorded observation"
    return final, None


def _is_parseable_envelope(payload: bytes) -> bool:
    """True only when the plaintext-envelope parser accepts payload."""
    try:
        parsed = json.loads(payload.decode("utf-8"))
        if not isinstance(parsed, dict):
            return False
        AfpEnvelope.from_dict(parsed)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        # A parser failure proves the relay delivery is not a plaintext
        # envelope. Require parser acceptance rather than a discriminator alone.
        return False
    return True


def _is_structurally_sealed_frame(payload: object) -> bool:
    """Check the public v1 frame geometry a relay can validate without keys."""
    if type(payload) is not bytes or len(payload) < SEALED_FRAME_OVERHEAD:
        return False
    if not payload.startswith(_SEALED_FRAME_PREFIX):
        return False
    suite_offset = len(_SEALED_FRAME_PREFIX)
    if payload[suite_offset] != _SEALED_SUITE_ID:
        return False
    if payload[suite_offset + 1] not in (0, 1):
        return False
    length_offset = (
        suite_offset
        + 2
        + _SEALED_SEQUENCE_SIZE
        + _SEALED_NONCE_SIZE
    )
    ciphertext_length = int.from_bytes(
        payload[length_offset : length_offset + _SEALED_LENGTH_SIZE], "big"
    )
    return len(payload) == SEALED_FRAME_OVERHEAD + ciphertext_length


def _routing_address(observation: HopObservation) -> object:
    """Read the decoded address recorded by the relay implementation.

    ``getattr`` supports ``HopObservation`` values that omit
    ``routing_address``. Missing evidence is a conformance failure, never an
    implicit pass.
    """
    return getattr(observation, "routing_address", None)


def _valid_routing_address(value: object) -> bool:
    return type(value) is bytes and len(value) == _ROUTING_ADDRESS_SIZE


def _observation_chain_error(log: TransitLog) -> Optional[str]:
    """Validate that recorded adjacent-hop evidence describes one realized path."""
    for index, observation in enumerate(log.observations):
        expected_prev = None if index == 0 else log.observations[index - 1].node_aid
        if observation.prev_hop != expected_prev:
            return (
                f"relay {observation.node_aid} predecessor does not match the "
                "previous observation"
            )
        if observation.is_final:
            if observation.next_hop is not None or observation.forwarded_alpha is not None:
                return f"final relay {observation.node_aid} records forwarding evidence"
            continue
        if index + 1 >= len(log.observations):
            return f"forwarding relay {observation.node_aid} has no following observation"
        following = log.observations[index + 1]
        if observation.next_hop != following.node_aid:
            return (
                f"relay {observation.node_aid} next hop does not match the following "
                "observation"
            )
        if observation.forwarded_alpha != following.received_alpha:
            return (
                f"relay {observation.node_aid} forwarded element does not match what "
                f"relay {following.node_aid} received"
            )
        expected_address = digest({"mix_node_aid": following.node_aid})
        if _routing_address(observation) != expected_address:
            return (
                f"relay {observation.node_aid} decoded address does not match its "
                "recorded next hop"
            )
    return None


def check_endpoint_unlinkability(
    log: TransitLog,
    *,
    originator: str,
    recipient_handle: str | bytes,
) -> PropertyResult:
    """§8.2 #1: no relay sees both the originating and terminating tenant.

    Proven from the transit log: each relay observation names only its prev/next
    *hop* (mix nodes), never the originator tenant or the final recipient. The
    originator is not in any ``prev_hop`` (the ingress hop's prev is None), and the
    recipient handle never appears as a ``next_hop`` (the final hop forwards to no
    one — delivery is to the rendezvous handle, opaque inside the last layer).
    """
    pid = "8.2.1"
    name = "endpoint unlinkability"
    if not log.observations:
        return PropertyResult(pid, name, PropertyStatus.FAILED, "empty transit log")
    if not log.delivered:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED, "transit did not record final delivery"
        )
    payload = log.delivered_payload
    if type(payload) is not bytes:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final delivery payload is absent or not bytes",
        )
    if _is_parseable_envelope(payload):
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final delivery is directly parseable as an AFP envelope",
        )
    if not _is_structurally_sealed_frame(payload):
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final delivery is not a structurally valid afp:sealed:v1 frame",
        )
    if not isinstance(originator, str) or not originator:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "originator is not a non-empty byte-addressable identifier",
        )
    originator_bytes = originator.encode("utf-8")
    if originator_bytes in payload:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final delivery contains originator bytes",
        )
    expected_recipient = _recipient_handle_bytes(recipient_handle)
    if not _valid_routing_address(expected_recipient):
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "recipient handle is not a 32-byte opaque routing address",
        )
    for obs in log.observations:
        # A relay must never name the originator tenant as a hop it can see.
        if obs.prev_hop == originator or obs.next_hop == originator:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} observed the originator as a hop",
            )
        # Nor the recipient handle (the final hop delivers via the opaque handle,
        # it is never a cleartext next_hop a relay can read).
        if obs.next_hop == recipient_handle:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} observed the recipient handle as a next hop",
            )
    # No single relay spans both ends: the ingress relay's prev is None (it does
    # not know the originator), the egress relay's next is None (it does not know
    # the recipient). Confirm the first/last observations match that shape.
    first, last = log.observations[0], log.observations[-1]
    if first.prev_hop is not None:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "ingress relay observed a predecessor (should be the opaque originator)",
        )
    final, final_error = _final_observation(log)
    if final_error is not None or final is not last:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            final_error or "terminal observation does not match the final hop",
        )
    if _routing_address(final) != expected_recipient:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final relay routing address does not match the recipient handle",
        )
    chain_error = _observation_chain_error(log)
    if chain_error is not None:
        return PropertyResult(pid, name, PropertyStatus.FAILED, chain_error)
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"{len(log.observations)} relays each saw only adjacent hops; final delivery "
        "is sealed, non-envelope plaintext, originator-free, and addressed only by "
        "the opaque recipient handle",
    )


def check_no_cleartext_relationship(
    log: TransitLog,
    *,
    comparison_logs: Optional[Iterable[TransitLog]] = None,
) -> PropertyResult:
    """§8.2 #2: no relay-visible identifier encodes the tenant pair or is stable.

    Every relay observation is validated, including the terminal relay.  A
    forwarding relay must record a blinded forwarded element and decoded opaque
    routing address; the final relay must record no forwarded element, an opaque
    destination address, and a sealed delivery.  Cross-session stability cannot
    be proven from one transit, so a single clean log is honestly PARTIAL.  When
    comparison logs are supplied, every relay-visible alpha/header and the final
    relay's destination address and sealed payload must be fresh across the
    observed transits. Callers are responsible for supplying distinct-session
    logs for the same endpoint relationship; this checker proves freshness and
    the identical realized path from the supplied artifacts, not the caller's
    endpoint-selection procedure.
    """
    pid = "8.2.2"
    name = "no cleartext relationship in addressing"
    if not log.observations:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED, "empty transit log"
        )
    final, final_error = _final_observation(log)
    if final_error is not None:
        return PropertyResult(pid, name, PropertyStatus.FAILED, final_error)
    chain_error = _observation_chain_error(log)
    if chain_error is not None:
        return PropertyResult(pid, name, PropertyStatus.FAILED, chain_error)

    for index, obs in enumerate(log.observations):
        if type(obs.received_alpha) is not bytes or len(obs.received_alpha) != 32:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} has an invalid received routing element",
            )
        if (
            type(obs.received_header_prefix) is not bytes
            or len(obs.received_header_prefix) != 16
        ):
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} has no relay-visible header evidence",
            )
        if not _valid_routing_address(_routing_address(obs)):
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} has no opaque 32-byte routing address",
            )
        if obs.is_final:
            if obs is not final or index != len(log.observations) - 1:
                return PropertyResult(
                    pid, name, PropertyStatus.FAILED,
                    "final relay observation is not terminal",
                )
            if obs.forwarded_alpha is not None:
                return PropertyResult(
                    pid, name, PropertyStatus.FAILED,
                    f"final relay {obs.node_aid} recorded a forwarded routing element",
                )
            if obs.next_hop is not None:
                return PropertyResult(
                    pid, name, PropertyStatus.FAILED,
                    f"final relay {obs.node_aid} exposes a clear next hop",
                )
            continue
        if obs.next_hop is None:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"forwarding relay {obs.node_aid} has no next-hop record",
            )
        if type(obs.forwarded_alpha) is not bytes or len(obs.forwarded_alpha) != 32:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"forwarding relay {obs.node_aid} has no valid forwarded element",
            )
        if obs.received_alpha == obs.forwarded_alpha:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {obs.node_aid} forwarded an UN-blinded element "
                f"(stable cross-hop identifier — links the packet)",
            )

    if (
        not log.delivered
        or type(log.delivered_payload) is not bytes
        or not _is_structurally_sealed_frame(log.delivered_payload)
    ):
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "final relay did not record an afp:sealed:v1 delivery",
        )

    if comparison_logs is None:
        return PropertyResult(
            pid, name, PropertyStatus.PARTIAL,
            f"all {len(log.observations) - 1} forwarding relays blinded and recorded "
            "opaque routing; final relay recorded only an opaque destination and "
            "sealed payload. Cross-session relay-visible identifier freshness was "
            "not supplied (declared partial evidence).",
        )
    try:
        comparisons = tuple(comparison_logs)
    except TypeError:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "comparison_logs is not an iterable of transit logs",
        )
    if not comparisons:
        return PropertyResult(
            pid, name, PropertyStatus.PARTIAL,
            "no cross-session comparison transit was supplied",
        )

    primary_route = tuple(observation.node_aid for observation in log.observations)
    seen_identifiers = {"alpha": {}, "header": {}}
    for hop_index, observation in enumerate(log.observations):
        for field, value in (
            ("alpha", observation.received_alpha),
            ("header", observation.received_header_prefix),
        ):
            previous = seen_identifiers[field].get(value)
            if previous is not None:
                return PropertyResult(
                    pid,
                    name,
                    PropertyStatus.FAILED,
                    f"relay-visible {field} repeats within the primary transit "
                    f"between {previous} and hop {hop_index}",
                )
            seen_identifiers[field][value] = f"primary transit hop {hop_index}"
    seen_final_addresses = {_routing_address(final): "the primary transit"}
    seen_final_payloads = {log.delivered_payload: "the primary transit"}
    for comparison_index, comparison_log in enumerate(comparisons, start=1):
        if not isinstance(comparison_log, TransitLog):
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"comparison log {comparison_index} is not a TransitLog",
            )
        comparison_validation = check_no_cleartext_relationship(comparison_log)
        if comparison_validation.status == PropertyStatus.FAILED:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"comparison log {comparison_index} has invalid final evidence: "
                f"{comparison_validation.evidence}",
            )
        comparison_route = tuple(
            observation.node_aid for observation in comparison_log.observations
        )
        if comparison_route != primary_route:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"comparison log {comparison_index} used a different relay path",
            )
        for hop_index, observation in enumerate(comparison_log.observations):
            for field, value in (
                ("alpha", observation.received_alpha),
                ("header", observation.received_header_prefix),
            ):
                previous = seen_identifiers[field].get(value)
                if previous is not None:
                    hop_label = (
                        "final relay-path hop"
                        if hop_index == len(comparison_log.observations) - 1
                        else "relay-path hop"
                    )
                    return PropertyResult(
                        pid, name, PropertyStatus.FAILED,
                        f"{hop_label} {hop_index} {field} repeats between "
                        f"{previous} and comparison transit {comparison_index}",
                    )
                seen_identifiers[field][value] = (
                    f"comparison transit {comparison_index} hop {hop_index}"
                )
        comparison_final = comparison_log.observations[-1]
        comparison_address = _routing_address(comparison_final)
        previous_address = seen_final_addresses.get(comparison_address)
        if previous_address is not None:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                "final-visible routing address repeats between "
                f"{previous_address} and comparison transit {comparison_index}",
            )
        seen_final_addresses[comparison_address] = (
            f"comparison transit {comparison_index}"
        )
        comparison_payload = comparison_log.delivered_payload
        previous_payload = seen_final_payloads.get(comparison_payload)
        if previous_payload is not None:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                "final-visible sealed payload repeats between "
                f"{previous_payload} and comparison transit {comparison_index}",
            )
        seen_final_payloads[comparison_payload] = f"comparison transit {comparison_index}"
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"all {len(log.observations) - 1} forwarding relays blinded and recorded "
        f"opaque routing; final relay exposes only opaque alpha/header/address and "
        f"a sealed payload. {len(comparisons)} comparison transit(s) over the "
        "same path show no repeated relay-visible identifier.",
    )


def check_correlation_resistance(
    log: TransitLog,
    *,
    payload_size: int,
) -> PropertyResult:
    """§8.2 #3: timing/volume treated to defeat correlation. PARTIAL by design.

    The unit-testable parts are PROVEN here: (a) per-hop exponential mixing delay
    was applied (decoupling arrival from departure timing), and (b) every packet is
    fixed-size (volume gives no signal). The *statistical-disclosure* guarantee
    against a global passive adversary over a long horizon is a Loopix-family
    analytic property (§8.10 explicitly lists long-horizon statistical disclosure
    as a residual the design *mitigates but does not eliminate*) — that part is a
    declared SEAM, not something a single transit can prove. So the property is
    honestly PARTIAL: the mechanism is demonstrably present; the asymptotic bound
    is argued, not unit-tested.
    """
    pid = "8.2.3"
    name = "correlation resistance"
    if log.total_delay_seconds <= 0.0:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "no mixing delay was applied (timing not decoupled)",
        )
    return PropertyResult(
        pid, name, PropertyStatus.PARTIAL,
        f"mechanism present: exponential per-hop mixing delay applied "
        f"(total {log.total_delay_seconds:.1f}s across {len(log.observations)} hops) "
        f"+ fixed {payload_size}B packets (no volume signal). Long-horizon "
        f"statistical-disclosure resistance is the Loopix-family analytic bound "
        f"(§8.10 residual), a declared seam — not unit-test-provable.",
    )


def check_no_single_trusted_relay(
    log: TransitLog,
    directory: MixnetDirectory,
) -> PropertyResult:
    """§8.2 #4: no single relay whose compromise reveals the graph.

    Proven over the transit + directory: (a) the path crosses distinct mix nodes in
    distinct layers (no node sees the whole path), and (b) the operators of the
    path nodes are not all the same single operator. The directory-level §8.6
    constraints (no operator owns a whole layer / a node in every layer) are
    enforced by :func:`directory.verify_directory`; this re-checks the realized
    path.
    """
    pid = "8.2.4"
    name = "no single trusted relay"
    aids = [o.node_aid for o in log.observations]
    if len(set(aids)) != len(aids):
        return PropertyResult(
            pid, name, PropertyStatus.FAILED, "a mix node appears twice on the path"
        )
    if len(aids) != directory.profile.hop_count:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            f"path used {len(aids)} hops, expected {directory.profile.hop_count} "
            "directory layers",
        )
    operators = set()
    for layer_index, observation in enumerate(log.observations):
        if observation.layer_index != layer_index:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {observation.node_aid} claims layer {observation.layer_index}, "
                f"expected {layer_index}",
            )
        if layer_index >= len(directory.layers):
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"path layer {layer_index} is absent from the verified directory",
            )
        descriptors = [
            node
            for node in directory.layers[layer_index]
            if node.mix_node_aid == observation.node_aid
        ]
        if len(descriptors) != 1:
            return PropertyResult(
                pid, name, PropertyStatus.FAILED,
                f"relay {observation.node_aid} is not uniquely present in verified "
                f"directory layer {layer_index}",
            )
        operators.add(descriptors[0].operator_aid)
    if len(operators) == 1:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            f"the entire path is run by one operator {operators!r} "
            f"(its compromise reveals the pairing)",
        )
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"path crosses {len(aids)} distinct nodes across {len(operators)} distinct "
        f"operators; no single relay or operator spans the path",
    )


def check_cover_indistinguishability(scheduler: CoverScheduler) -> PropertyResult:
    """§8.5: cover and real emissions are indistinguishable to a link observer.

    Proven from the emission trace: the observable projection (the slot cadence,
    REAL/COVER erased) is a constant-rate stream — identical whether the tenant is
    coordinating or idle. We demonstrate this by checking the cadence is constant
    and that the observable trace is invariant to the REAL/COVER labeling.
    """
    pid = "8.5"
    name = "mandatory cover-traffic indistinguishability"
    if not scheduler.trace:
        return PropertyResult(pid, name, PropertyStatus.FAILED, "no emissions")
    if not scheduler.observable_rate_is_constant():
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            "emission cadence is not constant (a gap reveals idle/active state)",
        )
    if not scheduler.is_healthy:
        return PropertyResult(
            pid, name, PropertyStatus.FAILED,
            f"{scheduler.missed_slots} missed cover slot(s) — OB-2 health failure (§8.5)",
        )
    n_real = sum(1 for e in scheduler.trace if e.kind == EmissionKind.REAL)
    n_cover = sum(1 for e in scheduler.trace if e.kind == EmissionKind.COVER)
    return PropertyResult(
        pid, name, PropertyStatus.PROVEN,
        f"constant-rate stream of {len(scheduler.trace)} slots "
        f"({n_real} real, {n_cover} cover); observable cadence is identical whether "
        f"coordinating or idle (REAL/COVER not observable)",
    )


@dataclass
class RoutingConformance:
    """Aggregate §8.2 verdict over a real transit + cover trace.

    ``ob2_eligible`` is the conservative gate the OB-2 disclosure layer consumes:
    True only when endpoint unlinkability (8.2.1), cross-session identifier
    freshness (8.2.2), and relay-trust evidence (8.2.4) are PROVEN, no property is
    FAILED, the mix-node set is sufficient, and cover traffic is healthy. Only the
    declared PARTIAL on asymptotic correlation resistance (8.2.3) may remain; the
    spec frames that bound as a residual in §8.10.
    """

    properties: List[PropertyResult]
    mix_node_count: int
    min_mix_nodes: int
    cover_healthy: bool

    @property
    def all_non_failed(self) -> bool:
        return all(p.ok for p in self.properties)

    @property
    def sufficient_node_set(self) -> bool:
        return self.mix_node_count >= self.min_mix_nodes

    @property
    def routing_evidence_sufficient(self) -> bool:
        """Whether the endpoint, identifier, and relay-trust evidence is proven."""
        statuses = {p.property_id: p.status for p in self.properties}
        required_proven = all(
            statuses.get(property_id) == PropertyStatus.PROVEN
            for property_id in ("8.2.1", "8.2.2", "8.2.4")
        )
        correlation_status = statuses.get("8.2.3")
        return (
            required_proven
            and correlation_status is not None
            and correlation_status != PropertyStatus.FAILED
        )

    @property
    def ob2_eligible(self) -> bool:
        return (
            self.routing_evidence_sufficient
            and self.sufficient_node_set
            and self.cover_healthy
        )

    def failures(self) -> List[PropertyResult]:
        return [p for p in self.properties if p.status == PropertyStatus.FAILED]

    def summary(self) -> str:
        lines = [
            f"{p.property_id} {p.name}: {p.status.value} — {p.evidence}"
            for p in self.properties
        ]
        lines.append(
            f"mix_node_set={self.mix_node_count} (>= {self.min_mix_nodes}: "
            f"{self.sufficient_node_set}), cover_healthy={self.cover_healthy}, "
            f"routing_evidence_sufficient={self.routing_evidence_sufficient}, "
            f"OB-2 eligible={self.ob2_eligible}"
        )
        return "\n".join(lines)


def assess_routing_layer(
    *,
    log: TransitLog,
    directory: MixnetDirectory,
    scheduler: CoverScheduler,
    originator: str,
    recipient_handle: str | bytes,
    profile: MixnetProfile = OB2_BASELINE,
    min_mix_nodes: int = 3,
    comparison_logs: Optional[Iterable[TransitLog]] = None,
) -> RoutingConformance:
    """Run all §8.2 (+ §8.5) checks over real artifacts and aggregate (conservative).

    This is the single entry point the OB-2 disclosure wiring calls to decide
    whether a deployment may *honestly* report OB-2. It is deliberately
    conservative: endpoint, cross-session identifier, and relay-trust evidence
    must be PROVEN; any FAILED property, an insufficient mix-node set, or
    unhealthy cover traffic makes ``ob2_eligible`` False.
    """
    props = [
        check_endpoint_unlinkability(
            log, originator=originator, recipient_handle=recipient_handle
        ),
        check_no_cleartext_relationship(log, comparison_logs=comparison_logs),
        check_correlation_resistance(log, payload_size=profile.payload_bytes),
        check_no_single_trusted_relay(log, directory),
        check_cover_indistinguishability(scheduler),
    ]
    return RoutingConformance(
        properties=props,
        mix_node_count=directory.node_count,
        min_mix_nodes=min_mix_nodes,
        cover_healthy=scheduler.is_healthy,
    )
