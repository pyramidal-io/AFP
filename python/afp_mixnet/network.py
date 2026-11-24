"""The stratified AFP Federation Mixnet — route selection and packet transit (§8.4).

This drives a Sphinx packet through a 3-layer stratified mix topology (§8.4):

  * **Route selection.** One mix node per layer is chosen (§8.4 "a packet
    traverses one node per layer"); ``ob2-baseline-v1`` requires 3 layers, so a
    route is >= 3 hops. The route is private to the sender (it is encoded only
    inside the Sphinx header — no relay or directory learns the full path).
  * **Transit.** Each hop peels one Sphinx layer (``MixNode.process``), learning
    only the immediately preceding and following hop. The mixnet records, per hop,
    *exactly what that relay observed* — this observation log is what the §8.2
    conformance tests assert over (a relay never sees both endpoints).
  * **Mixing.** Each hop samples an exponential delay; the simulator accumulates
    logical delay (the anonymity is in the construction, not wall-clock).

A :class:`TransitLog` is returned so the conformance layer can prove §8.2
properties 1–4 from real observations rather than by assertion.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from afp_session.canonical import digest

from . import crypto
from .directory import MixnetDirectory
from .mixnode import MixNode
from .sphinx import (
    SphinxParams,
    create_packet,
)

__all__ = [
    "MixnetError",
    "Route",
    "HopObservation",
    "TransitLog",
    "Mixnet",
]


class MixnetError(Exception):
    """A mixnet routing/transit failure (§8.4)."""


@dataclass(frozen=True)
class Route:
    """A selected path: one mix-node AID per layer, with their Sphinx public keys.

    The route is the sender's secret. ``addresses`` are the per-hop forward
    addresses (id of the next hop); the final hop carries the destination handle.
    """

    node_aids: List[str]
    public_keys: List[bytes]
    addresses: List[bytes]


@dataclass(frozen=True)
class HopObservation:
    """What a single relay observed while forwarding — the audit unit for §8.2.

    A relay sees the alpha and per-hop MAC/replay tag it received, its adjacent
    hop labels, and the routing address decoded from its own Sphinx layer. It
    MUST NOT see both the originating tenant and terminating tenant of a session
    (§8.2 property 1). ``received_alpha``/``forwarded_alpha`` let the conformance
    test prove unlinkability (they differ — blinding, §8.2 property 2).
    """

    node_aid: str
    layer_index: int
    received_alpha: bytes
    received_header_prefix: bytes  # per-hop MAC/replay tag, not a route address
    prev_hop: Optional[str]  # the hop it received from (None for ingress)
    next_hop: Optional[str]  # the hop it forwards to (None at final)
    is_final: bool
    forwarded_alpha: Optional[bytes] = None
    routing_address: Optional[bytes] = None  # decoded next-hop/destination address


@dataclass
class TransitLog:
    """The full record of a packet's transit, for conformance assertions (§8.2)."""

    observations: List[HopObservation] = field(default_factory=list)
    delivered_payload: Optional[bytes] = None
    total_delay_seconds: float = 0.0
    delivered: bool = False

    def relay_aids(self) -> List[str]:
        return [o.node_aid for o in self.observations]


class Mixnet:
    """A running stratified mixnet over a directory's mix-node set (§8.4).

    Construct from a verified :class:`MixnetDirectory` and the per-node
    :class:`MixNode` objects (which hold the private Sphinx keys). The sender uses
    :meth:`select_route` then :meth:`send` to route a payload to a destination
    handle; :meth:`send` returns a :class:`TransitLog`.
    """

    def __init__(
        self,
        directory: MixnetDirectory,
        nodes: Dict[str, MixNode],
        *,
        rng: Optional[random.Random] = None,
        params: Optional[SphinxParams] = None,
    ):
        self.directory = directory
        self.nodes = nodes
        self.rng = rng or random.Random()
        self.params = params or SphinxParams(
            max_hops=directory.profile.hop_count,
            payload_size=directory.profile.payload_bytes,
        )
        # Validate every layer's nodes are present.
        for layer in directory.layers:
            for desc in layer:
                if desc.mix_node_aid not in nodes:
                    raise MixnetError(
                        f"mix node {desc.mix_node_aid!r} in directory has no running node"
                    )

    @property
    def hop_count(self) -> int:
        return self.directory.profile.hop_count

    def select_route(self) -> Route:
        """Select one node per layer (a >= 3-hop stratified path), privately (§8.4).

        The route is encoded only inside the Sphinx header; nothing the relays or
        directory see reveals it. Raises if the directory has fewer layers than the
        profile's hop count (which :func:`directory.verify_directory` already
        rejects — this is defense in depth).
        """
        if len(self.directory.layers) < self.hop_count:
            raise MixnetError(
                f"directory has {len(self.directory.layers)} layers, need {self.hop_count}"
            )
        node_aids: List[str] = []
        public_keys: List[bytes] = []
        for layer in self.directory.layers[: self.hop_count]:
            desc = self.rng.choice(layer)
            node_aids.append(desc.mix_node_aid)
            public_keys.append(desc.sphinx_public_key)
        # addresses[i] = the id of hop i+1 (a per-hop forward address). Keep the
        # packet constructor's one-entry-per-hop contract by appending an explicit
        # unused final placeholder; the final Sphinx block carries the destination.
        addresses = [self._addr(aid) for aid in node_aids[1:]]
        addresses.append(b"\x00" * 32)
        return Route(node_aids=node_aids, public_keys=public_keys, addresses=addresses)

    @staticmethod
    def _addr(node_aid: str) -> bytes:
        """A fixed-size 32-byte routing address for a mix node (digest of its AID)."""
        return digest({"mix_node_aid": node_aid})

    def send(
        self,
        *,
        route: Route,
        destination_handle: bytes,
        payload: bytes,
        session_scalar: Optional[bytes] = None,
    ) -> TransitLog:
        """Route ``payload`` through ``route`` to ``destination_handle`` (§8.4).

        Builds a fixed-size Sphinx packet, drives it hop-by-hop through the mix
        nodes, and records a :class:`HopObservation` per hop. Returns a
        :class:`TransitLog` with the delivered payload, per-hop observations, and
        accumulated mixing delay. A malformed route or incomplete transit raises
        instead of returning partial evidence.

        Raises :class:`~afp_mixnet.sphinx.ReplayError` if a hop sees a replayed
        packet (the per-epoch replay set lives on each :class:`MixNode`).
        """
        route_length = len(route.node_aids)
        if route_length != self.hop_count:
            raise MixnetError(
                f"route has {route_length} hops, expected exactly {self.hop_count}"
            )
        if (
            len(route.public_keys) != route_length
            or len(route.addresses) != route_length
        ):
            raise MixnetError(
                "route node, public-key, and address lists must have equal lengths"
            )
        if type(destination_handle) is not bytes or len(destination_handle) != 32:
            raise MixnetError("destination handle must be exactly 32 bytes")
        expected_addresses = [
            self._addr(node_aid) for node_aid in route.node_aids[1:]
        ] + [b"\x00" * 32]
        if route.addresses != expected_addresses:
            raise MixnetError("route forwarding addresses do not match its node path")
        if len(set(route.node_aids)) != route_length:
            raise MixnetError("route must not repeat a mix node")
        for route_index, (node_aid, public_key) in enumerate(
            zip(route.node_aids, route.public_keys, strict=True)
        ):
            if route_index >= len(self.directory.layers):
                raise MixnetError(
                    f"verified directory has no layer {route_index} for the route"
                )
            descriptors = [
                descriptor
                for descriptor in self.directory.layers[route_index]
                if descriptor.mix_node_aid == node_aid
            ]
            if len(descriptors) != 1:
                raise MixnetError(
                    f"route node {node_aid!r} is not uniquely present in verified "
                    f"directory layer {route_index}"
                )
            descriptor = descriptors[0]
            node = self.nodes.get(node_aid)
            if node is None:
                raise MixnetError(f"route names unavailable mix node {node_aid!r}")
            if node.mix_node_aid != node_aid:
                raise MixnetError(
                    f"running node map entry {node_aid!r} identifies another node"
                )
            if node.layer_index != route_index:
                raise MixnetError(
                    f"route node {node_aid!r} belongs to layer {node.layer_index}, "
                    f"not route index {route_index}"
                )
            if (
                descriptor.sphinx_public_key != public_key
                or node.keypair.public_point != public_key
            ):
                raise MixnetError(
                    f"route public key does not match verified mix node {node_aid!r}"
                )
            if node.operator_aid != descriptor.operator_aid:
                raise MixnetError(
                    f"running operator does not match directory node {node_aid!r}"
                )
        x = session_scalar or crypto.random_scalar()
        packet = create_packet(
            session_scalar=x,
            hop_public_keys=route.public_keys,
            hop_addresses=route.addresses,
            destination=destination_handle,
            payload=payload,
            params=self.params,
        )

        log = TransitLog()
        current = packet
        prev_hop: Optional[str] = None
        for route_index, node_aid in enumerate(route.node_aids):
            node = self.nodes[node_aid]
            result = node.process(current, params=self.params)
            log.total_delay_seconds += result.delay_seconds
            processed = result.processed
            if processed.is_final:
                if route_index != route_length - 1:
                    raise MixnetError(
                        f"Sphinx packet reached a final hop early at route index {route_index}"
                    )
                if processed.delivered_payload is None:
                    raise MixnetError("final Sphinx result has no delivered payload")
                if processed.destination_address != destination_handle:
                    raise MixnetError(
                        "final Sphinx destination does not match the requested handle"
                    )
                log.observations.append(
                    HopObservation(
                        node_aid=node_aid,
                        layer_index=node.layer_index,
                        received_alpha=current.alpha,
                        received_header_prefix=current.header[:16],
                        prev_hop=prev_hop,
                        next_hop=None,
                        is_final=True,
                        routing_address=processed.destination_address,
                    )
                )
                log.delivered_payload = processed.delivered_payload
                log.delivered = True
                break
            if route_index == route_length - 1:
                raise MixnetError("Sphinx packet remained non-final at the end of the route")
            if processed.next_packet is None:
                raise MixnetError("forwarding Sphinx result has no next packet")
            if processed.next_address is None:
                raise MixnetError("forwarding Sphinx result has no next-hop address")
            next_aid = route.node_aids[route_index + 1]
            expected_next_address = self._addr(next_aid)
            if processed.next_address != expected_next_address:
                raise MixnetError(
                    f"decoded next-hop address does not match route node {next_aid!r}"
                )
            log.observations.append(
                HopObservation(
                    node_aid=node_aid,
                    layer_index=node.layer_index,
                    received_alpha=current.alpha,
                    received_header_prefix=current.header[:16],
                    prev_hop=prev_hop,
                    next_hop=next_aid,
                    is_final=False,
                    forwarded_alpha=processed.next_packet.alpha,
                    routing_address=processed.next_address,
                )
            )
            prev_hop = node_aid
            current = processed.next_packet
        if not log.delivered:
            raise MixnetError("route exhausted without a final Sphinx delivery")
        return log
