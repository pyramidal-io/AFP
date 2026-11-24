"""A single AFP mix node — continuous-time mixing + replay detection (§8.4/§8.6).

A mix node (§8.6) is operated by one of the mutually-distrusting parties. Its job
per §8.4:

  * **Peel exactly one Sphinx layer** (``afp_mixnet.sphinx.process_packet``),
    learning only the immediately preceding and following hop.
  * **Delay each packet** by an independent, exponentially-distributed random
    delay (client-selected per hop in canonical Loopix; here the node samples it,
    which is equivalent for the reference simulator). This decouples arrival from
    departure timing — the core of §8.2 property 3.
  * **Reject replays** within the directory epoch: each per-hop Sphinx MAC is a
    replay tag; a repeat is dropped.
  * **Emit loop cover traffic** into adjacent layers independent of tenant
    activity (§8.5) — handled by the cover scheduler, which the node feeds.

This is a *logical* mix node for the reference simulator: it does not open
sockets. ``process`` returns the next hop's address + packet (or a final
delivery) and the sampled delay; a network driver (``afp_mixnet.network``)
schedules delivery. The mixing/anonymity properties live in the construction, not
in wall-clock timing, so the simulator can run delays as logical quantities.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional, Set

from .profiles import OB2_BASELINE, MixnetProfile
from .sphinx import (
    MixNodeKeypair,
    ProcessedPacket,
    SphinxPacket,
    SphinxParams,
    process_packet,
)

__all__ = ["MixNode", "MixResult"]


@dataclass
class MixResult:
    """The outcome of a mix node processing a packet: the peeled result + delay."""

    processed: ProcessedPacket
    delay_seconds: float


@dataclass
class MixNode:
    """A logical AFP mix node (§8.4/§8.6).

    ``layer_index`` is its stratum (0..hop_count-1). ``seen_tags`` is its per-epoch
    replay set. ``rng`` is injectable for deterministic tests of the exponential
    delay sampling.
    """

    mix_node_aid: str
    operator_aid: str
    layer_index: int
    keypair: MixNodeKeypair
    profile: MixnetProfile = OB2_BASELINE
    seen_tags: Set[bytes] = field(default_factory=set)
    rng: random.Random = field(default_factory=random.Random)
    loop_cover_emitted: int = 0

    def _sample_delay(self) -> float:
        """Independent exponential delay, mean ``profile.mean_delay_seconds`` (§8.4)."""
        return self.rng.expovariate(1.0 / self.profile.mean_delay_seconds)

    def process(
        self,
        packet: SphinxPacket,
        *,
        params: SphinxParams = SphinxParams(),
    ) -> MixResult:
        """Peel one layer, sample the per-hop delay, and detect replays (§8.4).

        Raises :class:`~afp_mixnet.sphinx.ReplayError` on a replayed packet and
        :class:`~afp_mixnet.sphinx.IntegrityError` on a tampered header — both are
        "drop the packet", the single protocol consequence of a bad packet.
        """
        processed = process_packet(
            packet, self.keypair, seen_tags=self.seen_tags, params=params
        )
        return MixResult(processed=processed, delay_seconds=self._sample_delay())

    def reset_epoch(self) -> None:
        """Clear the replay set at a new directory epoch (§8.4 epoch boundary)."""
        self.seen_tags.clear()

    def emit_loop_cover(self) -> int:
        """Record a mix-node loop-cover emission (§8.5).

        Mix nodes MUST emit loop cover into adjacent layers so link-level traffic
        between mix nodes is constant independent of tenant activity. The reference
        simulator counts these; a deployment actually injects loop Sphinx packets.
        """
        self.loop_cover_emitted += 1
        return self.loop_cover_emitted
