"""AFP mixnet profiles — ``afp.mixnet.profile.ob2-baseline.v1`` (§8.4).

§8.4 fixes the baseline implementation profile so implementers do not pick weaker
deployment defaults. A deployment MAY define a *stricter* profile, but it MUST
disclose any deviation and still satisfy §8.2. This module captures the baseline
parameter table verbatim and provides the "not weaker than baseline" comparison a
directory verifier (§8.7) uses to reject a directory whose parameters are weaker
than ``ob2-baseline-v1``.

The §8.4 ``ob2-baseline-v1`` table:

  | Packet format        | Sphinx, fixed-size packets         |
  | Hop geometry         | 3 mix hops, one hop per layer      |
  | Layers               | 3 stratified layers                |
  | Payload class        | 4 KiB encrypted payload fragment   |
  | Per-hop delay        | Exponential, mean 30 s             |
  | Maximum packet TTL   | 15 min                             |
  | Tenant cover rate    | >= 1 packet every 10 s per tenant  |
  | Mix-node loop cover  | >= 1 loop every 10 s per node/layer|
  | Directory epoch      | At most 24 h                       |
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ProfileError", "MixnetProfile", "OB2_BASELINE", "OB2_BASELINE_NAME"]

OB2_BASELINE_NAME = "afp.mixnet.profile.ob2-baseline.v1"


class ProfileError(Exception):
    """A profile comparison or definition violated §8.4."""


@dataclass(frozen=True)
class MixnetProfile:
    """A mixnet implementation profile (§8.4).

    "Stricter" means: more hops/layers, smaller (or equal) cover intervals (more
    frequent cover), shorter directory epoch — and the same Sphinx packet format
    and exponential mixing. The :meth:`assert_not_weaker_than_baseline` check
    encodes exactly the §8.7 directory rejection: a directory whose profile is
    weaker than the required baseline MUST be rejected.
    """

    name: str
    packet_format: str  # MUST be "sphinx"
    hop_count: int
    layer_count: int
    payload_bytes: int
    delay_distribution: str  # MUST be "exponential"
    mean_delay_seconds: float
    packet_ttl_seconds: float
    tenant_cover_interval_seconds: float
    mix_loop_interval_seconds: float
    directory_epoch_seconds: float

    def assert_not_weaker_than_baseline(self, candidate: "MixnetProfile") -> None:
        """Raise if ``candidate`` is weaker than ``self`` for OB-2 (§8.4/§8.7).

        A weaker candidate is one that, on any conformance-relevant axis, gives a
        link observer *more* to work with than the baseline: fewer hops/layers, a
        non-Sphinx packet format, non-exponential mixing, a larger cover interval
        (less frequent cover), or a longer directory epoch. Equal-or-stricter on
        every axis passes.
        """
        if candidate.packet_format != "sphinx":
            raise ProfileError(
                f"profile {candidate.name!r} packet format {candidate.packet_format!r} "
                f"is not Sphinx (§8.4)"
            )
        if candidate.delay_distribution != "exponential":
            raise ProfileError(
                f"profile {candidate.name!r} mixing {candidate.delay_distribution!r} "
                f"is not exponential continuous-time mixing (§8.4)"
            )
        if candidate.hop_count < self.hop_count:
            raise ProfileError(
                f"profile {candidate.name!r} uses {candidate.hop_count} hops, weaker "
                f"than baseline {self.hop_count} (§8.4: MUST NOT use fewer than 3 hops)"
            )
        if candidate.layer_count < self.layer_count:
            raise ProfileError(
                f"profile {candidate.name!r} uses {candidate.layer_count} layers, "
                f"weaker than baseline {self.layer_count} (§8.4)"
            )
        if candidate.tenant_cover_interval_seconds > self.tenant_cover_interval_seconds:
            raise ProfileError(
                f"profile {candidate.name!r} tenant cover interval "
                f"{candidate.tenant_cover_interval_seconds}s is longer than baseline "
                f"{self.tenant_cover_interval_seconds}s (cover too infrequent, §8.5)"
            )
        if candidate.mix_loop_interval_seconds > self.mix_loop_interval_seconds:
            raise ProfileError(
                f"profile {candidate.name!r} mix loop interval "
                f"{candidate.mix_loop_interval_seconds}s is longer than baseline "
                f"{self.mix_loop_interval_seconds}s (§8.5)"
            )
        if candidate.directory_epoch_seconds > self.directory_epoch_seconds:
            raise ProfileError(
                f"profile {candidate.name!r} directory epoch "
                f"{candidate.directory_epoch_seconds}s exceeds baseline "
                f"{self.directory_epoch_seconds}s (§8.4: at most 24 h)"
            )


# The §8.4 ob2-baseline-v1 parameter table.
OB2_BASELINE = MixnetProfile(
    name=OB2_BASELINE_NAME,
    packet_format="sphinx",
    hop_count=3,
    layer_count=3,
    payload_bytes=4096,
    delay_distribution="exponential",
    mean_delay_seconds=30.0,
    packet_ttl_seconds=900.0,  # 15 min
    tenant_cover_interval_seconds=10.0,
    mix_loop_interval_seconds=10.0,
    directory_epoch_seconds=86400.0,  # 24 h
)
