"""AFP Federation Mixnet (§8) — Python reference implementation.

A stdlib-only reference implementation of the AFP **Metadata-Privacy Routing**
layer (specification §8), the layer that delivers **OB-2** (coordination-graph
privacy, §3.1). It is a Loopix-family mixnet (§8.3) built directly against the
§8.4 ``afp.mixnet.profile.ob2-baseline.v1`` parameter table, and it integrates
with the §12 Bilateral Session Core (``afp_session``) so a real bilateral session
can route its ``afp:envelope:v1`` THROUGH the mixnet (>= 3 hops, with mandatory
cover traffic).

Modules:

  * :mod:`afp_mixnet.crypto` — stdlib X25519 (RFC 7748), HKDF, a clean-room
    stream cipher + HMAC: the Sphinx primitives.
  * :mod:`afp_mixnet.sphinx` — the **Sphinx packet format** (§8.4): layered
    encryption, per-hop blinding (unlinkability), per-hop MAC == replay tag, fixed
    packet size. Real crypto, real roundtrip.
  * :mod:`afp_mixnet.profiles` — ``afp.mixnet.profile.ob2-baseline.v1`` and the
    "not weaker than baseline" comparison (§8.4).
  * :mod:`afp_mixnet.directory` — the **KERI-witnessed mix-node directory**
    (§8.7), reusing ``afp_session.keri`` witnesses + quorum receipts.
  * :mod:`afp_mixnet.mixnode` — a mix node: peel one layer, exponential mixing
    delay, replay detection (§8.4/§8.6).
  * :mod:`afp_mixnet.cover` — **mandatory cover traffic** (§8.5): constant-rate
    emission, REAL/COVER indistinguishability.
  * :mod:`afp_mixnet.network` — the stratified mixnet: route selection (one node
    per layer, >= 3 hops) + transit, with a per-hop observation log.
  * :mod:`afp_mixnet.conformance` — the **§8.2 conformance test** over real
    transit/cover artifacts, with honest proven/partial/seam verdicts.
  * :mod:`afp_mixnet.integration` — route an ``afp_session`` envelope through the
    mixnet and wire the result into the §3.5 honest OB-1/OB-2 disclosure guard.

Documented seams (honest, per §8.10 / the requirement): the clean-room reference
stream cipher (a production deployment uses audited AES-CTR/ChaCha20 — the Sphinx
*construction* is what this package proves); message fragmentation across multiple
Sphinx packets (§8.4 names it; this reference carries one 4 KiB payload class);
and the long-horizon statistical-disclosure asymptotic bound (a Loopix-family
analytic property, §8.10 residual — declared a seam, never unit-test-"proven").
"""

from __future__ import annotations

from .conformance import (
    PropertyResult,
    PropertyStatus,
    RoutingConformance,
    assess_routing_layer,
    check_cover_indistinguishability,
    check_correlation_resistance,
    check_endpoint_unlinkability,
    check_no_cleartext_relationship,
    check_no_single_trusted_relay,
)
from .cover import CoverScheduler, Emission, EmissionKind
from .directory import (
    DirectoryBuilder,
    DirectoryError,
    MixNodeDescriptor,
    MixnetDirectory,
    descriptor_for,
    verify_directory,
)
from .integration import (
    MixnetTransitError,
    MixnetTransitResult,
    deployment_profile_from_conformance,
    ob_claim_for_mixnet,
    rendezvous_handle,
    send_envelope_via_mixnet,
)
from .mixnode import MixNode, MixResult
from .network import (
    HopObservation,
    Mixnet,
    MixnetError,
    Route,
    TransitLog,
)
from .profiles import OB2_BASELINE, OB2_BASELINE_NAME, MixnetProfile, ProfileError
from .sphinx import (
    DEFAULT_PARAMS,
    IntegrityError,
    MixNodeKeypair,
    ProcessedPacket,
    ReplayError,
    SphinxError,
    SphinxPacket,
    SphinxParams,
    create_packet,
    process_packet,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # crypto / sphinx
    "MixNodeKeypair",
    "SphinxPacket",
    "ProcessedPacket",
    "SphinxParams",
    "DEFAULT_PARAMS",
    "create_packet",
    "process_packet",
    "SphinxError",
    "IntegrityError",
    "ReplayError",
    # profiles
    "MixnetProfile",
    "ProfileError",
    "OB2_BASELINE",
    "OB2_BASELINE_NAME",
    # directory
    "MixnetDirectory",
    "MixNodeDescriptor",
    "DirectoryBuilder",
    "DirectoryError",
    "verify_directory",
    "descriptor_for",
    # node / cover
    "MixNode",
    "MixResult",
    "CoverScheduler",
    "Emission",
    "EmissionKind",
    # network
    "Mixnet",
    "MixnetError",
    "Route",
    "HopObservation",
    "TransitLog",
    # conformance
    "PropertyStatus",
    "PropertyResult",
    "RoutingConformance",
    "assess_routing_layer",
    "check_endpoint_unlinkability",
    "check_no_cleartext_relationship",
    "check_correlation_resistance",
    "check_no_single_trusted_relay",
    "check_cover_indistinguishability",
    # integration
    "MixnetTransitResult",
    "MixnetTransitError",
    "rendezvous_handle",
    "send_envelope_via_mixnet",
    "deployment_profile_from_conformance",
    "ob_claim_for_mixnet",
]
