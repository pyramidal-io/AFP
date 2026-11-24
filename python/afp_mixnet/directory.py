"""KERI-witnessed mix-node directory (§8.7) — ``afp:mixnet-directory:v1``.

The set of mix nodes, their layer assignment, and their public keys are published
as a **directory** every tenant can verify without trusting any single party
(§8.7). AFP introduces no new trust authority for the directory: it reuses the
§4 KERI substrate. This module builds and verifies the directory the §8.7 way:

  * the directory document is signed by a **quorum of consortium witnesses**
    (real Ed25519 receipts over the directory digest, via ``afp_session.keri``
    :class:`~afp_session.keri.Witness`);
  * a tenant verifies the witness quorum the same way it verifies a peer's KEL —
    no operator contact needed;
  * the directory carries a ``keri_anchor_event_dig`` binding it into the
    consortium's KERI-witnessed structure so directory trust and federation
    identity share one root (§8.7).

A tenant MUST reject a directory if (§8.7):
  * the KERI anchor is absent;
  * the witness quorum is below the federation threshold;
  * the profile parameters are weaker than ``ob2-baseline-v1``;
  * any layer is empty;
  * the operator-control constraints of §8.6 are violated (no operator may
    control all nodes in a layer, nor enough adjacent-layer positions to observe
    a full path — modeled here as: no single operator owns a whole layer, and no
    single operator owns a node in *every* layer).

The verifier-facing shape mirrors the spec's ``AfpMixnetDirectory`` TypeScript
interface (§8.7). The witness/quorum machinery is the real ``afp_session.keri``
witness receipts — this is the "reuse §4, no new trust authority" requirement
made concrete.

``valid_from`` and ``valid_until`` are §1.6.1 UTC datetime strings
(``YYYY-MM-DDTHH:MM:SSZ``), and the witness quorum signs that text. A directory
that carries numbers instead is rejected, never translated: a directory built
by an older release that emitted numbers must be rebuilt and re-signed.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Dict, List, Optional

from afp_session import ed25519
from afp_session.atoms import (
    MAX_UTC_DATETIME_SECONDS,
    MIN_UTC_DATETIME_SECONDS,
    unix_to_utc_datetime,
    utc_datetime_to_unix,
    validate_utc_datetime,
)
from afp_session.canonical import digest, qb64
from afp_session.keri import Witness

from .profiles import OB2_BASELINE, MixnetProfile, ProfileError
from .sphinx import MixNodeKeypair

__all__ = [
    "DirectoryError",
    "MixNodeDescriptor",
    "MixnetDirectory",
    "DirectoryBuilder",
    "verify_directory",
    "DIRECTORY_KIND",
]

DIRECTORY_KIND = "afp:mixnet-directory:v1"


class DirectoryError(Exception):
    """A mix-node directory failed §8.7 verification."""


@dataclass(frozen=True)
class MixNodeDescriptor:
    """One mix node's verifier-facing record in the directory (§8.7).

    ``sphinx_keypair`` is held only by the node itself; the directory publishes
    ``sphinx_public_key``. ``operator_aid`` is the operator that runs the node —
    used to enforce the §8.6 no-single-operator-controls-a-path constraint.
    """

    mix_node_aid: str
    operator_aid: str
    endpoint: str
    sphinx_public_key: bytes
    software_ref: str = "afp-mixnet-reference/0.1.0"

    def to_public_dict(self) -> dict:
        return {
            "mix_node_aid": self.mix_node_aid,
            "operator_aid": self.operator_aid,
            "endpoint": self.endpoint,
            "sphinx_public_key": self.sphinx_public_key.hex(),
            "software_ref": self.software_ref,
        }


@dataclass(frozen=True)
class _QuorumSignature:
    witness_aid: str
    signature: bytes


@dataclass
class MixnetDirectory:
    """``afp:mixnet-directory:v1`` — the KERI-witnessed mix-node directory (§8.7)."""

    epoch: int
    valid_from: str  # §1.6.1 UTC datetime string
    valid_until: str  # §1.6.1 UTC datetime string
    keri_anchor_event_dig: str
    profile: MixnetProfile
    layers: List[List[MixNodeDescriptor]]
    quorum_signatures: List[_QuorumSignature] = field(default_factory=list)
    kind: str = DIRECTORY_KIND

    def __post_init__(self) -> None:
        validate_utc_datetime(self.valid_from, "valid_from")
        validate_utc_datetime(self.valid_until, "valid_until")

    def signing_content(self) -> dict:
        """The deterministic content the witness quorum signs (excludes signatures)."""
        # The dataclass is mutable, so check the wire values where they leave.
        validate_utc_datetime(self.valid_from, "valid_from")
        validate_utc_datetime(self.valid_until, "valid_until")
        return {
            "kind": self.kind,
            "profile": self.profile.name,
            "epoch": self.epoch,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "keri_anchor_event_dig": self.keri_anchor_event_dig,
            "sphinx": {
                "packet_payload_bytes": self.profile.payload_bytes,
                "hop_count": self.profile.hop_count,
            },
            "mixing": {
                "delay_distribution": "exponential",
                "mean_delay_seconds": self.profile.mean_delay_seconds,
                "packet_ttl_seconds": self.profile.packet_ttl_seconds,
            },
            "cover": {
                "tenant_packet_interval_seconds": self.profile.tenant_cover_interval_seconds,
                "mix_loop_interval_seconds": self.profile.mix_loop_interval_seconds,
            },
            "layers": [
                [node.to_public_dict() for node in layer] for layer in self.layers
            ],
        }

    @property
    def digest(self) -> str:
        return qb64("D", digest(self.signing_content()))

    @property
    def node_count(self) -> int:
        return sum(len(layer) for layer in self.layers)

    def all_nodes(self) -> List[MixNodeDescriptor]:
        return [node for layer in self.layers for node in layer]

    def find_public_key(self, mix_node_aid: str) -> Optional[bytes]:
        for node in self.all_nodes():
            if node.mix_node_aid == mix_node_aid:
                return node.sphinx_public_key
        return None


class DirectoryBuilder:
    """Builds and witness-signs a :class:`MixnetDirectory` (the consortium's job).

    The consortium witnesses are real ``afp_session.keri`` :class:`Witness`
    objects; signing produces real Ed25519 receipts over the directory digest, so
    a tenant verifies the quorum with the same code path it uses for a KEL (§8.7).
    """

    def __init__(self, witnesses: List[Witness], quorum_threshold: int):
        if quorum_threshold > len(witnesses):
            raise DirectoryError(
                f"quorum threshold {quorum_threshold} exceeds witness count {len(witnesses)}"
            )
        self._witnesses = list(witnesses)
        self.quorum_threshold = quorum_threshold

    @property
    def witness_keys(self) -> Dict[str, bytes]:
        """The witness AID -> public key map a verifier needs (§8.7 / §4.5)."""
        return {w.aid: w.public_key for w in self._witnesses}

    def build(
        self,
        *,
        epoch: int,
        layers: List[List[MixNodeDescriptor]],
        keri_anchor_event_dig: str,
        profile: MixnetProfile = OB2_BASELINE,
        valid_from: Optional[float] = None,
        ttl_seconds: Optional[float] = None,
        signing_witnesses: Optional[List[Witness]] = None,
    ) -> MixnetDirectory:
        """Build a directory and gather quorum signatures over its digest.

        ``signing_witnesses`` defaults to all configured witnesses; pass a subset
        to model a quorum that just meets (or, in a test, falls below) threshold.

        ``valid_from`` and ``ttl_seconds`` are scheduling inputs in Unix seconds.
        §1.6.1 puts whole-second UTC text on the wire, so an explicit
        ``valid_from`` rounds up (the directory is never valid before it), a
        default start is the current whole second (a fresh directory verifies at
        once), and the end ``valid_from + ttl_seconds`` rounds down. The sum is
        exact, never a float that can overflow. The exact start and end must
        lie in the UTC datetime range before any rounding, so a value just
        outside it is never rounded into it. An unusable input, an instant
        outside that range, or an empty window raises :class:`DirectoryError`.
        """
        ttl = ttl_seconds if ttl_seconds is not None else profile.directory_epoch_seconds
        explicit_start = valid_from is not None
        start = _scheduling_seconds(
            valid_from if explicit_start else time.time(), "valid_from"
        )
        end = start + _scheduling_seconds(ttl, "ttl_seconds")
        for name, instant in (("valid_from", start), ("valid_until", end)):
            if not MIN_UTC_DATETIME_SECONDS <= instant <= MAX_UTC_DATETIME_SECONDS:
                raise DirectoryError(
                    f"directory {name} is outside 0001-01-01T00:00:00Z through "
                    "9999-12-31T23:59:59Z"
                )
        # Both range ends are whole seconds, so rounding stays inside the range.
        starts = math.ceil(start) if explicit_start else math.floor(start)
        ends = math.floor(end)
        if ends <= starts:
            raise DirectoryError(
                "directory validity window is empty after whole-second rounding"
            )
        window = (unix_to_utc_datetime(starts), unix_to_utc_datetime(ends))
        directory = MixnetDirectory(
            epoch=epoch,
            valid_from=window[0],
            valid_until=window[1],
            keri_anchor_event_dig=keri_anchor_event_dig,
            profile=profile,
            layers=layers,
        )
        signers = signing_witnesses if signing_witnesses is not None else self._witnesses
        dig = directory.digest
        for w in signers:
            sig = w.keypair.sign(dig.encode("utf-8"))
            directory.quorum_signatures.append(
                _QuorumSignature(witness_aid=w.aid, signature=sig)
            )
        return directory


def _scheduling_seconds(value: object, name: str) -> Fraction:
    """Return a finite number of seconds as an exact rational.

    ``Fraction`` holds any int or finite float exactly, so the window
    arithmetic neither rounds nor overflows; the UTC range check then rejects
    a value that is too large.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DirectoryError(f"{name} must be a finite number of seconds")
    if isinstance(value, float) and not math.isfinite(value):
        raise DirectoryError(f"{name} must be a finite number of seconds")
    return Fraction(value)


def verify_directory(
    directory: MixnetDirectory,
    *,
    witness_keys: Dict[str, bytes],
    quorum_threshold: int,
    now: Optional[float] = None,
    require_profile: MixnetProfile = OB2_BASELINE,
) -> None:
    """Verify a directory per §8.7. Raises :class:`DirectoryError` on any failure.

    Checks, in order:
      1. kind/anchor present (§8.7 — reject if the KERI anchor is absent);
      2. not expired (§8.4 directory epoch; tenants MUST reject expired);
      3. no empty layer, and at least ``hop_count`` layers (§8.7);
      4. profile parameters not weaker than ``ob2-baseline-v1`` (§8.4/§8.7);
      5. §8.6 operator-control constraints;
      6. a witness quorum of valid Ed25519 receipts over the directory digest,
         at or above the federation threshold (§8.7 / §4.5).
    """
    if directory.kind != DIRECTORY_KIND:
        raise DirectoryError(f"directory kind must be {DIRECTORY_KIND}")
    if not directory.keri_anchor_event_dig:
        raise DirectoryError("directory has no KERI anchor (§8.7)")

    clock = _scheduling_seconds(now if now is not None else time.time(), "clock")
    try:
        valid_from = utc_datetime_to_unix(directory.valid_from, "valid_from")
        valid_until = utc_datetime_to_unix(directory.valid_until, "valid_until")
    except ValueError as exc:
        raise DirectoryError(f"directory validity window is malformed: {exc}") from exc
    if clock >= valid_until:
        raise DirectoryError("directory epoch has expired (§8.4)")
    if clock < valid_from:
        raise DirectoryError("directory is not yet valid")

    if len(directory.layers) < require_profile.hop_count:
        raise DirectoryError(
            f"directory has {len(directory.layers)} layers, profile requires "
            f"{require_profile.hop_count} (§8.4 hop geometry)"
        )
    for i, layer in enumerate(directory.layers):
        if not layer:
            raise DirectoryError(f"directory layer {i} is empty (§8.7)")

    # Profile must not be weaker than the required baseline (§8.4/§8.7). A profile
    # weakness is a directory-rejection reason, so surface it as DirectoryError.
    try:
        require_profile.assert_not_weaker_than_baseline(directory.profile)
    except ProfileError as exc:
        raise DirectoryError(str(exc)) from exc

    _check_operator_constraints(directory)

    _verify_quorum(directory, witness_keys, quorum_threshold)


def _check_operator_constraints(directory: MixnetDirectory) -> None:
    """§8.6: no single operator controls a full path-observing position.

    Modeled as two structural rules a directory verifier can check from the
    operator_aids alone:
      * no single operator owns *every* node in any layer (else it sees a whole
        stratum); and
      * no single operator owns at least one node in *every* layer (else a
        colluding self can occupy a full path).
    These are the directory-checkable shadow of "no operator may control all
    nodes in any layer or enough adjacent-layer positions to observe a full path".
    """
    for i, layer in enumerate(directory.layers):
        operators = {node.operator_aid for node in layer}
        if len(operators) == 1 and len(layer) >= 1:
            raise DirectoryError(
                f"layer {i} is controlled by a single operator "
                f"{next(iter(operators))!r} (§8.6 no single trusted relay)"
            )
    # No operator present in every layer.
    per_layer_ops = [{node.operator_aid for node in layer} for layer in directory.layers]
    spanning = set.intersection(*per_layer_ops) if per_layer_ops else set()
    if spanning:
        raise DirectoryError(
            f"operator(s) {sorted(spanning)!r} occupy a node in every layer — a "
            f"full path-observing position (§8.6)"
        )


def _verify_quorum(
    directory: MixnetDirectory,
    witness_keys: Dict[str, bytes],
    quorum_threshold: int,
) -> None:
    for witness_aid, public_key in witness_keys.items():
        try:
            ed25519.validate_public_key(public_key)
        except ValueError as exc:
            raise DirectoryError(
                f"directory witness {witness_aid!r} has invalid Ed25519 "
                "public-key material"
            ) from exc

    dig = directory.digest.encode("utf-8")
    valid = 0
    seen = set()
    for qs in directory.quorum_signatures:
        if qs.witness_aid in seen:
            continue
        pub = witness_keys.get(qs.witness_aid)
        if pub is None:
            continue
        if ed25519.verify_strict(dig, qs.signature, pub):
            seen.add(qs.witness_aid)
            valid += 1
    if valid < quorum_threshold:
        raise DirectoryError(
            f"directory has {valid} valid witness signatures, below the federation "
            f"quorum threshold {quorum_threshold} (§8.7)"
        )


def descriptor_for(
    keypair: MixNodeKeypair,
    *,
    mix_node_aid: str,
    operator_aid: str,
    endpoint: str,
    software_ref: str = "afp-mixnet-reference/0.1.0",
) -> MixNodeDescriptor:
    """Convenience: a public :class:`MixNodeDescriptor` from a node's keypair."""
    return MixNodeDescriptor(
        mix_node_aid=mix_node_aid,
        operator_aid=operator_aid,
        endpoint=endpoint,
        sphinx_public_key=keypair.public_point,
        software_ref=software_ref,
    )
