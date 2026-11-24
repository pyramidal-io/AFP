"""Mandatory cover traffic (§8.5) — the property OB-2 depends on.

§8.5 is normative and emphatic: cover traffic is **REQUIRED**, not optional, and
is the property on which OB-2 against a link observer depends. Every tenant MUST
emit coordination-plane traffic into the mixnet at a constant, scheduled rate at
all times while federated, **whether or not it has real coordination traffic to
send**. Real ``afp.*`` messages are slotted into this constant stream; when there
is no real message, a cover (loop) message is sent instead. Cover and real
packets are indistinguishable to any relay or observer (identical Sphinx form).

This module models that scheduler. The key conformance object is the **emission
trace**: the sequence of (slot, kind) a tenant emits, where ``kind`` is REAL or
COVER. The §8.2/§8.5 guarantee is that *the trace's observable shape is identical
whether the tenant is coordinating or idle* — a constant-rate stream either way.
:class:`CoverScheduler` enforces:

  * one packet per ``tenant_cover_interval_seconds`` slot, always (constant rate);
  * a real message, if queued, is slotted into the next slot; otherwise a cover
    packet fills the slot — so a slot is **never empty** and never reveals whether
    work was present;
  * a record of missed slots, which §8.5 says are an OB-2 health failure that MUST
    be disclosed in operator telemetry (without identifying counterparties).

The "indistinguishability" the conformance test asserts is structural: a REAL and
a COVER emission carry the same fixed-size Sphinx packet (built by
``afp_mixnet.sphinx`` with identical geometry), so the *only* difference is the
opaque encrypted payload — invisible to a relay/observer.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, List, Optional

from .profiles import OB2_BASELINE, MixnetProfile

__all__ = ["EmissionKind", "Emission", "CoverScheduler"]


class EmissionKind(str, Enum):
    REAL = "real"  # a slot carrying a real afp.* message (§5.3)
    COVER = "cover"  # a loop/cover packet filling an otherwise-idle slot (§8.5)


@dataclass(frozen=True)
class Emission:
    """One scheduled emission slot: which slot, REAL or COVER, and the payload tag.

    ``payload_ref`` is an opaque handle to the (Sphinx-wrapped) packet emitted;
    for the reference model it identifies the queued real message or a cover id.
    Crucially, the *observable* shape (a fixed-size Sphinx packet, emitted on
    schedule) is identical for REAL and COVER.
    """

    slot: int
    kind: EmissionKind
    payload_ref: str


@dataclass
class CoverScheduler:
    """A per-tenant constant-rate cover-traffic scheduler (§8.5).

    A tenant enqueues real messages with :meth:`enqueue_real`; the scheduler emits
    exactly one packet per slot (:meth:`tick`), drawing a real message if queued
    else emitting cover. The emission trace is the conformance artifact: its rate
    is constant and its observable shape is independent of whether work is present.
    """

    profile: MixnetProfile = OB2_BASELINE
    _queue: Deque[str] = field(default_factory=deque)
    _slot: int = 0
    trace: List[Emission] = field(default_factory=list)
    missed_slots: int = 0
    _cover_counter: int = 0

    @property
    def interval_seconds(self) -> float:
        return self.profile.tenant_cover_interval_seconds

    def enqueue_real(self, payload_ref: str) -> None:
        """Queue a real ``afp.*`` message to be slotted into the next cover slot."""
        self._queue.append(payload_ref)

    def tick(self) -> Emission:
        """Advance one slot and emit exactly one packet (REAL if queued, else COVER).

        A slot is NEVER empty: this is what makes the constant-rate stream identical
        whether the tenant is coordinating or idle (§8.5). Returns the emission.
        """
        slot = self._slot
        self._slot += 1
        if self._queue:
            ref = self._queue.popleft()
            emission = Emission(slot=slot, kind=EmissionKind.REAL, payload_ref=ref)
        else:
            self._cover_counter += 1
            emission = Emission(
                slot=slot,
                kind=EmissionKind.COVER,
                payload_ref=f"cover-{self._cover_counter}",
            )
        self.trace.append(emission)
        return emission

    def record_missed_slot(self) -> None:
        """Record a missed cover slot — an OB-2 health failure (§8.5).

        §8.5: missed cover slots MUST be disclosed in operator telemetry without
        identifying counterparties. The scheduler counts them; :meth:`is_healthy`
        reports the OB-2 health used by the conformance/disclosure layer.
        """
        self.missed_slots += 1

    @property
    def is_healthy(self) -> bool:
        """True iff no cover slot has been missed (the §8.5 OB-2 health condition)."""
        return self.missed_slots == 0

    def run_slots(self, count: int) -> List[Emission]:
        """Convenience: emit ``count`` slots and return the emissions."""
        return [self.tick() for _ in range(count)]

    def observable_rate_is_constant(self) -> bool:
        """True iff every slot up to now produced exactly one emission (constant rate).

        The conformance property: the trace has one emission per consecutive slot
        with no gaps — a constant-rate stream. (A real link observer sees exactly
        this cadence; the REAL/COVER kind is NOT observable.)
        """
        if not self.trace:
            return True
        slots = [e.slot for e in self.trace]
        return slots == list(range(slots[0], slots[0] + len(slots)))

    def observable_trace(self) -> List[int]:
        """What a link observer sees: just the slot cadence — REAL/COVER erased.

        This is the heart of the §8.5 indistinguishability argument: project the
        trace onto what is actually observable (the schedule), dropping the kind.
        Two traces — one all-cover (idle), one with reals slotted in — project to
        the SAME observable trace.
        """
        return [e.slot for e in self.trace]
