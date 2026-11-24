"""Mandatory cover-traffic tests (§8.5) — the OB-2-critical property.

Asserts the constant-rate emission discipline and the indistinguishability
argument: a tenant's observable emission trace is identical whether it is
coordinating or idle (the REAL/COVER kind is not observable).
"""

import _path  # noqa: F401

import unittest

from afp_mixnet.cover import CoverScheduler, EmissionKind

pytestmark = None


class CoverSchedulerTest(unittest.TestCase):
    def test_idle_tenant_emits_cover_every_slot(self):
        sched = CoverScheduler()
        emissions = sched.run_slots(5)
        self.assertEqual(len(emissions), 5)
        self.assertTrue(all(e.kind == EmissionKind.COVER for e in emissions))

    def test_real_message_is_slotted_in(self):
        sched = CoverScheduler()
        sched.run_slots(2)  # idle cover
        sched.enqueue_real("env-1")
        emission = sched.tick()
        self.assertEqual(emission.kind, EmissionKind.REAL)
        self.assertEqual(emission.payload_ref, "env-1")
        # Then back to cover when the queue drains.
        self.assertEqual(sched.tick().kind, EmissionKind.COVER)

    def test_a_slot_is_never_empty(self):
        sched = CoverScheduler()
        sched.run_slots(10)
        self.assertEqual(len(sched.trace), 10)
        self.assertTrue(sched.observable_rate_is_constant())

    def test_observable_trace_is_identical_idle_vs_active(self):
        # The §8.5 indistinguishability claim, made concrete: project both traces
        # onto what a link observer actually sees (slot cadence) — they match.
        idle = CoverScheduler()
        idle.run_slots(6)

        active = CoverScheduler()
        active.enqueue_real("a")
        active.enqueue_real("b")
        active.run_slots(6)  # two REAL slotted in, rest cover

        self.assertEqual(idle.observable_trace(), active.observable_trace())
        # But the underlying kinds DO differ (so this isn't a trivial equality).
        idle_kinds = [e.kind for e in idle.trace]
        active_kinds = [e.kind for e in active.trace]
        self.assertNotEqual(idle_kinds, active_kinds)

    def test_missed_slot_is_an_ob2_health_failure(self):
        sched = CoverScheduler()
        sched.run_slots(3)
        self.assertTrue(sched.is_healthy)
        sched.record_missed_slot()
        self.assertFalse(sched.is_healthy)
        self.assertEqual(sched.missed_slots, 1)

    def test_real_count_matches_enqueued(self):
        sched = CoverScheduler()
        for i in range(4):
            sched.enqueue_real(f"m{i}")
        sched.run_slots(10)
        reals = [e for e in sched.trace if e.kind == EmissionKind.REAL]
        self.assertEqual(len(reals), 4)


if __name__ == "__main__":
    unittest.main()
