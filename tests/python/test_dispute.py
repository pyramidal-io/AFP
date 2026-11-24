"""Bilateral dispute + optional pre-agreed arbiter tests (§12.5)."""

import _path  # noqa: F401

import unittest

import afp_session as afp
from afp_session import keri
from afp_session.dispute import ArbiterError, DivergenceRecord
from fixtures import make_witness


def _entity():
    tenant = keri.Identity.incept_tenant()
    return tenant, keri.Identity.incept_entity(tenant)


def _witnessed_entity(label):
    witness = make_witness()
    keys = {witness.aid: witness.public_key}
    tenant = keri.Identity.incept_tenant(witnesses=[witness], threshold=1)
    return tenant, keri.Identity.incept_entity(tenant, witnesses=[witness], threshold=1), keys


class DivergenceTest(unittest.TestCase):
    def test_signed_divergence_record_verifies(self):
        tenant, entity = _entity()
        rec = DivergenceRecord(
            id="div-1",
            session_ref="sess-1",
            raised_by="",
            kel_event_dig="",
            reason="cannot agree on reconciled state",
        )
        rec.sign(entity)
        self.assertTrue(rec.verify(entity.kel, tenant_kel=tenant.kel, witness_keys={}))

    def test_tampered_divergence_record_rejected(self):
        tenant, entity = _entity()
        rec = DivergenceRecord(
            id="div-1", session_ref="sess-1", raised_by="", kel_event_dig="", reason="r"
        )
        rec.sign(entity)
        rec.reason = "altered reason"  # tamper after signing
        self.assertFalse(rec.verify(entity.kel, tenant_kel=tenant.kel, witness_keys={}))

    def test_unsigned_record_does_not_verify(self):
        tenant, entity = _entity()
        rec = DivergenceRecord(
            id="d", session_ref="s", raised_by=entity.aid, kel_event_dig="", reason="r"
        )
        self.assertFalse(rec.verify(entity.kel, tenant_kel=tenant.kel, witness_keys={}))

    def test_witnessed_divergence_requires_map_and_receipts(self):
        tenant, entity, witness_keys = _witnessed_entity("divergence")
        rec = DivergenceRecord(
            id="div-witnessed", session_ref="s", raised_by="", kel_event_dig="", reason="r"
        ).sign(entity)
        self.assertTrue(rec.verify(entity.kel, tenant_kel=tenant.kel, witness_keys=witness_keys))
        self.assertFalse(rec.verify(entity.kel, tenant_kel=tenant.kel))
        event = entity.kel.events[0]
        entity.kel.receipts[event.digest] = []
        self.assertFalse(rec.verify(entity.kel, tenant_kel=tenant.kel, witness_keys=witness_keys))


class ArbiterTest(unittest.TestCase):
    def setUp(self):
        self.tA, self.eA = _entity()
        self.tB, self.eB = _entity()
        self.t_arb, self.e_arb = _entity()

    def test_arbiter_must_match_pre_agreed_aid(self):
        # An arbiter selected at dispute time (wrong AID) is rejected (§12.5).
        with self.assertRaises(ArbiterError):
            afp.Arbiter(self.e_arb, agreement_arbiter_aid="E_someone-else")

    def test_arbiter_decision_verifies(self):
        arb = afp.Arbiter(self.e_arb, agreement_arbiter_aid=self.e_arb.aid)
        decision = arb.decide(
            decision_id="dec-1", session_ref="sess-1", decision="favor responder"
        )
        self.assertTrue(decision.verify(self.e_arb.kel, tenant_kel=self.t_arb.kel, witness_keys={}))

    def test_witnessed_arbiter_decision_requires_map_and_receipts(self):
        tenant, entity, witness_keys = _witnessed_entity("arbiter")
        decision = afp.Arbiter(entity, agreement_arbiter_aid=entity.aid).decide(
            decision_id="dec-witnessed", session_ref="s", decision="advisory"
        )
        self.assertTrue(decision.verify(entity.kel, tenant_kel=tenant.kel, witness_keys=witness_keys))
        self.assertFalse(decision.verify(entity.kel, tenant_kel=tenant.kel))
        event = entity.kel.events[0]
        entity.kel.receipts[event.digest] = []
        self.assertFalse(decision.verify(entity.kel, tenant_kel=tenant.kel, witness_keys=witness_keys))

    def test_arbiter_cannot_force_a_commitment(self):
        """An arbiter co-signature does NOT substitute for a party signature (§12.5)."""
        arb = afp.Arbiter(self.e_arb, agreement_arbiter_aid=self.e_arb.aid)
        c = afp.build_commitment(
            commitment_id="c1",
            session_ref="sess-1",
            outcome_root=afp.outcome_root_for("o"),
            profile="work",
            sequence_number=0,
        )
        # Only the initiator + arbiter sign — responder has NOT signed.
        afp.sign_commitment(c, self.eA, role="initiator")
        arb.co_sign_commitment(c)
        self.assertFalse(c.is_fully_signed)  # still missing the responder
        with self.assertRaises(afp.CommitmentError):
            afp.verify_commitment(
                c,
                initiator_kel=self.eA.kel,
                responder_kel=self.eB.kel,
                initiator_tenant_kel=self.tA.kel,
                responder_tenant_kel=self.tB.kel,
                arbiter_kel=self.e_arb.kel,
                arbiter_tenant_kel=self.t_arb.kel,
                initiator_witness_keys={},
                responder_witness_keys={},
                arbiter_witness_keys={},
            )

    def test_arbiter_co_signature_is_additive_when_both_parties_sign(self):
        arb = afp.Arbiter(self.e_arb, agreement_arbiter_aid=self.e_arb.aid)
        c = afp.build_commitment(
            commitment_id="c1",
            session_ref="sess-1",
            outcome_root=afp.outcome_root_for("o"),
            profile="work",
            sequence_number=0,
        )
        afp.sign_commitment(c, self.eA, role="initiator")
        afp.sign_commitment(c, self.eB, role="responder")
        arb.co_sign_commitment(c)
        # Both parties signed AND the arbiter co-signed -> valid (§12.5).
        afp.verify_commitment(
            c,
            initiator_kel=self.eA.kel,
            responder_kel=self.eB.kel,
            initiator_tenant_kel=self.tA.kel,
            responder_tenant_kel=self.tB.kel,
            arbiter_kel=self.e_arb.kel,
            arbiter_tenant_kel=self.t_arb.kel,
            initiator_witness_keys={},
            responder_witness_keys={},
            arbiter_witness_keys={},
        )
        self.assertIsNotNone(c.arbiter_signature)

    def test_witnessed_arbiter_co_signature_requires_its_own_map(self):
        tA, eA, initiator_keys = _witnessed_entity("initiator")
        tB, eB, responder_keys = _witnessed_entity("responder")
        t_arb, e_arb, arbiter_keys = _witnessed_entity("arbiter")
        commitment = afp.build_commitment(
            commitment_id="co-signed-witnessed",
            session_ref="s",
            outcome_root=afp.outcome_root_for("o"),
            profile="work",
            sequence_number=0,
        )
        afp.sign_commitment(commitment, eA, role="initiator")
        afp.sign_commitment(commitment, eB, role="responder")
        afp.Arbiter(e_arb, agreement_arbiter_aid=e_arb.aid).co_sign_commitment(commitment)
        kwargs = {
            "initiator_kel": eA.kel,
            "responder_kel": eB.kel,
            "initiator_tenant_kel": tA.kel,
            "responder_tenant_kel": tB.kel,
            "initiator_witness_keys": initiator_keys,
            "responder_witness_keys": responder_keys,
            "arbiter_kel": e_arb.kel,
            "arbiter_tenant_kel": t_arb.kel,
        }
        with self.assertRaises(afp.CommitmentError):
            afp.verify_commitment(commitment, **kwargs)
        afp.verify_commitment(commitment, arbiter_witness_keys=arbiter_keys, **kwargs)


if __name__ == "__main__":
    unittest.main()
