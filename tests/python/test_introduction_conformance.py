"""§14 conformance properties — floor proven, reputation circuit an honest seam."""

import _path  # noqa: F401

import unittest

from afp_introduction import conformance
from afp_introduction.conformance import PropertyStatus
from afp_introduction.credentialing import CredentialingDecision
from test_introduction_handshake import credentialing_decision, introduction_request


class TestIntroductionConformance(unittest.TestCase):
    @staticmethod
    def _assess(**overrides):
        values = dict(
            interactions=[("zka_direct", "1", "0")],
            slash_arbiter_cosigned=True,
            reputation_circuit_operational=True,
            instance_attestation_v2_operational=True,
            escrow_operational=True,
        )
        values.update(overrides)
        return conformance.assess_introduction(**values)

    def test_floor_property_proven_when_all_interactions_bounded(self):
        rep = self._assess(
            interactions=[("zka_direct", "100", "0"), ("bonded", "50", "100")],
            reputation_circuit_operational=False)
        self.assertEqual(rep.property("14.5").status, PropertyStatus.PROVEN)

    def test_floor_property_fails_on_uncollateralized_exposure(self):
        rep = self._assess(
            interactions=[("bonded", "200", "100")],  # exposure > collateral
            reputation_circuit_operational=False)
        self.assertEqual(rep.property("14.5").status, PropertyStatus.FAILED)

    def test_reputation_circuit_is_an_honest_seam_until_operational(self):
        rep = self._assess(reputation_circuit_operational=False)
        self.assertEqual(rep.property("14.6").status, PropertyStatus.SEAM)
        self.assertFalse(rep.fully_operational)  # honest disclosure (§14.9)

    def test_no_clawback_property_proven(self):
        rep = self._assess()
        self.assertEqual(rep.property("14.7").status, PropertyStatus.PROVEN)

    def test_no_clawback_fails_without_arbiter_cosign(self):
        rep = self._assess(slash_arbiter_cosigned=False)
        self.assertEqual(rep.property("14.7").status, PropertyStatus.FAILED)
        self.assertFalse(rep.all_non_failed)
        self.assertIn(rep.property("14.7"), rep.failures())

    def test_growth_proven_when_circuit_operational(self):
        rep = self._assess()
        self.assertEqual(rep.property("14.6").status, PropertyStatus.PROVEN)

    def test_floor_partial_when_no_interactions(self):
        rep = self._assess(interactions=[])
        self.assertEqual(rep.property("14.5").status, PropertyStatus.PARTIAL)

    def test_safeguard_inheritance_proven(self):
        rep = self._assess()
        self.assertEqual(rep.property("14.8").status, PropertyStatus.PROVEN)

    def test_fully_operational_when_all_pass_and_circuit_live(self):
        request = introduction_request()
        decision = credentialing_decision(request=request)
        rep = self._assess(
            interactions=[("zka_direct", "100", "0"), ("bonded", "50", "100")],
            credentialing_request=request,
            credentialing_decision=decision,
        )
        self.assertTrue(rep.all_non_failed)
        self.assertTrue(rep.fully_operational)
        self.assertIsInstance(rep.summary(), str)
        self.assertIn("fully_operational", rep.summary())

    def test_property_lookup_raises_for_unknown_id(self):
        rep = self._assess()
        with self.assertRaises(KeyError):
            rep.property("99.9")

    def test_v2_attestation_path_is_an_honest_operational_seam(self):
        rep = self._assess(instance_attestation_v2_operational=False)
        self.assertFalse(rep.fully_operational)
        self.assertIn("instance_attestation_v2_operational=False", rep.summary())

    def test_escrow_is_an_honest_operational_seam(self):
        rep = self._assess(escrow_operational=False)
        self.assertFalse(rep.fully_operational)
        self.assertIn("escrow_operational=False", rep.summary())

    def test_absent_credentialing_evidence_keeps_deployment_non_operational(self):
        rep = self._assess()
        self.assertEqual(rep.property("14.3").status, PropertyStatus.SEAM)
        self.assertFalse(rep.fully_operational)


class CredentialingPropertyTest(unittest.TestCase):
    """§14.3 evidence must be a sealed decision, checked against its request."""

    def test_an_unsealed_lookalike_is_not_evidence(self):
        class Lookalike:
            accepted = True
            reasons = ()
            seams = ()
            proven_predicate_ids = ("anything-i-like",)

        result = conformance.check_credentialing_match(Lookalike(), object())
        self.assertEqual(result.status, conformance.PropertyStatus.FAILED)

    def test_a_forged_decision_subclass_is_not_evidence(self):
        class ForgedDecision(CredentialingDecision):
            accepted = True
            reasons = ()
            seams = ()
            proven_predicate_ids = ("anything-i-like",)

            def __new__(cls):
                return object.__new__(cls)

            def verify_for(self, _request):
                return True

        result = conformance.check_credentialing_match(ForgedDecision(), object())
        self.assertEqual(result.status, conformance.PropertyStatus.FAILED)

    def test_absent_evidence_is_a_seam_never_proven(self):
        result = conformance.check_credentialing_match(None, None)
        self.assertEqual(result.status, conformance.PropertyStatus.SEAM)


if __name__ == "__main__":
    unittest.main()
