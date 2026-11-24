"""§14.4/§14.6 — envelope growth (clean-reputation gated, curve-capped) + graduation."""

import _path  # noqa: F401

import unittest

from afp_introduction import agreement, atoms


def _policy(**kw):
    base = dict(
        permitted_entities=["Ea", "Eb"], permitted_assets=["USDC"],
        max_per_interaction="100", max_cumulative_outstanding="1000",
        bond_ref="escrow:0x", accepted_credentials=[atoms.AcceptedCredential(
            "zkc:proof:jurisdiction:v1", "2255-03-14T16:00:00Z")],
        accepted_instance_attestation_roots=[atoms.InstanceAttestationRoot(
            root_class="root:build-provenance",
            root_authority_identifier="rekor:sigstore.dev",
        )],
        rotation_policy="rot", growth_curve={"step_factor": "2", "cap": "10000"},
        agreement_expires_at="2255-03-14T16:00:00Z",
    )
    base.update(kw)
    return atoms.IntroductionPolicy(**base)


class TestAgreement(unittest.TestCase):
    def test_limit_adjustment_requires_clean_reputation_proof(self):
        new_pol = agreement.apply_limit_adjustment(
            _policy(), reputation=atoms.ReputationState(5, "500", 0, "cmt5"))
        self.assertEqual(new_pol.max_per_interaction, "200")  # 100 * step_factor 2

    def test_slash_event_blocks_growth(self):
        with self.assertRaises(agreement.GrowthRejected):
            agreement.apply_limit_adjustment(
                _policy(), reputation=atoms.ReputationState(5, "500", 1, "cmt5"))  # slash > 0

    def test_growth_respects_cap(self):
        new_pol = agreement.apply_limit_adjustment(
            _policy(max_per_interaction="9000"),
            reputation=atoms.ReputationState(9, "9000", 0, "cmt9"))
        self.assertEqual(new_pol.max_per_interaction, "10000")  # capped, not 18000

    def test_graduation_drops_tier_bond(self):
        std = agreement.graduate(_policy())
        self.assertIsNone(std.bond_ref)  # standard §5.5 agreement: no mandatory bond


if __name__ == "__main__":
    unittest.main()
