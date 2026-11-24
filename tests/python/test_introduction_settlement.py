"""§14.5/§14.7 — collateral-priced floor + escrow-bounded, never-base-layer recourse."""

import _path  # noqa: F401

import unittest

from afp_introduction import settlement
from afp_introduction.settlement import Rail


class TestSettlementFloor(unittest.TestCase):
    def test_zka_direct_is_always_within_floor(self):
        # no credit extended -> always allowed (the safe default)
        self.assertTrue(settlement.within_floor(
            rail=Rail.ZKA_DIRECT, exposure="100", posted_collateral="0"))

    def test_bonded_requires_exposure_le_collateral(self):
        self.assertTrue(settlement.within_floor(
            rail=Rail.BONDED, exposure="100", posted_collateral="100"))
        self.assertFalse(settlement.within_floor(
            rail=Rail.BONDED, exposure="101", posted_collateral="100"))

    def test_uncollateralized_credit_is_rejected(self):
        # there is no "credit" rail at the introduction tier
        with self.assertRaises(ValueError):
            settlement.within_floor(rail="credit", exposure="1", posted_collateral="0")

    def test_slash_is_bounded_to_escrow_never_base_layer(self):
        outcome = settlement.resolve_default(
            posted_collateral="100", claimed="250", arbiter_cosigned=True)
        self.assertEqual(outcome.slashed, "100")  # bounded to escrow
        self.assertFalse(outcome.touched_base_layer)  # Safeguard 3

    def test_slash_requires_arbiter_cosign(self):
        with self.assertRaises(settlement.RecourseError):
            settlement.resolve_default(
                posted_collateral="100", claimed="50", arbiter_cosigned=False)


if __name__ == "__main__":
    unittest.main()
