"""§14.1 willingness-to-federate directory — openness, not pairing; epoch binding."""

import _path  # noqa: F401

import unittest

from afp_introduction import atoms, directory


def _offer(tenant="EtenantA", epoch=1):
    return atoms.IntroductionOffer(
        tenant_aid=tenant,
        accepted_credential_classes=["zkc:proof:jurisdiction:v1"],
        entertained_envelope=atoms.Envelope(["USDC"], "100", "1000", True),
        route_handle="rv-" + tenant,
        directory_epoch=epoch,
    )


class TestIntroductionDirectory(unittest.TestCase):
    def test_publish_is_optional_and_lists_openness_not_pairing(self):
        d = directory.IntroductionDirectory(epoch=1)
        d.publish(_offer("EtenantA"))
        self.assertIn("EtenantA", [o.tenant_aid for o in d.offers()])
        # the directory has no concept of who paired (OB-2; §14.1)
        self.assertFalse(hasattr(d, "pairings"))

    def test_rejects_offer_from_stale_epoch(self):
        d = directory.IntroductionDirectory(epoch=5)
        with self.assertRaises(directory.DirectoryError):
            d.publish(_offer(epoch=1))  # epoch binding (anti-replay), mirrors §8.7

    def test_rejects_offer_from_future_epoch(self):
        # an offer ahead of the directory cannot be validated yet -> rejected
        d = directory.IntroductionDirectory(epoch=1)
        with self.assertRaises(directory.DirectoryError):
            d.publish(_offer(epoch=5))
        self.assertEqual(d.offers(), [])  # nothing was stored

    def test_resolves_route_for_published_tenant(self):
        d = directory.IntroductionDirectory(epoch=1)
        d.publish(_offer("EtenantB"))
        self.assertEqual(d.resolve_route("EtenantB"), "rv-EtenantB")
        with self.assertRaises(directory.DirectoryError):
            d.resolve_route("EunknownTenant")

    def test_reconciliation_no_work_descriptors(self):
        # §5.1 reconciliation: an offer carries NO work descriptor / open call
        offer = _offer()
        self.assertFalse(hasattr(offer, "work_descriptor"))
        self.assertFalse(hasattr(offer, "open_call"))


if __name__ == "__main__":
    unittest.main()
