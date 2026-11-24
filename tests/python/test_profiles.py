"""Profile registry tests (§13.2 / §13.3)."""

import _path  # noqa: F401

import unittest

from afp_session.profiles import (
    AfpProfileDescriptor,
    ProfileError,
    ProfileRegistry,
    default_registry,
)


class ProfileRegistryTest(unittest.TestCase):
    def test_default_registry_has_reference_profiles(self):
        reg = default_registry()
        self.assertEqual(reg.names(), ["pay", "pay_venue", "prp", "vxp", "work"])
        self.assertTrue(reg.is_registered("prp"))
        self.assertTrue(reg.is_registered("vxp"))
        self.assertTrue(reg.is_registered("work"))

    def test_default_registry_has_experimental_payment_profile(self):
        descriptor = default_registry().get("pay")
        self.assertEqual(descriptor.version, "1.0")
        self.assertEqual(descriptor.spec_ref, "AFP 0.3.12-draft §15")
        self.assertEqual(
            descriptor.atom_kinds,
            ["afp:payment-quote:v1", "afp:payment-receipt:v1"],
        )
        self.assertEqual(descriptor.policy_schema_ref, "afp:payment-policy:v1")
        self.assertEqual(descriptor.status, "experimental")

    def test_reserved_labels_are_recognized(self):
        reg = ProfileRegistry()
        # session/telemetry are core/operational, always recognized (§12.4).
        self.assertTrue(reg.is_registered("session"))
        self.assertTrue(reg.is_registered("telemetry"))
        # but a reference profile must actually be registered.
        self.assertFalse(reg.is_registered("prp"))

    def test_duplicate_name_rejected(self):
        reg = default_registry()
        with self.assertRaises(ProfileError):
            reg.register(
                AfpProfileDescriptor(
                    name="prp",
                    version="0.3",
                    spec_ref="x",
                    atom_kinds=["prp:foo:v3"],
                    policy_schema_ref="p",
                )
            )

    def test_atom_kind_collision_with_core_rejected(self):
        reg = ProfileRegistry()
        with self.assertRaises(ProfileError):
            reg.register(
                AfpProfileDescriptor(
                    name="bad",
                    version="0.1",
                    spec_ref="x",
                    atom_kinds=["afp:session:v1"],  # collides with the core kind
                    policy_schema_ref="p",
                )
            )

    def test_atom_kind_collision_across_profiles_rejected(self):
        reg = ProfileRegistry()
        reg.register(
            AfpProfileDescriptor(
                name="alpha",
                version="0.1",
                spec_ref="x",
                atom_kinds=["shared:kind:v1"],
                policy_schema_ref="p",
            )
        )
        with self.assertRaises(ProfileError):
            reg.register(
                AfpProfileDescriptor(
                    name="beta",
                    version="0.1",
                    spec_ref="x",
                    atom_kinds=["shared:kind:v1"],
                    policy_schema_ref="p",
                )
            )

    def test_experimental_profile_can_be_registered(self):
        reg = ProfileRegistry()
        reg.register(
            AfpProfileDescriptor(
                name="exp",
                version="0.0.1",
                spec_ref="x",
                atom_kinds=["exp:thing:v1"],
                policy_schema_ref="p",
                status="experimental",
            )
        )
        self.assertEqual(reg.get("exp").status, "experimental")

    def test_invalid_status_rejected(self):
        with self.assertRaises(ProfileError):
            AfpProfileDescriptor(
                name="x",
                version="0.1",
                spec_ref="x",
                atom_kinds=[],
                policy_schema_ref="p",
                status="bogus",
            )


if __name__ == "__main__":
    unittest.main()
