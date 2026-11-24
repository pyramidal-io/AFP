"""NATS namespace tests — afp.{tenant}.{profile}.* ownership (§12.4)."""

import _path  # noqa: F401

import unittest

from afp_session import namespace as ns
from afp_session.namespace import NamespaceError
from afp_session.profiles import default_registry
from afp_session.transport import InMemoryTransport


class SubjectTest(unittest.TestCase):
    def test_core_session_subject(self):
        s = ns.session_subject("tenantA", "propose")
        self.assertEqual(s, "afp.tenantA.session.propose")

    def test_profile_subject(self):
        s = ns.subject("tenantA", "prp", "compare", registered=True)
        self.assertEqual(s, "afp.tenantA.prp.compare")

    def test_standalone_namespace_is_non_conforming(self):
        # A bare vxp.* is not under the AFP root (§12.4 rule 1).
        self.assertFalse(ns.is_conforming_subject("vxp.exchange.intent"))
        self.assertTrue(ns.is_conforming_subject("afp.tenantA.vxp.exchange"))
        self.assertFalse(ns.is_conforming_subject("afp.tenantA.unknown.exchange"))

    def test_unregistered_profile_rejected(self):
        with self.assertRaises(NamespaceError):
            ns.subject("tenantA", "newprofile", "leaf", registered=False)

    def test_registration_result_must_be_a_boolean(self):
        for result in (1, "yes", ["registered"], object()):
            with self.subTest(result=result), self.assertRaises(NamespaceError):
                ns.subject("tenantA", "newprofile", "leaf", registered=result)

    def test_reserved_profile_does_not_need_registration_flag(self):
        # The core and operator labels remain available to the namespace helper.
        for profile, leaf in (("session", "propose"), ("work", "request"), ("telemetry", "health")):
            with self.subTest(profile=profile):
                self.assertEqual(
                    ns.subject("t", profile, leaf, registered=False),
                    f"afp.t.{profile}.{leaf}",
                )

    def test_published_reference_profiles_require_registry_result(self):
        for profile in ("prp", "vxp"):
            with self.subTest(profile=profile):
                with self.assertRaises(NamespaceError):
                    ns.subject("t", profile, "result", registered=False)
                self.assertEqual(
                    ns.subject("t", profile, "result", registered=True),
                    f"afp.t.{profile}.result",
                )

    def test_conformance_uses_supplied_registry_for_bilateral_extensions(self):
        default = default_registry()
        self.assertTrue(ns.is_conforming_subject("afp.t.prp.result", default))
        self.assertFalse(ns.is_conforming_subject("afp.t.other.result", default))

    def test_invalid_profile_name_rejected(self):
        with self.assertRaises(NamespaceError):
            ns.validate_profile_name("UPPER")
        with self.assertRaises(NamespaceError):
            ns.validate_profile_name("1bad")

    def test_parse_subject(self):
        parsed = ns.parse_subject("afp.tenantA.prp.evidence.submit")
        self.assertEqual(parsed["tenant"], "tenantA")
        self.assertEqual(parsed["profile"], "prp")
        self.assertEqual(parsed["leaves"], ["evidence", "submit"])

    def test_parse_non_afp_subject_raises(self):
        with self.assertRaises(NamespaceError):
            ns.parse_subject("nats.something.else")

    def test_parse_rejects_malformed_tenant_profile_and_leaves(self):
        for subject in (
            "afp..work.request",
            "afp.a..request",
            "afp.a.Work.request",
            "afp.a.work.",
            "afp.a.work.x.y*",
            "afp.a*.work.request",
            "afp.a>.work.request",
            "afp.a.work.request..result",
        ):
            with self.subTest(subject=subject), self.assertRaises(NamespaceError):
                ns.parse_subject(subject)

    def test_subject_rejects_non_string_leaf_with_namespace_error(self):
        for leaf in (None, 1, b"request", True):
            with self.subTest(leaf=leaf), self.assertRaises(NamespaceError):
                ns.subject("tenantA", "work", leaf, registered=True)


class TransportMatchTest(unittest.TestCase):
    def test_publish_to_subscriber(self):
        t = InMemoryTransport()
        received = []
        t.subscribe("afp.tenantA.prp.*", lambda subj, payload: received.append((subj, payload)))
        t.publish("afp.tenantA.prp.compare", b"hello")
        self.assertEqual(received, [("afp.tenantA.prp.compare", b"hello")])

    def test_wildcard_token_match(self):
        t = InMemoryTransport()
        hits = []
        t.subscribe("afp.*.session.*", lambda s, p: hits.append(s))
        t.publish("afp.tenantA.session.open", b"x")
        t.publish("afp.tenantB.session.close", b"x")
        t.publish("afp.tenantA.work.request", b"x")  # should not match
        self.assertEqual(hits, ["afp.tenantA.session.open", "afp.tenantB.session.close"])

    def test_tail_wildcard(self):
        t = InMemoryTransport()
        hits = []
        t.subscribe("afp.tenantA.>", lambda s, p: hits.append(s))
        t.publish("afp.tenantA.prp.evidence.submit", b"x")
        t.publish("afp.tenantB.prp.x", b"x")  # different tenant, no match
        self.assertEqual(hits, ["afp.tenantA.prp.evidence.submit"])

    def test_unsubscribe(self):
        t = InMemoryTransport()
        hits = []
        sub = t.subscribe("afp.>", lambda s, p: hits.append(s))
        t.publish("afp.t.work.x", b"1")
        sub.unsubscribe()
        t.publish("afp.t.work.y", b"2")
        self.assertEqual(hits, ["afp.t.work.x"])


if __name__ == "__main__":
    unittest.main()
