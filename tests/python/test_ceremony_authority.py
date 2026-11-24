"""§6.3.1 authority trust material: the two acceptance conditions and the KEL rules.

§6.3.1 states "exactly two acceptance conditions ... over accepted trust
material" — the pinned witness set and threshold, and the authority's
characterization of its own attestation as platform-layer self-attestation — and
they are "together the whole of the normative standing AFP grants an authority's
published material".
"""

import _path  # noqa: F401  (path setup)

import copy
import unittest

import ceremony_fixtures as cf

from afp_ceremony import (
    AUTHORITY_TRUST_MATERIAL_KIND,
    AfpAuthorityTrustMaterial,
    AnchoredSigner,
    ArtifactError,
    AuthorityTrustMaterialError,
    PUBLISHER_MANIFEST_ROOT_CLASS,
    STAGING_ENVIRONMENT,
    SELF_ATTESTATION_CHARACTERIZATION,
    SIGNER_ACTIVE,
    SIGNER_REVOKED,
    SIGNER_SUPERSEDED,
    accept_publisher_key_state,
    build_authority_trust_material,
    ceremony as ceremony_mod,
    resolve_publisher_key_state,
    verify_authority_trust_material,
    verify_pinned_witness_threshold,
)

_IDENTITY_KEY = b"\x01" + b"\x00" * 31
_ORDER_TWO_KEY = b"\xec" + b"\xff" * 30 + b"\x7f"
_MIXED_ORDER_KEY = bytes.fromhex(
    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
)
_NONCANONICAL_KEY = b"\xed" + b"\xff" * 30 + b"\x7f"


class _SpoofedKey(str):
    def partition(self, separator):
        _code, marker, payload = str(self).partition(separator)
        return ("K", marker, payload)


class TrustMaterialShapeTest(unittest.TestCase):
    """Constructing or decoding trust material enforces the acceptance conditions."""

    @classmethod
    def setUpClass(cls):
        cls.result = cf.staging_ceremony()

    def _material_dict(self):
        return copy.deepcopy(self.result.trust_material.to_dict())

    def test_kind_and_round_trip(self):
        data = self._material_dict()
        self.assertEqual(data["kind"], AUTHORITY_TRUST_MATERIAL_KIND)
        self.assertEqual(
            AfpAuthorityTrustMaterial.from_dict(data).to_dict(), data
        )

    def test_it_is_not_a_witness_bootstrap_record(self):
        """An authority is not a tenant (§2.1), so no tenant-scoped fields appear."""
        data = self._material_dict()
        self.assertNotIn("tenant_aid", data)
        self.assertNotIn("tenant_signature", data)
        self.assertNotEqual(data["kind"], "afp:witness-bootstrap:v1")

    def test_characterization_is_mandatory_and_exact(self):
        self.assertEqual(
            self.result.trust_material.attestation_characterization,
            SELF_ATTESTATION_CHARACTERIZATION,
        )
        data = self._material_dict()
        data["attestation_characterization"] = "third-party-attestation"
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)

    def test_publisher_manifest_class_must_be_accepted(self):
        data = self._material_dict()
        data["accepted_root_classes"] = ["root:build-provenance"]
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)
        self.assertIn(
            PUBLISHER_MANIFEST_ROOT_CLASS,
            self.result.trust_material.accepted_root_classes,
        )

    def test_a_witness_set_and_a_sane_threshold_are_mandatory(self):
        data = self._material_dict()
        data["pinned_witnesses"] = []
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)
        data = self._material_dict()
        data["pinned_witness_threshold"] = len(data["pinned_witnesses"]) + 1
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)
        data = self._material_dict()
        data["pinned_witness_threshold"] = 0
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)

    def test_unknown_members_are_rejected(self):
        data = self._material_dict()
        data["advisory_feed_url"] = "https://example.invalid/feed"
        with self.assertRaises(AuthorityTrustMaterialError):
            AfpAuthorityTrustMaterial.from_dict(data)

    def test_endpoints_are_unresolvable(self):
        for witness in self.result.trust_material.pinned_witnesses:
            self.assertIn(".invalid", witness.witness_endpoint)

    def test_malformed_witness_verification_material_is_rejected(self):
        valid = self._material_dict()["pinned_witnesses"][0][
            "witness_verification_material"
        ]
        valid_hex = valid.partition("_")[2]
        invalid_values = (
            "deadbeef",
            "X_" + valid_hex,
            _SpoofedKey("X_" + valid_hex),
            "K_" + valid_hex.upper(),
            "K_" + "00" * 31,
            "K_" + "00" * 33,
            "K_" + _IDENTITY_KEY.hex(),
            "K_" + _ORDER_TWO_KEY.hex(),
            "K_" + _MIXED_ORDER_KEY.hex(),
            "K_" + _NONCANONICAL_KEY.hex(),
        )
        for invalid_value in invalid_values:
            data = self._material_dict()
            data["pinned_witnesses"][0][
                "witness_verification_material"
            ] = invalid_value
            with self.subTest(value=invalid_value), self.assertRaises(
                AuthorityTrustMaterialError
            ):
                AfpAuthorityTrustMaterial.from_dict(data)

    def test_malformed_validity_timestamps_are_rejected(self):
        for field in ("issued_at", "expires_at"):
            with self.subTest(field=field):
                data = self._material_dict()
                data[field] = "not-a-timestamp"
                with self.assertRaises(AuthorityTrustMaterialError):
                    AfpAuthorityTrustMaterial.from_dict(data)


class NonProductionMarkerIsEnforcedOnEmitTest(unittest.TestCase):
    """A record claiming to be production material cannot be built, signed, or accepted.

    ``signed_content()`` folds the markers into the signature, so a mismarked
    record would be internally consistent and tamper-evident — it would look
    *more* credible, not less — while being derived from the seed phrase
    published in ``staging.py``. Enforcement therefore happens at construction,
    not only at decode.
    """

    @classmethod
    def setUpClass(cls):
        cls.result = cf.staging_ceremony()

    def _fields(self, **marker_overrides):
        material = self.result.trust_material
        markers = dict(material.markers)
        markers.update(marker_overrides)
        return dict(
            authority_aid=material.authority_aid,
            authority_inception_dig=material.authority_inception_dig,
            legal_entity_binding_statement=material.legal_entity_binding_statement,
            pinned_witnesses=material.pinned_witnesses,
            pinned_witness_threshold=material.pinned_witness_threshold,
            anchored_signers=material.anchored_signers,
            accepted_root_classes=material.accepted_root_classes,
            attestation_characterization=material.attestation_characterization,
            issued_at=material.issued_at,
            expires_at=material.expires_at,
            markers=markers,
            authority_signature=None,
        )

    def test_a_production_marked_record_cannot_be_constructed(self):
        for override in (
            {"environment": "production"},
            {"not_production": False},
            {"derivation_seed": "hsm-backed-not-published"},
            {"encoding": "cesr-qb64"},
        ):
            with self.subTest(override=override):
                with self.assertRaises(ArtifactError):
                    AfpAuthorityTrustMaterial(**self._fields(**override))

    def test_a_record_missing_a_marker_cannot_be_constructed(self):
        fields = self._fields()
        del fields["markers"]["not_production"]
        with self.assertRaises(ArtifactError):
            AfpAuthorityTrustMaterial(**fields)

    def test_the_builder_takes_no_markers_argument(self):
        """There is no legitimate caller that needs to choose them."""
        import inspect

        signature = inspect.signature(build_authority_trust_material)
        self.assertNotIn("markers", signature.parameters)

    def test_the_verify_path_refuses_a_mismarked_record(self):
        """Belt and braces: the check is on verify as well as on construction.

        Constructing one is now impossible, so the only way to produce the
        artifact under test is to bypass ``__post_init__`` on a copy — which is
        what an attacker patching this module would do.
        """
        copy_of = AfpAuthorityTrustMaterial.from_dict(
            copy.deepcopy(self.result.trust_material.to_dict())
        )
        object.__setattr__(
            copy_of, "markers", {**copy_of.markers, "environment": "production"}
        )
        self.assertNotEqual(copy_of.markers["environment"], STAGING_ENVIRONMENT)
        with self.assertRaises(ArtifactError):
            verify_authority_trust_material(
                copy_of,
                authority_kel=self.result.authority.kel,
                now=ceremony_mod.STAGING_NOW,
            )


class TrustMaterialVerificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = cf.staging_ceremony()
        cls.authority_kel = cls.result.authority.kel
        cls.signing_kel = cls.result.published_signer.kel
        cls.material = cls.result.trust_material
        cls.now = ceremony_mod.STAGING_NOW

    def _verify(self, material=None, **kwargs):
        verify_authority_trust_material(
            material or self.material,
            authority_kel=kwargs.pop("authority_kel", self.authority_kel),
            anchored_kels=kwargs.pop(
                "anchored_kels", {self.signing_kel.aid: self.signing_kel}
            ),
            now=kwargs.pop("now", self.now),
            **kwargs,
        )

    def test_happy_path(self):
        self._verify()

    def test_expired_material_is_rejected(self):
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(now="2030-01-01T00:00:00Z")

    def test_not_yet_valid_material_is_rejected(self):
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(now="2020-01-01T00:00:00Z")

    def test_validity_window_compares_instants_not_timestamp_strings(self):
        material = build_authority_trust_material(
            authority_kel=self.authority_kel,
            signing_material=self.result.authority.current,
            legal_entity_binding_statement=self.material.legal_entity_binding_statement,
            pinned_witnesses=self.material.pinned_witnesses,
            pinned_witness_threshold=self.material.pinned_witness_threshold,
            anchored_signers=self.material.anchored_signers,
            issued_at="2025-12-31T23:00:00Z",
            # This is 2026-01-01T00:00:00Z. Lexicographic comparison against
            # 00:30Z incorrectly treats the material as still valid.
            expires_at="2026-01-01T01:00:00+01:00",
        )
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(material, now="2026-01-01T00:30:00Z")

    def test_tampered_signed_content_breaks_the_signature(self):
        tampered = AfpAuthorityTrustMaterial.from_dict(
            {
                **self.material.to_dict(),
                "legal_entity_binding_statement": "Pyramidal Inc.",
            }
        )
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(tampered)

    def test_unsigned_material_is_rejected(self):
        data = dict(self.material.to_dict())
        data["authority_signature"] = None
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(AfpAuthorityTrustMaterial.from_dict(data))

    def test_material_for_another_authority_is_rejected(self):
        other, _signer, _anchor, _witnesses = cf.minimal_authority()
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(authority_kel=other.kel)

    def test_fork_against_previously_accepted_state_is_unresolvable(self):
        accepted = {0: self.authority_kel.events[0].digest}
        self._verify(previously_accepted=accepted)
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(previously_accepted={0: "D_" + "0" * 64})
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(previously_accepted={999: "D_" + "0" * 64})

    def test_pinned_threshold_is_enforced_over_the_authority_kel(self):
        """§6.3.1: verify authority-KEL events against the PINNED threshold."""
        self.assertGreater(self.material.pinned_witness_threshold, 1)
        stripped = ceremony_mod.kel_from_dict(
            ceremony_mod.kel_to_dict(self.authority_kel)
        )
        # Drop receipts until the inception event falls under the pinned threshold.
        inception_dig = stripped.events[0].digest
        stripped.receipts[inception_dig] = stripped.receipts[inception_dig][:1]
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(authority_kel=stripped)

    def test_pinned_threshold_is_enforced_over_anchored_kels(self):
        stripped = ceremony_mod.kel_from_dict(
            ceremony_mod.kel_to_dict(self.signing_kel)
        )
        for dig in list(stripped.receipts):
            stripped.receipts[dig] = []
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(anchored_kels={stripped.aid: stripped})

    def test_forged_receipts_do_not_count_toward_the_pinned_threshold(self):
        forged = ceremony_mod.kel_from_dict(
            ceremony_mod.kel_to_dict(self.authority_kel)
        )
        for dig, receipts in list(forged.receipts.items()):
            forged.receipts[dig] = [
                type(receipt)(
                    witness_aid=receipt.witness_aid,
                    event_dig=receipt.event_dig,
                    signature=bytes(64),
                )
                for receipt in receipts
            ]
        with self.assertRaises(AuthorityTrustMaterialError):
            verify_pinned_witness_threshold(
                forged,
                pinned_witness_aids=self.material.pinned_witness_aids,
                pinned_threshold=self.material.pinned_witness_threshold,
                witness_material=self.material.pinned_witness_material,
            )

    def test_receipts_from_unpinned_witnesses_do_not_count(self):
        extra = ceremony_mod.make_staging_witnesses(1)[0]
        with self.assertRaises(AuthorityTrustMaterialError):
            verify_pinned_witness_threshold(
                self.authority_kel,
                pinned_witness_aids=[extra.aid + "-unpinned"],
                pinned_threshold=1,
                witness_material={extra.aid + "-unpinned": extra.public_key},
            )

    def test_every_supplied_pinned_witness_key_is_validated(self):
        invalid_keys = (
            b"\x00" * 31,
            _IDENTITY_KEY,
            _ORDER_TWO_KEY,
            _MIXED_ORDER_KEY,
            _NONCANONICAL_KEY,
        )
        for invalid_key in invalid_keys:
            witness_material = dict(self.material.pinned_witness_material)
            witness_material["unused"] = invalid_key
            with self.subTest(public_key=invalid_key), self.assertRaisesRegex(
                AuthorityTrustMaterialError, "invalid Ed25519"
            ):
                verify_pinned_witness_threshold(
                    self.authority_kel,
                    pinned_witness_aids=self.material.pinned_witness_aids,
                    pinned_threshold=self.material.pinned_witness_threshold,
                    witness_material=witness_material,
                )

        with self.assertRaisesRegex(AuthorityTrustMaterialError, "invalid Ed25519"):
            verify_pinned_witness_threshold(
                self.authority_kel,
                pinned_witness_aids=(),
                pinned_threshold=0,
                witness_material={"unused": _IDENTITY_KEY},
            )

    def test_anchored_signer_must_match_a_real_delegation_anchor(self):
        data = copy.deepcopy(self.material.to_dict())
        data["anchored_signers"][0]["delegation_anchor_dig"] = "D_" + "0" * 64
        with self.assertRaises(AuthorityTrustMaterialError):
            self._verify(AfpAuthorityTrustMaterial.from_dict(data))

    def test_a_duplicated_delegation_anchor_is_unresolvable(self):
        """Two events anchoring one inception do not determine *the* anchor."""
        authority, signer, anchor, _witnesses = cf.minimal_authority()
        material = build_authority_trust_material(
            authority_kel=authority.kel,
            signing_material=authority.current,
            legal_entity_binding_statement="STAGING PLACEHOLDER — no legal entity",
            pinned_witnesses=self.material.pinned_witnesses,
            pinned_witness_threshold=1,
            anchored_signers=(
                AnchoredSigner(
                    signing_aid=signer.aid,
                    delegation_anchor_dig=anchor,
                    purpose="probe",
                    status=SIGNER_ACTIVE,
                ),
            ),
            issued_at=ceremony_mod.STAGING_ISSUED_AT,
            expires_at=ceremony_mod.STAGING_EXPIRES_AT,
        )
        verify_authority_trust_material(
            material,
            authority_kel=authority.kel,
            anchored_kels={signer.aid: signer.kel},
            now=ceremony_mod.STAGING_NOW,
        )
        # Re-anchor the same delegated inception a second time.
        authority.as_keri_identity()._anchor_delegation(
            signer.aid, signer.kel.events[0].digest
        )
        with self.assertRaises(AuthorityTrustMaterialError) as ctx:
            verify_authority_trust_material(
                material,
                authority_kel=authority.kel,
                anchored_kels={signer.aid: signer.kel},
                now=ceremony_mod.STAGING_NOW,
            )
        self.assertIn("not uniquely determined", str(ctx.exception))


class PublisherKeyStateAcceptanceTest(unittest.TestCase):
    """§6.3.1's stale / revoked / untrusted-authority rejections."""

    @classmethod
    def setUpClass(cls):
        cls.result = cf.staging_ceremony()
        cls.state = cls.result.published_key_state
        cls.signing_kel = cls.result.published_signer.kel
        cls.material = cls.result.trust_material

    def test_active_signer_is_accepted(self):
        accept_publisher_key_state(
            self.state, material=self.material, signing_kel=self.signing_kel
        )

    def test_superseded_signer_is_rejected(self):
        superseded = self.material.with_signers(
            [
                AnchoredSigner(
                    signing_aid=self.state.signing_aid,
                    delegation_anchor_dig=self.state.delegation_anchor_dig,
                    purpose="ADAMAS release build manifest signing",
                    status=SIGNER_SUPERSEDED,
                )
            ]
        )
        with self.assertRaises(AuthorityTrustMaterialError):
            accept_publisher_key_state(
                self.state, material=superseded, signing_kel=self.signing_kel
            )

    def test_revoked_signer_is_rejected(self):
        revoked = self.material.with_signers(
            [
                AnchoredSigner(
                    signing_aid=self.state.signing_aid,
                    delegation_anchor_dig=self.state.delegation_anchor_dig,
                    purpose="ADAMAS release build manifest signing",
                    status=SIGNER_REVOKED,
                )
            ]
        )
        with self.assertRaises(AuthorityTrustMaterialError):
            accept_publisher_key_state(
                self.state, material=revoked, signing_kel=self.signing_kel
            )

    def test_unlisted_signer_is_rejected(self):
        empty = self.material.with_signers([])
        with self.assertRaises(AuthorityTrustMaterialError):
            accept_publisher_key_state(
                self.state, material=empty, signing_kel=self.signing_kel
            )

    def test_superseded_key_state_is_rejected_after_a_rotation(self):
        """A committed state superseded by a published rotation must not verify."""
        authority, signer, anchor, witnesses = cf.minimal_authority()
        witness_material = {w.aid: w.public_key for w in witnesses}
        before = resolve_publisher_key_state(
            authority_kel=authority.kel,
            signing_kel=signer.kel,
            witness_keys=witness_material,
        )
        rotated = ceremony_mod.rotate_identity(signer)
        ceremony_mod.anchor_rotation(
            authority,
            delegate_aid=rotated.aid,
            rotation_dig=rotated.kel.latest.digest,
        )
        after = resolve_publisher_key_state(
            authority_kel=authority.kel,
            signing_kel=rotated.kel,
            witness_keys=witness_material,
        )
        self.assertNotEqual(
            before.root_material_digest(), after.root_material_digest()
        )
        material = build_authority_trust_material(
            authority_kel=authority.kel,
            signing_material=authority.current,
            legal_entity_binding_statement="STAGING PLACEHOLDER — no legal entity",
            pinned_witnesses=self.material.pinned_witnesses,
            pinned_witness_threshold=1,
            anchored_signers=(
                AnchoredSigner(
                    signing_aid=signer.aid,
                    delegation_anchor_dig=anchor,
                    purpose="probe",
                    status=SIGNER_ACTIVE,
                ),
            ),
            issued_at=ceremony_mod.STAGING_ISSUED_AT,
            expires_at=ceremony_mod.STAGING_EXPIRES_AT,
        )
        accept_publisher_key_state(
            after, material=material, signing_kel=rotated.kel
        )
        with self.assertRaises(AuthorityTrustMaterialError):
            accept_publisher_key_state(
                before, material=material, signing_kel=rotated.kel
            )
        # And the rotation is anchored in the authority KEL, as §6.3.1 requires.
        ceremony_mod.find_rotation_anchor(
            authority.kel,
            delegate_aid=rotated.aid,
            rotation_dig=rotated.kel.latest.digest,
        )

    def test_key_state_naming_another_authority_is_rejected(self):
        other, _signer, _anchor, _witnesses = cf.minimal_authority()
        foreign = self.material.with_signers(list(self.material.anchored_signers))
        data = foreign.to_dict()
        data["authority_aid"] = other.aid
        data["authority_inception_dig"] = other.inception_dig
        with self.assertRaises(AuthorityTrustMaterialError):
            accept_publisher_key_state(
                self.state,
                material=AfpAuthorityTrustMaterial.from_dict(data),
                signing_kel=self.signing_kel,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
