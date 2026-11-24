"""``afp:authority-trust-material:v1`` — the authority's out-of-band trust material.

**Why this is not ``afp:witness-bootstrap:v1``.** The obvious-looking move — have
the attestation authority publish the §4.5.1 witness bootstrap record for its
organizational root — is non-conformant, and the specification closes the door
from three directions:

* ``afp:witness-bootstrap:v1`` is hard-scoped to a **tenant**. Its fields are
  ``tenant_aid`` and ``tenant_signature``; §4.5.3 step 1 verifies "the tenant
  root AID"; and its failure semantics are that the verifier "declines AFP
  session establishment with that tenant". None of that has a meaning for an
  authority.
* An authority **is not a tenant**. §2.1 closes the principal enumeration at
  three and says an authority is "likewise not an AFP principal"; §6.3.1
  restates it — "an authority is not a tenant (§2.1), so the §4.5 tenant-scoped
  witness duties do not attach to it of their own force" — and again in the
  disclosure split: "an authority is not an AFP principal and not an AFP
  conformance subject (§1.5, §2.1)".
* Emitting one anyway would either assert the authority *is* a tenant, or
  require renaming the fields of a published record — a wire-shape change
  ADR-0005 forbids.

**What the specification requires instead.** §6.3.1, "Authority-KEL integrity is
not assumed": a verifier "MUST therefore verify authority-KEL events — and the
KEL events of any AID that authority anchors — against a witness set and
threshold **pinned in the authority trust material it accepted into its
verification policy**, applying the receipt-threshold rule of §4.5". That is the
hook this record fills: it is the out-of-band material a verifier accepts
*before* receiving any proof, and the witness set and threshold it pins are the
ones :func:`verify_authority_trust_material` enforces — over the authority's own
KEL and over every KEL the authority anchors — regardless of what those events
declare for themselves.

§6.3.1 states exactly two acceptance conditions over accepted trust material,
and both live here: the pinned witness set and threshold above, and the
authority's half of the disclosure duty — "a verifier MUST NOT accept an
authority under this class unless the trust material it accepted characterizes
the attestation as platform-layer self-attestation rather than as third-party
attestation". :data:`SELF_ATTESTATION_CHARACTERIZATION` is that characterization,
and it is a required, exact-match field.

**This kind is ours, not AFP's.** §6.3.1 requires a verifier to pin a witness set
and threshold in the authority trust material it accepted, and requires that
material to characterize the attestation truthfully — but it defines **no record
kind and no wire shape** for trust material, and the specification's change log
announces exactly one new artifact kind for this revision
(``afp:publisher-key-state:v1``). ``afp:authority-trust-material:v1`` is
therefore Pyramidal Inc.'s own encoding of material AFP requires a verifier to
hold, not an AFP-defined artifact: a reader MUST NOT implement it as though the
specification fixed its fields, and another authority may encode the same
material differently and be equally conformant. (The staging-only artifacts
this package emits alongside it are namespaced ``x-afp-staging:`` for the same
reason — see :mod:`afp_ceremony.ceremony`.)

This record is **not** an authority feed, registry, or status service. §6.3.1
keeps every authority-published feed off the normative path, AFP "maintains no
authority registry", and §1.2/§1.5.1 rule out a conformance mark or published
implementer list. The record describes exactly one authority — itself — and
carries no statement about any other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from afp_session import ed25519, keri
from afp_session.canonical import qb64_payload

from .errors import AuthorityTrustMaterialError
from .jcs import jcs_bytes
from .keystate import (
    AfpPublisherKeyState,
    ESTABLISHMENT_ILKS,
    delegation_seal,
)
from .staging import enforce_not_production, staging_markers

__all__ = [
    "AUTHORITY_TRUST_MATERIAL_KIND",
    "SELF_ATTESTATION_CHARACTERIZATION",
    "PUBLISHER_MANIFEST_ROOT_CLASS",
    "SIGNER_ACTIVE",
    "SIGNER_SUPERSEDED",
    "SIGNER_REVOKED",
    "PinnedWitness",
    "AnchoredSigner",
    "AfpAuthorityTrustMaterial",
    "build_authority_trust_material",
    "verify_authority_trust_material",
    "verify_pinned_witness_threshold",
    "accept_publisher_key_state",
]

AUTHORITY_TRUST_MATERIAL_KIND = "afp:authority-trust-material:v1"

#: §6.3.1: the authority's half of the split disclosure duty, stated as a
#: verifier acceptance condition over accepted trust material.
SELF_ATTESTATION_CHARACTERIZATION = "platform-layer-self-attestation"

PUBLISHER_MANIFEST_ROOT_CLASS = "root:publisher-manifest"

SIGNER_ACTIVE = "active"
SIGNER_SUPERSEDED = "superseded"
SIGNER_REVOKED = "revoked"

_SIGNER_STATUSES = frozenset({SIGNER_ACTIVE, SIGNER_SUPERSEDED, SIGNER_REVOKED})


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityTrustMaterialError(f"{field_name} must be a non-empty string")
    return value


def _parse_instant(value: Any, field_name: str) -> datetime:
    """Parse a timezone-aware ISO 8601 value and normalize it to UTC."""
    text = _require_text(value, field_name)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuthorityTrustMaterialError(
            f"{field_name} must be a timezone-aware ISO 8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityTrustMaterialError(
            f"{field_name} must include a UTC offset or Z suffix"
        )
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class PinnedWitness:
    """One witness in the pinned set (§6.3.1, applying the §4.5 receipt rule).

    ``witness_verification_material`` carries the witness's Ed25519 public key
    as ``afp_session.canonical.qb64`` hex. In full KERI a verifier resolves that
    key by walking the witness's own KEL to ``witness_kel_dig``; the reference
    subset does not walk witness KELs (a documented seam, see
    :mod:`afp_ceremony.conformance`), so the material travels with the pin.
    """

    witness_aid: str
    witness_endpoint: str
    witness_kel_dig: str
    witness_verification_material: str

    def __post_init__(self) -> None:
        _require_text(self.witness_aid, "witness_aid")
        _require_text(self.witness_endpoint, "witness_endpoint")
        _require_text(self.witness_kel_dig, "witness_kel_dig")
        _require_text(
            self.witness_verification_material, "witness_verification_material"
        )
        _ = self.verification_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "witness_aid": self.witness_aid,
            "witness_endpoint": self.witness_endpoint,
            "witness_kel_dig": self.witness_kel_dig,
            "witness_verification_material": self.witness_verification_material,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "PinnedWitness":
        if not isinstance(data, Mapping):
            raise AuthorityTrustMaterialError("pinned witness must be a JSON object")
        expected = {
            "witness_aid",
            "witness_endpoint",
            "witness_kel_dig",
            "witness_verification_material",
        }
        if set(data) != expected:
            raise AuthorityTrustMaterialError("pinned witness has noncanonical members")
        return cls(**{name: data[name] for name in expected})

    @property
    def verification_bytes(self) -> bytes:
        try:
            material = self.witness_verification_material
            if type(material) is not str or material.partition("_")[0] != "K":
                raise ValueError("witness public key must use the K derivation code")
            public_key = qb64_payload(material)
            ed25519.validate_public_key(public_key)
            return public_key
        except ValueError as exc:
            raise AuthorityTrustMaterialError(
                f"witness {self.witness_aid} verification material must be "
                "canonical K_<64 lowercase hex> prime-order Ed25519 material"
            ) from exc


@dataclass(frozen=True)
class AnchoredSigner:
    """A signing AID the authority anchors in its own KEL (§4.2, §6.3.1).

    ``delegation_anchor_dig`` is the SAID of the authority-KEL event anchoring
    the delegated inception — the same value ``afp:publisher-key-state:v1``
    carries, so the two artifacts pin one delegation, not two.
    """

    signing_aid: str
    delegation_anchor_dig: str
    purpose: str
    status: str = SIGNER_ACTIVE

    def __post_init__(self) -> None:
        _require_text(self.signing_aid, "signing_aid")
        _require_text(self.delegation_anchor_dig, "delegation_anchor_dig")
        _require_text(self.purpose, "purpose")
        if self.status not in _SIGNER_STATUSES:
            raise AuthorityTrustMaterialError(
                f"anchored signer status must be one of {sorted(_SIGNER_STATUSES)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signing_aid": self.signing_aid,
            "delegation_anchor_dig": self.delegation_anchor_dig,
            "purpose": self.purpose,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AnchoredSigner":
        if not isinstance(data, Mapping):
            raise AuthorityTrustMaterialError("anchored signer must be a JSON object")
        expected = {"signing_aid", "delegation_anchor_dig", "purpose", "status"}
        if set(data) != expected:
            raise AuthorityTrustMaterialError("anchored signer has noncanonical members")
        return cls(**{name: data[name] for name in expected})


@dataclass(frozen=True)
class AfpAuthorityTrustMaterial:
    """Out-of-band trust material a verifier accepts into its verification policy.

    §6.3.1: "The binding between an authority AID and the legal entity it denotes
    is established **out-of-band**, at the moment a verifier accepts that
    authority's trust material into its verification policy; AFP defines no
    on-wire representation of that binding and no protocol step that establishes
    it." ``legal_entity_binding_statement`` records the *claim* the accepting
    party evaluates out-of-band; it is not, and cannot be, a protocol proof.
    """

    authority_aid: str
    authority_inception_dig: str
    legal_entity_binding_statement: str
    pinned_witnesses: Tuple[PinnedWitness, ...]
    pinned_witness_threshold: int
    anchored_signers: Tuple[AnchoredSigner, ...]
    accepted_root_classes: Tuple[str, ...]
    attestation_characterization: str
    issued_at: str
    expires_at: str
    markers: Mapping[str, Any] = field(default_factory=staging_markers)
    authority_signature: Optional[str] = None

    def __post_init__(self) -> None:
        # Enforced on CONSTRUCTION, not only on decode. ``signed_content`` folds
        # the markers into the signature, so a record carrying
        # ``environment: production`` would be internally consistent and
        # tamper-evident — more credible-looking, not less — while being built
        # from the seed phrase published in ``staging.py``. Refusing at
        # ``__post_init__`` means no such record can be instantiated, and
        # therefore none can be signed or emitted.
        object.__setattr__(self, "markers", dict(self.markers))
        enforce_not_production(dict(self.markers), what="authority trust material")
        _require_text(self.authority_aid, "authority_aid")
        _require_text(self.authority_inception_dig, "authority_inception_dig")
        _require_text(
            self.legal_entity_binding_statement, "legal_entity_binding_statement"
        )
        _require_text(self.issued_at, "issued_at")
        _require_text(self.expires_at, "expires_at")
        issued = _parse_instant(self.issued_at, "issued_at")
        expires = _parse_instant(self.expires_at, "expires_at")
        if expires <= issued:
            raise AuthorityTrustMaterialError("expires_at must be later than issued_at")
        if not self.pinned_witnesses:
            raise AuthorityTrustMaterialError(
                "authority trust material MUST pin a witness set (§6.3.1)"
            )
        witness_aids = [witness.witness_aid for witness in self.pinned_witnesses]
        if len(set(witness_aids)) != len(witness_aids):
            raise AuthorityTrustMaterialError(
                "the pinned witness set must name distinct witness_aid values"
            )
        threshold = self.pinned_witness_threshold
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise AuthorityTrustMaterialError("pinned_witness_threshold must be an integer")
        if threshold < 1 or threshold > len(self.pinned_witnesses):
            raise AuthorityTrustMaterialError(
                "pinned_witness_threshold must be between 1 and the pinned set size"
            )
        if self.attestation_characterization != SELF_ATTESTATION_CHARACTERIZATION:
            raise AuthorityTrustMaterialError(
                "trust material MUST characterize the attestation as "
                f"{SELF_ATTESTATION_CHARACTERIZATION!r}; §6.3.1 makes a verifier's "
                "acceptance conditional on that characterization and forbids "
                "describing the result as third-party attestation"
            )
        if PUBLISHER_MANIFEST_ROOT_CLASS not in self.accepted_root_classes:
            raise AuthorityTrustMaterialError(
                f"accepted_root_classes must include {PUBLISHER_MANIFEST_ROOT_CLASS!r}"
            )
        seen = set()
        for signer in self.anchored_signers:
            if signer.signing_aid in seen:
                raise AuthorityTrustMaterialError(
                    f"anchored signer {signer.signing_aid} appears twice"
                )
            seen.add(signer.signing_aid)

    # -- serialization -----------------------------------------------------

    def signed_content(self) -> Dict[str, Any]:
        """Everything the authority signs — markers included, so they cannot be stripped."""
        content: Dict[str, Any] = {
            "kind": AUTHORITY_TRUST_MATERIAL_KIND,
            "authority_aid": self.authority_aid,
            "authority_inception_dig": self.authority_inception_dig,
            "legal_entity_binding_statement": self.legal_entity_binding_statement,
            "pinned_witnesses": [w.to_dict() for w in self.pinned_witnesses],
            "pinned_witness_threshold": self.pinned_witness_threshold,
            "anchored_signers": [s.to_dict() for s in self.anchored_signers],
            "accepted_root_classes": list(self.accepted_root_classes),
            "attestation_characterization": self.attestation_characterization,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        content.update(dict(self.markers))
        return content

    def to_dict(self) -> Dict[str, Any]:
        data = self.signed_content()
        data["authority_signature"] = self.authority_signature
        return data

    @classmethod
    def from_dict(cls, data: Any) -> "AfpAuthorityTrustMaterial":
        if not isinstance(data, Mapping):
            raise AuthorityTrustMaterialError("trust material must be a JSON object")
        if data.get("kind") != AUTHORITY_TRUST_MATERIAL_KIND:
            raise AuthorityTrustMaterialError(
                f"trust material kind must be {AUTHORITY_TRUST_MATERIAL_KIND!r}"
            )
        enforce_not_production(dict(data), what="authority trust material")
        marker_names = set(staging_markers())
        core = {
            "kind",
            "authority_aid",
            "authority_inception_dig",
            "legal_entity_binding_statement",
            "pinned_witnesses",
            "pinned_witness_threshold",
            "anchored_signers",
            "accepted_root_classes",
            "attestation_characterization",
            "issued_at",
            "expires_at",
            "authority_signature",
        }
        if set(data) != core | marker_names:
            raise AuthorityTrustMaterialError("trust material has noncanonical members")
        witnesses = data["pinned_witnesses"]
        signers = data["anchored_signers"]
        if not isinstance(witnesses, list) or not isinstance(signers, list):
            raise AuthorityTrustMaterialError(
                "pinned_witnesses and anchored_signers must be arrays"
            )
        return cls(
            authority_aid=data["authority_aid"],
            authority_inception_dig=data["authority_inception_dig"],
            legal_entity_binding_statement=data["legal_entity_binding_statement"],
            pinned_witnesses=tuple(PinnedWitness.from_dict(w) for w in witnesses),
            pinned_witness_threshold=data["pinned_witness_threshold"],
            anchored_signers=tuple(AnchoredSigner.from_dict(s) for s in signers),
            accepted_root_classes=tuple(data["accepted_root_classes"]),
            attestation_characterization=data["attestation_characterization"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            markers={name: data[name] for name in marker_names},
            authority_signature=data["authority_signature"],
        )

    # -- accessors ---------------------------------------------------------

    @property
    def pinned_witness_aids(self) -> Tuple[str, ...]:
        return tuple(w.witness_aid for w in self.pinned_witnesses)

    @property
    def pinned_witness_material(self) -> Dict[str, bytes]:
        return {w.witness_aid: w.verification_bytes for w in self.pinned_witnesses}

    def signer(self, signing_aid: str) -> Optional[AnchoredSigner]:
        for entry in self.anchored_signers:
            if entry.signing_aid == signing_aid:
                return entry
        return None

    def with_signers(
        self, signers: Sequence[AnchoredSigner]
    ) -> "AfpAuthorityTrustMaterial":
        """Return an unsigned copy carrying ``signers`` (re-signing is the caller's job)."""
        return AfpAuthorityTrustMaterial(
            authority_aid=self.authority_aid,
            authority_inception_dig=self.authority_inception_dig,
            legal_entity_binding_statement=self.legal_entity_binding_statement,
            pinned_witnesses=self.pinned_witnesses,
            pinned_witness_threshold=self.pinned_witness_threshold,
            anchored_signers=tuple(signers),
            accepted_root_classes=self.accepted_root_classes,
            attestation_characterization=self.attestation_characterization,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            markers=dict(self.markers),
            authority_signature=None,
        )


def build_authority_trust_material(
    *,
    authority_kel: keri.Kel,
    signing_material: keri.KeyPair,
    legal_entity_binding_statement: str,
    pinned_witnesses: Sequence[PinnedWitness],
    pinned_witness_threshold: int,
    anchored_signers: Sequence[AnchoredSigner],
    issued_at: str,
    expires_at: str,
) -> AfpAuthorityTrustMaterial:
    """Build and sign trust material with the authority's current signing key.

    The signature is a real Ed25519 signature over the RFC 8785 JCS bytes of
    :meth:`AfpAuthorityTrustMaterial.signed_content`, verifiable against the key
    the authority's KEL currently establishes.

    There is deliberately **no** ``markers`` parameter: the markers are always
    :func:`afp_ceremony.staging.staging_markers`. No legitimate caller needs to
    choose them, and a caller that could choose them could sign a record
    asserting it is production material.
    """
    unsigned = AfpAuthorityTrustMaterial(
        authority_aid=authority_kel.aid,
        authority_inception_dig=authority_kel.events[0].digest,
        legal_entity_binding_statement=legal_entity_binding_statement,
        pinned_witnesses=tuple(pinned_witnesses),
        pinned_witness_threshold=pinned_witness_threshold,
        anchored_signers=tuple(anchored_signers),
        accepted_root_classes=(PUBLISHER_MANIFEST_ROOT_CLASS,),
        attestation_characterization=SELF_ATTESTATION_CHARACTERIZATION,
        issued_at=issued_at,
        expires_at=expires_at,
        markers=staging_markers(),
        authority_signature=None,
    )
    signature = signing_material.sign(jcs_bytes(unsigned.signed_content()))
    return AfpAuthorityTrustMaterial(
        authority_aid=unsigned.authority_aid,
        authority_inception_dig=unsigned.authority_inception_dig,
        legal_entity_binding_statement=unsigned.legal_entity_binding_statement,
        pinned_witnesses=unsigned.pinned_witnesses,
        pinned_witness_threshold=unsigned.pinned_witness_threshold,
        anchored_signers=unsigned.anchored_signers,
        accepted_root_classes=unsigned.accepted_root_classes,
        attestation_characterization=unsigned.attestation_characterization,
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        markers=dict(unsigned.markers),
        authority_signature=signature.hex(),
    )


def verify_pinned_witness_threshold(
    kel: keri.Kel,
    *,
    pinned_witness_aids: Sequence[str],
    pinned_threshold: int,
    witness_material: Mapping[str, bytes],
    label: str = "KEL",
) -> None:
    """Apply §4.5's receipt-threshold rule using the **pinned** set and threshold.

    §6.3.1, "Authority-KEL integrity is not assumed": an authority is not a
    tenant, so the threshold an event declares for itself carries no
    tenant-conformance force here. The verifier's obligation is against the set
    and threshold *it pinned* in the trust material it accepted, applied to the
    authority's own KEL and to the KELs of any AID the authority anchors. A KEL
    that does not meet the pinned threshold is unresolvable authority key state.
    """
    for witness_aid, public_key in witness_material.items():
        try:
            ed25519.validate_public_key(public_key)
        except ValueError as exc:
            raise AuthorityTrustMaterialError(
                f"pinned witness {witness_aid!r} has invalid Ed25519 "
                "public-key material"
            ) from exc

    pinned = set(pinned_witness_aids)
    if pinned_threshold < 1:
        raise AuthorityTrustMaterialError("pinned threshold must be at least 1")
    for event in kel.events:
        valid = 0
        counted = set()
        for receipt in kel.receipts.get(event.digest, []):
            if type(receipt.event_dig) is not str or receipt.event_dig != event.digest:
                continue
            if receipt.witness_aid in counted or receipt.witness_aid not in pinned:
                continue
            material = witness_material.get(receipt.witness_aid)
            if material is None:
                continue
            if ed25519.verify_strict(
                keri.receipt_signing_input(event.digest), receipt.signature, material
            ):
                counted.add(receipt.witness_aid)
                valid += 1
        if valid < pinned_threshold:
            raise AuthorityTrustMaterialError(
                f"unresolvable authority key state: {label} event sn={event.sn} has "
                f"{valid} valid receipts from the pinned witness set, below the "
                f"pinned threshold {pinned_threshold} (§6.3.1)"
            )


def _verify_no_fork(
    kel: keri.Kel, previously_accepted: Mapping[int, str], label: str
) -> None:
    """§6.3.1: a KEL that forks against previously accepted events is unresolvable."""
    by_sn = {event.sn: event.digest for event in kel.events}
    for sn, accepted_dig in previously_accepted.items():
        current = by_sn.get(sn)
        if current is None:
            raise AuthorityTrustMaterialError(
                f"unresolvable authority key state: {label} no longer carries an "
                f"event at sn={sn} the verifier previously accepted"
            )
        if current != accepted_dig:
            raise AuthorityTrustMaterialError(
                f"unresolvable authority key state: {label} forks at sn={sn} against "
                "an event the verifier previously accepted (§6.3.1)"
            )


def verify_authority_trust_material(
    material: AfpAuthorityTrustMaterial,
    *,
    authority_kel: keri.Kel,
    anchored_kels: Optional[Mapping[str, keri.Kel]] = None,
    now: str,
    previously_accepted: Optional[Mapping[int, str]] = None,
) -> None:
    """Verify trust material before accepting it into a verification policy.

    Checks, in order:

    1. the record's AID and inception SAID match the supplied authority KEL, and
       the KEL is self-certifying with an intact chain and honored pre-rotation
       commitments (§4.4, via ``afp_session.keri.verify_kel``);
    2. the authority signature verifies under the key the authority's KEL
       *currently* establishes;
    3. the pinned witness set and threshold are enforced over the authority KEL
       **and** over every KEL the authority anchors (§6.3.1, applying §4.5);
    4. no fork against events the verifier previously accepted (§6.3.1);
    5. the record has not expired;
    6. every anchored signer entry resolves to a real anchoring event in the
       authority KEL, at the SAID the entry names.

    The characterization and root-class acceptance conditions are enforced at
    construction/decoding time by :class:`AfpAuthorityTrustMaterial` itself.

    Failure raises :class:`AuthorityTrustMaterialError`. Per §6.3.1 the only
    permitted consequence is declining the affected interaction (or an alert on
    the telemetry path); it never gates or mutates tenant state.
    """
    anchored: Mapping[str, keri.Kel] = anchored_kels or {}
    # Refused on the verify path as well as the load path: a record that claims
    # to be production material is never accepted by this staging tooling,
    # however it was constructed.
    enforce_not_production(dict(material.markers), what="authority trust material")
    if material.authority_aid != authority_kel.aid:
        raise AuthorityTrustMaterialError(
            "trust material names a different authority AID than the supplied KEL"
        )
    keri.verify_kel(authority_kel)
    if material.authority_inception_dig != authority_kel.events[0].digest:
        raise AuthorityTrustMaterialError(
            "authority_inception_dig does not match the authority KEL inception event"
        )

    signature_hex = material.authority_signature
    if not isinstance(signature_hex, str) or not signature_hex:
        raise AuthorityTrustMaterialError("trust material is unsigned")
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise AuthorityTrustMaterialError("authority signature is not hex") from exc
    current = keri.resolve_current_key(authority_kel)
    if not ed25519.verify_strict(
        jcs_bytes(material.signed_content()), signature, current
    ):
        raise AuthorityTrustMaterialError(
            "authority signature does not verify under the authority KEL's current "
            "signing key state"
        )

    witness_material = material.pinned_witness_material
    verify_pinned_witness_threshold(
        authority_kel,
        pinned_witness_aids=material.pinned_witness_aids,
        pinned_threshold=material.pinned_witness_threshold,
        witness_material=witness_material,
        label="authority KEL",
    )
    for signing_aid, kel in anchored.items():
        verify_pinned_witness_threshold(
            kel,
            pinned_witness_aids=material.pinned_witness_aids,
            pinned_threshold=material.pinned_witness_threshold,
            witness_material=witness_material,
            label=f"anchored KEL {signing_aid}",
        )

    if previously_accepted:
        _verify_no_fork(authority_kel, previously_accepted, "authority KEL")

    now_instant = _parse_instant(now, "now")
    issued_instant = _parse_instant(material.issued_at, "issued_at")
    expires_instant = _parse_instant(material.expires_at, "expires_at")
    if now_instant >= expires_instant:
        raise AuthorityTrustMaterialError(
            f"authority trust material expired at {material.expires_at}"
        )
    if now_instant < issued_instant:
        raise AuthorityTrustMaterialError(
            f"authority trust material is not yet valid (issued_at {material.issued_at})"
        )

    anchor_digs = {
        event.digest for event in authority_kel.events if event.ilk == "ixn"
    }
    for signer in material.anchored_signers:
        if signer.delegation_anchor_dig not in anchor_digs:
            raise AuthorityTrustMaterialError(
                f"anchored signer {signer.signing_aid} names a delegation anchor that "
                "is not an interaction event in the authority KEL"
            )
        kel = anchored.get(signer.signing_aid)
        if kel is None:
            continue
        inception = kel.events[0]
        if inception.ilk != "dip" or inception.delegator_aid != authority_kel.aid:
            raise AuthorityTrustMaterialError(
                f"anchored signer {signer.signing_aid} is not delegated from this authority"
            )
        expected_seal = delegation_seal(kel.aid, inception.digest)
        anchoring = [
            event
            for event in authority_kel.events
            if event.ilk == "ixn" and event.seal == expected_seal
        ]
        if len(anchoring) > 1:
            # Mirrors ``keystate.find_delegation_anchor``: §6.3.1 names *the*
            # anchoring event, and it is digest-committed. More than one makes
            # the choice — and so ``root_material_digest`` — verifier-dependent.
            raise AuthorityTrustMaterialError(
                "unresolvable authority key state: the authority KEL carries "
                f"{len(anchoring)} events anchoring the delegated inception of "
                f"{signer.signing_aid}, so its delegation anchor is not uniquely "
                "determined (§6.3.1)"
            )
        if not anchoring or anchoring[0].digest != signer.delegation_anchor_dig:
            raise AuthorityTrustMaterialError(
                f"anchored signer {signer.signing_aid} delegation anchor does not match "
                "the authority KEL event that anchors its inception"
            )


def accept_publisher_key_state(
    key_state: AfpPublisherKeyState,
    *,
    material: AfpAuthorityTrustMaterial,
    signing_kel: keri.Kel,
) -> None:
    """Policy check tying a resolved key state to accepted trust material (§6.3.1).

    §6.3.1 requires a verifier to reject "a proof whose committed signing-key
    state is superseded by a published rotation" or "whose delegated signing
    AID's delegation has been revoked", determined "from the authority's KEL and
    the KELs it anchors".
    """
    if key_state.authority_aid != material.authority_aid:
        raise AuthorityTrustMaterialError(
            "key state names an authority the verifier has not accepted "
            "(instance_attestation_untrusted_authority)"
        )
    if key_state.signing_aid != signing_kel.aid:
        raise AuthorityTrustMaterialError("key state does not describe this signing KEL")
    if key_state.is_delegated:
        entry = material.signer(key_state.signing_aid)
        if entry is None:
            raise AuthorityTrustMaterialError(
                "signing AID is not an anchored signer in the accepted trust material"
            )
        if entry.status != SIGNER_ACTIVE:
            raise AuthorityTrustMaterialError(
                f"signing AID delegation is {entry.status}, not active (§6.3.1)"
            )
        if entry.delegation_anchor_dig != key_state.delegation_anchor_dig:
            raise AuthorityTrustMaterialError(
                "key state delegation anchor disagrees with the accepted trust material"
            )
    latest: Optional[keri.KelEvent] = None
    for event in reversed(signing_kel.events):
        if event.ilk in ESTABLISHMENT_ILKS:
            latest = event
            break
    if latest is None:
        raise AuthorityTrustMaterialError("signing KEL has no key-establishing event")
    if key_state.key_state_event_dig != latest.digest:
        raise AuthorityTrustMaterialError(
            "committed signing-key state is superseded by a published rotation "
            "(kel_keystate_stale, §6.3.1)"
        )
