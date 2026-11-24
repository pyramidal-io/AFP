"""``afp:publisher-key-state:v1`` and ``root_material_digest`` (AFP §6.3.1).

§6.3.1 "Publisher signing-key state (normative)" fixes, for the
``root:publisher-manifest`` root class, exactly what ``root_material_digest``
commits to: the RFC 8785 JCS bytes of a record carrying ``kind`` plus nine
fields, digested as ``sha256:`` followed by lowercase hex SHA-256.

Three properties of that definition drive this module:

* **The record is derived, never transmitted.** "Every field is derived from
  published KEL events, so the record is a re-encoding of state the verifier
  already holds; it is never transmitted as an AFP message, adds no public
  input, and adds no wire field." :func:`resolve_publisher_key_state` is
  therefore the primary constructor: it reads two KELs and nothing else.
* **KEL-native fields are carried verbatim.** ``delegation_anchor_dig``,
  ``key_state_event_dig``, each element of ``signing_public_keys`` and
  ``next_key_digests``, and both thresholds are copied exactly as the
  establishment event lists them, and are **NOT** re-encoded under the
  ``sha256:``-prefixed ``*_digest`` rule. :class:`AfpPublisherKeyState` enforces
  that by rejecting a KEL-native field that arrives ``sha256:``-prefixed.
* **Determinism is the security property.** "A verifier MUST recompute this
  digest from the key state it independently resolves out of the signing AID's
  KEL, reached through the delegation anchors in the authority's KEL", and
  §6.3.1 spells out what is forfeited otherwise: without the recomputation a
  party "could construct a key-state record naming another organization's root
  AID as ``authority_aid``, sign its own manifest with its own keys, and satisfy
  every in-circuit constraint".

**Threshold honesty.** §4.4.2 fixes the current AFP encoding to one current
and one next key, with implicit signing thresholds of one. The resolver uses
the canonical string :data:`SUBSET_SIGNING_THRESHOLD` (``"1"``) for both
§6.3.1 threshold fields and takes no caller override. The witness receipt
``threshold`` is a different mechanism and never supplies these fields.
The record type retains its union for future encodings; accepting a weighted
record for canonicalization does not make it resolvable from today's KEL.
True M-of-N signing custody remains unsupported and must not be claimed by the
staging ceremony. See ``afp_ceremony.conformance`` for that limitation.

**Sequence-number encoding.** ``key_state_sequence_number`` is a JSON *number*:
the value of the establishment event's sequence number. A production resolver
reads it from KERI's ``s`` field, which KERI serializes as **lowercase
hexadecimal** (``"a"``, ``"10"``); :func:`kel_sequence_number` performs exactly
that conversion so a production adapter cannot accidentally read ``s = "10"`` as
decimal ten and digest different bytes than a verifier that read sixteen. The
reference subset stores ``sn`` as a Python ``int``, so the conversion is a
no-op here and the helper exists for the production path and its test.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from afp_session import keri

from .errors import KeyStateError
from .jcs import jcs_bytes

__all__ = [
    "PUBLISHER_KEY_STATE_KIND",
    "SUBSET_SIGNING_THRESHOLD",
    "ESTABLISHMENT_ILKS",
    "Threshold",
    "AfpPublisherKeyState",
    "delegation_seal",
    "find_delegation_anchor",
    "rotation_anchor_seal",
    "find_rotation_anchor",
    "establishment_event",
    "kel_sequence_number",
    "resolve_publisher_key_state",
]

#: The ``kind`` discriminator §6.3.1 fixes for this AFP-authored record.
PUBLISHER_KEY_STATE_KIND = "afp:publisher-key-state:v1"

#: ``kt``/``nt`` value implied by the single-signing-key reference KERI subset.
SUBSET_SIGNING_THRESHOLD = "1"

#: KEL ilks that establish key state (§4.4). ``ixn`` does not rotate.
ESTABLISHMENT_ILKS = ("icp", "dip", "rot")

#: A KERI ``kt``/``nt``: a hex string, or the nested list of fraction strings
#: KERI uses for a weighted multisig threshold (§6.3.1 — "which is why the type
#: is a union").
Threshold = Union[str, Tuple[str, ...], Tuple[Tuple[str, ...], ...]]

_SHA256_PREFIX = "sha256:"


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise KeyStateError(f"{field} must be a non-empty string")
    if value.startswith(_SHA256_PREFIX):
        raise KeyStateError(
            f"{field} carries a {_SHA256_PREFIX!r}-prefixed digest; §6.3.1 requires "
            "KEL-native identifiers verbatim and explicitly does NOT re-encode them "
            "under the *_digest rule"
        )
    return value


def _normalize_threshold(value: Any, field: str) -> Threshold:
    """Validate a ``kt``/``nt`` and return an immutable canonical form."""
    if isinstance(value, str):
        if not value:
            raise KeyStateError(f"{field} must be a non-empty string")
        return value
    if isinstance(value, (list, tuple)):
        if not value:
            raise KeyStateError(f"{field} must not be an empty list")
        weighted: List[Any] = []
        for item in value:
            if isinstance(item, str):
                if not item:
                    raise KeyStateError(f"{field} contains an empty weight")
                weighted.append(item)
            elif isinstance(item, (list, tuple)):
                if not item:
                    raise KeyStateError(f"{field} contains an empty clause")
                clause = []
                for weight in item:
                    if not isinstance(weight, str) or not weight:
                        raise KeyStateError(
                            f"{field} clause weights must be non-empty strings"
                        )
                    clause.append(weight)
                weighted.append(tuple(clause))
            else:
                raise KeyStateError(
                    f"{field} must be a string, a list of strings, or a list of "
                    "lists of strings (KERI weighted threshold)"
                )
        if any(isinstance(x, tuple) for x in weighted) and any(
            isinstance(x, str) for x in weighted
        ):
            raise KeyStateError(f"{field} mixes weighted clauses with bare weights")
        return tuple(weighted)  # type: ignore[return-value]
    raise KeyStateError(f"{field} must be a KERI kt/nt value")


def _threshold_key(value: Threshold) -> Any:
    """A hashable projection of a threshold, so the dataclass can stay frozen."""
    if isinstance(value, str):
        return value
    return value


def _threshold_json(value: Threshold) -> Any:
    if isinstance(value, str):
        return value
    return [list(item) if isinstance(item, tuple) else item for item in value]


@dataclass(frozen=True)
class AfpPublisherKeyState:
    """The §6.3.1 publisher signing-key state record.

    Field order below follows the specification's interface. JCS sorts members
    on serialization, so the declaration order is documentation only.
    """

    authority_aid: str
    signing_aid: str
    delegation_anchor_dig: Optional[str]
    key_state_event_dig: str
    key_state_sequence_number: int
    signing_public_keys: Tuple[str, ...]
    signing_threshold: Threshold
    next_key_digests: Tuple[str, ...]
    next_threshold: Threshold

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "authority_aid", _require_identifier(self.authority_aid, "authority_aid")
        )
        object.__setattr__(
            self, "signing_aid", _require_identifier(self.signing_aid, "signing_aid")
        )
        object.__setattr__(
            self,
            "key_state_event_dig",
            _require_identifier(self.key_state_event_dig, "key_state_event_dig"),
        )

        delegated = self.signing_aid != self.authority_aid
        anchor = self.delegation_anchor_dig
        if delegated:
            if anchor is None:
                raise KeyStateError(
                    "delegation_anchor_dig is null but the signing AID differs from "
                    "the authority AID; §6.3.1 requires null iff they are equal"
                )
            object.__setattr__(
                self,
                "delegation_anchor_dig",
                _require_identifier(anchor, "delegation_anchor_dig"),
            )
        else:
            if anchor is not None:
                raise KeyStateError(
                    "delegation_anchor_dig must be null when signing is not delegated "
                    "(signing_aid == authority_aid), per §6.3.1"
                )

        sn = self.key_state_sequence_number
        if isinstance(sn, bool) or not isinstance(sn, int) or sn < 0:
            raise KeyStateError("key_state_sequence_number must be a non-negative integer")

        for field, values in (
            ("signing_public_keys", self.signing_public_keys),
            ("next_key_digests", self.next_key_digests),
        ):
            if isinstance(values, (str, bytes)) or not isinstance(
                values, (list, tuple)
            ):
                raise KeyStateError(f"{field} must be an ordered list of strings")
            if not values:
                raise KeyStateError(f"{field} must not be empty")
            normalized = tuple(
                _require_identifier(item, f"{field}[{i}]")
                for i, item in enumerate(values)
            )
            object.__setattr__(self, field, normalized)

        object.__setattr__(
            self,
            "signing_threshold",
            _normalize_threshold(self.signing_threshold, "signing_threshold"),
        )
        object.__setattr__(
            self,
            "next_threshold",
            _normalize_threshold(self.next_threshold, "next_threshold"),
        )

    # -- identity / hashing ------------------------------------------------

    def __hash__(self) -> int:  # thresholds may be lists; project them
        return hash(
            (
                self.authority_aid,
                self.signing_aid,
                self.delegation_anchor_dig,
                self.key_state_event_dig,
                self.key_state_sequence_number,
                self.signing_public_keys,
                _threshold_key(self.signing_threshold),
                self.next_key_digests,
                _threshold_key(self.next_threshold),
            )
        )

    # -- serialization -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """The exact §6.3.1 record: ``kind`` plus the nine defined fields."""
        return {
            "kind": PUBLISHER_KEY_STATE_KIND,
            "authority_aid": self.authority_aid,
            "signing_aid": self.signing_aid,
            "delegation_anchor_dig": self.delegation_anchor_dig,
            "key_state_event_dig": self.key_state_event_dig,
            "key_state_sequence_number": self.key_state_sequence_number,
            "signing_public_keys": list(self.signing_public_keys),
            "signing_threshold": _threshold_json(self.signing_threshold),
            "next_key_digests": list(self.next_key_digests),
            "next_threshold": _threshold_json(self.next_threshold),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AfpPublisherKeyState":
        """Strictly decode a record; unknown or missing members are rejected."""
        if not isinstance(data, Mapping):
            raise KeyStateError("publisher key state must be a JSON object")
        expected = {
            "kind",
            "authority_aid",
            "signing_aid",
            "delegation_anchor_dig",
            "key_state_event_dig",
            "key_state_sequence_number",
            "signing_public_keys",
            "signing_threshold",
            "next_key_digests",
            "next_threshold",
        }
        if set(data) != expected:
            missing = sorted(expected - set(data))
            extra = sorted(set(data) - expected)
            raise KeyStateError(
                f"publisher key state has noncanonical members "
                f"(missing={missing}, unexpected={extra})"
            )
        if data["kind"] != PUBLISHER_KEY_STATE_KIND:
            raise KeyStateError(
                f"publisher key state kind must be {PUBLISHER_KEY_STATE_KIND!r}"
            )
        for field in ("signing_public_keys", "next_key_digests"):
            if not isinstance(data[field], list):
                raise KeyStateError(f"{field} must be an ordered JSON list")
        return cls(
            authority_aid=data["authority_aid"],
            signing_aid=data["signing_aid"],
            delegation_anchor_dig=data["delegation_anchor_dig"],
            key_state_event_dig=data["key_state_event_dig"],
            key_state_sequence_number=data["key_state_sequence_number"],
            signing_public_keys=tuple(data["signing_public_keys"]),
            signing_threshold=data["signing_threshold"],
            next_key_digests=tuple(data["next_key_digests"]),
            next_threshold=data["next_threshold"],
        )

    def jcs_bytes(self) -> bytes:
        """The RFC 8785 JCS preimage §6.3.1 fixes for ``root_material_digest``."""
        return jcs_bytes(self.to_dict())

    def root_material_digest(self) -> str:
        """``sha256:`` + lowercase hex SHA-256 of :meth:`jcs_bytes` (§6.3.1)."""
        return _SHA256_PREFIX + hashlib.sha256(self.jcs_bytes()).hexdigest()

    @property
    def is_delegated(self) -> bool:
        return self.signing_aid != self.authority_aid


# -- resolution out of published KEL state --------------------------------


def delegation_seal(delegate_aid: str, delegate_inception_dig: str) -> str:
    """The ``ixn`` seal anchoring a delegated inception (§4.2, §6.3.1).

    The seal shape is owned by ``afp_session.keri``; this delegates to it so
    the authority path and the session core apply one rule.
    """
    return keri.delegation_seal(delegate_aid, delegate_inception_dig)


def find_delegation_anchor(authority_kel: keri.Kel, signing_kel: keri.Kel) -> str:
    """Return the SAID of the authority-KEL event anchoring ``signing_kel``'s ``dip``.

    §6.3.1: ``delegation_anchor_dig`` is the "said of the authority-KEL event
    anchoring the delegated inception". That is the anchoring interaction event
    itself, not the seal it carries.

    **An ambiguous anchor is unresolvable, not first-wins.** §6.3.1 names *the*
    anchoring event, singular, and ``delegation_anchor_dig`` is one of the nine
    fields ``root_material_digest`` commits to. An authority KEL carrying more
    than one event with the same delegation seal — a re-anchor after a recovery,
    a duplicity repair, or an attacker-appended replay — would let two honest
    verifiers commit to different SAIDs and so compute different digests over
    identical KEL state, one rejecting the other's accepted proof with
    ``instance_attestation_untrusted_authority``. Selecting the first (or the
    last) match would silently pick a side of that disagreement, so this
    function refuses instead: an ambiguous anchor is treated as unresolvable
    authority key state, which is the consequence §6.3.1 already assigns to
    authority key state a verifier cannot resolve.
    """
    if not signing_kel.events:
        raise KeyStateError("signing KEL is empty")
    inception = signing_kel.events[0]
    if inception.ilk != "dip":
        raise KeyStateError("signing KEL does not open with a delegated inception")
    if inception.delegator_aid != authority_kel.aid:
        raise KeyStateError(
            "delegated inception names a different delegator than the authority AID"
        )
    expected = delegation_seal(signing_kel.aid, inception.digest)
    anchors = [
        event.digest
        for event in authority_kel.events
        if event.ilk == "ixn" and event.seal == expected
    ]
    if not anchors:
        raise KeyStateError("delegation is not anchored in the authority KEL")
    if len(anchors) > 1:
        raise KeyStateError(
            "unresolvable authority key state: the authority KEL carries "
            f"{len(anchors)} events anchoring the same delegated inception, so "
            "delegation_anchor_dig — and therefore root_material_digest — is not "
            "uniquely determined by the published KEL state (§6.3.1)"
        )
    return anchors[0]


def rotation_anchor_seal(delegate_aid: str, rotation_dig: str) -> str:
    """Seal anchoring a *delegated rotation* in the authority KEL (§4.2, §6.3.1).

    §6.3.1 requires "the delegated inception **and each delegated rotation** as
    events in the signing AID's KEL, each anchored by a seal in the authority's
    KEL", exactly as §4.2 requires of an entity. The seal shape is owned by
    ``afp_session.keri``.
    """
    return keri.rotation_anchor_seal(delegate_aid, rotation_dig)


def find_rotation_anchor(
    authority_kel: keri.Kel, *, delegate_aid: str, rotation_dig: str
) -> str:
    """Return the SAID of the authority-KEL event anchoring a delegated rotation.

    Raises :class:`KeyStateError` when no such anchor exists. §6.3.1: "It is
    through those anchors that the authority remains the authoritative source
    for the signing key's state" — so a delegated rotation the authority never
    anchored does not establish key state a verifier may resolve.
    """
    expected = rotation_anchor_seal(delegate_aid, rotation_dig)
    for event in authority_kel.events:
        if event.ilk == "ixn" and event.seal == expected:
            return event.digest
    raise KeyStateError(
        "unresolvable authority key state: the delegated rotation at the head of "
        "the signing KEL is not anchored by a seal in the authority KEL, so the "
        "authority is not the authoritative source for this key state (§6.3.1)"
    )


def establishment_event(kel: keri.Kel) -> keri.KelEvent:
    """The latest key-establishing event (``icp``/``dip``/``rot``) in ``kel`` (§4.4)."""
    for event in reversed(kel.events):
        if event.ilk in ESTABLISHMENT_ILKS:
            return event
    raise KeyStateError("KEL has no key-establishing event")


def kel_sequence_number(value: Any) -> int:
    """The integer sequence number §6.3.1's ``key_state_sequence_number`` carries.

    KERI serializes an event's sequence number in the ``s`` field as **lowercase
    hexadecimal** (``"a"`` is ten, ``"10"`` is sixteen), while §6.3.1 types the
    record field as a JSON ``number``. A production adapter that reads ``s``
    as decimal digests different bytes than one that reads it as hex, and the
    two verifiers then disagree on ``root_material_digest`` over identical KEL
    state. This helper fixes the conversion in one place: an ``int`` passes
    through (the reference subset already stores ``sn`` as an ``int``), and a
    string is read as base 16.
    """
    if isinstance(value, bool):
        raise KeyStateError("sequence number must not be a boolean")
    if isinstance(value, int):
        if value < 0:
            raise KeyStateError("sequence number must be non-negative")
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text or any(ch not in "0123456789abcdef" for ch in text):
            raise KeyStateError(
                f"KERI sequence number {value!r} is not lowercase hexadecimal"
            )
        return int(text, 16)
    raise KeyStateError("sequence number must be an int or a KERI hex string")


def resolve_publisher_key_state(
    *,
    authority_kel: keri.Kel,
    signing_kel: keri.Kel,
    witness_keys: Optional[Mapping[str, bytes]] = None,
) -> AfpPublisherKeyState:
    """Resolve ``afp:publisher-key-state:v1`` from published KEL state alone.

    This is the verifier-side computation §6.3.1 makes mandatory: "A verifier
    MUST recompute this digest from the key state it independently resolves out
    of the **signing AID's** KEL, reached through the delegation anchors in the
    authority's KEL". Both the delegated case and the non-delegated case
    (``signing_aid == authority_aid``, ``delegation_anchor_dig`` null — "Where
    signing is not delegated the signing AID *is* the authority AID and the two
    KELs coincide") are handled here.

    The KELs are verified before anything is read out of them (chain,
    self-certification, pre-rotation, delegation anchoring, and — when
    ``witness_keys`` is supplied — witness receipt thresholds), so an
    unverifiable KEL raises rather than yielding a digest.

    ``verify_kel`` applies the §4.2 delegation rule that §6.3.1 reuses: the
    delegated inception **and each delegated rotation** must be anchored by a
    seal in the authority's KEL, and a delegation the authority has revoked
    resolves nothing. One further obligation is enforced here: **the delegation
    anchor must be unique** (see :func:`find_delegation_anchor`), because
    ``delegation_anchor_dig`` names it.

    ``signing_threshold``/``next_threshold`` are **not** parameters: there is no
    ``kt``/``nt`` on a reference-subset KEL event to resolve them from, so both
    are the subset constant :data:`SUBSET_SIGNING_THRESHOLD`. Accepting them
    from a caller would let a verifier feed values out of the very record it is
    checking, which is exactly the recomputation §6.3.1 makes mandatory being
    performed against prover-supplied input. That gap is reported as a seam by
    ``afp_ceremony.conformance.check_kel_native_threshold_resolution``.
    """
    delegated = signing_kel.aid != authority_kel.aid
    witness_map: Optional[Dict[str, bytes]] = (
        dict(witness_keys) if witness_keys is not None else None
    )

    if delegated:
        try:
            keri.verify_kel(
                signing_kel, tenant_kel=authority_kel, witness_keys=witness_map
            )
        except keri.DelegationError as exc:
            raise KeyStateError(
                f"unresolvable authority key state: {exc} (§6.3.1)"
            ) from exc
        anchor_dig: Optional[str] = find_delegation_anchor(authority_kel, signing_kel)
    else:
        keri.verify_kel(signing_kel, witness_keys=witness_map)
        anchor_dig = None

    event = establishment_event(signing_kel)
    return AfpPublisherKeyState(
        authority_aid=authority_kel.aid,
        signing_aid=signing_kel.aid,
        delegation_anchor_dig=anchor_dig,
        key_state_event_dig=event.digest,
        key_state_sequence_number=kel_sequence_number(event.sn),
        signing_public_keys=tuple(event.keys),
        signing_threshold=SUBSET_SIGNING_THRESHOLD,
        next_key_digests=(event.next_key_digest,),
        next_threshold=SUBSET_SIGNING_THRESHOLD,
    )
