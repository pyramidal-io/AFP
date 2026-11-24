"""AFP profile descriptors and the lightweight profile registry (§13.2).

A profile is a *named behavior over the Bilateral Session Core* (§13.1). It is
registered **lightly** — AFP deliberately avoids a heavyweight, queryable,
marketplace-style directory (§13.2 rule 2; §8.8). A profile is defined by a small
declarative descriptor; two tenants recognize a profile by naming it in their
federation agreement.

This registry is the in-process set of descriptors (the reference profiles
published with the spec, §13.3, plus any a federation adds bilaterally). It
enforces:
  * unique ``{profile}`` label, valid name (§12.4 / §13.2 rule 1);
  * atom-kind discriminators do not collide with the core ``afp:*:v1`` kinds or
    another profile's (§13.2 rule 3);
  * a profile must be registered before its §12.4 subtree is used (rule 2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from .atoms import ANCHOR_KIND, COMMITMENT_KIND, ENVELOPE_KIND, SESSION_KIND
from .namespace import RESERVED_PROFILES, validate_profile_name
from .credential import CREDENTIAL_ENVELOPE_KIND

__all__ = ["ProfileError", "AfpProfileDescriptor", "ProfileRegistry", "default_registry"]

_CORE_KINDS = frozenset({SESSION_KIND, ENVELOPE_KIND, CREDENTIAL_ENVELOPE_KIND, COMMITMENT_KIND, ANCHOR_KIND})


class ProfileError(Exception):
    """A profile registration violated §13.2."""


@dataclass
class AfpProfileDescriptor:
    """An ``AfpProfileDescriptor`` (§13.2)."""

    name: str
    version: str
    spec_ref: str
    atom_kinds: List[str]
    policy_schema_ref: str
    status: str = "reference"  # reference | experimental | deprecated

    def __post_init__(self) -> None:
        validate_profile_name(self.name)
        if self.status not in ("reference", "experimental", "deprecated"):
            raise ProfileError(f"invalid profile status {self.status!r}")


class ProfileRegistry:
    """In-process profile registry (§13.2)."""

    def __init__(self) -> None:
        self._by_name: Dict[str, AfpProfileDescriptor] = {}
        self._claimed_kinds: Dict[str, str] = {}  # kind -> owning profile name

    def register(self, descriptor: AfpProfileDescriptor) -> None:
        name = descriptor.name
        if name in self._by_name:
            raise ProfileError(f"profile {name!r} is already registered (§13.2 rule 1)")
        for kind in descriptor.atom_kinds:
            if kind in _CORE_KINDS:
                raise ProfileError(
                    f"profile {name!r} atom kind {kind!r} collides with a core "
                    f"afp:*:v1 kind (§13.2 rule 3)"
                )
            owner = self._claimed_kinds.get(kind)
            if owner is not None and owner != name:
                raise ProfileError(
                    f"atom kind {kind!r} already claimed by profile {owner!r} "
                    f"(§13.2 rule 3)"
                )
        self._by_name[name] = descriptor
        for kind in descriptor.atom_kinds:
            self._claimed_kinds[kind] = name

    def is_registered(self, name: str) -> bool:
        # The reserved core/operational labels (session, work, telemetry) are
        # always recognized; reference profiles must be registered.
        return name in self._by_name or name in (RESERVED_PROFILES - {"prp", "vxp"})

    def get(self, name: str) -> AfpProfileDescriptor:
        if name not in self._by_name:
            raise ProfileError(f"profile {name!r} is not registered")
        return self._by_name[name]

    def names(self) -> List[str]:
        return sorted(self._by_name)


def default_registry() -> ProfileRegistry:
    """The profile set published with AFP (§13.3)."""
    reg = ProfileRegistry()
    reg.register(
        AfpProfileDescriptor(
            name="work",
            version="0.3.1",
            spec_ref="AFP §5 + §12",
            atom_kinds=[],  # work reuses the core afp:* kinds + §5.3 message classes
            policy_schema_ref="afp:agreement-policy:work:v1",
            status="reference",
        )
    )
    reg.register(
        AfpProfileDescriptor(
            name="prp",
            version="0.2",
            spec_ref="PRP v0.2",
            atom_kinds=[
                "prp:session:v2",
                "prp:comparison:v2",
                "prp:divergence:v2",
                "prp:evidence:v2",
                "prp:resolution:v2",
                "prp:commitment:v2",
                "prp:anchor:v2",
            ],
            policy_schema_ref="afp:agreement-policy:prp:v1",
            status="reference",
        )
    )
    reg.register(
        AfpProfileDescriptor(
            name="vxp",
            version="0.2",
            spec_ref="VXP v0.2",
            atom_kinds=[
                "vxp:intent:v1",
                "vxp:negotiation:v1",
                "vxp:commitment:v1",
                "vxp:fulfillment:v1",
                "vxp:settlement:v1",
                "vxp:dispute:v1",
                "vxp:channel:v1",
                "vxp:subscription:v1",
            ],
            policy_schema_ref="afp:agreement-policy:vxp:v1",
            status="reference",
        )
    )
    reg.register(
        AfpProfileDescriptor(
            name="pay",
            version="1.0",
            spec_ref="AFP 0.3.12-draft §15",
            atom_kinds=[
                "afp:payment-quote:v1",
                "afp:payment-receipt:v1",
            ],
            policy_schema_ref="afp:payment-policy:v1",
            status="experimental",
        )
    )
    reg.register(
        AfpProfileDescriptor(
            name="pay_venue",
            version="2.0",
            spec_ref="AFP 0.3.12-draft §15.9",
            atom_kinds=[
                "afp:payment-quote:v2",
                "afp:payment-receipt:v2",
            ],
            policy_schema_ref="afp:payment-policy:v2",
            status="experimental",
        )
    )
    return reg
