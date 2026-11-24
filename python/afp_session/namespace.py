"""AFP NATS namespace ownership — ``afp.{tenant}.{profile}.*`` (§12.4).

**AFP owns the federation subject tree.** No profile defines a standalone
namespace. This module is the single place that constructs and validates AFP
subjects so the §12.4 normative rules are enforced in one spot:

  1. A profile's subjects MUST live under ``afp.{tenant}.{profile}.*`` and
     nowhere else; a bare ``vxp.*`` / ``prp.{org}.*`` is non-conforming.
  2. A profile name occupies exactly one ``{profile}`` label and MUST be
     registered (§13.2) before its subtree is used.
  3. The logical namespace's on-the-wire form is metadata-private (§8); that is
     the routing layer's concern (the in-memory transport here is for tests).

The reserved leaf families:
    afp.{tenant}.session.*    core session lifecycle (propose/accept/close/status)
    afp.{tenant}.work.*       base work-exchange (the §5.3 message classes)
    afp.{tenant}.prp.*        PRP profile subtree
    afp.{tenant}.vxp.*        VXP profile subtree
    afp.{tenant}.telemetry.*  tenant<->operator telemetry (§6.5)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .profiles import ProfileRegistry

__all__ = [
    "NamespaceError",
    "ROOT",
    "RESERVED_PROFILES",
    "subject",
    "session_subject",
    "parse_subject",
    "validate_profile_name",
    "validate_tenant_label",
    "is_conforming_subject",
]

ROOT = "afp"

# Profiles known to the core (§13.3) plus reserved operational leaves.
# 'session' and 'work' are core; 'prp'/'vxp' are reference profiles;
# 'telemetry' is operator-facing (§6.5), not a bilateral profile.
RESERVED_PROFILES = frozenset({"session", "work", "prp", "vxp", "telemetry"})
_IMPLICIT_PROFILES = RESERVED_PROFILES - {"prp", "vxp"}

# A profile label: lowercase, starts with a letter, alnum/underscore (§13.2).
_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_]*\Z")
# A tenant label is exactly one NATS token: no separator, no wildcard (§12.4).
_TENANT_RE = re.compile(r"^[A-Za-z0-9_:-]+\Z")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]+\Z")


class NamespaceError(Exception):
    """A subject violates the §12.4 namespace rules."""


def validate_profile_name(profile: str) -> None:
    """Validate a ``{profile}`` label (§13.2 rules)."""
    if type(profile) is not str or not _PROFILE_RE.match(profile):
        raise NamespaceError(
            f"profile name {profile!r} must be lowercase and match {_PROFILE_RE.pattern}"
        )


def validate_tenant_label(tenant: str) -> None:
    """Validate a ``{tenant}`` label: one non-empty token (§12.4)."""
    if type(tenant) is not str or not _TENANT_RE.match(tenant):
        raise NamespaceError(
            f"tenant label {tenant!r} must be one token matching {_TENANT_RE.pattern}"
        )


def subject(tenant: str, profile: str, *leaves: str, registered: bool) -> str:
    """Build a conforming ``afp.{tenant}.{profile}.<leaves...>`` subject.

    ``registered`` is the caller's profile-registry membership result for
    ``profile`` (§12.4 rule 2); there is deliberately no default. For the
    reserved core/operational labels registration is implicit.
    """
    validate_profile_name(profile)
    validate_tenant_label(tenant)
    if type(registered) is not bool:
        raise NamespaceError("registered must be a boolean profile-registry result")
    if profile not in _IMPLICIT_PROFILES and not registered:
        raise NamespaceError(
            f"profile {profile!r} must be registered (§13.2) before its subtree is used"
        )
    for leaf in leaves:
        if type(leaf) is not str or not _TOKEN_RE.match(leaf):
            raise NamespaceError(f"subject leaf {leaf!r} is not a valid token")
    parts = [ROOT, tenant, profile, *leaves]
    return ".".join(parts)


def session_subject(tenant: str, *leaves: str) -> str:
    """Build a core ``afp.{tenant}.session.*`` lifecycle subject (§12.4)."""
    return subject(tenant, "session", *leaves, registered=True)


def parse_subject(subj: str) -> dict:
    """Parse a subject into ``{root, tenant, profile, leaves}``; raise if non-conforming."""
    if type(subj) is not str:
        raise NamespaceError("subject must be a string")
    parts = subj.split(".")
    if len(parts) < 3 or parts[0] != ROOT:
        raise NamespaceError(
            f"subject {subj!r} is not under the AFP root tree {ROOT}.* (§12.4 rule 1)"
        )
    validate_tenant_label(parts[1])
    validate_profile_name(parts[2])
    for leaf in parts[3:]:
        if not _TOKEN_RE.match(leaf):
            raise NamespaceError(f"subject leaf {leaf!r} is not a valid token")
    return {
        "root": parts[0],
        "tenant": parts[1],
        "profile": parts[2],
        "leaves": parts[3:],
    }


def is_conforming_subject(
    subj: str, registry: Optional[ProfileRegistry] = None
) -> bool:
    """True iff ``subj`` is a conforming ``afp.{tenant}.{profile}.*`` subject.

    The profile must be registered in ``registry`` (§12.4 rule 2), which
    defaults to the published profile set. Core/operational labels are implicit.
    """
    try:
        parsed = parse_subject(subj)
    except NamespaceError:
        return False
    if registry is None:
        # profiles imports this module's validators; defer the reverse import.
        from .profiles import default_registry

        registry = default_registry()
    return registry.is_registered(parsed["profile"])
