"""Domain exception hierarchy for the AFP attestation-authority key ceremony.

Every failure raised by :mod:`afp_ceremony` derives from :class:`CeremonyError`
so a caller can decline an interaction without having to enumerate causes. This
mirrors the failure discipline the specification itself imposes: an
authority-related failure routes to "decline this interaction and nothing more"
(§6.3.1), never to any mutation of tenant state.
"""

from __future__ import annotations

__all__ = [
    "CeremonyError",
    "StagingGuardError",
    "JcsError",
    "KeyStateError",
    "AuthorityTrustMaterialError",
    "ArtifactError",
]


class CeremonyError(Exception):
    """Base class for every ceremony-tooling failure."""


class StagingGuardError(CeremonyError):
    """A non-production guard refused the requested operation (see ``staging``)."""


class JcsError(CeremonyError):
    """A value cannot be canonicalized under RFC 8785 (see ``jcs``)."""


class KeyStateError(CeremonyError):
    """An ``afp:publisher-key-state:v1`` record is malformed or unresolvable (§6.3.1)."""


class AuthorityTrustMaterialError(CeremonyError):
    """Authority trust material failed verification (§6.3.1 acceptance conditions)."""


class ArtifactError(CeremonyError):
    """A ceremony artifact is malformed, or is missing its non-production markers."""
