"""Shared fixtures for the AFP key-ceremony test suite.

The staging ceremony is genuinely expensive: every KEL event is receipted by a
real pure-Python Ed25519 signature from every witness, and every resolution
re-verifies them. A 3-of-5 run costs roughly ten seconds, so the whole suite
shares **one** ceremony, built lazily on first use and cached for the process.
Tests that need to mutate state work on the artifacts or on cheap purpose-built
KELs instead of re-running the ceremony.
"""

import _path  # noqa: F401  (path setup)

from typing import Optional, Tuple

from afp_session import keri
from afp_ceremony import ceremony

_CEREMONY: Optional[ceremony.CeremonyResult] = None

#: Kept small on purpose: §4.5 witness thresholds are what this exercises, and a
#: 3-of-5 set proves the threshold rule without scaling the CI signature budget.
WITNESS_COUNT = 5
WITNESS_THRESHOLD = 3


def staging_ceremony() -> ceremony.CeremonyResult:
    """The process-wide staging ceremony (built once, then cached)."""
    global _CEREMONY
    if _CEREMONY is None:
        _CEREMONY = ceremony.run_staging_ceremony(
            witness_count=WITNESS_COUNT, threshold=WITNESS_THRESHOLD
        )
    return _CEREMONY


def minimal_authority(
    witness_count: int = 2, threshold: int = 2
) -> Tuple[
    ceremony.StagedIdentity,
    ceremony.StagedIdentity,
    str,
    Tuple[keri.Witness, ...],
]:
    """A cheap authority + delegated signer pair, for negative-path tests."""
    witnesses = ceremony.make_staging_witnesses(witness_count)
    authority = ceremony.incept_authority_root(
        label="probe-authority", witnesses=witnesses, threshold=threshold
    )
    signer, anchor = ceremony.incept_delegated_signer(authority, label="probe-signer")
    return authority, signer, anchor, witnesses
