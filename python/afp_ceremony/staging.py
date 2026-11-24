"""Non-production guards for the AFP attestation-authority key ceremony.

Pyramidal Inc.'s organizational root AID **has not been incepted** (§6.3.1, the
non-normative note: "no AID value is asserted here or anywhere else in this
specification"). This package therefore ships a *staging dry run only*. The
production ceremony is a human, air-gapped event; nothing in this repository
performs it and nothing here may be mistaken for having performed it.

The hazard is concrete. §6.3.1 makes the authority's material load-bearing: a
verifier that accepted staging material into its verification policy would
resolve a delegation chain to a staging root and accept forged attributions from
anyone who read this repository — the published seed below is literally public.
Five independent, non-overlapping markers make that mistake structurally loud
rather than silent, so no single slip promotes staging material:

1. **Opt-in is mandatory.** :func:`require_staging` refuses unless the caller
   passes an explicit staging flag, and refuses outright when the ``CI``
   environment variable is set, so the *executable* never generates key material
   on a runner. (The library's staging ceremony **is** exercised by the reference
   test suite in CI — see marker 3 for why that is harmless. The separate
   production-ceremony procedure makes the same executable/library distinction.)
2. **In-band markers, enforced on construction and on load.** Every artifact
   carries ``environment``/``not_production``/``encoding``/``derivation_seed``
   values; :func:`enforce_not_production` *rejects* an artifact missing or
   contradicting them, so the marker is a gate rather than a comment. Signed
   records enforce it in ``__post_init__`` as well, because a signature over
   false markers would make a mismarked record look *more* credible, not less —
   the check has to bite before anything can be signed, not only when something
   is read back.
3. **Worthless material by construction.** Every staging secret derives from
   :data:`PUBLISHED_STAGING_SEED_PHRASE`, an ASCII phrase committed in this
   file. Material anyone can regenerate has zero trust value — a stronger
   guarantee than any label.
4. **Nothing resolves.** Every endpoint is under the RFC 2606 ``.invalid``
   top-level domain, so an operational mistake fails to connect instead of
   quietly working.
5. **Structurally not KERI.** Identifiers are ``afp_session.canonical.qb64``'s
   readable ``<code>_<hex>`` form, not CESR/qb64, so a staging AID cannot be
   pasted into a real KERI tool at all (see :mod:`afp_ceremony.conformance`).

The default ceremony output directories are additionally ``.gitignore``d, and
``scripts/run_key_ceremony.py`` refuses an ``--out`` destination inside this
repository that git does not ignore — so a local run cannot be committed by
accident, which ``.gitignore`` alone would not deliver for an arbitrary path.
"""

from __future__ import annotations

import functools
import hmac
import hashlib
import os
from typing import Any, Mapping, MutableMapping, Optional

from afp_session import keri

from .errors import ArtifactError, StagingGuardError

__all__ = [
    "STAGING_ENVIRONMENT",
    "STAGING_ENCODING",
    "PUBLISHED_STAGING_SEED_PHRASE",
    "STAGING_ENDPOINT_SUFFIX",
    "STAGING_AUTHORITY_LABEL",
    "MARKER_FIELDS",
    "require_staging",
    "staging_markers",
    "stamp_not_production",
    "enforce_not_production",
    "derive_staging_material",
    "staging_endpoint",
]

#: In-band environment marker present on every emitted artifact.
STAGING_ENVIRONMENT = "staging-non-production"

#: In-band encoding marker. The reference KERI subset emits AFP's readable
#: ``<code>_<hex>`` identifiers, never CESR/qb64 (``afp_session.canonical.qb64``).
STAGING_ENCODING = "afp-reference-readable-not-cesr"

#: The staging derivation phrase, published here on purpose. Every staging
#: private seed is ``HMAC-SHA256(phrase, label)``, so all staging secrets are
#: public and worthless. Never use this for anything but the dry run.
PUBLISHED_STAGING_SEED_PHRASE = (
    "AFP-STAGING-CEREMONY-DERIVATION-PHRASE-PUBLISHED-NOT-SECRET-v1"
)

#: RFC 2606 reserved TLD: staging endpoints are guaranteed not to resolve.
STAGING_ENDPOINT_SUFFIX = "staging.afp-ceremony.invalid"

#: Reserved placeholder standing in for the organizational root AID. Pyramidal
#: Inc.'s real root AID does not exist and is not asserted anywhere.
STAGING_AUTHORITY_LABEL = "staging-placeholder-authority-not-pyramidal-inc"

#: The marker fields :func:`enforce_not_production` requires, with their only
#: acceptable values.
MARKER_FIELDS: Mapping[str, Any] = {
    "environment": STAGING_ENVIRONMENT,
    "not_production": True,
    "encoding": STAGING_ENCODING,
    "derivation_seed": PUBLISHED_STAGING_SEED_PHRASE,
}


def require_staging(
    *,
    staging: bool,
    env: Optional[Mapping[str, str]] = None,
    operation: str = "key ceremony",
) -> None:
    """Refuse anything that is not an explicitly-requested staging dry run.

    Two refusals, both unconditional:

    * ``staging`` must be ``True``. There is no production code path here; the
      production ceremony is an air-gapped human event carried out under the
      published runbook, and this tooling must never be the thing that performs
      it.
    * ``CI`` must be unset. Continuous integration is a shared, logged, network
      -attached environment; generating authority key material there is
      forbidden regardless of the ``staging`` flag.

    ``env`` defaults to :data:`os.environ` and exists so tests can exercise both
    branches without mutating process state.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    if not staging:
        raise StagingGuardError(
            f"refusing to run the {operation} without an explicit --staging flag: "
            "this tooling performs a NON-PRODUCTION dry run only. Pyramidal Inc.'s "
            "organizational root AID has not been incepted and MUST NOT be incepted "
            "here; the production ceremony runs air-gapped under the published "
            "ceremony runbook and custody policy."
        )
    ci_value = environ.get("CI")
    if ci_value is not None and ci_value.strip() != "":
        raise StagingGuardError(
            f"refusing to run the {operation} with CI={ci_value!r} set: this "
            "executable never generates key material in continuous integration. "
            "(The library's staging ceremony IS exercised by the reference test "
            "suite on a runner; every seed it uses derives from the phrase "
            "published in this file, so that material is worthless by "
            "construction. This guard exists so nobody can point the *tool* at a "
            "ceremony from a shared, logged, network-attached environment.)"
        )


def staging_markers() -> dict:
    """Return a fresh copy of the mandatory in-band non-production markers."""
    return dict(MARKER_FIELDS)


def stamp_not_production(record: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """Stamp ``record`` in place with the non-production markers and return it."""
    record.update(staging_markers())
    return record


def enforce_not_production(record: Any, *, what: str = "artifact") -> None:
    """Reject an artifact that is not marked non-production.

    This is the *enforcement* half of marker (2): a loader calls it before
    handing an artifact to any other code, so an unmarked or mismarked artifact
    never reaches verification at all. A marker that is merely documented is not
    a control; a marker that fails the load is.
    """
    if not isinstance(record, dict):
        raise ArtifactError(f"{what} must be a JSON object")
    for name, expected in MARKER_FIELDS.items():
        if name not in record:
            raise ArtifactError(
                f"{what} is missing the mandatory non-production marker {name!r}; "
                "this loader refuses artifacts that are not self-evidently staging"
            )
        actual = record[name]
        # ``not_production`` is a JSON boolean: 1 must not pass for True.
        if isinstance(expected, bool):
            if actual is not expected:
                raise ArtifactError(
                    f"{what} marker {name!r} is {actual!r}, expected {expected!r}"
                )
        elif actual != expected:
            raise ArtifactError(
                f"{what} marker {name!r} is {actual!r}, expected {expected!r}"
            )


@functools.lru_cache(maxsize=None)
def derive_staging_material(label: str) -> keri.KeyPair:
    """Derive a deterministic, **publicly reproducible** staging Ed25519 keypair.

    ``seed = HMAC-SHA256(PUBLISHED_STAGING_SEED_PHRASE, label)``. The signatures
    it produces are real RFC 8032 Ed25519 (``afp_session.ed25519``); the secret
    is not secret. That is the point: staging material carries no trust because
    anyone reading this file can recreate it.

    Memoized: the function is pure and deterministic, and pure-Python Ed25519
    key derivation is slow enough to matter to the reference suite's CI budget.
    """
    if not isinstance(label, str) or not label:
        raise StagingGuardError("staging derivation label must be a non-empty string")
    seed = hmac.new(
        PUBLISHED_STAGING_SEED_PHRASE.encode("utf-8"),
        label.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return keri.KeyPair.from_seed(seed)


def staging_endpoint(name: str) -> str:
    """Return a guaranteed-unresolvable staging endpoint under ``.invalid``."""
    if not isinstance(name, str) or not name:
        raise StagingGuardError("staging endpoint name must be a non-empty string")
    return f"https://{name}.{STAGING_ENDPOINT_SUFFIX}/kel-receipts"
