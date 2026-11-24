"""AFP attestation-authority key-ceremony reference tooling (§4, §6.3.1).

Scope, stated up front because it is load-bearing: this package performs a
**non-production staging dry run only**. Pyramidal Inc.'s organizational root
AID has not been incepted — §6.3.1's non-normative note says so explicitly, and
"no AID value is asserted here or anywhere else in this specification" — and it
is neither created nor creatable by anything here. The production ceremony is an
air-gapped human event run under the published ceremony runbook and custody
policy; a dry run is not evidence that it happened.

Modules:

* :mod:`afp_ceremony.jcs` — RFC 8785 JSON Canonicalization, the preimage
  encoding §6.3.1 fixes for ``root_material_digest``.
* :mod:`afp_ceremony.keystate` — ``afp:publisher-key-state:v1`` and its digest,
  resolved from published KEL state alone.
* :mod:`afp_ceremony.authority` — ``afp:authority-trust-material:v1``: the
  out-of-band material a verifier accepts into its verification policy, pinning
  the witness set and threshold §6.3.1 requires. Deliberately **not**
  ``afp:witness-bootstrap:v1``, which is tenant-scoped; see that module.
* :mod:`afp_ceremony.ceremony` — org-root inception, delegated publisher
  inception, rotation, succession, and artifact emission/verification.
* :mod:`afp_ceremony.staging` — the guards that make staging material
  structurally unusable as production trust material.
* :mod:`afp_ceremony.conformance` — an honest proven/seam report.
"""

from __future__ import annotations

from .errors import (
    ArtifactError,
    AuthorityTrustMaterialError,
    CeremonyError,
    JcsError,
    KeyStateError,
    StagingGuardError,
)
from .jcs import jcs_bytes, jcs_string
from .keystate import (
    PUBLISHER_KEY_STATE_KIND,
    SUBSET_SIGNING_THRESHOLD,
    AfpPublisherKeyState,
    delegation_seal,
    establishment_event,
    find_delegation_anchor,
    find_rotation_anchor,
    kel_sequence_number,
    resolve_publisher_key_state,
    rotation_anchor_seal,
)
from .authority import (
    AUTHORITY_TRUST_MATERIAL_KIND,
    PUBLISHER_MANIFEST_ROOT_CLASS,
    SELF_ATTESTATION_CHARACTERIZATION,
    SIGNER_ACTIVE,
    SIGNER_REVOKED,
    SIGNER_SUPERSEDED,
    AfpAuthorityTrustMaterial,
    AnchoredSigner,
    PinnedWitness,
    accept_publisher_key_state,
    build_authority_trust_material,
    verify_authority_trust_material,
    verify_pinned_witness_threshold,
)
from .ceremony import (
    ARTIFACT_FILENAMES,
    CeremonyResult,
    StagedIdentity,
    anchor_rotation,
    incept_authority_root,
    incept_delegated_signer,
    kel_from_dict,
    kel_to_dict,
    load_ceremony_artifacts,
    make_staging_witnesses,
    rotate_identity,
    run_staging_ceremony,
    verify_ceremony_artifacts,
    write_ceremony_artifacts,
)
from .staging import (
    MARKER_FIELDS,
    PUBLISHED_STAGING_SEED_PHRASE,
    STAGING_AUTHORITY_LABEL,
    STAGING_ENCODING,
    STAGING_ENDPOINT_SUFFIX,
    STAGING_ENVIRONMENT,
    derive_staging_material,
    enforce_not_production,
    require_staging,
    staging_endpoint,
    staging_markers,
    stamp_not_production,
)
from .conformance import (
    CeremonyConformance,
    PropertyResult,
    PropertyStatus,
    assess_ceremony,
)

__all__ = [
    # errors
    "CeremonyError",
    "StagingGuardError",
    "JcsError",
    "KeyStateError",
    "AuthorityTrustMaterialError",
    "ArtifactError",
    # canonicalization
    "jcs_bytes",
    "jcs_string",
    # publisher key state
    "PUBLISHER_KEY_STATE_KIND",
    "SUBSET_SIGNING_THRESHOLD",
    "AfpPublisherKeyState",
    "resolve_publisher_key_state",
    "delegation_seal",
    "find_delegation_anchor",
    "rotation_anchor_seal",
    "find_rotation_anchor",
    "establishment_event",
    "kel_sequence_number",
    # authority trust material
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
    # ceremony
    "ARTIFACT_FILENAMES",
    "StagedIdentity",
    "CeremonyResult",
    "make_staging_witnesses",
    "incept_authority_root",
    "incept_delegated_signer",
    "rotate_identity",
    "anchor_rotation",
    "run_staging_ceremony",
    "kel_to_dict",
    "kel_from_dict",
    "write_ceremony_artifacts",
    "load_ceremony_artifacts",
    "verify_ceremony_artifacts",
    # staging guards
    "MARKER_FIELDS",
    "STAGING_ENVIRONMENT",
    "STAGING_ENCODING",
    "STAGING_ENDPOINT_SUFFIX",
    "STAGING_AUTHORITY_LABEL",
    "PUBLISHED_STAGING_SEED_PHRASE",
    "require_staging",
    "staging_markers",
    "stamp_not_production",
    "enforce_not_production",
    "derive_staging_material",
    "staging_endpoint",
    # conformance
    "PropertyStatus",
    "PropertyResult",
    "CeremonyConformance",
    "assess_ceremony",
]
