"""AFP framing and fail-closed acceptance for canonical ZKA/Coord v2 proofs.

ZKA owns the proof, receipt, and artifact semantics.  This module deliberately
does not reimplement Poseidon folds or attempt to decode witnesses: it accepts
only the published public wire form, binds it to an authenticated AFP session,
and delegates cryptographic verification to a deployment-bound ZKA verifier.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Callable, Mapping, Protocol
import re
from types import MappingProxyType

from .canonical import canonical_json, digest, qb64
from .kdc import BN254_SCALAR_MODULUS

__all__ = [
    "COORD_V2_RECEIPT",
    "COORD_V2_RECEIPT_KIND",
    "COORD_ACCEPTANCE_POLICY",
    "COORD_COMPLETION_MESSAGE_CLASS",
    "COORD_RECURSIVE_ARTIFACT_ROLE",
    "COORD_RECURSIVE_CIRCUIT",
    "COORD_RECURSIVE_VERIFICATION_KEY_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH",
    "COORD_PRIVATE_RECONCILIATION_PROFILE_BINDING",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH",
    "COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_BINDING",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH",
    "COORD_VXP_RECIPROCAL_ACK_PROFILE_BINDING",
    "BN254_ZERO_FIELD",
    "CoordAssurance",
    "CoordFailureCode",
    "CoordVerificationError",
    "CoordVerifierRejected",
    "CoordVerifierUnavailable",
    "CoordProfileBinding",
    "CoordArtifactBinding",
    "CoordAcceptancePolicy",
    "CoordFinalProof",
    "CoordEvidenceReference",
    "CoordVerifierResult",
    "CoordVerifierRequest",
    "CoordVerificationReport",
    "CoordFinalProofVerifier",
    "CoordCompletionVerificationContext",
    "CoordCompletionRecord",
    "CoordRecordResult",
    "CoordCompletionStore",
    "InMemoryCoordCompletionStore",
    "SqliteCoordCompletionStore",
    "CoordCompletion",
    "derive_coord_context",
]


COORD_V2_RECEIPT = "zka:coord:receipt:v2"
"""Canonical ZKA/Coord receipt ABI identifier."""
COORD_V2_RECEIPT_KIND = COORD_V2_RECEIPT
COORD_ACCEPTANCE_POLICY = "afp:coord-acceptance-policy:v1"
COORD_COMPLETION_MESSAGE_CLASS = "result"
COORD_RECURSIVE_ARTIFACT_ROLE = "0x" + "00" * 31 + "02"
COORD_RECURSIVE_CIRCUIT = "zka_coordination_v2_recursive"
COORD_RECURSIVE_VERIFICATION_KEY_HASH = (
    "0x2e72267c8a0c8750a5cfe2e2893ec689ae9b4a488938ac084aeff1b470d055a2"
)

BN254_ZERO_FIELD = "0x" + "00" * 32

# These identifiers are byte-folded by ZKA and intentionally fixed here; AFP
# compares the resulting public field rather than trying to recreate a ZKA fold.
COORD_PRIVATE_RECONCILIATION_PROFILE = "zka:coord:private-reconciliation:v1"
COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD = (
    "0x147446fe0f34833135f89bc9d7aa756cb778f8e8fbd77e570996ff1a8df752e1"
)
COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH = (
    "0x00502511877b0c7502792ccc35e841e36d067ba98925728253bc66ccb1082768"
)
COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH = (
    "0x0bd66b2eb5d199726ef90f307069782beae1afe6d9a7488ec2c1e251d7b78f63"
)
COORD_PRIVATE_RECONCILIATION_PROFILE_BINDING = (
    COORD_PRIVATE_RECONCILIATION_PROFILE,
    COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD,
)
COORD_VXP_RECIPROCAL_COMPUTE_PROFILE = "zka:coord:vxp-reciprocal-compute:v1"
COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD = (
    "0x1aba8f8267027cdbd3e5ac25dc6767ffaf379e08541452dd1ea6b7a6f9710607"
)
COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH = (
    "0x21b14f3d82f54bfef2ae81ca254081bf0e94dd6ae7c0d7ca7a42684ef3d5a61c"
)
COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH = (
    "0x2073432bf50f20e8cd5127a9734419ff866ce08e0d2b6a7b8a09e6491e425319"
)
COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_BINDING = (
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE,
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD,
)
COORD_VXP_RECIPROCAL_ACK_PROFILE = "zka:coord:vxp-reciprocal-ack:v1"
COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD = (
    "0x23087cc4ad08d9dbc80318a7e7eb8df9618112319bca1c10f93fcd37073ebc6d"
)
COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH = (
    "0x2b622e9a71c5e351bfef8d54e970084c483f7f1c158fe893296cdbaa117f2f1d"
)
COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH = (
    "0x1bce6effb5f61fce0f27a7257ff301b67538699e675d0c6617da014d6cbf29dd"
)
COORD_VXP_RECIPROCAL_ACK_PROFILE_BINDING = (
    COORD_VXP_RECIPROCAL_ACK_PROFILE,
    COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD,
)

_FIELD_RE = re.compile(r"0x[0-9a-f]{64}\Z")
_X_CONTEXT_RE = re.compile(r"X_[0-9a-f]{64}\Z")
_TARGETS = frozenset({"offchain", "evm", "aztec"})
_RECEIPT_KEYS = frozenset(
    {
        "protocolVersion", "workflowDefinitionHash", "workflowInstanceId", "context",
        "initialStateCommitment", "profileId", "profileVersion", "profileManifestHash",
        "profileVkHash", "verifierPolicyRoot", "assuranceClass", "stepId", "stepIndex",
        "predecessorCount", "predecessorStepIds", "inputCommitments", "inputSetCommitment",
        "preStateCommitment", "outputCommitment", "postStateCommitment",
        "externalFactCommitment", "dataAvailabilityCommitment", "topologyCommitment",
        "receiptCommitment", "graphCommitment", "proofNodeCount", "maxDepth",
    }
)
_ARTIFACT_KEYS = frozenset(
    {"role", "circuitId", "artifactEntryHash", "schemaHash", "target", "verificationKeyHash"}
)
_PROFILE_BINDING_KEYS = frozenset(
    {"profileVersion", "profileManifestHash", "profileVkHash", "assuranceClass"}
)
_POLICY_KEYS = frozenset(
    {
        "kind", "receiptKind", "afpProfile", "profileId", "profileIdField",
        "workflowDefinitionHash", "workflowInstanceId", "completionStepId",
        "verifierPolicyRoot", "acceptedProfileBindings", "acceptedArtifacts",
        "requireDataAvailability", "requireExternalFacts",
        "expectedInitialStateCommitment", "expectedOutputCommitment",
        "expectedPostStateCommitment",
    }
)
_FORBIDDEN_PRIVATE_KEY_PARTS = (
    "witness", "private", "proving", "plaintext", "delivery", "secret", "nonce",
)


class CoordAssurance(str, Enum):
    """ZKA wire assurance labels; values are never translated in transit."""

    ZK_NATIVE = "zkNative"
    PROOF_PRODUCING_EXTERNAL = "proofProducingExternal"
    ATTESTED = "attested"


_PROFILE_REQUIREMENTS = {
    COORD_PRIVATE_RECONCILIATION_PROFILE_BINDING: (
        "prp",
        CoordAssurance.ZK_NATIVE,
        True,
        False,
        1,
        COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH,
        COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH,
        "initiator",
    ),
    COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_BINDING: (
        "vxp",
        CoordAssurance.ZK_NATIVE,
        True,
        False,
        1,
        COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH,
        COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH,
        "initiator",
    ),
    COORD_VXP_RECIPROCAL_ACK_PROFILE_BINDING: (
        "vxp",
        CoordAssurance.ATTESTED,
        False,
        True,
        1,
        COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH,
        COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH,
        "responder",
    ),
}


class CoordFailureCode(str, Enum):
    """Stable public diagnostic codes (never a witness or backend message)."""

    VERSION = "COORD_V2_VERSION"
    IDENTIFIER = "COORD_V2_IDENTIFIER"
    PREDECESSOR_COUNT = "COORD_V2_PREDECESSOR_COUNT"
    INACTIVE_SLOT = "COORD_V2_INACTIVE_SLOT"
    ASSURANCE = "COORD_V2_ASSURANCE"
    PROFILE_POLICY = "COORD_V2_PROFILE_POLICY"
    ARTIFACT = "COORD_V2_ARTIFACT"
    APPLICATION_PROOF = "COORD_V2_APPLICATION_PROOF"
    SCOPE = "COORD_V2_SCOPE"
    INCOMPLETE_WORKFLOW = "COORD_V2_INCOMPLETE_WORKFLOW"
    DATA_UNAVAILABLE = "COORD_V2_DATA_UNAVAILABLE"
    REPLAY = "COORD_V2_REPLAY"
    MALFORMED = "COORD_V2_MALFORMED"
    VERIFIER_FAILURE = "COORD_V2_VERIFIER_FAILURE"
    IDENTITY = "AFP_COORD_IDENTITY"
    SESSION_CONTEXT = "AFP_COORD_SESSION_CONTEXT"


_VERIFIER_REJECTION_CODES = frozenset(
    {
        CoordFailureCode.VERSION,
        CoordFailureCode.IDENTIFIER,
        CoordFailureCode.PREDECESSOR_COUNT,
        CoordFailureCode.INACTIVE_SLOT,
        CoordFailureCode.ASSURANCE,
        CoordFailureCode.PROFILE_POLICY,
        CoordFailureCode.ARTIFACT,
        CoordFailureCode.APPLICATION_PROOF,
        CoordFailureCode.SCOPE,
        CoordFailureCode.INCOMPLETE_WORKFLOW,
    }
)


class CoordVerificationError(ValueError):
    """A redacted Coord acceptance failure."""

    def __init__(self, code: CoordFailureCode, *, retryable: bool = False) -> None:
        self.code = code
        self.retryable = code is CoordFailureCode.DATA_UNAVAILABLE
        super().__init__(code.value)

    def __str__(self) -> str:
        return self.code.value


class CoordVerifierRejected(Exception):
    """Allowlisted terminal ZKA rejection from the configured verifier."""

    def __init__(self, code: CoordFailureCode) -> None:
        if not isinstance(code, CoordFailureCode) or code not in _VERIFIER_REJECTION_CODES:
            raise ValueError("unsupported Coord verifier rejection code")
        self.code = code
        super().__init__(code.value)

    def __str__(self) -> str:
        return self.code.value


class CoordVerifierUnavailable(Exception):
    """Typed temporary outage signal accepted only from the configured verifier."""

    def __init__(self) -> None:
        super().__init__("configured Coord verifier is temporarily unavailable")


def _fail(code: CoordFailureCode, *, retryable: bool = False) -> None:
    raise CoordVerificationError(code, retryable=retryable) from None


def _fail_verifier_rejection(error: CoordVerifierRejected) -> None:
    code = getattr(error, "code", None)
    if not isinstance(code, CoordFailureCode) or code not in _VERIFIER_REJECTION_CODES:
        _fail(CoordFailureCode.VERIFIER_FAILURE)
    _fail(code)


def _field(value: object, name: str, *, zero: bool = False) -> str:
    if not isinstance(value, str) or _FIELD_RE.fullmatch(value) is None:
        _fail(CoordFailureCode.MALFORMED)
    parsed = int(value[2:], 16)
    if parsed >= BN254_SCALAR_MODULUS or (not zero and parsed == 0):
        _fail(CoordFailureCode.IDENTIFIER)
    return value


def _nonempty(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail(CoordFailureCode.MALFORMED)
    return value


def derive_coord_context(session_context: str) -> str:
    """Reduce the exact AFP ``X_`` context payload into nonzero BN254 Fr."""
    if not isinstance(session_context, str) or _X_CONTEXT_RE.fullmatch(session_context) is None:
        _fail(CoordFailureCode.IDENTIFIER)
    value = int(session_context[2:], 16) % BN254_SCALAR_MODULUS
    if value == 0:
        _fail(CoordFailureCode.IDENTIFIER)
    return f"0x{value:064x}"


@dataclass(frozen=True)
class CoordProfileBinding:
    """Exact immutable application-profile coordinates accepted by a policy."""

    profile_version: int
    manifest_hash: str
    verification_key_hash: str
    assurance: CoordAssurance

    def __post_init__(self) -> None:
        if type(self.profile_version) is not int or not 1 <= self.profile_version <= 2**32 - 1:
            _fail(CoordFailureCode.PROFILE_POLICY)
        _field(self.manifest_hash, "profile manifest hash")
        _field(self.verification_key_hash, "profile verification-key hash")
        if not isinstance(self.assurance, CoordAssurance):
            _fail(CoordFailureCode.ASSURANCE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profileVersion": self.profile_version,
            "profileManifestHash": self.manifest_hash,
            "profileVkHash": self.verification_key_hash,
            "assuranceClass": self.assurance.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CoordProfileBinding":
        if not isinstance(value, Mapping) or set(value) != _PROFILE_BINDING_KEYS:
            _fail(CoordFailureCode.PROFILE_POLICY)
        try:
            assurance = CoordAssurance(value["assuranceClass"])
        except (TypeError, ValueError):
            _fail(CoordFailureCode.ASSURANCE)
        return cls(
            profile_version=value["profileVersion"],
            manifest_hash=value["profileManifestHash"],
            verification_key_hash=value["profileVkHash"],
            assurance=assurance,
        )


@dataclass(frozen=True)
class CoordArtifactBinding:
    """Exact ZKA recursive-verifier artifact coordinates accepted by a policy."""

    role: str
    circuit_id: str
    artifact_entry_hash: str
    schema_hash: str
    target: str
    verification_key_hash: str

    def __post_init__(self) -> None:
        _field(self.role, "artifact role")
        _nonempty(self.circuit_id)
        for value in (
            self.artifact_entry_hash,
            self.schema_hash,
            self.verification_key_hash,
        ):
            _field(value, "artifact hash")
        if self.target not in _TARGETS:
            _fail(CoordFailureCode.ARTIFACT)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CoordArtifactBinding":
        if not isinstance(value, Mapping) or set(value) != _ARTIFACT_KEYS:
            _fail(CoordFailureCode.MALFORMED)
        return cls(
            role=value["role"],
            circuit_id=value["circuitId"],
            artifact_entry_hash=value["artifactEntryHash"],
            schema_hash=value["schemaHash"],
            target=value["target"],
            verification_key_hash=value["verificationKeyHash"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "circuitId": self.circuit_id,
            "artifactEntryHash": self.artifact_entry_hash,
            "schemaHash": self.schema_hash,
            "target": self.target,
            "verificationKeyHash": self.verification_key_hash,
        }

def _canonical_bindings(values: object, expected_type: type) -> tuple[Any, ...]:
    if not isinstance(values, (tuple, list)) or not values:
        _fail(CoordFailureCode.PROFILE_POLICY)
    result = tuple(values)
    if any(not isinstance(value, expected_type) for value in result):
        _fail(CoordFailureCode.PROFILE_POLICY)
    encodings = tuple(canonical_json(value.to_dict()) for value in result)
    if encodings != tuple(sorted(encodings)) or len(set(encodings)) != len(encodings):
        _fail(CoordFailureCode.PROFILE_POLICY)
    return result


@dataclass(frozen=True)
class CoordAcceptancePolicy:
    """AFP's public acceptance contract for one Coord completion."""

    afp_profile: str
    profile_id: str
    profile_id_field: str
    workflow_definition_hash: str
    workflow_instance_id: str
    completion_step_id: str
    verifier_policy_root: str
    accepted_profile_bindings: tuple[CoordProfileBinding, ...]
    accepted_artifacts: tuple[CoordArtifactBinding, ...]
    require_data_availability: bool
    require_external_facts: bool
    expected_initial_state_commitment: str
    expected_output_commitment: str
    expected_post_state_commitment: str
    kind: str = COORD_ACCEPTANCE_POLICY
    receipt_kind: str = COORD_V2_RECEIPT

    def __post_init__(self) -> None:
        if self.kind != COORD_ACCEPTANCE_POLICY or self.receipt_kind != COORD_V2_RECEIPT:
            _fail(CoordFailureCode.PROFILE_POLICY)
        _nonempty(self.afp_profile)
        _nonempty(self.profile_id)
        for value in (
            self.profile_id_field, self.workflow_definition_hash, self.workflow_instance_id,
            self.completion_step_id, self.verifier_policy_root,
            self.expected_initial_state_commitment, self.expected_output_commitment,
            self.expected_post_state_commitment,
        ):
            _field(value, "policy field")
        profile_key = (self.profile_id, self.profile_id_field)
        requirements = _PROFILE_REQUIREMENTS.get(profile_key)
        if requirements is None:
            _fail(CoordFailureCode.PROFILE_POLICY)
        (
            required_afp_profile,
            required_assurance,
            required_da,
            required_external,
            required_version,
            required_manifest,
            required_vk,
            _required_sender_role,
        ) = requirements
        if (
            self.afp_profile != required_afp_profile
            or self.require_data_availability is not required_da
            or self.require_external_facts is not required_external
        ):
            _fail(CoordFailureCode.PROFILE_POLICY)
        profiles = _canonical_bindings(self.accepted_profile_bindings, CoordProfileBinding)
        if any(binding.assurance is not required_assurance for binding in profiles):
            _fail(CoordFailureCode.ASSURANCE)
        expected_profile = CoordProfileBinding(
            profile_version=required_version,
            manifest_hash=required_manifest,
            verification_key_hash=required_vk,
            assurance=required_assurance,
        )
        if profiles != (expected_profile,):
            _fail(CoordFailureCode.PROFILE_POLICY)
        object.__setattr__(self, "accepted_profile_bindings", profiles)
        artifacts = _canonical_bindings(self.accepted_artifacts, CoordArtifactBinding)
        if any(
            binding.role != COORD_RECURSIVE_ARTIFACT_ROLE
            or binding.circuit_id != COORD_RECURSIVE_CIRCUIT
            or binding.verification_key_hash
            != COORD_RECURSIVE_VERIFICATION_KEY_HASH
            for binding in artifacts
        ):
            _fail(CoordFailureCode.ARTIFACT)
        object.__setattr__(self, "accepted_artifacts", artifacts)
        if type(self.require_data_availability) is not bool or type(self.require_external_facts) is not bool:
            _fail(CoordFailureCode.MALFORMED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "receiptKind": self.receipt_kind,
            "afpProfile": self.afp_profile,
            "profileId": self.profile_id,
            "profileIdField": self.profile_id_field,
            "workflowDefinitionHash": self.workflow_definition_hash,
            "workflowInstanceId": self.workflow_instance_id,
            "completionStepId": self.completion_step_id,
            "verifierPolicyRoot": self.verifier_policy_root,
            "acceptedProfileBindings": [value.to_dict() for value in self.accepted_profile_bindings],
            "acceptedArtifacts": [value.to_dict() for value in self.accepted_artifacts],
            "requireDataAvailability": self.require_data_availability,
            "requireExternalFacts": self.require_external_facts,
            "expectedInitialStateCommitment": self.expected_initial_state_commitment,
            "expectedOutputCommitment": self.expected_output_commitment,
            "expectedPostStateCommitment": self.expected_post_state_commitment,
        }

    @property
    def policy_hash(self) -> str:
        return qb64("D", digest(self.to_dict()))

    @property
    def content_hash(self) -> str:
        """Alias used by AFP's signed ``profile_policy_hash`` session field."""
        return self.policy_hash

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CoordAcceptancePolicy":
        """Parse the exact canonical policy object committed by an AFP session."""
        if not isinstance(value, Mapping) or set(value) != _POLICY_KEYS:
            _fail(CoordFailureCode.PROFILE_POLICY)
        profiles = value["acceptedProfileBindings"]
        artifacts = value["acceptedArtifacts"]
        if not isinstance(profiles, list) or not isinstance(artifacts, list):
            _fail(CoordFailureCode.PROFILE_POLICY)
        return cls(
            afp_profile=value["afpProfile"],
            profile_id=value["profileId"],
            profile_id_field=value["profileIdField"],
            workflow_definition_hash=value["workflowDefinitionHash"],
            workflow_instance_id=value["workflowInstanceId"],
            completion_step_id=value["completionStepId"],
            verifier_policy_root=value["verifierPolicyRoot"],
            accepted_profile_bindings=tuple(
                CoordProfileBinding.from_dict(item) for item in profiles
            ),
            accepted_artifacts=tuple(
                CoordArtifactBinding.from_dict(item) for item in artifacts
            ),
            require_data_availability=value["requireDataAvailability"],
            require_external_facts=value["requireExternalFacts"],
            expected_initial_state_commitment=value["expectedInitialStateCommitment"],
            expected_output_commitment=value["expectedOutputCommitment"],
            expected_post_state_commitment=value["expectedPostStateCommitment"],
            kind=value["kind"],
            receipt_kind=value["receiptKind"],
        )


def _reject_private(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or any(part in key.lower() for part in _FORBIDDEN_PRIVATE_KEY_PARTS):
                _fail(CoordFailureCode.MALFORMED)
            _reject_private(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_private(nested)


def _exact_object(value: object, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(CoordFailureCode.MALFORMED)
    return value


def _receipt(value: object) -> dict[str, Any]:
    receipt = _exact_object(value, _RECEIPT_KEYS)
    if type(receipt["protocolVersion"]) is not int or receipt["protocolVersion"] != 2:
        _fail(CoordFailureCode.VERSION)
    field_names = (
        "workflowDefinitionHash", "workflowInstanceId", "context", "initialStateCommitment",
        "profileId", "profileManifestHash", "profileVkHash", "verifierPolicyRoot", "stepId",
        "inputSetCommitment", "preStateCommitment", "outputCommitment", "postStateCommitment",
        "externalFactCommitment", "dataAvailabilityCommitment", "topologyCommitment",
        "receiptCommitment", "graphCommitment",
    )
    for key in field_names:
        _field(receipt[key], key, zero=True)
    for key in ("predecessorStepIds", "inputCommitments"):
        values = receipt[key]
        if not isinstance(values, list) or len(values) != 4:
            _fail(CoordFailureCode.MALFORMED)
        for item in values:
            _field(item, key, zero=True)
    assurance = receipt["assuranceClass"]
    try:
        CoordAssurance(assurance)
    except (TypeError, ValueError):
        _fail(CoordFailureCode.ASSURANCE)
    for key, lower, upper in (
        ("profileVersion", 0, 2**32 - 1), ("stepIndex", 0, 2**32 - 2),
        ("predecessorCount", 0, 4), ("proofNodeCount", 1, 4096), ("maxDepth", 1, 32),
    ):
        if type(receipt[key]) is not int or not lower <= receipt[key] <= upper:
            _fail(CoordFailureCode.MALFORMED)
    count = receipt["predecessorCount"]
    if any(value != BN254_ZERO_FIELD for value in receipt["predecessorStepIds"][count:]) or any(
        value != BN254_ZERO_FIELD for value in receipt["inputCommitments"][count:]
    ):
        _fail(CoordFailureCode.INACTIVE_SLOT)
    return receipt


def _artifact(value: object) -> dict[str, Any]:
    artifact = _exact_object(value, _ARTIFACT_KEYS)
    _field(artifact["role"], "artifact.role", zero=True)
    _nonempty(artifact["circuitId"])
    for name in ("artifactEntryHash", "schemaHash", "verificationKeyHash"):
        _field(artifact[name], name, zero=True)
    if not isinstance(artifact["target"], str) or artifact["target"] not in _TARGETS:
        _fail(CoordFailureCode.ARTIFACT)
    return artifact


@dataclass(frozen=True)
class CoordFinalProof:
    """Canonical public ZKA final-proof wire object; proof bytes remain opaque."""

    proof: tuple[int, ...]
    receipt: Mapping[str, Any]
    artifact: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.proof, tuple) or not self.proof or any(type(byte) is not int or not 0 <= byte <= 255 for byte in self.proof):
            _fail(CoordFailureCode.MALFORMED)
        try:
            receipt = deepcopy(dict(self.receipt))
            artifact = deepcopy(dict(self.artifact))
        except (TypeError, ValueError):
            _fail(CoordFailureCode.MALFORMED)
        _reject_private({"receipt": receipt, "artifact": artifact})
        receipt = _receipt(receipt)
        receipt["predecessorStepIds"] = tuple(receipt["predecessorStepIds"])
        receipt["inputCommitments"] = tuple(receipt["inputCommitments"])
        object.__setattr__(self, "receipt", MappingProxyType(receipt))
        object.__setattr__(self, "artifact", MappingProxyType(_artifact(artifact)))

    @classmethod
    def from_dict(cls, data: object) -> "CoordFinalProof":
        wire = _exact_object(data, frozenset({"proof", "receipt", "artifact"}))
        if not isinstance(wire["proof"], list):
            _fail(CoordFailureCode.MALFORMED)
        return cls(tuple(wire["proof"]), wire["receipt"], wire["artifact"])

    def to_dict(self) -> dict[str, Any]:
        receipt = dict(self.receipt)
        receipt["predecessorStepIds"] = list(receipt["predecessorStepIds"])
        receipt["inputCommitments"] = list(receipt["inputCommitments"])
        return {"proof": list(self.proof), "receipt": receipt, "artifact": dict(self.artifact)}

    @property
    def proof_digest(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_json(self.to_dict()).encode()).hexdigest()


@dataclass(frozen=True)
class CoordEvidenceReference:
    """An AFP-local opaque evidence handle; its bytes never enter Coord wire data."""

    aggregate_commitment: str
    opaque_reference: str
    kind: str

    def __post_init__(self) -> None:
        _field(self.aggregate_commitment, "aggregate_commitment")
        _nonempty(self.opaque_reference)
        _nonempty(self.kind)

    @property
    def reference_digest(self) -> str:
        """Opaque identifier a verifier returns after checking this exact reference."""
        preimage = {
            "aggregateCommitment": self.aggregate_commitment,
            "opaqueReference": self.opaque_reference,
            "kind": self.kind,
        }
        return "sha256:" + hashlib.sha256(canonical_json(preimage).encode()).hexdigest()


@dataclass(frozen=True)
class CoordVerifierResult:
    """Typed acknowledgement from the independently configured ZKA verifier."""

    proof_digest: str
    verified_evidence_digests: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.proof_digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.proof_digest
        ) is None:
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        if not isinstance(self.verified_evidence_digests, (tuple, list)):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        values = tuple(self.verified_evidence_digests)
        if (
            any(
                not isinstance(value, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
                for value in values
            )
            or values != tuple(sorted(values))
            or len(set(values)) != len(values)
        ):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        object.__setattr__(self, "verified_evidence_digests", values)


@dataclass(frozen=True)
class CoordVerifierRequest:
    session_ref: str
    original_context: str
    derived_context: str
    party_a_aid: str
    party_b_aid: str
    sender_aid: str
    recipient_aid: str
    verification_time: int
    policy: CoordAcceptancePolicy
    evidence_references: tuple[CoordEvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        _nonempty(self.session_ref)
        if derive_coord_context(self.original_context) != self.derived_context:
            _fail(CoordFailureCode.SCOPE)
        _field(self.derived_context, "derived_context")
        _nonempty(self.party_a_aid)
        _nonempty(self.party_b_aid)
        _nonempty(self.sender_aid)
        _nonempty(self.recipient_aid)
        if self.party_a_aid == self.party_b_aid or not isinstance(self.policy, CoordAcceptancePolicy):
            _fail(CoordFailureCode.SCOPE)
        if type(self.verification_time) is not int or self.verification_time < 0:
            _fail(CoordFailureCode.SCOPE)
        requirements = _PROFILE_REQUIREMENTS.get(
            (self.policy.profile_id, self.policy.profile_id_field)
        )
        if requirements is None:
            _fail(CoordFailureCode.PROFILE_POLICY)
        expected_sender = (
            self.party_a_aid if requirements[7] == "initiator" else self.party_b_aid
        )
        expected_recipient = (
            self.party_b_aid if requirements[7] == "initiator" else self.party_a_aid
        )
        if (
            self.sender_aid != expected_sender
            or self.recipient_aid != expected_recipient
        ):
            _fail(CoordFailureCode.SCOPE)
        if not isinstance(self.evidence_references, (tuple, list)):
            _fail(CoordFailureCode.MALFORMED)
        refs = tuple(self.evidence_references)
        if any(not isinstance(item, CoordEvidenceReference) for item in refs):
            _fail(CoordFailureCode.MALFORMED)
        if len({(item.kind, item.aggregate_commitment) for item in refs}) != len(refs):
            _fail(CoordFailureCode.MALFORMED)
        refs = tuple(sorted(refs, key=lambda item: item.reference_digest))
        object.__setattr__(self, "evidence_references", refs)


@dataclass(frozen=True)
class CoordVerificationReport:
    proof_digest: str
    receipt_digest: str
    completion_digest: str
    profile_id: str
    receipt_commitment: str
    verified_evidence_commitments: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (
            self.proof_digest,
            self.receipt_digest,
            self.completion_digest,
        ):
            if not isinstance(value, str) or re.fullmatch(
                r"sha256:[0-9a-f]{64}", value
            ) is None:
                _fail(CoordFailureCode.VERIFIER_FAILURE)
        _nonempty(self.profile_id)
        _field(self.receipt_commitment, "receipt_commitment")
        if not isinstance(self.verified_evidence_commitments, (tuple, list)):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        commitments = tuple(self.verified_evidence_commitments)
        if (
            any(
                not isinstance(value, str) or _FIELD_RE.fullmatch(value) is None
                for value in commitments
            )
            or commitments != tuple(sorted(commitments))
            or len(set(commitments)) != len(commitments)
        ):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        object.__setattr__(self, "verified_evidence_commitments", commitments)


@dataclass(frozen=True)
class _CoordBundleVerification:
    """Unexported capability proving this context verified the bound bundle."""

    owner: object
    request: CoordVerifierRequest
    proof_digest: str
    bundle_digest: str


class CoordFinalProofVerifier(Protocol):
    """The deployment-bound ZKA bundle and final-proof verification seam."""

    def verify_bundle(
        self,
        bundle: object,
        request: CoordVerifierRequest,
    ) -> bool:
        """Verify the complete canonical ``zka:bundle:v1`` under authenticated state."""

    def verify_final_proof(
        self,
        proof: CoordFinalProof,
        request: CoordVerifierRequest,
    ) -> CoordVerifierResult:
        """Verify the exact proof and every returned authorized evidence reference."""


def _check_evidence(
    proof: CoordFinalProof,
    request: CoordVerifierRequest,
    verifier_result: CoordVerifierResult,
) -> tuple[str, ...]:
    receipt = proof.receipt
    refs = request.evidence_references
    expected_reference_digests = tuple(sorted(item.reference_digest for item in refs))
    if verifier_result.verified_evidence_digests != expected_reference_digests:
        _fail(CoordFailureCode.APPLICATION_PROOF)
    da = receipt["dataAvailabilityCommitment"]
    external = receipt["externalFactCommitment"]
    commitments = {item.aggregate_commitment for item in refs}
    bound = {value for value in (da, external) if value != BN254_ZERO_FIELD}
    if len(refs) != len(bound) or commitments != bound:
        _fail(CoordFailureCode.SCOPE)
    if request.policy.require_data_availability:
        if da == BN254_ZERO_FIELD:
            _fail(CoordFailureCode.SCOPE)
        if not refs:
            _fail(CoordFailureCode.SCOPE)
        if da not in commitments:
            _fail(CoordFailureCode.SCOPE)
    elif da != BN254_ZERO_FIELD:
        _fail(CoordFailureCode.SCOPE)
    if request.policy.require_external_facts:
        if external == BN254_ZERO_FIELD:
            _fail(CoordFailureCode.SCOPE)
        if not refs:
            _fail(CoordFailureCode.SCOPE)
        if external not in commitments:
            _fail(CoordFailureCode.SCOPE)
    elif external != BN254_ZERO_FIELD:
        _fail(CoordFailureCode.SCOPE)
    for commitment in (da, external):
        if commitment != BN254_ZERO_FIELD and refs and commitment not in commitments:
            _fail(CoordFailureCode.SCOPE)
    return tuple(sorted(commitments & bound))


def _check_public_bindings(
    proof: CoordFinalProof,
    request: CoordVerifierRequest,
) -> None:
    receipt = proof.receipt
    policy = request.policy
    expected = {
        "workflowDefinitionHash": policy.workflow_definition_hash,
        "workflowInstanceId": policy.workflow_instance_id,
        "context": request.derived_context,
        "profileId": policy.profile_id_field,
        "verifierPolicyRoot": policy.verifier_policy_root,
        "stepId": policy.completion_step_id,
    }
    if any(receipt[name] != value for name, value in expected.items()):
        _fail(CoordFailureCode.SCOPE)
    profile_binding = CoordProfileBinding(
        profile_version=receipt["profileVersion"],
        manifest_hash=receipt["profileManifestHash"],
        verification_key_hash=receipt["profileVkHash"],
        assurance=CoordAssurance(receipt["assuranceClass"]),
    )
    if profile_binding not in policy.accepted_profile_bindings:
        _fail(CoordFailureCode.PROFILE_POLICY)
    artifact = CoordArtifactBinding.from_dict(proof.artifact)
    if artifact not in policy.accepted_artifacts:
        _fail(CoordFailureCode.ARTIFACT)
    if (
        receipt["initialStateCommitment"] != policy.expected_initial_state_commitment
        or receipt["outputCommitment"] != policy.expected_output_commitment
        or receipt["postStateCommitment"] != policy.expected_post_state_commitment
    ):
        _fail(CoordFailureCode.SCOPE)
    bound_evidence = {
        value
        for value in (
            receipt["dataAvailabilityCommitment"],
            receipt["externalFactCommitment"],
        )
        if value != BN254_ZERO_FIELD
    }
    reference_commitments = {
        item.aggregate_commitment for item in request.evidence_references
    }
    if (
        len(request.evidence_references) != len(bound_evidence)
        or reference_commitments != bound_evidence
        or (
            policy.require_data_availability
            and receipt["dataAvailabilityCommitment"] == BN254_ZERO_FIELD
        )
        or (
            not policy.require_data_availability
            and receipt["dataAvailabilityCommitment"] != BN254_ZERO_FIELD
        )
        or (
            policy.require_external_facts
            and receipt["externalFactCommitment"] == BN254_ZERO_FIELD
        )
        or (
            not policy.require_external_facts
            and receipt["externalFactCommitment"] != BN254_ZERO_FIELD
        )
    ):
        _fail(CoordFailureCode.SCOPE)
    return None


def _build_report(
    proof: CoordFinalProof,
    request: CoordVerifierRequest,
    commitments: tuple[str, ...],
) -> CoordVerificationReport:
    receipt_wire = proof.to_dict()["receipt"]
    completion_preimage = {
        "sessionRef": request.session_ref,
        "sessionContext": request.original_context,
        "derivedContext": request.derived_context,
        "partyAAid": request.party_a_aid,
        "partyBAid": request.party_b_aid,
        "senderAid": request.sender_aid,
        "recipientAid": request.recipient_aid,
        "policyHash": request.policy.policy_hash,
        "receipt": receipt_wire,
        "artifact": proof.to_dict()["artifact"],
        "evidenceReferences": [
            {
                "aggregateCommitment": item.aggregate_commitment,
                "opaqueReference": item.opaque_reference,
                "kind": item.kind,
            }
            for item in request.evidence_references
        ],
    }
    return CoordVerificationReport(
        proof_digest=proof.proof_digest,
        receipt_digest="sha256:"
        + hashlib.sha256(canonical_json(receipt_wire).encode()).hexdigest(),
        completion_digest="sha256:"
        + hashlib.sha256(canonical_json(completion_preimage).encode()).hexdigest(),
        profile_id=request.policy.profile_id,
        receipt_commitment=proof.receipt["receiptCommitment"],
        verified_evidence_commitments=commitments,
    )


def _verify_coord_final_proof(
    proof: CoordFinalProof, request: CoordVerifierRequest, verifier: CoordFinalProofVerifier
) -> CoordVerificationReport:
    """Verify ZKA proof material then AFP-owned public session acceptance checks."""
    if not isinstance(proof, CoordFinalProof) or not isinstance(request, CoordVerifierRequest):
        _fail(CoordFailureCode.MALFORMED)
    if verifier is None or not callable(getattr(verifier, "verify_final_proof", None)):
        _fail(CoordFailureCode.VERIFIER_FAILURE)
    _check_public_bindings(proof, request)
    try:
        verified = verifier.verify_final_proof(proof, request)
    except CoordVerifierRejected as error:
        _fail_verifier_rejection(error)
    except CoordVerifierUnavailable:
        _fail(CoordFailureCode.DATA_UNAVAILABLE, retryable=True)
    except Exception:
        _fail(CoordFailureCode.VERIFIER_FAILURE)
    if not isinstance(verified, CoordVerifierResult) or verified.proof_digest != proof.proof_digest:
        _fail(CoordFailureCode.APPLICATION_PROOF)
    commitments = _check_evidence(proof, request, verified)
    return _build_report(proof, request, commitments)


@dataclass(frozen=True)
class CoordCompletionRecord:
    """One authoritative durable completion row and its canonical inbox effect."""

    session_ref: str
    workflow_instance_id: str
    receipt_commitment: str
    completion_digest: str
    report: CoordVerificationReport
    envelope_wire: bytes

    def __post_init__(self) -> None:
        _nonempty(self.session_ref)
        _field(self.workflow_instance_id, "workflow_instance_id")
        _field(self.receipt_commitment, "receipt_commitment")
        if not isinstance(self.completion_digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.completion_digest
        ) is None:
            _fail(CoordFailureCode.REPLAY)
        if (
            not isinstance(self.report, CoordVerificationReport)
            or self.report.receipt_commitment != self.receipt_commitment
            or self.report.completion_digest != self.completion_digest
        ):
            _fail(CoordFailureCode.REPLAY)
        if not isinstance(self.envelope_wire, bytes) or not self.envelope_wire:
            _fail(CoordFailureCode.REPLAY)
        object.__setattr__(self, "envelope_wire", bytes(self.envelope_wire))

    @property
    def envelope_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.envelope_wire).hexdigest()


@dataclass(frozen=True)
class CoordRecordResult:
    """Result of atomically recording or reading an exact retransmission."""

    record: CoordCompletionRecord
    created: bool

    def __post_init__(self) -> None:
        if not isinstance(self.record, CoordCompletionRecord) or type(self.created) is not bool:
            _fail(CoordFailureCode.REPLAY)


class CoordCompletionStore(Protocol):
    """Atomic durable authority for replay identity and the completion effect."""

    def record_completion(self, record: CoordCompletionRecord) -> CoordRecordResult:
        """Insert once or return the exact stored record for a retransmission."""

    def lookup_completion(
        self, workflow_instance_id: str
    ) -> CoordCompletionRecord | None:
        """Read the authoritative record for exact-retransmission recovery."""


class InMemoryCoordCompletionStore:
    """Atomic process-local completion store used by deterministic unit tests."""

    def __init__(self) -> None:
        self._by_instance: dict[str, CoordCompletionRecord] = {}
        self._lock = Lock()

    def record_completion(self, record: CoordCompletionRecord) -> CoordRecordResult:
        if not isinstance(record, CoordCompletionRecord):
            _fail(CoordFailureCode.REPLAY)
        with self._lock:
            prior = self._by_instance.get(record.workflow_instance_id)
            if prior is None:
                self._by_instance[record.workflow_instance_id] = record
                return CoordRecordResult(record=record, created=True)
            if prior == record:
                return CoordRecordResult(record=prior, created=False)
            _fail(CoordFailureCode.REPLAY)

    def lookup_completion(
        self, workflow_instance_id: str
    ) -> CoordCompletionRecord | None:
        _field(workflow_instance_id, "workflow_instance_id")
        with self._lock:
            return self._by_instance.get(workflow_instance_id)

    @property
    def completion_count(self) -> int:
        with self._lock:
            return len(self._by_instance)


class SqliteCoordCompletionStore:
    """SQLite-backed completion store with one replay/effect transaction."""

    def __init__(self, path: str | Path) -> None:
        if not isinstance(path, (str, Path)):
            _fail(CoordFailureCode.REPLAY)
        rendered_path = str(path)
        if (
            not rendered_path
            or rendered_path == ":memory:"
            or rendered_path.startswith("file:")
        ):
            _fail(CoordFailureCode.REPLAY)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                rendered_path, isolation_level=None, check_same_thread=False
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS coord_completions ("
                "workflow_instance_id TEXT PRIMARY KEY, "
                "session_ref TEXT NOT NULL, "
                "receipt_commitment TEXT NOT NULL, "
                "completion_digest TEXT NOT NULL, "
                "proof_digest TEXT NOT NULL, "
                "receipt_digest TEXT NOT NULL, "
                "profile_id TEXT NOT NULL, "
                "verified_evidence_commitments TEXT NOT NULL, "
                "envelope_wire BLOB NOT NULL)"
            )
        except (OSError, sqlite3.Error):
            if connection is not None:
                connection.close()
            _fail(CoordFailureCode.REPLAY)
        self._connection = connection
        self._lock = Lock()

    @staticmethod
    def _from_row(row: tuple[Any, ...]) -> CoordCompletionRecord:
        return CoordCompletionRecord(
            workflow_instance_id=row[0],
            session_ref=row[1],
            receipt_commitment=row[2],
            completion_digest=row[3],
            report=CoordVerificationReport(
                proof_digest=row[4],
                receipt_digest=row[5],
                completion_digest=row[3],
                profile_id=row[6],
                receipt_commitment=row[2],
                verified_evidence_commitments=tuple(json.loads(row[7])),
            ),
            envelope_wire=bytes(row[8]),
        )

    def record_completion(self, record: CoordCompletionRecord) -> CoordRecordResult:
        if not isinstance(record, CoordCompletionRecord):
            _fail(CoordFailureCode.REPLAY)
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT workflow_instance_id, session_ref, receipt_commitment, "
                    "completion_digest, proof_digest, receipt_digest, profile_id, "
                    "verified_evidence_commitments, envelope_wire "
                    "FROM coord_completions "
                    "WHERE workflow_instance_id = ?",
                    (record.workflow_instance_id,),
                ).fetchone()
                if row is None:
                    self._connection.execute(
                        "INSERT INTO coord_completions "
                        "(workflow_instance_id, session_ref, receipt_commitment, "
                        "completion_digest, proof_digest, receipt_digest, profile_id, "
                        "verified_evidence_commitments, envelope_wire) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            record.workflow_instance_id,
                            record.session_ref,
                            record.receipt_commitment,
                            record.completion_digest,
                            record.report.proof_digest,
                            record.report.receipt_digest,
                            record.report.profile_id,
                            canonical_json(
                                list(record.report.verified_evidence_commitments)
                            ),
                            sqlite3.Binary(record.envelope_wire),
                        ),
                    )
                    self._connection.execute("COMMIT")
                    return CoordRecordResult(record=record, created=True)
                prior = self._from_row(row)
                if prior != record:
                    _fail(CoordFailureCode.REPLAY)
                self._connection.execute("COMMIT")
                return CoordRecordResult(record=prior, created=False)
            except CoordVerificationError:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            except (OSError, sqlite3.Error, TypeError, ValueError):
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                _fail(CoordFailureCode.REPLAY)

    def lookup_completion(
        self, workflow_instance_id: str
    ) -> CoordCompletionRecord | None:
        _field(workflow_instance_id, "workflow_instance_id")
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT workflow_instance_id, session_ref, receipt_commitment, "
                    "completion_digest, proof_digest, receipt_digest, profile_id, "
                    "verified_evidence_commitments, envelope_wire "
                    "FROM coord_completions WHERE workflow_instance_id = ?",
                    (workflow_instance_id,),
                ).fetchone()
            except (sqlite3.Error, TypeError, ValueError):
                _fail(CoordFailureCode.REPLAY)
            if row is None:
                return None
            try:
                return self._from_row(row)
            except (CoordVerificationError, TypeError, ValueError, json.JSONDecodeError):
                _fail(CoordFailureCode.REPLAY)

    @property
    def completion_count(self) -> int:
        with self._lock:
            try:
                row = self._connection.execute(
                    "SELECT COUNT(*) FROM coord_completions"
                ).fetchone()
            except sqlite3.Error:
                _fail(CoordFailureCode.REPLAY)
            return int(row[0])

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.close()
            except sqlite3.Error:
                _fail(CoordFailureCode.REPLAY)

    def __enter__(self) -> "SqliteCoordCompletionStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class CoordCompletionVerificationContext:
    """Deployment-owned verifier and durable completion authority."""

    def __init__(
        self,
        *,
        verifier: CoordFinalProofVerifier,
        completion_store: CoordCompletionStore,
    ) -> None:
        if (
            verifier is None
            or not callable(getattr(verifier, "verify_bundle", None))
            or not callable(getattr(verifier, "verify_final_proof", None))
        ):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        if (
            completion_store is None
            or not callable(getattr(completion_store, "record_completion", None))
            or not callable(getattr(completion_store, "lookup_completion", None))
        ):
            _fail(CoordFailureCode.REPLAY)
        self._verifier = verifier
        self._completion_store = completion_store
        self._capability = object()

    def _lookup_completion(
        self, workflow_instance_id: str
    ) -> CoordCompletionRecord | None:
        try:
            record = self._completion_store.lookup_completion(workflow_instance_id)
        except Exception:
            _fail(CoordFailureCode.REPLAY)
        if record is None:
            return None
        if (
            not isinstance(record, CoordCompletionRecord)
            or record.workflow_instance_id != workflow_instance_id
        ):
            _fail(CoordFailureCode.REPLAY)
        return record

    def _verify_bundle(
        self,
        bundle: object,
        request: CoordVerifierRequest,
    ) -> _CoordBundleVerification:
        proof = self._validate_bundle_bindings(bundle, request)
        try:
            bundle_wire = canonical_json(bundle.to_dict())
            verifier_bundle = deepcopy(bundle)
        except (AttributeError, TypeError, ValueError):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        try:
            verified = self._verifier.verify_bundle(verifier_bundle, request)
        except CoordVerifierRejected as error:
            _fail_verifier_rejection(error)
        except CoordVerifierUnavailable:
            _fail(CoordFailureCode.DATA_UNAVAILABLE, retryable=True)
        except Exception:
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        try:
            unchanged = canonical_json(verifier_bundle.to_dict()) == bundle_wire
        except (AttributeError, TypeError, ValueError):
            unchanged = False
        if verified is not True or not unchanged:
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        return _CoordBundleVerification(
            owner=self._capability,
            request=request,
            proof_digest=proof.proof_digest,
            bundle_digest="sha256:"
            + hashlib.sha256(bundle_wire.encode()).hexdigest(),
        )

    def _validate_bundle_bindings(
        self,
        bundle: object,
        request: CoordVerifierRequest,
    ) -> CoordFinalProof:
        """Parse and minimize public bindings without external/store access."""
        if not isinstance(request, CoordVerifierRequest):
            _fail(CoordFailureCode.MALFORMED)
        try:
            payload = bundle.to_dict()
            proof = CoordFinalProof.from_dict(payload["coord_proof"])
        except (AttributeError, KeyError, TypeError, ValueError):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        # Minimize and bind verifier-local evidence before either configured
        # verifier method can retrieve it as a confused deputy.
        _check_public_bindings(proof, request)
        return proof

    def _record_completion(self, record: CoordCompletionRecord) -> CoordRecordResult:
        try:
            result = self._completion_store.record_completion(record)
        except CoordVerificationError:
            _fail(CoordFailureCode.REPLAY)
        except Exception:
            _fail(CoordFailureCode.REPLAY)
        if not isinstance(result, CoordRecordResult) or result.record != record:
            _fail(CoordFailureCode.REPLAY)
        return result

    def _verify_and_record(
        self,
        proof: CoordFinalProof,
        request: CoordVerifierRequest,
        verification: _CoordBundleVerification,
        bundle: object,
        envelope_wire: bytes,
        record_completion: Callable[[CoordCompletionRecord], CoordRecordResult]
        | None = None,
    ) -> "CoordCompletion":
        try:
            bundle_digest = "sha256:" + hashlib.sha256(
                canonical_json(bundle.to_dict()).encode()
            ).hexdigest()
        except (AttributeError, TypeError, ValueError):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        if (
            not isinstance(verification, _CoordBundleVerification)
            or verification.owner is not self._capability
            or verification.request is not request
            or verification.proof_digest != proof.proof_digest
            or verification.bundle_digest != bundle_digest
        ):
            _fail(CoordFailureCode.VERIFIER_FAILURE)
        report = _verify_coord_final_proof(proof, request, self._verifier)
        record = CoordCompletionRecord(
            session_ref=request.session_ref,
            workflow_instance_id=request.policy.workflow_instance_id,
            receipt_commitment=report.receipt_commitment,
            completion_digest=report.completion_digest,
            report=report,
            envelope_wire=envelope_wire,
        )
        stored = (
            self._record_completion(record)
            if record_completion is None
            else record_completion(record)
        )
        if not isinstance(stored, CoordRecordResult) or stored.record != record:
            _fail(CoordFailureCode.REPLAY)
        return CoordCompletion(
            session_ref=request.session_ref,
            workflow_instance_id=request.policy.workflow_instance_id,
            receipt_commitment=report.receipt_commitment,
            report=report,
            record=stored.record,
            retransmission=not stored.created,
        )

    def _recover_retransmission(
        self,
        record: CoordCompletionRecord,
        proof: CoordFinalProof,
        request: CoordVerifierRequest,
        envelope_wire: bytes,
    ) -> "CoordCompletion":
        if (
            not isinstance(record, CoordCompletionRecord)
            or record.session_ref != request.session_ref
            or record.workflow_instance_id != request.policy.workflow_instance_id
            or record.envelope_wire != envelope_wire
        ):
            _fail(CoordFailureCode.REPLAY)
        _check_public_bindings(proof, request)
        candidate = _build_report(
            proof,
            request,
            record.report.verified_evidence_commitments,
        )
        if candidate != record.report:
            _fail(CoordFailureCode.REPLAY)
        return CoordCompletion(
            session_ref=record.session_ref,
            workflow_instance_id=record.workflow_instance_id,
            receipt_commitment=record.receipt_commitment,
            report=record.report,
            record=record,
            retransmission=True,
        )


@dataclass(frozen=True)
class CoordCompletion:
    session_ref: str
    workflow_instance_id: str
    receipt_commitment: str
    report: CoordVerificationReport
    record: CoordCompletionRecord
    retransmission: bool = False
