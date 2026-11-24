"""Coord v2 reconciliation/reciprocal-exchange integration conformance tests."""

import _path  # noqa: F401  (path setup)

from copy import deepcopy
from dataclasses import dataclass, replace
import json
from pathlib import Path
import tempfile
from threading import Barrier, Thread
import traceback
import unittest

import afp_session as afp
from afp_session.canonical import canonical_bytes
from fixtures import establish_channels


CONFORMANCE_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "afp_coord_v2_cross_org_conformance_v1.json"
)

# All session, envelope, and canonical-bundle freshness checks use the same
# deterministic instant: 2026-08-26T00:05:00Z.
FIXED_NOW = 1_787_702_700
GENERATED_AT = "2026-08-26T00:00:00Z"
EXPIRES_AT = "2026-08-26T00:10:00Z"


def _clock() -> float:
    return float(FIXED_NOW)


def _fr(value: int) -> str:
    return f"0x{value:064x}"


@dataclass(frozen=True)
class _ProfileCase:
    name: str
    afp_profile: str
    profile_id: str
    profile_id_field: str
    manifest_hash: str
    profile_vk_hash: str
    assurance: afp.CoordAssurance
    require_data_availability: bool
    require_external_facts: bool
    sender_role: str


_PROFILE_CASES = (
    _ProfileCase(
        "private-reconciliation",
        "prp",
        afp.COORD_PRIVATE_RECONCILIATION_PROFILE,
        afp.COORD_PRIVATE_RECONCILIATION_PROFILE_FIELD,
        afp.COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH,
        afp.COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH,
        afp.CoordAssurance.ZK_NATIVE,
        True,
        False,
        "initiator",
    ),
    _ProfileCase(
        "reciprocal-compute",
        "vxp",
        afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE,
        afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_FIELD,
        afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH,
        afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH,
        afp.CoordAssurance.ZK_NATIVE,
        True,
        False,
        "initiator",
    ),
    _ProfileCase(
        "reciprocal-ack",
        "vxp",
        afp.COORD_VXP_RECIPROCAL_ACK_PROFILE,
        afp.COORD_VXP_RECIPROCAL_ACK_PROFILE_FIELD,
        afp.COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH,
        afp.COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH,
        afp.CoordAssurance.ATTESTED,
        False,
        True,
        "responder",
    ),
)


def _policy(
    case: _ProfileCase,
    *,
    workflow_instance: str = _fr(2),
) -> afp.CoordAcceptancePolicy:
    return afp.CoordAcceptancePolicy(
        afp_profile=case.afp_profile,
        profile_id=case.profile_id,
        profile_id_field=case.profile_id_field,
        workflow_definition_hash=_fr(1),
        workflow_instance_id=workflow_instance,
        completion_step_id=_fr(3),
        verifier_policy_root=_fr(4),
        accepted_profile_bindings=(
            afp.CoordProfileBinding(
                profile_version=1,
                manifest_hash=case.manifest_hash,
                verification_key_hash=case.profile_vk_hash,
                assurance=case.assurance,
            ),
        ),
        accepted_artifacts=(
            afp.CoordArtifactBinding(
                role=afp.COORD_RECURSIVE_ARTIFACT_ROLE,
                circuit_id=afp.COORD_RECURSIVE_CIRCUIT,
                artifact_entry_hash=(
                    "0x1520451d4710b91c59f982d7c148ba89c52d7e10c842bbb30a3a25b083784fae"
                ),
                schema_hash=(
                    "0x18a3537ebe76dccbc7ca7a3f80eab71cdb3602df63bc6ad27bc4a7b5b9937c4a"
                ),
                target="offchain",
                verification_key_hash=afp.COORD_RECURSIVE_VERIFICATION_KEY_HASH,
            ),
        ),
        require_data_availability=case.require_data_availability,
        require_external_facts=case.require_external_facts,
        expected_initial_state_commitment=_fr(10),
        expected_output_commitment=_fr(11),
        expected_post_state_commitment=_fr(12),
    )


def _evidence(case: _ProfileCase) -> tuple[afp.CoordEvidenceReference, ...]:
    if case.require_data_availability:
        commitment = _fr(30)
        kind = "data-availability"
    else:
        commitment = _fr(31)
        kind = "external-fact"
    return (
        afp.CoordEvidenceReference(
            aggregate_commitment=commitment,
            opaque_reference=f"vault://cross-org/{case.name}/evidence-7",
            kind=kind,
        ),
    )


def _proof_wire(
    policy: afp.CoordAcceptancePolicy,
    context: str,
    evidence: tuple[afp.CoordEvidenceReference, ...],
) -> dict:
    profile = policy.accepted_profile_bindings[0]
    artifact = policy.accepted_artifacts[0]
    data_availability = (
        evidence[0].aggregate_commitment
        if policy.require_data_availability
        else afp.BN254_ZERO_FIELD
    )
    external_fact = (
        evidence[0].aggregate_commitment
        if policy.require_external_facts
        else afp.BN254_ZERO_FIELD
    )
    return {
        "proof": [1, 3, 3, 7, 42, 255],
        "receipt": {
            "protocolVersion": 2,
            "workflowDefinitionHash": policy.workflow_definition_hash,
            "workflowInstanceId": policy.workflow_instance_id,
            "context": context,
            "initialStateCommitment": policy.expected_initial_state_commitment,
            "profileId": policy.profile_id_field,
            "profileVersion": profile.profile_version,
            "profileManifestHash": profile.manifest_hash,
            "profileVkHash": profile.verification_key_hash,
            "verifierPolicyRoot": policy.verifier_policy_root,
            "assuranceClass": profile.assurance.value,
            "stepId": policy.completion_step_id,
            "stepIndex": 3,
            "predecessorCount": 1,
            "predecessorStepIds": [
                _fr(13),
                afp.BN254_ZERO_FIELD,
                afp.BN254_ZERO_FIELD,
                afp.BN254_ZERO_FIELD,
            ],
            "inputCommitments": [
                _fr(14),
                afp.BN254_ZERO_FIELD,
                afp.BN254_ZERO_FIELD,
                afp.BN254_ZERO_FIELD,
            ],
            "inputSetCommitment": _fr(15),
            "preStateCommitment": _fr(16),
            "outputCommitment": policy.expected_output_commitment,
            "postStateCommitment": policy.expected_post_state_commitment,
            "externalFactCommitment": external_fact,
            "dataAvailabilityCommitment": data_availability,
            "topologyCommitment": _fr(17),
            "receiptCommitment": _fr(18),
            "graphCommitment": _fr(19),
            "proofNodeCount": 4,
            "maxDepth": 3,
        },
        "artifact": artifact.to_dict(),
    }


def _proof(
    policy: afp.CoordAcceptancePolicy,
    session_context: str,
    evidence: tuple[afp.CoordEvidenceReference, ...],
) -> afp.CoordFinalProof:
    return afp.CoordFinalProof.from_dict(
        _proof_wire(policy, afp.derive_coord_context(session_context), evidence)
    )


def _canonical_bundle(
    proof: afp.CoordFinalProof | object,
    context: str,
    *,
    generated_at: str = GENERATED_AT,
    expires_at: str = EXPIRES_AT,
) -> afp.ZkaBundle:
    coord_proof = proof.to_dict() if isinstance(proof, afp.CoordFinalProof) else proof
    return afp.ZkaBundle.from_canonical_payload(
        {
            "compliance": {"proofs": []},
            "coord_proof": coord_proof,
            "metadata": {
                "version": afp.BUNDLE_VERSION,
                "generatedAt": generated_at,
                "expiresAt": expires_at,
                "context": context,
            },
        }
    )


class _PinnedVerifier:
    """Deterministic stand-in for one deployment-configured ZKA verifier."""

    def __init__(
        self,
        evidence: tuple[afp.CoordEvidenceReference, ...],
        *,
        bundle_effects: tuple[object, ...] = (),
        proof_effects: tuple[object, ...] = (),
        exception_message: str = "configured verifier failed",
    ) -> None:
        self.expected_proof_digest: str | None = None
        self.expected_evidence_digests = tuple(
            sorted(item.reference_digest for item in evidence)
        )
        self.bundle_effects = list(bundle_effects)
        self.proof_effects = list(proof_effects)
        self.exception_message = exception_message
        self.bundle_calls = []
        self.proof_calls = []

    def pin(self, proof: afp.CoordFinalProof) -> None:
        self.expected_proof_digest = proof.proof_digest

    @staticmethod
    def _next(effects: list[object]) -> object:
        return effects.pop(0) if effects else "ok"

    def verify_bundle(self, bundle, request):
        self.bundle_calls.append((bundle, request))
        effect = self._next(self.bundle_effects)
        if effect == "unavailable":
            raise afp.CoordVerifierUnavailable()
        if effect == "error":
            raise RuntimeError(self.exception_message)
        if isinstance(effect, afp.CoordFailureCode):
            try:
                raise RuntimeError(self.exception_message)
            except RuntimeError:
                raise afp.CoordVerifierRejected(effect)
        if effect == "reject":
            return False
        if effect == "mutate":
            # A configured verifier is outside AFP's trust boundary. Exercise
            # the object-aliasing attack the receiver-side snapshot must catch.
            bundle.coord_proof["proof"][0] ^= 1
        return True

    def verify_final_proof(self, proof, request):
        self.proof_calls.append((proof, request))
        effect = self._next(self.proof_effects)
        if effect == "unavailable":
            raise afp.CoordVerifierUnavailable()
        if effect == "error":
            raise RuntimeError(self.exception_message)
        if isinstance(effect, afp.CoordFailureCode):
            try:
                raise RuntimeError(self.exception_message)
            except RuntimeError:
                raise afp.CoordVerifierRejected(effect)
        if effect == "reject":
            return afp.CoordVerifierResult(
                proof_digest="sha256:" + "00" * 32,
                verified_evidence_digests=self.expected_evidence_digests,
            )
        if self.expected_proof_digest is None:
            raise AssertionError("test verifier was not pinned to an expected proof")
        return afp.CoordVerifierResult(
            proof_digest=self.expected_proof_digest,
            verified_evidence_digests=self.expected_evidence_digests,
        )


class _RecordingCompletionStore:
    def __init__(self) -> None:
        self.inner = afp.InMemoryCoordCompletionStore()
        self.calls = []
        self.lookup_calls = []
        self.lookup_barrier = None

    def record_completion(self, record):
        self.calls.append(record)
        return self.inner.record_completion(record)

    def lookup_completion(self, workflow_instance_id):
        self.lookup_calls.append(workflow_instance_id)
        if self.lookup_barrier is not None:
            self.lookup_barrier.wait(timeout=10)
        return self.inner.lookup_completion(workflow_instance_id)

    @property
    def completion_count(self) -> int:
        return self.inner.completion_count


class _FailingCompletionStore:
    def __init__(self, message: str) -> None:
        self.message = message
        self.calls = []

    def record_completion(self, record):
        self.calls.append(record)
        raise RuntimeError(self.message)

    def lookup_completion(self, workflow_instance_id):
        return None


@dataclass
class _Opened:
    instance_a: afp.Instance
    instance_b: afp.Instance
    remote_a: afp.RemoteParty
    remote_b: afp.RemoteParty
    fsm_a: afp.SessionFSM
    fsm_b: afp.SessionFSM
    live_a: afp.VerifiedLiveSession
    live_b: afp.VerifiedLiveSession
    channel_a: afp.SessionChannel
    channel_b: afp.SessionChannel


@dataclass(frozen=True)
class _Flow:
    sender: afp.Instance
    receiver: afp.Instance
    sender_fsm: afp.SessionFSM
    receiver_fsm: afp.SessionFSM
    receiver_live: afp.VerifiedLiveSession
    sender_remote: afp.RemoteParty
    sender_channel: afp.SessionChannel
    receiver_channel: afp.SessionChannel


def _make_pair(verifier, completion_store):
    transport = afp.InMemoryTransport()
    tenant_a = afp.Identity.incept_tenant()
    entity_a = afp.Identity.incept_entity(tenant_a)
    tenant_b = afp.Identity.incept_tenant()
    entity_b = afp.Identity.incept_entity(tenant_b)
    verification_context = afp.CoordCompletionVerificationContext(
        verifier=verifier,
        completion_store=completion_store,
    )
    instance_a = afp.Instance(
        tenant=tenant_a,
        entity=entity_a,
        transport=transport,
        clock=_clock,
        coord_completion_context=verification_context,
    )
    instance_b = afp.Instance(
        tenant=tenant_b,
        entity=entity_b,
        transport=transport,
        clock=_clock,
        coord_completion_context=verification_context,
    )
    remote_a = afp.RemoteParty(entity_a.kel, tenant_a.kel, witness_keys={})
    remote_b = afp.RemoteParty(entity_b.kel, tenant_b.kel, witness_keys={})
    return instance_a, instance_b, remote_a, remote_b


def _open_on_pair(
    instance_a: afp.Instance,
    instance_b: afp.Instance,
    remote_a: afp.RemoteParty,
    remote_b: afp.RemoteParty,
    policy: afp.CoordAcceptancePolicy,
    *,
    session_id: str,
) -> _Opened:
    fsm_a = instance_a.propose(
        responder_tenant_aid=instance_b.tenant_aid,
        responder_entity_aid=instance_b.entity_aid,
        agreement_ref="agr_cross_org_coord_v2",
        agreement_version="1",
        profile=policy.afp_profile,
        profile_policy_hash=policy.policy_hash,
        responder_remote=remote_b,
        ttl_seconds=10 * 365 * 24 * 60 * 60,
        session_id=session_id,
    )
    fsm_b = instance_b.accept(fsm_a.atom, initiator_remote=remote_a)
    instance_a.confirm_open(fsm_a, fsm_b.atom, responder_remote=remote_b)
    channel_a, channel_b = establish_channels(
        instance_a, instance_b, remote_a, remote_b, fsm_a.atom
    )
    instance_a.activate(fsm_a)
    instance_b.activate(fsm_b)
    return _Opened(
        instance_a,
        instance_b,
        remote_a,
        remote_b,
        fsm_a,
        fsm_b,
        instance_a.verified_live_session(fsm_a),
        instance_b.verified_live_session(fsm_b),
        channel_a,
        channel_b,
    )


def _open(
    policy: afp.CoordAcceptancePolicy,
    verifier,
    completion_store,
    *,
    session_id: str = "sess_coord_v2",
) -> _Opened:
    return _open_on_pair(
        *_make_pair(verifier, completion_store),
        policy,
        session_id=session_id,
    )


def _flow(opened: _Opened, sender_role: str) -> _Flow:
    if sender_role == "initiator":
        return _Flow(
            opened.instance_a,
            opened.instance_b,
            opened.fsm_a,
            opened.fsm_b,
            opened.live_b,
            opened.remote_a,
            opened.channel_a,
            opened.channel_b,
        )
    if sender_role == "responder":
        return _Flow(
            opened.instance_b,
            opened.instance_a,
            opened.fsm_b,
            opened.fsm_a,
            opened.live_a,
            opened.remote_b,
            opened.channel_b,
            opened.channel_a,
        )
    raise AssertionError(f"unknown test sender role {sender_role!r}")


def _envelope(
    opened: _Opened,
    proof: afp.CoordFinalProof,
    *,
    sender_role: str,
    bundle_context: str | None = None,
    message_class: str = afp.COORD_COMPLETION_MESSAGE_CLASS,
    generated_at: str = GENERATED_AT,
    expires_at: str = EXPIRES_AT,
) -> afp.AfpEnvelope:
    flow = _flow(opened, sender_role)
    context = bundle_context or afp.derive_coord_context(
        opened.fsm_a.atom.session_context
    )
    built = flow.sender.build_envelope(
        flow.sender_fsm,
        bundle=_canonical_bundle(
            proof,
            context,
            generated_at=generated_at,
            expires_at=expires_at,
        ),
        message_class=message_class,
    )
    # Exercise public wire parsing rather than sharing sender-owned objects.
    return afp.AfpEnvelope.from_dict(built.to_dict())


def _receive(
    opened: _Opened,
    envelope: afp.AfpEnvelope,
    policy: afp.CoordAcceptancePolicy,
    evidence: tuple[afp.CoordEvidenceReference, ...],
    *,
    sender_role: str,
):
    flow = _flow(opened, sender_role)
    sealed = flow.sender_channel.seal(
        canonical_bytes(envelope.to_dict()),
        message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
    )
    return flow.receiver.receive_coord_completion(
        flow.receiver_live,
        sealed,
        channel=flow.receiver_channel,
        sender_remote=flow.sender_remote,
        policy=policy,
        evidence_references=evidence,
    )


def _resign(envelope: afp.AfpEnvelope, instance: afp.Instance) -> None:
    envelope.sender.signature = instance.entity.sign(
        envelope.content_hash.encode("utf-8")
    ).hex()


class CoordV2AcceptanceTest(unittest.TestCase):
    def assert_coord_error(self, expected, callback, *, retryable=False):
        with self.assertRaises(afp.CoordVerificationError) as caught:
            callback()
        self.assertIs(caught.exception.code, expected)
        self.assertEqual(caught.exception.retryable, retryable)
        self.assertEqual(str(caught.exception), expected.value)
        return caught.exception

    def test_exact_profile_manifest_vk_and_recursive_vk_coordinates_are_pinned(self):
        self.assertEqual(
            afp.COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH,
            "0x00502511877b0c7502792ccc35e841e36d067ba98925728253bc66ccb1082768",
        )
        self.assertEqual(
            afp.COORD_PRIVATE_RECONCILIATION_PROFILE_VK_HASH,
            "0x0bd66b2eb5d199726ef90f307069782beae1afe6d9a7488ec2c1e251d7b78f63",
        )
        self.assertEqual(
            afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_MANIFEST_HASH,
            "0x21b14f3d82f54bfef2ae81ca254081bf0e94dd6ae7c0d7ca7a42684ef3d5a61c",
        )
        self.assertEqual(
            afp.COORD_VXP_RECIPROCAL_COMPUTE_PROFILE_VK_HASH,
            "0x2073432bf50f20e8cd5127a9734419ff866ce08e0d2b6a7b8a09e6491e425319",
        )
        self.assertEqual(
            afp.COORD_VXP_RECIPROCAL_ACK_PROFILE_MANIFEST_HASH,
            "0x2b622e9a71c5e351bfef8d54e970084c483f7f1c158fe893296cdbaa117f2f1d",
        )
        self.assertEqual(
            afp.COORD_VXP_RECIPROCAL_ACK_PROFILE_VK_HASH,
            "0x1bce6effb5f61fce0f27a7257ff301b67538699e675d0c6617da014d6cbf29dd",
        )
        self.assertEqual(
            afp.COORD_RECURSIVE_VERIFICATION_KEY_HASH,
            "0x2e72267c8a0c8750a5cfe2e2893ec689ae9b4a488938ac084aeff1b470d055a2",
        )

    def test_authenticated_bilateral_prp_compute_and_ack_use_pinned_direction_and_result_class(self):
        for index, case in enumerate(_PROFILE_CASES):
            with self.subTest(profile=case.name):
                policy = _policy(case, workflow_instance=_fr(100 + index))
                evidence = _evidence(case)
                verifier = _PinnedVerifier(evidence)
                store = _RecordingCompletionStore()
                opened = _open(
                    policy,
                    verifier,
                    store,
                    session_id=f"sess_{case.name}",
                )
                proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
                verifier.pin(proof)
                envelope = _envelope(
                    opened,
                    proof,
                    sender_role=case.sender_role,
                )

                completion = _receive(
                    opened,
                    envelope,
                    policy,
                    evidence,
                    sender_role=case.sender_role,
                )

                flow = _flow(opened, case.sender_role)
                request = verifier.proof_calls[0][1]
                self.assertEqual(envelope.message_class, "result")
                self.assertEqual(request.sender_aid, flow.sender.entity_aid)
                self.assertEqual(request.recipient_aid, flow.receiver.entity_aid)
                self.assertEqual(request.verification_time, FIXED_NOW)
                self.assertEqual(
                    request.derived_context,
                    afp.derive_coord_context(opened.fsm_a.atom.session_context),
                )
                self.assertFalse(completion.retransmission)
                self.assertEqual(completion.report.profile_id, case.profile_id)
                self.assertEqual(
                    completion.report.verified_evidence_commitments,
                    (evidence[0].aggregate_commitment,),
                )
                self.assertEqual(len(verifier.bundle_calls), 1)
                self.assertEqual(len(verifier.proof_calls), 1)
                self.assertEqual(len(store.calls), 1)
                self.assertEqual(len(flow.receiver.inbox[flow.receiver_fsm.atom.id]), 1)
                self.assertNotIn(
                    evidence[0].opaque_reference,
                    json.dumps(envelope.bundle.to_dict()),
                )

    def test_wrong_profile_direction_is_rejected_before_verification_or_recording(self):
        for index, case in enumerate(_PROFILE_CASES):
            with self.subTest(profile=case.name):
                policy = _policy(case, workflow_instance=_fr(200 + index))
                evidence = _evidence(case)
                verifier = _PinnedVerifier(evidence)
                store = _RecordingCompletionStore()
                opened = _open(
                    policy,
                    verifier,
                    store,
                    session_id=f"sess_wrong_direction_{index}",
                )
                proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
                verifier.pin(proof)
                wrong_role = (
                    "responder" if case.sender_role == "initiator" else "initiator"
                )
                envelope = _envelope(opened, proof, sender_role=wrong_role)

                self.assert_coord_error(
                    afp.CoordFailureCode.SCOPE,
                    lambda: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role=wrong_role,
                    ),
                )
                self.assertEqual(verifier.bundle_calls, [])
                self.assertEqual(verifier.proof_calls, [])
                self.assertEqual(store.calls, [])
                wrong_flow = _flow(opened, wrong_role)
                self.assertNotIn(
                    wrong_flow.receiver_fsm.atom.id,
                    wrong_flow.receiver.inbox,
                )

    def test_unknown_or_unsigned_policy_and_wrong_result_class_fail_closed(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        with self.assertRaises(afp.CoordVerificationError) as unknown:
            replace(
                policy,
                profile_id="zka:coord:unknown:v1",
                profile_id_field=_fr(999),
            )
        self.assertIs(unknown.exception.code, afp.CoordFailureCode.PROFILE_POLICY)

        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)

        other_policy = replace(policy, verifier_policy_root=_fr(998))
        envelope = _envelope(opened, proof, sender_role=case.sender_role)
        self.assert_coord_error(
            afp.CoordFailureCode.PROFILE_POLICY,
            lambda: _receive(
                opened,
                envelope,
                other_policy,
                evidence,
                sender_role=case.sender_role,
            ),
        )

        wrong_class = _envelope(
            opened,
            proof,
            sender_role=case.sender_role,
            message_class="coord.result",
        )
        self.assert_coord_error(
            afp.CoordFailureCode.MALFORMED,
            lambda: _receive(
                opened,
                wrong_class,
                policy,
                evidence,
                sender_role=case.sender_role,
            ),
        )
        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])

    def test_generic_receive_envelope_cannot_bypass_coord_completion_acceptance(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        flow = _flow(opened, "initiator")
        sealed = flow.sender_channel.seal(
            canonical_bytes(envelope.to_dict()),
            message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
        )

        with self.assertRaises(afp.EnvelopeError):
            flow.receiver.receive_envelope(
                flow.receiver_fsm,
                sealed,
                message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
                channel=flow.receiver_channel,
                sender_remote=flow.sender_remote,
                bundle_verifier=lambda bundle: (
                    afp.BundleVerificationResult.accepted(bundle)
                ),
            )

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(flow.receiver_fsm.atom.id, flow.receiver.inbox)

    def test_coord_completion_rejects_non_pure_bundle_side_channels_before_effects(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        flow = _flow(opened, "initiator")
        context = afp.derive_coord_context(opened.fsm_a.atom.session_context)
        private_marker = "private-witness-side-channel-never-persist"

        variants = (
            (
                "compliance-aggregation",
                lambda payload: payload["compliance"].update(
                    {"aggregation": private_marker}
                ),
            ),
            ("null-transaction", lambda payload: payload.update({"transaction": None})),
            ("null-binding", lambda payload: payload.update({"binding": None})),
        )
        for name, mutate in variants:
            with self.subTest(shape=name):
                payload = _canonical_bundle(proof, context).to_dict()
                mutate(payload)
                bundle = afp.ZkaBundle.from_canonical_payload(payload)
                self.assertFalse(bundle.is_pure_coord_payload)
                built = flow.sender.build_envelope(
                    flow.sender_fsm,
                    bundle=bundle,
                    message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
                )
                envelope = afp.AfpEnvelope.from_dict(built.to_dict())
                self.assert_coord_error(
                    afp.CoordFailureCode.MALFORMED,
                    lambda envelope=envelope: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role="initiator",
                    ),
                )

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.lookup_calls, [])
        self.assertEqual(store.calls, [])
        self.assertEqual(store.completion_count, 0)
        self.assertIsNone(store.inner.lookup_completion(policy.workflow_instance_id))
        self.assertNotIn(private_marker, repr(store.inner.__dict__))
        self.assertNotIn(flow.receiver_fsm.atom.id, flow.receiver.inbox)

    def test_attacker_cannot_supply_a_per_request_verifier_or_store(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        flow = _flow(opened, "initiator")
        attacker_verifier = _PinnedVerifier(evidence)
        attacker_store = _RecordingCompletionStore()
        sealed = flow.sender_channel.seal(
            canonical_bytes(envelope.to_dict()),
            message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
        )

        for extra in (
            {"verifier": attacker_verifier},
            {"completion_store": attacker_store},
            {"replay_store": attacker_store},
        ):
            with self.subTest(extra=next(iter(extra))):
                with self.assertRaises(TypeError):
                    flow.receiver.receive_coord_completion(
                        flow.receiver_live,
                        sealed,
                        channel=flow.receiver_channel,
                        sender_remote=flow.sender_remote,
                        policy=policy,
                        evidence_references=evidence,
                        **extra,
                    )

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertEqual(attacker_verifier.bundle_calls, [])
        self.assertEqual(attacker_store.calls, [])
        self.assertNotIn(flow.receiver_fsm.atom.id, flow.receiver.inbox)

    def test_identity_session_and_bundle_bindings_fail_without_effect(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        flow = _flow(opened, "initiator")

        for mutation in ("session_ref", "session_context", "bundle_context", "profile"):
            with self.subTest(mutation=mutation):
                if mutation == "bundle_context":
                    envelope = _envelope(
                        opened,
                        proof,
                        sender_role="initiator",
                        bundle_context=_fr(999),
                    )
                else:
                    envelope = _envelope(opened, proof, sender_role="initiator")
                    if mutation == "session_ref":
                        envelope.session_ref = "sess_different"
                    elif mutation == "session_context":
                        envelope.session_context = "X_" + "ab" * 32
                    else:
                        envelope.profile = "vxp"
                    _resign(envelope, opened.instance_a)
                self.assert_coord_error(
                    afp.CoordFailureCode.SESSION_CONTEXT,
                    lambda envelope=envelope: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role="initiator",
                    ),
                )

        tenant_c = afp.Identity.incept_tenant()
        entity_c = afp.Identity.incept_entity(tenant_c)
        instance_c = afp.Instance(
            tenant=tenant_c,
            entity=entity_c,
            transport=opened.instance_a.transport,
            clock=_clock,
        )
        remote_c = afp.RemoteParty(entity_c.kel, tenant_c.kel, witness_keys={})
        third_party = _envelope(opened, proof, sender_role="initiator")
        third_party.sender = afp.AfpPartyRef(
            tenant_aid=tenant_c.aid,
            entity_aid=entity_c.aid,
            kel_event_dig=entity_c.kel.latest_dig,
            signature="",
        )
        _resign(third_party, instance_c)
        sealed_third_party = flow.sender_channel.seal(
            canonical_bytes(third_party.to_dict()),
            message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
        )
        self.assert_coord_error(
            afp.CoordFailureCode.IDENTITY,
            lambda: flow.receiver.receive_coord_completion(
                flow.receiver_live,
                sealed_third_party,
                channel=flow.receiver_channel,
                sender_remote=remote_c,
                policy=policy,
                evidence_references=evidence,
            ),
        )

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(flow.receiver_fsm.atom.id, flow.receiver.inbox)

    def test_profile_artifact_assurance_and_workflow_substitutions_fail_closed(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        original = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        mutations = (
            (
                "workflow",
                ("receipt", "workflowDefinitionHash"),
                _fr(700),
                afp.CoordFailureCode.SCOPE,
            ),
            (
                "manifest",
                ("receipt", "profileManifestHash"),
                _fr(701),
                afp.CoordFailureCode.PROFILE_POLICY,
            ),
            (
                "profile-vk",
                ("receipt", "profileVkHash"),
                _fr(702),
                afp.CoordFailureCode.PROFILE_POLICY,
            ),
            (
                "assurance",
                ("receipt", "assuranceClass"),
                "attested",
                afp.CoordFailureCode.PROFILE_POLICY,
            ),
            (
                "artifact",
                ("artifact", "artifactEntryHash"),
                _fr(703),
                afp.CoordFailureCode.ARTIFACT,
            ),
            (
                "recursive-vk",
                ("artifact", "verificationKeyHash"),
                _fr(704),
                afp.CoordFailureCode.ARTIFACT,
            ),
        )
        for name, path, replacement, expected_code in mutations:
            with self.subTest(binding=name):
                wire = original.to_dict()
                wire[path[0]][path[1]] = replacement
                changed = afp.CoordFinalProof.from_dict(wire)
                verifier.pin(changed)
                envelope = _envelope(opened, changed, sender_role="initiator")
                self.assert_coord_error(
                    expected_code,
                    lambda envelope=envelope: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role="initiator",
                    ),
                )

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_evidence_references_have_no_available_flag_and_missing_is_terminal(self):
        case = _PROFILE_CASES[0]
        with self.assertRaises(TypeError):
            afp.CoordEvidenceReference(
                aggregate_commitment=_fr(30),
                opaque_reference="vault://attacker/asserts-available",
                kind="data-availability",
                available=True,
            )

        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")

        self.assert_coord_error(
            afp.CoordFailureCode.SCOPE,
            lambda: _receive(
                opened,
                envelope,
                policy,
                (),
                sender_role="initiator",
            ),
            retryable=False,
        )
        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_extra_evidence_references_fail_scope_before_verifier_or_store_access(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        private_marker = "private-extra-evidence-never-observed"
        scenarios = (
            (
                "unrelated-commitment",
                evidence
                + (
                    afp.CoordEvidenceReference(
                        aggregate_commitment=_fr(901),
                        opaque_reference=f"vault://{private_marker}/unrelated",
                        kind="unrelated-evidence",
                    ),
                ),
            ),
            (
                "same-commitment-different-kind",
                evidence
                + (
                    afp.CoordEvidenceReference(
                        aggregate_commitment=evidence[0].aggregate_commitment,
                        opaque_reference=f"vault://{private_marker}/duplicate",
                        kind="unrelated-evidence",
                    ),
                ),
            ),
        )
        for name, references in scenarios:
            with self.subTest(shape=name):
                error = self.assert_coord_error(
                    afp.CoordFailureCode.SCOPE,
                    lambda references=references: _receive(
                        opened,
                        envelope,
                        policy,
                        references,
                        sender_role="initiator",
                    ),
                    retryable=False,
                )
                rendered = "".join(
                    traceback.format_exception(
                        type(error), error, error.__traceback__
                    )
                )
                self.assertNotIn(private_marker, rendered)
                self.assertNotIn(private_marker, str(error))

        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.lookup_calls, [])
        self.assertEqual(store.calls, [])
        self.assertEqual(store.completion_count, 0)
        self.assertIsNone(store.inner.lookup_completion(policy.workflow_instance_id))
        self.assertNotIn(private_marker, repr(store.inner.__dict__))
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_altered_evidence_or_proof_never_records_completion(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")

        altered_reference = (
            replace(evidence[0], opaque_reference="vault://cross-org/altered"),
        )
        self.assert_coord_error(
            afp.CoordFailureCode.APPLICATION_PROOF,
            lambda: _receive(
                opened,
                envelope,
                policy,
                altered_reference,
                sender_role="initiator",
            ),
        )

        changed_wire = proof.to_dict()
        changed_wire["proof"][0] ^= 1
        changed = afp.CoordFinalProof.from_dict(changed_wire)
        changed_envelope = _envelope(opened, changed, sender_role="initiator")
        self.assert_coord_error(
            afp.CoordFailureCode.APPLICATION_PROOF,
            lambda: _receive(
                opened,
                changed_envelope,
                policy,
                evidence,
                sender_role="initiator",
            ),
        )

        self.assertEqual(len(verifier.bundle_calls), 2)
        self.assertEqual(len(verifier.proof_calls), 2)
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_typed_verifier_unavailable_is_retryable_and_retry_succeeds(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)

        for stage in ("bundle", "proof"):
            with self.subTest(stage=stage):
                verifier = _PinnedVerifier(
                    evidence,
                    bundle_effects=("unavailable",) if stage == "bundle" else (),
                    proof_effects=("unavailable",) if stage == "proof" else (),
                )
                store = _RecordingCompletionStore()
                opened = _open(
                    policy,
                    verifier,
                    store,
                    session_id=f"sess_unavailable_{stage}",
                )
                proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
                verifier.pin(proof)
                envelope = _envelope(opened, proof, sender_role="initiator")

                self.assert_coord_error(
                    afp.CoordFailureCode.DATA_UNAVAILABLE,
                    lambda: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role="initiator",
                    ),
                    retryable=True,
                )
                self.assertEqual(store.calls, [])
                self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

                completion = _receive(
                    opened,
                    envelope,
                    policy,
                    evidence,
                    sender_role="initiator",
                )
                self.assertFalse(completion.retransmission)
                self.assertEqual(len(store.calls), 1)
                self.assertEqual(len(opened.instance_b.inbox[opened.fsm_b.atom.id]), 1)

    def test_typed_verifier_terminal_rejections_preserve_only_allowlisted_codes(self):
        with self.assertRaises(ValueError):
            afp.CoordVerifierRejected(afp.CoordFailureCode.REPLAY)

        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        secret = "backend-private-predecessor-state-never-log"
        scenarios = (
            ("bundle", afp.CoordFailureCode.PREDECESSOR_COUNT),
            ("proof", afp.CoordFailureCode.INCOMPLETE_WORKFLOW),
        )
        for stage, expected_code in scenarios:
            with self.subTest(stage=stage, code=expected_code.value):
                verifier = _PinnedVerifier(
                    evidence,
                    bundle_effects=(expected_code,) if stage == "bundle" else (),
                    proof_effects=(expected_code,) if stage == "proof" else (),
                    exception_message=secret,
                )
                store = _RecordingCompletionStore()
                opened = _open(
                    policy,
                    verifier,
                    store,
                    session_id=f"sess_terminal_{stage}",
                )
                proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
                verifier.pin(proof)
                envelope = _envelope(opened, proof, sender_role="initiator")

                error = self.assert_coord_error(
                    expected_code,
                    lambda: _receive(
                        opened,
                        envelope,
                        policy,
                        evidence,
                        sender_role="initiator",
                    ),
                    retryable=False,
                )
                rendered = "".join(
                    traceback.format_exception(
                        type(error), error, error.__traceback__
                    )
                )
                self.assertTrue(error.__suppress_context__)
                self.assertNotIn(secret, rendered)
                self.assertNotIn("backend-private", str(error))
                self.assertEqual(len(verifier.bundle_calls), 1)
                self.assertEqual(
                    len(verifier.proof_calls),
                    1 if stage == "proof" else 0,
                )
                self.assertEqual(store.calls, [])
                self.assertEqual(store.completion_count, 0)
                self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_generic_verifier_exception_is_terminal_and_redacted(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        secret = "private-witness: account=alpha nonce=never-log-this"
        verifier = _PinnedVerifier(
            evidence,
            proof_effects=("error",),
            exception_message=secret,
        )
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")

        error = self.assert_coord_error(
            afp.CoordFailureCode.VERIFIER_FAILURE,
            lambda: _receive(
                opened,
                envelope,
                policy,
                evidence,
                sender_role="initiator",
            ),
            retryable=False,
        )
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertTrue(error.__suppress_context__)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("private-witness", str(error))
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_verifier_cannot_mutate_the_receiver_snapshot_before_recording(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence, bundle_effects=("mutate",))
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        original_wire = envelope.to_dict()

        self.assert_coord_error(
            afp.CoordFailureCode.VERIFIER_FAILURE,
            lambda: _receive(
                opened,
                envelope,
                policy,
                evidence,
                sender_role="initiator",
            ),
        )
        self.assertEqual(envelope.to_dict(), original_wire)
        self.assertEqual(len(verifier.bundle_calls), 1)
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_malformed_and_expired_bundle_timestamps_never_record(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        context = afp.derive_coord_context(opened.fsm_a.atom.session_context)

        with self.assertRaises(ValueError):
            _canonical_bundle(
                proof,
                context,
                generated_at="not-rfc3339",
            )

        expired = _envelope(
            opened,
            proof,
            sender_role="initiator",
            generated_at="2026-08-25T23:40:00Z",
            expires_at="2026-08-25T23:50:00Z",
        )
        self.assert_coord_error(
            afp.CoordFailureCode.SESSION_CONTEXT,
            lambda: _receive(
                opened,
                expired,
                policy,
                evidence,
                sender_role="initiator",
            ),
        )
        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_coord_envelope_decode_rejects_noncanonical_objects_and_times(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        flow = _flow(opened, "initiator")
        base = envelope.to_dict()

        extra_envelope = deepcopy(base)
        extra_envelope["ignored"] = "must-not-normalize-away"
        extra_sender = deepcopy(base)
        extra_sender["sender"]["ignored"] = "must-not-normalize-away"
        missing = deepcopy(base)
        del missing["generated_at"]
        wrong_type = deepcopy(base)
        wrong_type["expires_at"] = "1787702700"
        nonfinite = deepcopy(base)
        nonfinite["generated_at"] = float("nan")
        giant_integer = deepcopy(base)
        giant_integer["expires_at"] = -(10 ** 400)
        canonical = canonical_bytes(base)
        duplicate = canonical.replace(
            b'"profile":"prp"',
            b'"profile":"prp","profile":"prp"',
            1,
        )
        self.assertNotEqual(duplicate, canonical)

        payloads = (
            canonical_bytes(extra_envelope),
            canonical_bytes(extra_sender),
            canonical_bytes(missing),
            canonical_bytes(wrong_type),
            canonical_bytes(nonfinite),
            canonical_bytes(giant_integer),
            duplicate,
        )
        for index, payload in enumerate(payloads):
            with self.subTest(case=index):
                sealed = flow.sender_channel.seal(
                    payload,
                    message_class=afp.COORD_COMPLETION_MESSAGE_CLASS,
                )
                self.assert_coord_error(
                    afp.CoordFailureCode.SESSION_CONTEXT,
                    lambda sealed=sealed: flow.receiver.receive_coord_completion(
                        flow.receiver_live,
                        sealed,
                        channel=flow.receiver_channel,
                        sender_remote=flow.sender_remote,
                        policy=policy,
                        evidence_references=evidence,
                    ),
                )
        self.assertEqual(verifier.bundle_calls, [])
        self.assertEqual(verifier.proof_calls, [])
        self.assertEqual(store.calls, [])

    def test_direct_session_abort_after_verification_prevents_the_durable_effect(self):
        class _AbortingVerifier(_PinnedVerifier):
            receiver_fsm = None

            def verify_final_proof(self, proof, request):
                result = super().verify_final_proof(proof, request)
                self.receiver_fsm.abort()
                return result

        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _AbortingVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        verifier.receiver_fsm = opened.fsm_b
        self.assertIs(opened.fsm_a._state_lock, opened.instance_a._coord_state_lock)
        self.assertIs(opened.fsm_b._state_lock, opened.instance_b._coord_state_lock)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)

        self.assert_coord_error(
            afp.CoordFailureCode.SESSION_CONTEXT,
            lambda: _receive(
                opened,
                _envelope(opened, proof, sender_role="initiator"),
                policy,
                evidence,
                sender_role="initiator",
            ),
        )
        self.assertEqual(len(verifier.bundle_calls), 1)
        self.assertEqual(len(verifier.proof_calls), 1)
        self.assertEqual(store.calls, [])
        self.assertEqual(store.completion_count, 0)
        self.assertNotIn(opened.fsm_b.atom.id, opened.instance_b.inbox)

    def test_atomic_record_and_inbox_projection_are_idempotent_or_no_effect(self):
        case = _PROFILE_CASES[1]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(policy, verifier, store)
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")

        first = _receive(
            opened,
            envelope,
            policy,
            evidence,
            sender_role="initiator",
        )
        second = _receive(
            opened,
            envelope,
            policy,
            evidence,
            sender_role="initiator",
        )
        self.assertFalse(first.retransmission)
        self.assertTrue(second.retransmission)
        self.assertEqual(first.record, second.record)
        self.assertEqual(store.completion_count, 1)
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(store.lookup_calls), 2)
        self.assertEqual(len(verifier.bundle_calls), 1)
        self.assertEqual(len(verifier.proof_calls), 1)
        self.assertEqual(len(opened.instance_b.inbox[opened.fsm_b.atom.id]), 1)

        # The durable record is authoritative. An exact authenticated resend
        # repairs a lost inbox projection even while the external verifier is
        # unavailable, and it never calls that verifier again.
        opened.instance_b.inbox[opened.fsm_b.atom.id].clear()
        verifier.bundle_effects.append("unavailable")
        verifier.proof_effects.append("unavailable")
        bundle_calls = len(verifier.bundle_calls)
        proof_calls = len(verifier.proof_calls)
        repaired = _receive(
            opened,
            envelope,
            policy,
            evidence,
            sender_role="initiator",
        )
        self.assertTrue(repaired.retransmission)
        self.assertEqual(repaired.report, first.report)
        self.assertEqual(len(verifier.bundle_calls), bundle_calls)
        self.assertEqual(len(verifier.proof_calls), proof_calls)
        self.assertEqual(verifier.bundle_effects, ["unavailable"])
        self.assertEqual(verifier.proof_effects, ["unavailable"])
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(len(opened.instance_b.inbox[opened.fsm_b.atom.id]), 1)

        failing_store = _FailingCompletionStore("db row leaked a private witness")
        failing_verifier = _PinnedVerifier(evidence)
        failing_opened = _open(
            policy,
            failing_verifier,
            failing_store,
            session_id="sess_atomic_store_failure",
        )
        failing_proof = _proof(
            policy,
            failing_opened.fsm_a.atom.session_context,
            evidence,
        )
        failing_verifier.pin(failing_proof)
        self.assert_coord_error(
            afp.CoordFailureCode.REPLAY,
            lambda: _receive(
                failing_opened,
                _envelope(
                    failing_opened,
                    failing_proof,
                    sender_role="initiator",
                ),
                policy,
                evidence,
                sender_role="initiator",
            ),
        )
        self.assertEqual(len(failing_store.calls), 1)
        self.assertNotIn(
            failing_opened.fsm_b.atom.id,
            failing_opened.instance_b.inbox,
        )

    def test_concurrent_exact_retransmissions_repair_inbox_once_without_verifier(self):
        case = _PROFILE_CASES[1]
        policy = _policy(case)
        evidence = _evidence(case)
        verifier = _PinnedVerifier(evidence)
        store = _RecordingCompletionStore()
        opened = _open(
            policy,
            verifier,
            store,
            session_id="sess_concurrent_exact_retransmission",
        )
        proof = _proof(policy, opened.fsm_a.atom.session_context, evidence)
        verifier.pin(proof)
        envelope = _envelope(opened, proof, sender_role="initiator")
        accepted = _receive(
            opened,
            envelope,
            policy,
            evidence,
            sender_role="initiator",
        )
        self.assertFalse(accepted.retransmission)
        self.assertEqual(store.completion_count, 1)

        opened.instance_b.inbox[opened.fsm_b.atom.id].clear()
        bundle_calls = len(verifier.bundle_calls)
        proof_calls = len(verifier.proof_calls)
        verifier.bundle_effects.append("unavailable")
        verifier.proof_effects.append("unavailable")
        store.lookup_barrier = Barrier(2)
        results = [None, None]
        errors = [None, None]

        def deliver(index):
            try:
                results[index] = _receive(
                    opened,
                    envelope,
                    policy,
                    evidence,
                    sender_role="initiator",
                )
            except BaseException as error:  # surfaced in the owning test thread
                errors[index] = error

        threads = [Thread(target=deliver, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [None, None])
        self.assertTrue(all(result.retransmission for result in results))
        self.assertTrue(all(result.record == accepted.record for result in results))
        self.assertEqual(len(verifier.bundle_calls), bundle_calls)
        self.assertEqual(len(verifier.proof_calls), proof_calls)
        self.assertEqual(verifier.bundle_effects, ["unavailable"])
        self.assertEqual(verifier.proof_effects, ["unavailable"])
        self.assertEqual(len(store.calls), 1)
        self.assertEqual(store.completion_count, 1)
        self.assertEqual(len(opened.instance_b.inbox[opened.fsm_b.atom.id]), 1)

    def test_sqlite_store_persists_retransmission_and_replay_across_reopen(self):
        case = _PROFILE_CASES[2]
        policy = _policy(case, workflow_instance=_fr(800))
        evidence = _evidence(case)
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "coord-completions.sqlite3"
            verifier_one = _PinnedVerifier(evidence)
            store_one = afp.SqliteCoordCompletionStore(database)
            opened_one = _open(
                policy,
                verifier_one,
                store_one,
                session_id="sess_sqlite_one",
            )
            proof_one = _proof(
                policy,
                opened_one.fsm_a.atom.session_context,
                evidence,
            )
            verifier_one.pin(proof_one)
            completion = _receive(
                opened_one,
                _envelope(opened_one, proof_one, sender_role="responder"),
                policy,
                evidence,
                sender_role="responder",
            )
            self.assertEqual(store_one.completion_count, 1)
            store_one.close()

            store_two = afp.SqliteCoordCompletionStore(database)
            try:
                self.assertEqual(store_two.completion_count, 1)
                reopened = store_two.lookup_completion(policy.workflow_instance_id)
                self.assertIsNotNone(reopened)
                self.assertEqual(reopened, completion.record)
                self.assertEqual(reopened.report, completion.report)
                exact = store_two.record_completion(completion.record)
                self.assertFalse(exact.created)
                self.assertEqual(exact.record, completion.record)
                self.assertEqual(exact.record.report, completion.report)

                verifier_two = _PinnedVerifier(evidence)
                opened_two = _open(
                    policy,
                    verifier_two,
                    store_two,
                    session_id="sess_sqlite_two",
                )
                proof_two = _proof(
                    policy,
                    opened_two.fsm_a.atom.session_context,
                    evidence,
                )
                verifier_two.pin(proof_two)
                self.assert_coord_error(
                    afp.CoordFailureCode.REPLAY,
                    lambda: _receive(
                        opened_two,
                        _envelope(
                            opened_two,
                            proof_two,
                            sender_role="responder",
                        ),
                        policy,
                        evidence,
                        sender_role="responder",
                    ),
                )
                self.assertEqual(store_two.completion_count, 1)
                self.assertNotIn(
                    opened_two.fsm_a.atom.id,
                    opened_two.instance_a.inbox,
                )
            finally:
                store_two.close()

    def test_sqlite_completion_store_rejects_ephemeral_database_modes(self):
        for path in ("", ":memory:", "file:coord?mode=memory&cache=shared"):
            with self.subTest(path=path):
                self.assert_coord_error(
                    afp.CoordFailureCode.REPLAY,
                    lambda path=path: afp.SqliteCoordCompletionStore(path),
                )


class CoordV2ParsingTest(unittest.TestCase):
    def test_low_level_completion_helpers_are_not_public_api(self):
        self.assertFalse(hasattr(afp, "verify_coord_completion"))
        self.assertFalse(hasattr(afp, "verify_coord_final_proof"))
        self.assertNotIn("verify_coord_completion", afp.__all__)
        self.assertNotIn("verify_coord_final_proof", afp.__all__)

    def test_machine_readable_conformance_context_profile_and_policy_kats(self):
        fixture = json.loads(CONFORMANCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(fixture["format"], "afp-coord-v2-cross-org-conformance-v1")
        self.assertFalse(fixture["scope"]["wire_extension"])

        mapping = fixture["context_mapping"]
        for vector in mapping["accepted_kats"]:
            with self.subTest(context=vector["name"]):
                self.assertEqual(
                    afp.derive_coord_context(vector["session_context"]),
                    vector["coord_context"],
                )
        for vector in mapping["rejected_kats"]:
            with self.subTest(rejected_context=vector["name"]):
                with self.assertRaises(afp.CoordVerificationError):
                    afp.derive_coord_context(vector["session_context"])

        profiles = fixture["profile_mappings"]
        self.assertEqual(
            [profile["profile_id_field"] for profile in profiles],
            [case.profile_id_field for case in _PROFILE_CASES],
        )
        self.assertEqual(
            [profile["pinned_profile_manifest_field"] for profile in profiles],
            [case.manifest_hash for case in _PROFILE_CASES],
        )
        self.assertEqual(
            [profile["application_vk_field_hash"] for profile in profiles],
            [case.profile_vk_hash for case in _PROFILE_CASES],
        )

        policy_kat = fixture["acceptance_policy"]["hash_kat"]
        self.assertEqual(
            policy_kat["policy"]["acceptedProfileBindings"][0][
                "profileManifestHash"
            ],
            afp.COORD_PRIVATE_RECONCILIATION_PROFILE_MANIFEST_HASH,
        )
        self.assertEqual(
            policy_kat["policy"]["acceptedArtifacts"][0]["verificationKeyHash"],
            afp.COORD_RECURSIVE_VERIFICATION_KEY_HASH,
        )
        policy = afp.CoordAcceptancePolicy.from_dict(policy_kat["policy"])
        self.assertEqual(policy.to_dict(), policy_kat["policy"])
        self.assertEqual(
            policy_kat["profile_policy_hash"],
            "D_90a1362e9eebb1a4d0bafd4a522d3c786282678dba7890fae092094f57eeb2a3",
        )
        self.assertEqual(policy.policy_hash, policy_kat["profile_policy_hash"])

    def test_final_proof_and_canonical_bundle_parse_detached_immutable_snapshots(self):
        case = _PROFILE_CASES[0]
        policy = _policy(case)
        evidence = _evidence(case)
        source = _proof_wire(policy, _fr(200), evidence)
        expected = deepcopy(source)
        proof = afp.CoordFinalProof.from_dict(source)

        source["proof"][0] = 99
        source["receipt"]["outputCommitment"] = _fr(999)
        source["artifact"]["target"] = "evm"
        self.assertEqual(proof.to_dict(), expected)
        with self.assertRaises(TypeError):
            proof.receipt["outputCommitment"] = _fr(998)
        with self.assertRaises(TypeError):
            proof.artifact["target"] = "aztec"
        detached = proof.to_dict()
        detached["receipt"]["outputCommitment"] = _fr(997)
        self.assertEqual(
            proof.receipt["outputCommitment"],
            expected["receipt"]["outputCommitment"],
        )

        bundle_source = {
            "compliance": {"proofs": []},
            "coord_proof": expected,
            "metadata": {
                "version": afp.BUNDLE_VERSION,
                "generatedAt": GENERATED_AT,
                "expiresAt": EXPIRES_AT,
                "context": _fr(200),
            },
        }
        bundle_expected = deepcopy(bundle_source)
        bundle = afp.ZkaBundle.from_canonical_payload(bundle_source)
        bundle_source["coord_proof"]["proof"][0] = 88
        bundle_source["metadata"]["context"] = _fr(201)
        self.assertEqual(bundle.to_dict(), bundle_expected)
        returned = bundle.to_dict()
        returned["coord_proof"]["proof"][0] = 77
        self.assertEqual(bundle.to_dict(), bundle_expected)


if __name__ == "__main__":
    unittest.main()
