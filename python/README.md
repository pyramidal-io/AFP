# AFP Python Reference Packages

Reference implementations for the **Agent Federation Protocol (AFP)**, using stdlib-only, flat-package, `unittest`-discovered conventions shared by the protocol family.

## `afp_session` — AFP §12 Bilateral Session Core

A complete, tested reference implementation of the **Bilateral Session Core** (AFP specification §12) — the substrate the VXP, PRP, and `work` profiles (§13) all build on. Everything is **standard-library only** (no third-party crypto): cryptography is real, not mocked.

### What it implements

| §12 concern | Module | Status |
|---|---|---|
| KERI AID + KEL verification to the tenant root (§4 / §12.3) | `keri.py` | Full (minimal verifiable subset) |
| Session lifecycle propose→open→active→closing→closed, abort/expire, timeout (§12.2) | `session.py` (`SessionFSM`, `Instance`) | Full |
| `afp:envelope:v1` over an opaque `zka:bundle:v1` (§12.7) | `atoms.py`, `bundle.py` | Full envelope; bundle proofs opaque (seam) |
| Native `afp:credential-envelope:v1` credential-only carriage (§12.7.2) | `credential.py`, `session.py` | Signed/sealed native ZKC presentation + APR; injected ZKC verification and receive-issued capability, no ZKA bundle |
| Coord v2 PRP/VXP completion acceptance (§12.7.1) | `coord.py`, `session.py` (`receive_coord_completion`) | Full AFP policy/context/evidence/durable-completion boundary; ZKA proof verification is an explicit seam |
| NATS namespace `afp.{tenant}.{profile}.*` (§12.4) | `namespace.py`, `transport.py` | Full; in-memory transport + nats-py seam |
| Bilateral dispute + optional pre-agreed arbiter (§12.5) | `dispute.py` | Full |
| Commitment + optional anchor (§12.6) | `commitment.py` | Full; APL on-chain submission is a seam |
| Profile registry (§13.2) | `profiles.py` | Full |
| ZKC v0.4 flow policy + AID/credential/APR/session binding (§5.9) | `presentation.py` | Full AFP boundary; ZKC proof verification is an explicit seam |
| AFP-KDC v1.0.3 field tags + external fixed-byte ownership validation (Appendix A; v1.0.2 cryptographic profile retained) | `kdc.py` | Full, KAT/collision checked |
| Entity-to-entity sealed channel (`afp:sealed:v1`) | `channel.py` | Clean-room SHA-256-CTR/HMAC reference; KEL-bound bilateral establishment, replay window, and terminal close-on-rotation |
| Honest OB-1/OB-2 disclosure conformance (§3.5 / §8.9) | `conformance.py` | Evidence-gated reference guard; OB-1 requires a receiver-minted sealed-transit capability |
| Ed25519 (RFC 8032) signing/verification | `ed25519.py` | Full; strict boundary + executable backend conformance gate |

### Quick start — the acceptance criterion

Two in-process instances open a real bilateral session, exchange a signed, signature-verified envelope, and close:

```python
import os

import afp_session as afp
from afp_session import kdc, keri

transport = afp.InMemoryTransport()

# Two ADAMAS instances: a tenant root + delegated entity AID each (§4).
tenant_a = keri.Identity.incept_tenant(); entity_a = keri.Identity.incept_entity(tenant_a)
tenant_b = keri.Identity.incept_tenant(); entity_b = keri.Identity.incept_entity(tenant_b)
A = afp.Instance(tenant=tenant_a, entity=entity_a, transport=transport)
B = afp.Instance(tenant=tenant_b, entity=entity_b, transport=transport)
remote_a = afp.RemoteParty(entity_a.kel, tenant_a.kel, witness_keys={})
remote_b = afp.RemoteParty(entity_b.kel, tenant_b.kel, witness_keys={})

# propose -> open (mutual KERI authentication up to each tenant root, §12.3)
fsm_a = A.propose(responder_tenant_aid=tenant_b.aid, responder_entity_aid=entity_b.aid, responder_remote=remote_b,
                  agreement_ref="agr", agreement_version="1",
                  profile="work", profile_policy_hash="h")
fsm_b = B.accept(fsm_a.atom, initiator_remote=remote_a)
A.confirm_open(fsm_a, fsm_b.atom, responder_remote=remote_b)

# Establish the mandatory session-bound entity channel (§5.2). In deployment,
# each M' comes from that entity's KDC hierarchy, never from shared material.
binding = afp.ChannelBinding.from_session(fsm_a.atom)
endpoint_a = afp.ChannelEndpoint.create(
    binding, afp.ChannelRole.INITIATOR,
    kdc.derive_entity_subseed(os.urandom(32), "entity-a"), entity_a)
endpoint_b = afp.ChannelEndpoint.create(
    binding, afp.ChannelRole.RESPONDER,
    kdc.derive_entity_subseed(os.urandom(32), "entity-b"), entity_b)
channel_a = endpoint_a.establish(endpoint_b.attestation, remote_b)
channel_b = endpoint_b.establish(endpoint_a.attestation, remote_a)

# active -> exchange a signed envelope inside an authenticated sealed frame.
# AFP keeps the X_ digest in the envelope and projects it exactly once for the
# ZKA field slot; `verify_zka_bundle` sees that canonical field-valued bundle.
bundle = afp.ZkaBundle(kind="zka:bundle:v1",
                       context=afp.session_context_field(
                           fsm_a.atom.session_context),
                       coord_proof="opaque")
envelope = A.send_envelope(
    fsm_a, bundle=bundle, message_class="result", channel=channel_a)
B.receive_envelope(
    fsm_b, transport.published[-1][1], message_class="result",
    channel=channel_b, sender_remote=remote_a,
    bundle_verifier=verify_zka_bundle)  # opens, then verifies §12.7

# close (§12.2.2)
A.close(fsm_a); B.close(fsm_b)
```

Low-level profile integrations can call the exported `verify_party_ref(ref, content_hash, remote)` helper to apply the same §12.3 KEL-current, delegated-identity, witness-threshold, and Ed25519 checks without duplicating session-core cryptography. Session proposal creation and value-transfer profiles require `RemoteParty.witness_keys` explicitly; `{}` is valid for a threshold-zero KEL. Value-transfer integrations also obtain a `VerifiedLiveSession` from `Instance.verified_live_session(fsm)` after a normal ACTIVE transition; they do not authorize payment from a caller-rewritable raw session status field. The handle remains bound to that live `Instance`: each access rechecks the exact owned FSM and the owner's clock, so close, abort, or expiry invalidates it. Do not serialize or persist the handle. After restart, rehydrate the durable session/FSM, restore lifecycle provenance, and mint a new handle.

`Instance(profile_registry=...)` accepts a `ProfileRegistry` containing the profiles recognized by that party's governing agreement; omitting it selects `default_registry()`, the published set. Bilateral extensions need an `AfpProfileDescriptor` registered on each party. Proposal, acceptance, and envelope operations reject a profile absent from that instance's registry before signing, activation, or transport publication. `session` and `telemetry` are operational subject families, not bilateral session profiles. Low-level `namespace.subject` calls must pass an explicit Boolean `registered=` result; only the core/operational `work`, `session`, and `telemetry` labels have implicit registration. `is_conforming_subject` checks the supplied registry or the published set by default. Tenant labels are single nonempty tokens without separators or wildcards, and bilateral messages use the sender's own tenant label (§12.4).

PRP and VXP integrations use that same live-session capability with `Instance.receive_coord_completion`. The method receives sealed channel bytes and an established `SessionChannel`; it authenticates and opens the channel before parsing the signed envelope. An idempotent completion retry carries the same canonical envelope inside a fresh channel frame, because replaying a consumed sealed frame is rejected by the channel. A deployment constructs the receiving `Instance` with one `CoordCompletionVerificationContext`, which binds its `CoordFinalProofVerifier` and `CoordCompletionStore`; the receive call cannot replace either capability. The method accepts only a canonical, unexpired `zka:bundle:v1` containing one Coord v2 final proof under the existing `result` message class and profile-defined direction. That pure Coord bundle has exactly `compliance`, `coord_proof`, and `metadata`, with `compliance == {"proofs": []}`; transaction, binding, compliance aggregation/proofs, null placeholders, and unknown members are rejected as side channels. It derives the proof-system context from the signed AFP context, compares the exact `D_` policy hash committed at session open, pins the selected profile version/manifest/VK and recursive artifact/VK, and requires exactly one verifier-local reference for each nonzero receipt evidence commitment—no extras—before asking the same configured verifier to authenticate the complete bundle, final proof, and admitted evidence.

After verification, the receiver revalidates the active authenticated session and the completion store atomically writes the replay tuple and canonical envelope bytes as one authoritative durable effect; an abort or expiry observed while a verifier was running records nothing. `Instance.inbox` is an idempotent projection that an exact retransmission can repair after a restart. Once session authentication, structural/freshness checks, and policy binding reproduce a byte-identical durable record, recovery does not depend on the verifier or evidence backend still being available. `SqliteCoordCompletionStore` is the durable stdlib reference and rejects SQLite memory/temporary modes, while `InMemoryCoordCompletionStore` is explicitly process-local test support. Byte-identical retransmissions create no second record or inbox effect; changed envelopes, receipts, policies, evidence references, directions, parties, or cross-session uses fail terminally. The Coord receive decoder requires exact envelope and sender member sets, rejects duplicate JSON names, and stops non-finite timestamps at the redacted session boundary. The generic `receive_envelope` path rejects a PRP/VXP `coord_proof`, so it cannot bypass completion policy or replay enforcement. Only the configured verifier's exact typed temporary-unavailability outcome is retryable for an unseen completion. A typed `CoordVerifierRejected` may preserve one exact allowlisted terminal ZKA code; unsupported codes, extended failure bodies, plain exceptions, and backend text collapse to a redacted verifier failure.

### Native credential-only exchange

For pre-transaction credentialing, use `Instance.build_credential_envelope`,
`seal_credential_envelope` or `send_credential_envelope`, then
`receive_credential_envelope` with the session's established channel. The wire
contains the complete native `zkc:proof:v1` or `zkc:proof:v2` JSON presentation
and exact signed APR. It contains no `ZkaBundle`; a compliance-only ZKA bundle
still fails `EMPTY_BUNDLE`. The existing substantive envelope API is unchanged.

Native receive takes the verifier's authenticated `expected_flow` and
`RequiredPredicatePolicy`. Its required `credential_verifier` receives immutable
canonical envelope bytes and authenticated session/party/policy comparands and
returns `NativeCredentialVerification` binding that content hash to structured
`ZkcPresentationEvidence` and `ZkcVerifiedPublicStatement`. The adapter must
verify the exact proof and APR, derive the credential subject and public meaning,
and enforce native schema, issuer trust, freshness and consent. An absent
verifier, boolean result, wrong subject/context/predicate, callback mutation or
exception fails closed. AFP supplies no production ZKC subject-AID adapter;
the test adapter verifies synthetic signed statements and is explicitly not a
ZKC circuit implementation.

The scoped profile needs an explicit deployment APR signer binding resolver:
the KERI reference has 32-byte Ed25519 keys, while ZKC's frozen scoped identity
derivation consumes a 33-byte SEC1-compressed APR signer key. No key conversion
is performed. The typed binding must independently establish the key's current
KEL/AID association; the native adapter must authenticate the APR under it.
Missing/stale/substituted binding fails closed. The package supplies no
production binding adapter, and synthetic scoped fixtures do not qualify one.

Successful receive returns an `AcceptedCredentialEnvelope`. Revalidation with
`require_verified_native_credential` checks the issuing instance, retained
record and live session; accessors return detached snapshots. Re-delivery of
the same signed carrier in a fresh sealed frame is rejected without another
inbox effect. Failed crypto does not activate an OPEN session. This replay ledger
and capability are process-local, so they are not durable evidence or authority
after restart.

The Introduction Tier consumes that capability using
`evaluate_native_credentialing`, then
`IntroductionFSM.present_native_credentials`. Its policy evaluation compares the
exact requested predicate set, signed accepted roots, offer and attestation
window without constructing a ZKA bundle. Both calls require the verifier's explicit `expected_session_profile`, compared
to the authenticated native session. The existing canonical introduction
descriptor uses `afp.introduction`, which the reference's single-token namespace
does not currently admit; its namespace/registration repair remains companion
work. Tests use a declared synthetic one-token profile and do not qualify that
canonical introduction deployment. The verified sender's KERI delegation
maps the entity presenter to the tenant-level introduction parties. Historical
`CredentialPresentation`/`evaluate_credentialing` remain for explicitly versioned
legacy comparison artifacts; they do not provide a native wire alias.

### Mandatory Ed25519 verification boundary

Every session-core, KEL-witness, mixnet-directory, payment, and ceremony
signature consumer in these packages routes through `ed25519.verify_strict`.
That boundary accepts only exact octet inputs, canonical encodings for both the
public key `A` and signature point `R`, prime-order membership for both points
(therefore rejecting identity, torsion, and mixed-order points), and a canonical
scalar `S < L`. External public keys MUST also pass
`ed25519.validate_public_key` when they enter a KEL, witness, directory, payment,
or authority trust boundary; validating only when one signature happens to be
checked is not a substitute for rejecting invalid trust material at ingestion.

A production deployment MAY substitute an independently audited Ed25519
implementation for the reference arithmetic, but its `(message, signature,
public_key) -> bool` adapter MUST preserve all of the strict semantics above and
MUST pass `ed25519.validate_verifier_backend` during build or startup. Raw
library acceptance is not an AFP verification boundary. The gate requires exact
Boolean results, valid RFC 8032 known-answer signatures for empty and non-empty
messages, and non-vacuous
negative vectors covering exact input lengths, tampering, all eight torsion
encodings in `A` and `R`, identity, non-canonical points, independent
mixed-order `A` and `R`, and scalar malleability via a valid signature with
`S + L`. Passing the finite suite is required and does not replace an
independent audit. The public
`tests/python/test_ed25519.py` suite also inventories every repository consumer;
a new or migrated consumer that bypasses `verify_strict` fails CI.

### Documented seams (AFP frames/binds; a lower layer proves)

These are intentional, spec-aligned boundaries — AFP "never reimplements a primitive that ZKA, ZKC, or KERI already defines" (§2.2):

- **ZKA prover** — `zka:bundle:v1` proofs are carried verbatim and treated as opaque (§12.7); a real ZKA verifier plugs in via the `bundle_verifier` seam in `verify_bundle` / `Instance.receive_envelope`.
- **ZKC v0.4 verifier** — `presentation.verify_presentation_binding` enforces AFP's flow, KERI AID, credential-subject, APR signer, scope, profile, context, carrier-version, and handle-minimization rules. A deployment supplies the real ZKC verifier callback that validates proof/APR cryptography and returns the verified public statement; AFP does not reimplement ZKC circuits.
- **ZKA prover** — `zka:bundle:v1` proofs are carried verbatim and treated as opaque (§12.7); a real ZKA verifier runs through the **required** `bundle_verifier` seam in `verify_bundle` / `Instance.receive_envelope`. After checking the exact bundle, the callback returns `BundleVerificationResult.accepted(bundle)` or `BundleVerificationResult.rejected(bundle)`, which binds the verdict to that bundle's canonical content hash; raw booleans, truthy substitutes, mismatched receipts, and callback mutation fail closed. §12.7 verification is two-layer, so the parameter has no default: an absent verifier fails closed rather than passing on the structural checks alone.
- **ZKC v0.4 verifier** — `presentation.verify_presentation_binding` enforces AFP's flow, KERI AID, credential-subject, APR signer, scope, profile, context, carrier-version, and handle-minimization rules, and binds *meaning*: the predicates a presentation proves must satisfy the caller's `RequiredPredicatePolicy` for the authenticated `expected_flow` (§6.3/§6.3.1/§14.4). `presentation_proof_context` first requires the original session value to be a canonical nonzero-projecting `X_` digest, retains that original value in the v2 JCS record, folds the authoritative flow into the exact `afp:trust-flow:<flow>` purpose, hashes the JCS bytes with SHA-256, and canonically reduces the big-endian digest modulo the BN254 scalar modulus; zero is rejected without fallback or rehash. Current verification rejects legacy v1, missing-purpose, cross-flow, malformed session, noncanonical-field, and zero contexts. A deployment supplies the real ZKC verifier callback that validates proof/APR cryptography. It returns a structured `ZkcVerifiedPublicStatement` only when the verified proof context, proof-authenticated credential-subject AID, and predicate set match the evidence and caller-authenticated responder exactly; rejection returns `None`, never a caller-asserted boolean. The subject AID must come from an issuer-authenticated claim or independently verified companion proof, not an echoed evidence label; generic ZKC KYC and jurisdiction profiles do not establish it alone. This package ships no production adapter or companion profile—its fixed-subject callbacks are synthetic fixtures—so a deployment with only those generic profiles must reject and cannot claim the introduction/open-federation credentialing path is operational. Rotation-rebind declarations fail closed because this reference path has no cryptographic §4.6.2 verifier. AFP does not reimplement ZKC circuits.
  `presentation_conformance.run_presentation_conformance(verify)` runs the §5.9 identity, purpose, and meaning vectors against a supplied verifier, so a flow-blind or meaning-blind implementation fails conformance. A vector rejected by the reference types during construction is `NOT_EXERCISED`, never a verifier pass: `not_exercised()` lists these coverage gaps separately from `failures()`, and any gap makes `.conforms` false. The unknown-root-class vector currently has this limitation, including for the reference verifier. `summary()` reports both counts. `docs/afp_presentation_public_input_classification_v1.json` states, per field and per profile, which public inputs are bound, derived, or free.
- **Poseidon2** — the in-circuit `outcome_root` hash (§12.6.1) uses SHA-256 in this reference (`commitment.outcome_root_for`); a ZK-bound deployment substitutes the Poseidon2 root. The bilateral-signature / chaining / opacity semantics are hash-agnostic.
- **§8 mixnet wire form** — the in-memory transport models *logical* delivery; the §8 Sphinx/cover-traffic mixnet that delivers OB-2 is now a real reference package, **`afp_mixnet`** (below). `transport.NatsTransport` remains the nats-py seam for the underlying link, and `conformance.py` enforces honest OB-2 disclosure — now driven by the live `afp_mixnet` conformance assessment.
- **APL on-chain anchor** — `commitment.anchor_commitment` builds the verifier-facing `afp:anchor:v1`; the actual L2 submission is an APL concern.
- **Tenant-root key recovery (§4.6)** is an AFP §10 open item with no event to implement. An entity is recovered by revocation and re-delegation (`Identity.revoke_delegation`).
- **KEL encoding (§4.4.2)** is AFP's own normative encoding (`E_`/`D_`/`K_` qualified values, RFC 8785 JSON, SHA-256, domain-separated controller signatures and receipts), with published known-answer vectors. It is not KERI/CESR wire-compatible; that is an AFP §10 open item.
- **KEL retrieval (§4.5)** — the reference does not query witnesses or watchers; callers supply the KEL state they obtained. Each `Instance`, or a caller-supplied `keri.KelStateStore` on `RemoteParty.kel_state`, retains the latest verified KEL per AID, including a tenant KEL whose revocation rejected an entity. It rejects a truncated KEL as `kel_keystate_stale` and a fork as duplicity, except KERI superseding recovery, where a `rot` replaces an `ixn`. An `Instance` always consults its own store and attaches it to a `RemoteParty` that carries none. A fresh verifier with no retained state cannot detect truncation on its own; that is what witness retrieval is for.
- **§5.2 channel encryption / production AEAD** — `channel.py` is a clean-room `afp:sealed:v1` reference using SHA-256-derived CTR encryption plus HMAC authentication so the package remains standard-library-only. Production deployments substitute an independently audited AEAD, such as AES-GCM or ChaCha20-Poly1305, while preserving the channel’s authenticated-binding semantics under a separately named and versioned production suite. Each establishment uses fresh ephemeral X25519 scalars that the KEL-current key only authenticates, so a later `M'` or signing-key compromise does not decrypt recorded channels. A KEL rotation invalidates the channel binding: implementations MUST close the channel and establish a fresh one against the rotated KEL state; they must never continue or silently rekey an existing channel.
  A successful authenticated receive also mints a short-lived, process-local `SealedChannelAttestation`; the OB-1 disclosure guard revalidates that evidence and rejects caller-supplied booleans.

## `afp_mixnet` — AFP §8 Federation Mixnet (OB-2 routing)

A tested, **standard-library-only** reference implementation of the **Metadata-Privacy Routing** layer (AFP §8) — the Loopix-family mixnet that delivers **OB-2** (coordination-graph privacy, §3.1). It carries `afp_session` envelopes through a real, multi-hop Sphinx mixnet, and it is the live source of truth the OB-1/OB-2 disclosure guard consults.

### What it implements

| §8 concern | Module | Status |
|---|---|---|
| **Sphinx packet format** — layered encryption, per-hop blinding (unlinkability), per-hop MAC == replay tag, fixed size (§8.4) | `sphinx.py` (+ `crypto.py`) | Full, real X25519 (RFC 7748) roundtrip |
| `afp.mixnet.profile.ob2-baseline.v1` + "not weaker than baseline" check (§8.4) | `profiles.py` | Full |
| **KERI-witnessed mix-node directory** (§8.7), reusing `afp_session.keri` witnesses | `directory.py` | Full (quorum receipts + §8.6 operator constraints) |
| Mix node: peel one layer, exponential mixing delay, replay detection (§8.4/§8.6) | `mixnode.py` | Full |
| **Mandatory cover traffic** — constant-rate emission, REAL/COVER indistinguishability (§8.5) | `cover.py` | Full |
| Stratified mixnet: route selection (one node/layer, ≥3 hops) + transit | `network.py` | Full, with per-hop observation log |
| **§8.2 conformance test** over real transit/cover artifacts | `conformance.py` | Properties 1/4 + cover **proven**; property 2 **proven** with a same-path, distinct-session comparison (**partial** for one transit); property 3 honestly **partial** (asymptotic bound = §8.10 seam) |
| Route an `afp_session` envelope through the mixnet + honest OB-2 disclosure wiring | `integration.py` | Full |

### Quick start — the acceptance criterion

A running mixnet meeting the §8.2 conformance properties carries AFP session traffic, and OB-2 then becomes *honestly* claimable:

```python
import afp_mixnet as mix
# (build a KERI-witnessed 3-layer directory + running mix nodes; see
#  tests/python/mixnet_fixtures.py:build_mixnet)

# Build and sign the session's afp:envelope:v1, seal it as afp:sealed:v1, then
# slot the resulting sealed frame into the tenant's mandatory cover stream and
# route it through the mixnet (>= 3 hops) to the recipient's rendezvous handle:
cover = mix.CoverScheduler(); cover.run_slots(4)  # constant cover while idle (§8.5)
result = mix.send_envelope_via_mixnet(
    sender=A, fsm=fsm_a, bundle=bundle, message_class="result",
    receiver=B, receiver_fsm=fsm_b, sender_remote=remote_a,
    sender_channel=channel_a, receiver_channel=channel_b,
    mixnet=mixnet, sender_cover=cover, recipient_entity_aid=entity_b.aid,
    bundle_verifier=verify_zka_bundle,
)
# B verified the envelope via the unchanged §12.7 path after transit.

# `comparison_result` carries a fresh AFP session for the same endpoints over the
# same relay path (see test_mixnet_acceptance.py for the complete setup). The
# honest OB disclosure now legitimately reads OB-2. It falls back to OB-1 if a
# §8.2/§8.5 precondition or the comparison is removed, and to no OB level if the
# sealed-channel capability is absent, expired, or bound to another session/KEL:
claim = mix.ob_claim_for_mixnet(
    name="ob2-pilot",
    channel_encryption_operational=result.channel_attestation,
    channel_session_context=fsm_a.atom.session_context,
    channel_kel_event_dig=fsm_a.atom.initiator.kel_event_dig,
    directory=directory,
    transit_log=result.transit_log, scheduler=cover,
    originator=entity_a.aid, recipient_handle=handle.hex(),
    comparison_logs=(comparison_result.transit_log,))
assert claim.claimed_level.value == "ob-2"
```

### Documented seams (honest — per §8.10 and the requirement)

- **Clean-room reference stream cipher** — `crypto.stream_xor` is a SHA-256-CTR keystream (stdlib has no AES). The Sphinx **construction** (layering, blinding, unlinkability, replay tags) is what this package proves and is cipher-agnostic; a production deployment substitutes audited AES-CTR / ChaCha20.
- **Clean-room §5.2 channel AEAD** — mixnet integration carries an already sealed `afp:sealed:v1` frame. Its end-to-end recipient confidentiality comes from `afp_session.channel`, independently of Sphinx's source-layered, per-relay onion protection. The standard-library reference uses SHA-256-CTR plus HMAC; a production deployment substitutes a separately named, independently audited AEAD suite without treating Sphinx as the entity channel.
- **Rendezvous candidate resistance** — the clean-room helper's unkeyed digest demonstrates per-session non-stability and absence of a cleartext AID encoding, not resistance to offline testing of known candidate inputs. A deployment claiming that stronger property derives destination values with bilateral secret material.
- **Message fragmentation** — §8.4 fragments large messages across Sphinx packets; this reference carries one 4 KiB payload class and raises if an envelope exceeds it (a deployment seam, flagged not faked).
- **Long-horizon statistical disclosure** (§8.2 property 3 / §8.10) — the *mechanism* (exponential mixing + fixed-size + cover traffic) is proven present; the asymptotic anonymity bound against a global passive adversary is a Loopix-family analytic property, declared a **seam**, never unit-test-"proven". `conformance.py` reports it as `partial`, not `proven`.

## `afp_introduction` — AFP §14 Introduction Tier

A tested, **standard-library-only** reference for the **Introduction Tier** (AFP §14) — stranger onboarding over the §12 core. Two ADAMAS instances with no prior relationship run a credential + ZKC-proof handshake that auto-negotiates a scoped, **collateral-priced** provisional §5.5 agreement, grow the envelope with provable history, graduate, and degrade/terminate safely — composing §8 OB-2 routing and inheriting the §12.8 Freedom Safeguards.

### What it implements

| §14 concern | Module | Status |
|---|---|---|
| The seven `afp:introduction-*` atom kinds + content addressing (§14.1–§14.7) | `atoms.py` | Full (reuses `afp_session` canonical hashing + `AfpCommitSignature`) |
| Willingness-to-federate directory — openness, **not** pairing; epoch binding (§14.1) | `directory.py` | Full; KERI witness-quorum verification is the §8.7-shared seam |
| Handshake FSM PROPOSED→…→ACTIVE, decline-not-freeze, unconditional abort (§14.3) | `handshake.py` | Full |
| Envelope growth (clean-reputation gated, curve-capped) + graduation (§14.4/§14.6) | `agreement.py` | Full mechanism; the ZK reputation *circuit* is a seam |
| Collateral-priced floor (ZKA-direct **or** bonded) + escrow-bounded recourse (§14.5/§14.7) | `settlement.py` | Full; on-chain escrow submission is a seam |
| §14 conformance properties with honest `proven`/`seam` verdicts (§14.9) | `conformance.py` | Floor + no-clawback + safeguards **proven**; reputation circuit honestly **seam** |

### Quick start — the acceptance criterion

```python
import afp_introduction as intro
from afp_introduction.handshake import State

fsm = intro.IntroductionFSM.propose(initiator="EtenantA", responder="EtenantB")
fsm.open_credentialing(
    request=request, session_context=session_context
)                                           # PROPOSED -> CREDENTIALING (§14.3)

# CREDENTIALING is a comparison, not a report. The deployment callback receives
# this exact opaque presentation, verifies its ZKA/ZKC bundle, and derives its
# presenter, session, and proven predicates from the cryptographic public statement.
def verify_credential_presentation(exact_presentation):
    # Return None on rejection, or intro.VerifiedCredentialPresentation(...)
    # carrying this exact bundle object and facts derived from its verified proofs.
    # Never return a caller-supplied boolean or trust presentation labels.
    ...

# AFP compares the verifier-issued facts to the request and signed §14.4 policy,
# then issues the sealed decision the FSM accepts.
decision = intro.evaluate_credentialing(
    request=request, presentation=presentation, policy=policy, offer=offer,
    expected_session_context=session_context,
    presentation_verifier=verify_credential_presentation,
    root_authority_resolver=resolve_root_authority)
fsm.present_credentials(
    decision=decision, request=request, presentation=presentation
)
fsm.agree_envelope(requires_bond=True)      # scoped envelope agreed -> BONDING
fsm.post_bond()                             # collateral posted -> ACTIVE
assert fsm.state is State.ACTIVE

# The §14 conformance assessment is conservative + honest: it reports
# fully_operational only once all three lower-layer seams are live (§14.9).
report = intro.assess_introduction(
    interactions=[("zka_direct", "100", "0"), ("bonded", "50", "100")],
    slash_arbiter_cosigned=True,
    reputation_circuit_operational=False,
    instance_attestation_v2_operational=False,
    escrow_operational=False)
assert report.property("14.5").status.value == "proven"      # collateral-priced floor
assert report.property("14.6").status.value == "seam"        # reputation circuit not yet live
assert report.fully_operational is False                     # honest disclosure (§14.9)
```

### Documented seams (AFP frames/binds; a companion req proves)

Honest, per §14.9 and the §3.5/§8.9 disclosure discipline:

- **ZK reputation circuit (§14.6)** — the clean-history growth *mechanism* is proven; the actual `ZKA/Reputation` proof is companion work, declared a **seam**, never unit-test-"proven". `conformance.py` reports it as `seam` and `fully_operational` stays False until it is operational.
- **On-chain bilateral escrow + arbiter (§14.5/§14.7)** — the floor + recourse *semantics* (bonded ≤ collateral; slash bounded to escrow + arbiter co-sign, never base-layer) are proven; the escrow contract/submission is a companion req (ADAMAS.Network / ZKA escrow). `conformance.py` requires an explicit `escrow_operational=True` before reporting the profile fully operational.
- **Instance-attestation circuit (§14.2)** — the credential is the §6.3 `afp.telemetry.instance_attestation.v2` predicate under a signed accepted-root policy; the ZKC credential/schema realization is a companion req. The handshake carries the `zka:bundle:v1` verbatim and treats its proofs as opaque (the §12.7 ZKA-prover seam). `conformance.py` requires an explicit `instance_attestation_v2_operational=True` before reporting full operation.

## `afp_payment` — AFP §15 USD Obligation / WETH Settlement

A tested, **standard-library-only** reference for the experimental `pay` v1.0 profile. It authenticates a USD-minor-unit commercial obligation and an exact WETH-wei quote, binds both to a live AFP session and the configured immutable Base ZKA pool, rejects replay, and tracks monotonic settlement finality.

The package implements canonical quote/policy hashing, the pinned ZKA/Pay Poseidon2 interaction-context fold (§15.4, ADR-0006 — it reads `docs/kdc_v1_0_2_poseidon2_parameters.json` at derivation time; override the path with `AFP_KDC_POSEIDON2_PROFILE`), deterministic ceiling-rate arithmetic, bilateral KERI signatures, in-memory and SQLite replay stores, finality-aware receipts, and interaction-local failure semantics. Route dispatch (`PaymentReceiptVerificationContext.route_from_accepted`) requires the live-session capability and the context's deployment-owned `clock`, and refuses a claim outside the quote window or after the session ends. A party that learns of a transaction late claims it with `route_from_observation`, which needs no live session or clock but requires the accepted policy, a receipt that matches the route, finality at the policy's `required_finality`, and verified inclusion strictly before `expires_at`; a rejected observation does not consume the claim. The injected finality verifier receives the quote's `expires_at` and must prove inclusion strictly before it. For v1 it must also prove, from the chain, the payment's `interaction_context`, the pool context and a single payment per transaction, plus the payee's slot-0 note disclosure. Both replay ledgers let one transaction settle at most one accepted quote. `AcceptedPaymentQuote` seals the live session's `profile_policy_hash`; the tracker rejects any other policy, and dispatch rejects a session under another policy. It does not price the obligation, verify a ZKA proof, submit a transaction, or custody funds: AFP owns quote semantics, ZKA owns private settlement and pool state, and APL owns route execution and finality observation.

The launch policy is deliberately narrow: Base chain ID `8453`, Base WETH9, one separately deployed immutable single-asset pool, and `zka:asset-risk:s3-hard:v1`. Each additional asset requires its own deployment and risk profile. A native stable unit is an independent future protocol, not a dependency of AFP `pay` or the Base WETH launch.

## `afp_ceremony` — AFP §4 / §6.3.1 Attestation-Authority Key Ceremony

Tooling for an organizational attestation root authority: an organizational root AID, a delegated product-scoped publisher AID anchored in the organizational KEL (§4.2), the `afp:publisher-key-state:v1` record and its `root_material_digest` (§6.3.1, with a real RFC 8785 JCS canonicalizer), and `afp:authority-trust-material:v1` — the out-of-band material a verifier accepts into its verification policy, pinning the witness set and threshold §6.3.1 requires. It is deliberately **not** `afp:witness-bootstrap:v1`, which is tenant-scoped; an authority is not a tenant (§2.1). Note the asymmetry: `afp:publisher-key-state:v1` is fixed by §6.3.1 field for field, while `afp:authority-trust-material:v1` is this project's own encoding of material AFP requires a verifier to hold but defines no shape for. Staging-only scratch artifacts are namespaced `x-afp-staging:`, outside the protocol namespace.

**This package performs a NON-PRODUCTION staging dry run only.** Pyramidal Inc.'s organizational root AID has not been incepted and is not created here; the production ceremony is an air-gapped human event under the published ceremony runbook and custody policy. `scripts/run_key_ceremony.py` refuses to run without `--staging` and refuses outright when `CI` is set, every emitted artifact carries a non-production marker enforced on construction as well as on load, all staging key material derives from a phrase published in `staging.py`, and the emitter refuses any in-repo `--out` that git does not ignore.

What the run genuinely establishes: self-certifying AID derivation, controller signatures on every KEL event under the key set that authorizes it (§4.4), pre-rotation enforcement, delegation and rotation anchoring (including refusing an unanchored delegated rotation and an ambiguous delegation anchor), witness receipt thresholds, and digest determinism — all on real RFC 8032 Ed25519. What it does
**not**: CESR/qb64 wire interoperability (the run uses AFP's §4.4.2 encoding, not KERI's), M-of-N `kt`/`nt` signing custody (the reference KERI subset is single-signing-key), resolving explicit or weighted `kt`/`nt` from KEL state (the current §4.4.2 encoding instead fixes both signing thresholds to `"1"`), an organizational root-key rotation, guardian/recovery events, or walking witness KELs. `conformance.py` reports each of those as a seam and never reports the production ceremony as performed.

## Running the tests

```bash
python3 -m unittest discover -s tests/python -t tests/python -v
# or, as CI runs it:
coverage run -m unittest discover -s tests/python -t tests/python -v && coverage report --include="*/afp_session/*" --include="*/afp_mixnet/*" --include="*/afp_introduction/*" --include="*/afp_payment/*" --include="*/afp_ceremony/*"
```


### Published experimental payment venue profile

`afp_payment.venue` implements the [payment venue v2 profile](../docs/payment_venue_profile_v2.md)
as standard-library-only, offline reference code. `VenueDeployment` pins the
trusted Aztec/L1 asset, portal, class, instance, manifest and profile tuple;
`VenueSettlement` signs the exact recipient and atomic amount. V2 quote/policy
hashing retains the existing canonical hash and interaction-context algorithms.
The existing Base v1 classes, parsers, descriptor and fixed vectors are unchanged.

`venue_profile_descriptor()` and `default_registry()` expose the published
experimental descriptor for bilateral negotiation. Registry presence does not
activate a route, and the acceptance API does not consult the registry.
`sign_payment_quote` and `accept_payment_quote` support the
v2 types only with the matching session profile and policy. V2 quote content
commits the complete policy hash. The shared receipt
verification context selects `PaymentRouteEvidenceV2` from the accepted quote;
`AfpPaymentReceiptV2` echoes the full settlement, pins a verified note/log
occurrence across finality advancement, and requires a trusted injected
finality verifier. No Aztec RPC, contract deployment, manifest attestation or
production route activation is implemented. The synthetic conformance fixture
is not a live target. Normative publication and qualification gates are stated
in AFP 0.3.12-draft §15.9.
