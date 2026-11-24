# Agent Federation Protocol (AFP)

**Version:** 0.3.14-draft
**Status:** Draft Specification
**License:** Apache 2.0
**Normative documents:** the AFP specification set that `docs/afp_specification.md` §11 lists: `docs/afp_specification.md` (core), `docs/afp_routing_specification.md`, `docs/afp_introduction_profile.md` and `docs/kdc_specification.md`

AFP is the protocol layer for verifiable interaction between tenants. A tenant is a runtime that federates as a principal under its own tenant root AID. Federating tenants are independent agent-platform instances and need not run the same platform or any particular vendor's platform. Every tenant must satisfy the AFP tenant conformance profile; a shortfall makes it a non-conforming tenant, not a non-principal. ADAMAS is the reference implementation, not the definition. It defines exactly three relationships:

1. Tenant-to-tenant bilateral work exchange.
2. Tenant-to-operator telemetry by ZKC proof.
3. Identity continuity across operator and topology changes.

AFP v0.3.14-draft uses self-certifying AIDs with KERI semantics and KELs, in the AFP encoding of §4.4.2 (not KERI/CESR wire-compatible), for identity, ZKA v0.9.2-draft bundles for work artifacts, ZKC v0.4.1-draft anonymous/scoped/consented-linkable proofs for compliance and telemetry, scoped-v2 or consented-linkable-v1 proofs for credential rebinding, AFP-KDC v1.0.3 for shared key derivation and fixed-byte ownership metadata while retaining the normative v1.0.2 Poseidon2 parameter and conformance packages, and the AFP Federation Mixnet for OB-2 metadata privacy. The machine-checked composition boundary is family epoch `zka:protocol-family:2026-10-26.1`.

Credential-only exchange uses `afp:credential-envelope:v1` (§12.7.2) to carry a native ZKC presentation and its exact signed APR inside an authenticated encrypted session. A substantive transaction or Coord exchange retains `afp:envelope:v1` over `zka:bundle:v1`; compliance-only ZKA bundles fail `EMPTY_BUNDLE`. The reference includes synthetic conformance adapters; production subject proofs and scoped APR-key binding remain deployment obligations.

Open federation and introduction require scoped ZKC continuity bound to the presenter AID, proof-authenticated credential-subject AID, authenticated APR signer, and AFP session. Telemetry and known-counterparty bilateral flows remain anonymous by default. Every current presentation binds its authoritative trust-flow purpose in `afp:zkc-presentation-context:v2`, whose SHA-256/JCS digest is canonically reduced to a nonzero BN254 scalar; verifiers fail closed on missing subject proof, zero/noncanonical context, or fallback to historical v1. Generic KYC and jurisdiction proofs require a separate issuer-authenticated AID claim or companion subject-binding proof; AFP ships no production adapter for that mechanism, so those credentialing flows remain non-operational without one.

Instance attestation v2 supports three registered root classes: reproducible-build provenance with transparency-log inclusion, TEE remote attestation, and an organizational authority signing manifests for builds it produces. Each verifier selects accepted root classes and authorities in its own policy. The publisher- manifest class is self-attested at the platform layer, not third-party-issued, and carries public-sample-binding and honest-disclosure duties. V1 remains frozen under its original publisher-issued semantics. The operator-facing telemetry predicate catalog stays closed; predicate pluralism applies to bilateral tenant- to-tenant attestation, where each verifier sets its own policy.

The experimental `pay` v1.0 profile binds a bilaterally authenticated USD-minor-unit obligation to an exact WETH-wei quote and the immutable Base ZKA-native WETH pool. The separately versioned experimental `pay_venue` v2.0 profile binds an exact venue, network, asset, recipient, amount, manifest, policy, and holder-disclosed receipt occurrence. Publication makes v2 negotiable but does not qualify a deployment or activate a route; V6, manifest, audit, holder, and APL gates remain independent.

The v0.2.0 marketplace-oriented draft is superseded. Its agent manifest schema, capability-discovery feed, task-delegation broker, observation contribution, reputation accumulation, trust ladder, NKey identity, and HTTP bridge are retired and must not be implemented as current AFP. That narrowing followed one implementation's product scope, not a property of federation: a fully open, multi-platform ecosystem would have to re-add most of that surface, and a discovery feed in particular is in direct tension with the coordination-graph privacy AFP guarantees. AFP does not carry that surface today.
