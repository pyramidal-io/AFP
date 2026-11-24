# AFP — Concept Brief

*Working draft v0.1 — what the Agent Federation Protocol is, why it exists, and what makes it different from the federation models it replaces.*

---

## The claim

**AFP is the protocol layer that lets two organizations' agent systems work together without trusting the network they meet on, the operator that runs it, or each other beyond what the work actually requires.**

Identity is self-certifying. Confidentiality is structural: end-to-end encryption protects work content (OB-1), while the §8 routing properties protect the coordination graph (OB-2) within the §8.10 limits. Federation membership remains visible; mixing and cover traffic mitigate but do not eliminate long-horizon statistical disclosure, especially in small federations.

---

## What it is

AFP is an open specification for federation between tenants. A tenant is any runtime that federates as a principal under its own tenant root AID; federating tenants are independent agent-platform instances and need not run the same platform or vendor's implementation. Every tenant must satisfy the AFP tenant conformance profile; a shortfall makes it a non-conforming tenant, not a non-principal. ADAMAS is the reference implementation, not the definition. AFP defines three relationships and nothing else: how two instances coordinate work across organizational lines, how the operator of a transport verifies the platform is healthy without learning what tenants do, and how a tenant's identity and accumulated relationships survive a move between operators or deployment topologies. It is not a marketplace, not a third-party agent registry, not a capability-discovery feed, and not a directory of agents for hire. The v0.2.0 draft attempted all of those; v0.3.0 retires them as protocol surface and keeps only the three relationships that actually need a wire format.

AFP sits above ZKA, ZKC, and KERI, and below nothing. ZKA carries the work artifacts and value transfers; ZKC carries the compliance proofs the operator is allowed to see; KERI carries identity. AFP is the envelope: which proof is requested, in which session, against which counterparty, on which terms, with which key, witnessed by whom.

---

## How it works

**Identity is a self-certifying identifier with KERI semantics.** AFP defines its own KEL encoding (specification §4.4.2); it is not KERI/CESR wire-compatible. Each tenant has a master seed and a tenant-root AID governed by a Key Event Log. Each named entity within the tenant (a domain multi-agent system) is a delegated AID anchored in the tenant's KEL. Pre-rotation is mandatory; every event commits to the next key set in advance. A counterparty verifies a tenant by checking its KEL against the tenant's published witnesses — no registry lookup, no operator dependency. If the tenant moves operators or migrates to a self-hosted appliance, the master seed re-derives the same entity AIDs, the KEL travels with it, and no counterparty relationship has to be re-established.

**Tenant ↔ tenant exchanges are bilateral and ZKA-mediated.** The parties either use a bilateral federation agreement with a known counterparty or, in open federation, establish trust per interaction through mutual ZKC compliance attestation. AFP has no open call, solver, or discovery feed: first contact and its route remain out of band. A session opens between two entity AIDs, each authenticated through its delegation chain to a tenant root and its witnesses. The channel is end-to-end encrypted. Every proof and message inside the session is bound to a session context that prevents replay to another counterparty or another session. Work artifacts and value transfers travel as ZKA notes and Coord proofs; AFP specifies only the envelope around them.

**Tenant ↔ operator telemetry is ZKC-proved, not transport-observed.** The operator does not learn that "tenant X did N tasks today." Instead, the tenant emits ZKC proofs of the predicates the operator is contractually entitled to verify — health, rate-limit compliance, policy adherence — and the operator checks them. The operator gets the assurance and nothing else.

**Metadata privacy is a separate, explicit mechanism.** Encrypting payloads while leaking the coordination graph is a known failure mode for confidentiality platforms; AFP treats it as one. The AFP Federation Mixnet — a self-contained, consortium-operated Loopix-family mix network with mandatory cover traffic — provides endpoint unlinkability, no cleartext relationship in addressing, correlation resistance, and no single trusted relay (§8.2), including protection against passive observers of inter-relay links. Until the mixnet is in place for a given deployment, that deployment cannot claim graph-privacy conformance and must say so.

**Limits (§8.10).** Federation membership remains visible: a tenant's constant emission reveals that it participates. Mixing and cover traffic mitigate but do not eliminate long-horizon statistical disclosure by an adversary observing a small federation over a long period. These residual limitations apply even to an operational, conforming mixnet.

---

## Why it holds

Federation protocols typically trade in one of two postures. Either the network is a directory — agents register, capabilities are advertised, work is matched — which makes the directory operator a load-bearing party that sees who is doing what with whom. Or the network is a bilateral mesh with no shared layer at all, which pushes identity, key management, and audit onto each pair to reinvent. The first posture cannot deliver confidentiality because the operator is on the data path; the second cannot deliver continuity because nothing crosses the pair. AFP takes the second posture — protocol carries proofs and envelopes, not policy and not a directory — and adds the substrate that makes continuity work without re-introducing the operator: self-certifying identity, witnesses, a mixnet, and ZK-proved telemetry.

The operator-blindness property earns its weight from being a *capability* claim, not a *conduct* claim. "We don't look" is a promise the next acquirer, subpoena, or breach can revoke. AFP requires end-to-end content encryption (OB-1) and the routing properties of §8.2 (OB-2), and it disallows claiming OB-2 for deployments that have not actually wired up the routing layer that delivers it. Inspection must also account for the §8.10 limits: membership remains visible, and long-horizon statistical disclosure is mitigated but not eliminated, especially in small federations.

---

## Freedom Safeguards

AFP inherits the six Freedom Safeguards defined normatively in ZKA v0.9.2-draft §1.6, and every AFP interaction is bound by them. In AFP's shape they read:

- **No unilateral re-identification.** No counterparty, witness, operator, or third party may compose AFP-mediated interactions into a re-identification of a tenant or entity that the tenant did not consent to.
- **No revocability of confidentiality.** Confidentiality guarantees are properties of the protocol, not promises by the operator. There is no policy switch that turns them off.
- **No privileged issuer, witness, or operator.** Witness sets, ZKC issuers, and transport operators are all plural and substitutable. No party is hard-coded into a conforming AFP deployment.
- **Open-source verification.** Verification logic for every AFP-required proof predicate is open-source, versioned, and publicly reviewable. SDKs refuse opaque predicates by default.
- **Minimal disclosure.** A session reveals what the work requires and nothing else. Bundling disclosures requires per-predicate consent.
- **Verifier accountability.** A party that requests a compliance proof must issue an authenticated request under a stable KERI identity, and the holder retains a receipt of what was asked — no signature, no proof. This is the first safeguard that constrains the requesting counterparty rather than the operator, and it is load-bearing for open federation between mutually unknown tenants (§5.8).

These are protocol-level commitments. A conforming implementation cannot drift into a single-operator, single-witness, or surveillance-by-default posture later without ceasing to conform.

---

## What's underneath

AFP normatively references ZKA v0.9.2-draft (settlement and coordination), ZKC v0.4.1-draft (anonymous/scoped/consented-linkable compliance presentations, with credential rebind limited to scoped v2 or consented linkable v1), and KERI (identity). Shared derivation lives in **AFP Appendix A — AFP-KDC v1.0.3**, whose metadata-only ownership patch retains the exact v1.0.2 Poseidon2 parameterization and cross-repository vectors without changing any value. The dependency graph remains acyclic: KDC depends on nothing; ZKA and ZKC depend on KDC; AFP depends on all three.

Transport is NATS — subjects, JetStream for durable streams, leaf nodes for cross-instance links — but transport is assumed untrusted. End-to-end content confidentiality holds regardless of who runs the broker. The §8 mixnet sits between AFP sessions and the transport and provides the §8.2 routing properties. Federation membership remains visible; mixing and cover traffic mitigate but do not eliminate long-horizon statistical disclosure, especially in small federations (§8.10).

---

## What's real today

The specification is at v0.3.14-draft and is the load-bearing artifact. It pins the three relationships, KERI identity with mandatory pre-rotation, profile-minimized rotation presentation, operator blindness, ZKC v0.4 presentation policy, metadata-private routing, and the Freedom Safeguards. Credential-only exchanges now carry native ZKC presentations and their exact signed APR in `afp:credential-envelope:v1` inside an authenticated encrypted session; compliance-only ZKA bundles remain invalid. The current `afp:zkc-presentation-context:v2` binds the verifier-selected telemetry, bilateral, introduction, or open-federation purpose into every accepted presentation, while verified predicate meaning remains bound independently to caller-authenticated policy. Telemetry and known-counterparty bilateral proofs default anonymous; introduction and open federation require scoped continuity bound to KERI presenter, credential subject, APR signer, AFP policy, session, and flow purpose; global linkability requires explicit consent. Instance attestation v2 selects a verifier-approved build-provenance, TEE, or disclosed publisher-manifest root without changing v1. Experimental §15 retains the Base-specific `pay` v1 profile and publishes the separate `pay_venue` v2 profile for an exact venue, asset, recipient, manifest, policy, and holder-disclosed receipt binding without activating a deployment. AFP-KDC v1.0.3 retains all v1.0.0 derivation values, activates the fixed-byte ownership metadata, and reuses the exact v1.0.2 Poseidon2 parameters and cross-repository vector gate. The v0.2.0 marketplace surface remains explicitly retired.

The mixnet specification (§8) is in the spec; the consortium that operates it and the bootstrap path for new tenants' witness configurations are the next layers of work. The spec is what implementations and integrations build against.
