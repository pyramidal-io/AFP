# AFP v0.3 — Scope Note

> **Status:** Architectural decision. Foundation for a forthcoming AFP v0.3 specification.
>
> **Supersedes the scope of:** `Agent_Federation_Protocol_AFP.md` (v0.2.0-draft, Dec 2025), `AFP_AGENT_IDENTITY_ADDENDUM.md` (v0.1.1-draft, Mar 2026).
>
> **Promotes:** `keri_afp_mapping.md` (v0.1.0-draft, Feb 2026) from research proposal to adopted direction.
>
> **Date:** May 2026 · **License:** Apache 2.0

---

## Why this exists

AFP v0.2.0 was scoped as a *boundary protocol between AKG-native and external agents* — designed to let third-party frameworks (LangGraph, CrewAI, AutoGen, others) register agents, advertise capabilities, accept delegated tasks, contribute observations, and accumulate reputation inside ADAMAS networks. That model assumed an open agent marketplace.

ADAMAS's product scope has since narrowed. ADAMAS is not a platform for agent developers; it is a platform for life-sciences work, run by named domain entities that are themselves ADAMAS multi-agent systems. There are no third-party agents to integrate, no untrusted-agent problem to solve, no marketplace to police. Most of v0.2's protocol surface was built for problems that no longer exist.

What remains, and what v0.3 will specify, is much smaller and sharper.

---

## What AFP is now

AFP is the protocol layer for three relationships, all between identifiable, cryptographically-verifiable principals:

### 1. Tenant ↔ tenant

Two ADAMAS instances — both running the same platform, both running ADAMAS-native entities — collaborating across organizational lines. Pharma A's Viksana needs Pharma B's CRO to run an analysis; neither side reveals more than the work requires. The protocol is what makes that interaction safe and verifiable.

This is the *only* kind of "federation" in scope. Federation does not mean *integrating a third-party agent into your instance*; it means *two ADAMAS instances talking to each other*.

### 2. Tenant ↔ operator

The operator (initially: Pyramidal, running the SaaS) needs telemetry to know that the platform is healthy — workload, latency, error rates, resource utilization, agent execution traces — without learning what tenants are *doing*. The platform sees its own pulse; it doesn't see the work. The protocol is what enforces that asymmetry.

This is the load-bearing case for ZKC (zero-knowledge compliance): the operator proves the platform is functioning and compliant without seeing tenant interactions, counterparty identities, payment flows, or work content. *Telemetry without surveillance* — and that contract is structural, not policy.

### 3. Identity continuity across deployment topology

A tenant starts on SaaS. A year later, they move to a self-hosted appliance. Their identity, their reputation, their federation relationships, and any attestations they've accumulated all have to survive the move. The protocol is what makes identity portable across the topology change.

This case is the reason KERI alignment is no longer optional. Self-certifying identifiers are the only kind that survive *operator change*, because they don't depend on the operator running a registry.

---

## What AFP is no longer

A clean inventory, so we know what to remove from v0.2's surface area when v0.3 is written:

| v0.2 concern | v0.3 status |
|---|---|
| Agent manifest schema for third-party agents | Out. Entities have manifests inside their instance; nothing of that shape crosses the protocol boundary. |
| Capability discovery as a wire protocol | Out as a marketplace mechanism. A narrower case survives — "what does this tenant expose to federated counterparties" — framed under tenant ↔ tenant, not as a discovery feed. |
| Task delegation (§4.3–4.5) as a wire protocol | Internal for intra-tenant. Cross-tenant requests are a specific case under the federation relationship, not the protocol's central feature. |
| Observation contribution from external agents | Out. Observations come from ADAMAS-internal entities only. |
| Reputation accumulation for external agents | Out as an individual-agent mechanism. Whether *instance-level* reputation survives is open (see §"What this doesn't decide"). |
| Trust-level escalation ladder (federated → integrated → AKG-native) | Out. The ladder existed to manage an untrusted-agent problem that no longer exists. There is one trust level — *verified ADAMAS instance* — plus whatever federation-relationship-specific trust two instances negotiate bilaterally. |
| HTTP bridge (§9) | Out. Cross-instance traffic is between ADAMAS systems on the same transport (NATS / leaf nodes); no HTTP-only third-party use case remains. |

The corresponding mass of protocol surface — registration challenges for third parties, capability-schema validation, probationary periods, observation quarantine, trust scoring — is descoped along with the marketplace model. Where any of it survives, it survives as *internal ADAMAS implementation*, not as wire protocol.

---

## What becomes load-bearing

**KERI-aligned self-certifying identity.** Adopted. The Identity Addendum's hash-derived `aid_${blake3(genesis_nkey + created_at + provider)}` is replaced by self-certifying forms (`aid_${base64url(genesis_nkey)}`, or KERI's prefixed `B…`/`D…`). The KERI mapping document, previously a research proposal, becomes the canonical reference for identity. Pre-rotation (commitment to next key at every rotation event) is required, not optional. A Key Event Log (KEL) replaces the flat `nkey_history` array.

*Rationale:* appliance support requires identifier verification without operator lookup. Hash-derived identifiers can't deliver that property; self-certifying ones can. This decision retires the central conflict identified in the prior AFP review.

**ZKA and ZKC as substrate, not siblings.** AFP v0.2 mentions ZKA once and ZKC not at all. v0.3 will be built on top of both. The tenant ↔ tenant relationship rides on ZKA (selective disclosure of capabilities, attestations, work artifacts). The tenant ↔ operator relationship rides on ZKC (the operator proves platform health and compliance without seeing tenant content). AFP's job in both cases is to define *how* ZK-mediated interaction is initiated, authenticated, sequenced, and recorded — not to reinvent the cryptography. The next protocol-review pass should read ZKA and ZKC with this seam in mind.

**Witnesses (KERI sense) for KEL availability and consistency.** The Identity Addendum has guardians (for recovery) but not witnesses (for receipting events). Both are now in scope. Witnesses are the mechanism by which a counterparty appliance — with no access to the original operator — can verify that an instance's key history is consistent and hasn't forked.

**Telemetry boundaries as an explicit protocol surface.** A surface that v0.2 didn't specify because it didn't need to: what telemetry the operator publishes, what is proven (via ZKC) rather than disclosed, and what is structurally invisible. This must be written down precisely, because the alternative is operators *trying to be good* — which is not a credible privacy story for a biomedical platform, and it's the credibility hinge for the SaaS-to-appliance transition.

---

## What this scope note doesn't decide

Surfaced now so they can be addressed in the v0.3 spec proper, not lost in the transition:

- **Inter-entity routing within a tenant** is ADAMAS-internal, not AFP. But when a cross-tenant request arrives, the receiving tenant's routing of that request to the right entity is internal — the protocol only sees tenant addresses. v0.3 needs this boundary stated explicitly.
- **Instance attestation.** How does a counterparty appliance verify that a peer is *actually* an ADAMAS instance, not a malicious actor speaking the protocol? Likely a separate attestation mechanism (build provenance, signed releases, TVF-style validation) rather than something baked into AFP. v0.3 will need to reference it explicitly.
- **HyperTalk as federation actor.** A HyperTalk session is a tenant-facing surface; does HyperTalk itself participate in cross-tenant federation, or only via the entities? Almost certainly the latter — but worth confirming and stating.
- **Third-party consumption of tenant-exposed DGP gateways.** A tenant may expose a DGP gateway to a third-party tool. That's DGP's scope, not AFP's, but the interaction *between* a DGP gateway and AFP-mediated cross-tenant federation needs to be named so the seams are clear.
- **Operator ↔ operator federation.** If a second operator (not Pyramidal) someday runs an ADAMAS instance, the operator ↔ operator relationship is unspecified. Probably deferred to a later version, but worth marking the gap so it isn't forgotten.
- **The reputation question.** v0.2 spent significant pages on reputation as an individual-agent mechanism. v0.3's narrower scope may not need *individual* reputation at all — but *instance-level* reputation between tenants is a real question. Pending decision; one path is bilateral federation agreements supersede the need for portable scoring entirely.

---

## What happens to the existing AFP documents

| Doc | Status under v0.3 |
|---|---|
| `Agent_Federation_Protocol_AFP.md` (v0.2.0-draft) | **Superseded in scope.** Retain as historical reference; do not implement against it. Some wire-protocol details (NATS subjects, JetStream configuration) are partially reusable as implementation reference; the semantic model is replaced. |
| `AFP_AGENT_IDENTITY_ADDENDUM.md` (v0.1.1-draft) | **Superseded in scope.** Identity-lifecycle concepts (rotation, delegation, recovery, succession) survive into v0.3 in KERI-aligned form. The flat `nkey_history` model and the hash-derived `identity_id` are replaced. Recovery and succession will be re-specified on top of the KEL. |
| `keri_afp_mapping.md` (v0.1.0-draft) | **Promoted from research proposal to canonical direction.** The "Aligned approach" in §1.2 becomes the v0.3 identity model. Phases 1–3 of its implementation path move from research backlog to v0.3 specification work. Phase 4 (blockchain anchoring) remains optional. |

---

## Sequencing

1. **Now:** this scope note locks the architectural decision.
2. **Next:** read ZKA and ZKC with this scope as the frame. The questions to answer are *what AFP needs from each* and *where the seams between AFP and each protocol sit*. The goal is seam identification, not a parallel review of ZKA/ZKC for internal consistency — that comes later.
3. **Then:** draft AFP v0.3 itself, on the foundation of ZKA, ZKC, and KERI. The result will be substantially shorter than v0.2 because most of v0.2's surface area is no longer in scope.

---

*v0.3 narrows AFP from open-marketplace federation to instance-level federation, makes KERI-aligned identity load-bearing, and treats ZKA/ZKC as substrate rather than peer protocols. The marketplace model that v0.2 carefully designed has been retired with the broader product scope it served.*
