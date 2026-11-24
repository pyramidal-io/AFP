# AFP v0.3 Scope Note — Addendum: Architectural Decisions

> **Status:** Addendum to the AFP v0.3 Scope Note. Locks two architectural decisions that the scope note enumerated as open.
>
> **Companion to:** `afp_v0_3_scope_note.md` (v0.3-scope, May 2026).
>
> **Date:** May 2026 · **License:** Apache 2.0

---

## Why this exists

The v0.3 scope note enumerated six "what this doesn't decide" items, deferring them to the v0.3 spec proper. Two have working answers now — emergent from the ZKA and ZKC seam reviews and the original-intent reveal that ZKC was designed for inter-agent payments. Capturing those answers here, before spec work begins, prevents them from drifting back to "open" status. Both decisions are mutually reinforcing: KERI's delegation maps onto multi-entity tenants without strain; transport-observability-where-possible plus ZK-where-necessary maps onto SaaS-and-appliance without strain. The Safeguards do real work in both — Safeguard 3 keeps the operator structurally constrained without trust assumptions, Safeguard 5 makes the appliance-migration story cryptographic.

---

## Decision 1: Identity model

**KERI hierarchy with BIP32-style master-seed derivation.** Each tenant has one master seed that generates the tenant's root KERI AID and, by deterministic sub-derivation, the seeds for each entity within the tenant. Entities are delegated AIDs in KERI's sense, with their own KELs anchored in the tenant's. ZKA's key hierarchy derives from the entity's sub-seed, not from the tenant master directly.

### Structure

- **Tenant root.** A KERI AID with master seed `M`. The tenant's KEL is governed by its chosen witnesses (own infrastructure plus partners, per the KERI mapping's recommended setup). The tenant's KERI AID is the canonical identifier of the tenant across the federation.
- **Each entity within the tenant** (Viksana, Alochana, etc.). A delegated AID with seed `M' = HKDF(M, "entity/{name}")`. The entity's KEL begins with a `dip` (delegated inception) event anchored in the tenant's KEL. The entity's ZKA key hierarchy — spending key, viewing key, proof key, credential binding key — derives from `M'` using ZKA's standard derivations (ZKA v0.6.0 §2.2).
- **Pyramidal-as-operator.** Its own KERI AID with its own master seed, structurally identical to any tenant. Operator privileges (running SaaS infrastructure) are operational, not protocol-level; Safeguard 3 ensures no privileged data path into tenant state.
- **HyperTalk sessions.** No cross-tenant identity. Federation always traverses entities, never sessions — when a session needs to cross a tenant boundary, the entity is the principal. Within-tenant user identity is separate (internal access control) and outside AFP scope.

### Properties

| Property | How it's delivered |
|---|---|
| Tenant control over entity keys | KERI delegation: tenant can rotate, revoke, or replace any entity AID via events in its own KEL |
| Cryptographic separation between entities | Distinct `M'` per entity; compromising one entity's seed does not expose siblings |
| Appliance migration is one move | Move `M`; all `M'` re-derive; KEL state moves with the tenant |
| Pre-rotation works end-to-end | At every KEL event, commit `next_key_digest`; rotation reveals next `M` and pre-commits the one after |
| Operator structurally constrained | Operator is just another holder; Safeguard 3 enforces no admin path |
| Per-entity attestation | Each entity has its own signing key derived from `M'`; cross-tenant entity-to-entity work attribution is cryptographic |
| Witness threshold per tenant | Tenant chooses its witnesses; appliance migration carries the witness configuration |
| Multi-tenant federation from one deployment | Multiple tenant AIDs share a transport but never an identity |

### What this resolves vs. leaves open

**Resolves:**
- *How ZKA's master-seed identity relates to KERI's AID* — the master seed sits below the AID; ZKA keys derive from per-entity sub-seeds.
- *Tenant/entity nesting* — entities are delegated AIDs, not free-floating principals.
- *Pre-rotation at the upper layer* — handled cleanly by standard KERI pre-rotation on the tenant's KEL and each entity's KEL.
- *Appliance migration of identity* — moving the master seed moves the whole tree.
- *The scope-note open question about HyperTalk as federation actor* — confirmed no: federation traverses entities.

**Leaves open:**
- *On-chain note migration during a master-seed rotation.* ZKA §5.7's Draft rotation/recovery covers the *lower* layer — how viewing/spending keys rotate without revealing the old↔new link on-chain. KERI alignment handles the *upper* layer cleanly but does not solve the on-chain problem. Pre-rotation gives the framework; the cryptographic on-chain migration is still §5.7 work. AFP v0.3 can specify upper-layer behavior and reference §5.7 for the lower-layer mechanism when finalized.
- *Initial witness set bootstrapping.* New tenants need an initial witness configuration. Pyramidal-operated bootstrap witnesses are natural for the SaaS case; the appliance case needs an explicit bring-your-own-witnesses path. Mechanism: spec work.

---

## Decision 2: Operator telemetry usage pattern

**Two layers, tenant-push, with a deployment-topology-dependent boundary.** Telemetry splits into what's directly observable at the transport layer (SaaS only) and what must be ZK-proved (always). The boundary moves with the deployment topology: in appliance mode the entire telemetry signal becomes ZK-proved, because the operator no longer runs the transport.

### Layer 1 — Transport-observed (SaaS)

The operator runs NATS. Connection metadata, cadence, NKey-attributed traffic patterns, aggregate request counts are directly observable at the transport layer. No ZK required. End-to-end encryption of payloads (ZKA notes are encrypted; AFP work-product bundles ride on those) plus Safeguard 3 means the operator sees the envelope but never the contents. *Tenant X is connected and active* is operational visibility; *what tenant X is doing* is structurally invisible. This is the same kind of metadata any IaaS provider sees, scoped by the operational contract.

For aggregate operational metrics across the tenant base (total CPU, total errors), simple aggregation or differential privacy handles it. No per-tenant proofs needed.

### Layer 2 — ZK-proved (SaaS and appliance)

A narrower set of claims the operator needs per tenant, proved via ZKC:

| Claim | Issuer model | Predicate shape |
|---|---|---|
| Instance attestation — "I'm a verified ADAMAS, build hash X" | Pyramidal signs build manifest; tenant proves possession | Third-party-issued, standard ZKC |
| Build currency — "on a supported build" | Pyramidal signs supported-build set; tenant proves set membership | Third-party-issued, set membership |
| Compute-quota compliance | Self-attested (tenant signs Merkle root of usage log) | Self-issued; consistency to transport-observed aggregates where available |
| Audit-log integrity | Self-attested (tenant signs current log head) | Self-issued |

The pattern: **third-party attestations for *what* the tenant is; self-attestations with public-sample consistency for *how* it's behaving.** Self-attested claims pair with public samples (NATS subject digests, aggregate counts) the operator can independently observe in SaaS, or that an appliance can selectively reveal. Cryptographic consistency between the signed assertion and the public sample is the anti-lying mechanism.

### Appliance deployment asymmetry

When the tenant runs an appliance, Layer 1 collapses into Layer 2. The operator no longer runs the NATS server the tenant publishes to; the appliance reaches out to a Pyramidal-side NATS bridge. Cadence, traffic patterns, connection health all become predicates the appliance proves rather than facts the operator observes. ZKC's role expands; the predicate set grows; the AFP-level protocol surface is the same in both topologies.

This is structural, not policy: in the appliance case, the operator literally cannot see anything that isn't proven. SaaS works the same way for *contents*; appliance works the same way for *contents and metadata*. The contract — "the operator sees only what tenants prove" — is invariant; deployment topology determines the size of the proof surface.

### Push model and failure semantics

**Tenant-push** on a `afp.telemetry.{tenant}.*` subject the operator subscribes to. Tenants control timing; operator monitors cadence (transport-observed in SaaS, predicate-proved in appliance). Cadence violation is itself a detectable signal — missing-proof-within-window is operationally meaningful.

Failed proofs do **not** trigger automated remediation. Safeguard 3 prohibits operator-side automated intervention in tenant state. Telemetry-proof failures propagate as alerts on a separate NATS subject the operator monitors; human investigation follows. This is the structural difference between operator telemetry and the gate patterns in ZKC §6.3 — those are deny-or-allow; this is observe-and-alert.

### What this resolves vs. leaves open

**Resolves:**
- *The "operator-as-verifier" shape mismatch* identified in the ZKC seam review — split into Layer 1 (transport-observed) and Layer 2 (ZK-proved), with the boundary moving by deployment topology.
- *Push vs. pull* — tenant-push, with cadence enforcement.
- *Failure semantics* — alerts and human follow-up; no automated intervention.
- *The scope-note open question about instance attestation* — Pyramidal-issued third-party predicate, standard ZKC machinery.

**Leaves open:**
- *The concrete telemetry predicate catalog.* What exactly the operator needs to know, written as Noir circuits with public review periods. Spec work.
- *Public-sample consistency mechanism for self-attested predicates.* The cryptographic glue between a tenant's signed assertion and the operator's independent observation needs to be specified. Especially relevant in the appliance case, where "independent observation" itself becomes a proven claim.
- *Appliance-to-SaaS-bridge details.* The NATS bridge an appliance reaches out to needs its own protocol surface — authentication, rate limits, subject scoping. Implementation rather than protocol, but worth flagging.

---

## Update to the scope note's open questions

Of the six items the v0.3 scope note left open:

| Open item | Status after this addendum |
|---|---|
| Inter-entity routing within a tenant | Bounded but not fully resolved. Tenant/entity nesting is now defined; cross-tenant requests address tenants, internal routing addresses entities. Detailed routing semantics remain spec work. |
| Instance attestation | **Resolved.** Third-party-issued predicate, Pyramidal-signed build manifest, standard ZKC. |
| HyperTalk as federation actor | **Resolved.** No: federation traverses entities. |
| Third-party DGP gateway consumption | Unchanged, deferred. |
| Operator ↔ operator federation | Unchanged, deferred. |
| The reputation question | Indirectly addressed. The bilateral-trust model implicit in both the tenant ↔ operator and tenant ↔ tenant relationships points toward bilateral federation agreements over portable reputation scoring. Final disposition is spec work. |

---

## Sequencing

The path to AFP v0.3 itself is now:

1. ✓ Scope set (`afp_v0_3_scope_note.md`)
2. ✓ ZKA seam mapped
3. ✓ ZKC seam mapped
4. ✓ Identity model chosen *(this document)*
5. ✓ Telemetry pattern chosen *(this document)*
6. → Draft AFP v0.3 itself, on the foundation above.

The remaining open items in the table above are appropriate to leave for the v0.3 spec, not for further scope-level addenda.

---

*Two decisions, both architectural: KERI delegation handles tenant/entity nesting and appliance migration; transport-observability plus ZK-proved telemetry handles the operator relationship across deployment topologies. AFP v0.3 spec work can proceed on this foundation.*
