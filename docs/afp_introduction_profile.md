# AFP Introduction Tier: the `afp.introduction` profile

**Interface version:** 0.3.14-draft
**Document revision:** 5 (2026-11-18)
**Specification set:** AFP, listed in `docs/afp_specification.md` §11
**Profile:** `afp.introduction` (experimental; §13.3)
**Profile version:** 1.0 (the §13.2 descriptor `version`, §14.2)

---

## 14. Introduction Tier

This section is **normative**. It specifies how two tenants with **no prior relationship** bootstrap a working bilateral relationship automatically: a credential and ZKC-proof handshake negotiates a **scoped, collateral-priced** provisional federation agreement (§5.5), grows the envelope with provable interaction history, graduates to a standard agreement, and degrades or terminates safely without weakening operator blindness (§3), OB-2 routing (§8), or the Freedom Safeguards (§9 / §12.8).

The introduction tier is AFP's path from strangers to a first agreement. It is an `afp.introduction.v1` **profile** (§13) over the Bilateral Session Core (§12), with the bounded opening rule in §12.1. Its progressive-trust model has four steps: **(1)** opt-in discovery and a credential handshake produce a scoped, small-limit provisional agreement; **(2)** first value interactions settle on the ZKA-direct rail or under collateral-anchored small-limit channels; **(3)** limits grow with ZK-provable interaction history; and **(4)** the relationship graduates to a standard §5.5 agreement and fast APL channels.

### 14.1 The willingness-to-federate directory

Discovery is **opt-in**. [AFP-0023] An instance that wishes to be approachable by strangers MAY publish an offer record to a KERI-anchored, witness-replicated directory, structurally the same object as the §8.7 mix-node directory:

```typescript
interface AfpIntroductionOffer {           // afp:introduction-offer:v1
  kind: 'afp:introduction-offer:v1';
  tenant_aid: string;                       // who is open to being approached
  accepted_credential_classes: string[];    // e.g. ['zkc:proof:jurisdiction:v2',
                                            //       'zkc:proof:kyc:v2',
                                            //       'afp.telemetry.instance_attestation.v2']
  entertained_envelope: {                   // the CEILING it will negotiate within — not an offer of credit
    assets: string[];
    max_per_interaction: string;            // decimal string
    max_cumulative: string;
    collateral_required: boolean;
  };
  route_handle: string;                     // §8.8 private-route resolution handle (not a clear address)
  directory_epoch: number;                  // binds to the directory epoch (anti-replay), as §8.7
}
```

[AFP-0024] The directory is **KERI-anchored** and verified exactly as §8.7's mix-node directory: a tenant MUST reject an offer whose KERI anchor is absent, whose witness quorum is below the federation threshold (§4.5), or whose `directory_epoch` does not match the directory's current epoch **exactly** (a stale epoch is replay; a future epoch cannot yet be validated).

**Directory boundary (normative).** This directory is not a work marketplace (§1.2) and does **not** weaken OB-2 (§3, §8):

- It carries **no work descriptor and no open call for work** — only a tenant's *consent to be approached for an introduction*. §5.1 bans a *work*-discovery feed; a willingness directory is a different object and is permitted.
- It reveals which tenants are **open**, never which tenants have **paired**. First contact is routed over the §8 mixnet, so the actual tenant pairing remains OB-2-private. The directory is no more graph-revealing than §8.7's published list of mix nodes.
- [AFP-0025] Publishing is OPTIONAL. A non-publishing instance remains reachable by an out-of-band-provided tenant AID; the directory is a convenience for open instances, not a precondition for the handshake.

The directory's hosting, epoch rotation, and gossip operation are a federation-operational concern outside AFP scope, not a tenant-internal one — the record is witness-replicated and verifiable without trusting any single party, structurally like the §8.7 mix-node directory, so no single tenant discharges it (a companion requirement); this section specifies the **record shape, the OB reconciliation, and the conformance rules** only.

### 14.2 The `afp.introduction.v1` profile and the bootstrap exception

The introduction tier is an AFP **profile** (§13), registered with the descriptor:

```typescript
{
  name: 'afp.introduction',
  version: '1.0',
  spec_ref: 'AFP 0.3.14-draft §14',
  atom_kinds: [
    'afp:introduction-offer:v1',
    'afp:introduction-request:v1',
    'afp:credential-presentation:v1',     // frozen v1 form (§12.9)
    'afp:provisional-agreement:v1',
    'afp:limit-adjustment:v1',
    'afp:downgrade:v1',
    'afp:termination:v1',
  ],
  policy_schema_ref: 'afp:introduction-policy:v1',
  status: 'experimental',                   // promoted to 'reference' once the lower layers are operational federation-wide (§14.9)
}
```

The descriptor lists the frozen `afp:credential-presentation:v1` record (§12.9). The credential-only step uses the core carrier (§12.7.2), which is not added to this profile-owned atom list.

**Bounded session-opening rule.** Section 13.2 rule 4 forbids a profile from altering the core. Section 12.1 expressly permits `afp.introduction.v1` to open for the purpose of **minting a provisional agreement** in place of a pre-existing one; no other profile may use that rule. [AFP-0026] Mutual authentication (§5.2 step 2), end-to-end encryption, OB-2 routing (§8), and context binding (§5.2 step 4) remain REQUIRED. Open federation (§5.8) is a separate core trust basis: it opens with no agreement through per-interaction ZKC attestation and does not mint a provisional agreement. Section 12.1 enumerates all three trust bases.

The **instance-attestation** credential named below is §6.3 `afp.telemetry.instance_attestation.v2`. [AFP-0027] Each side's introduction policy MUST name the root classes and root-authority identifiers it accepts; the proving side selects one accepted pair and proves the v2 predicate under that branch. The verifier performs the matching §6.3.1 root-specific obligations in addition to ordinary ZKC v0.4.1-draft verification, including out-of-circuit resolution of any delegated publisher signing AID to the named authority root. Neither side is required to accept any particular authority; a policy naming no authority declines v2 attestation rather than defaulting to one, and an authority an implementation ships as a default entry has this standing only once that party signs it into the policy (§14.4). [AFP-0028] A v1 proof does not satisfy a v2 request and MUST NOT be reinterpreted as carrying a generic root class.

### 14.3 The handshake

The handshake runs inside one §12 bilateral session (`profile: 'afp.introduction'`) and drives it from zero trust to a signed provisional agreement:

```
PROPOSED ──▶ CREDENTIALING ──▶ NEGOTIATING ──▶ BONDING ──▶ ACTIVE
   │              │                  │             │          │
   └─▶ABORTED     └─▶DECLINED        └─▶DECLINED   └─▶ABORTED  ├─▶ DOWNGRADED ──▶ (ACTIVE)
       /ABORTED       /ABORTED                                 ├─▶ TERMINATED
                                                               └─▶ GRADUATED
```

The opener fixes the credential-validity interval used by any v2 instance-attestation APR:

```typescript
interface AfpIntroductionRequest {          // afp:introduction-request:v1
  kind: 'afp:introduction-request:v1';
  initiator_tenant_aid: string;
  responder_tenant_aid: string;
  offered_credential_classes: string[];
  required_credential_classes: string[];
  proposed_envelope: object;                // the §14.4 envelope fields
  attestation_window: { starts_at: datetime; ends_at: datetime };
}
```

[AFP-0029] Every introduction request MUST carry `attestation_window`; `starts_at` MUST precede `ends_at`, and both endpoints MUST lie within the introduction session lifetime. [AFP-0030] If v2 is requested, its APR and proof MUST copy this exact window. Requiring the field universally keeps the v1 request shape deterministic even when a request does not ask for instance attestation.

**Relationship to ZKM mandates.** The provisional agreement produced here is a bilateral AFP policy envelope; a ZKM mandate is a unilateral, principal-issued authorization consumed by an agent. [AFP-0031] An interaction MAY be subject to both. The AFP per-interaction/cumulative limits and the ZKM cap, expiry, policy, and revocation checks are evaluated independently, and both must accept. Forming, downgrading, terminating, or graduating an AFP agreement does not issue, widen, revoke, or consume a ZKM mandate. Conversely, ZKM revocation does not mutate the AFP agreement or any underlying ZKA note.

- **PROPOSED.** The initiator opens the session to the responder tenant AID (resolved via §14.1 or out-of-band) carrying an `afp:introduction-request:v1`: the credential classes it offers, the classes it requires, the explicit v2 `attestation_window`, and a proposed envelope (assets, limits, collateral, rotation policy, expiries).
- **CREDENTIALING.** Each side presents the canonical native `afp:credential-envelope:v1` (§12.7.2), carrying its exact signed APR and native ZKC presentation of **atomic**, scoped ZKC v0.4.1-draft `zkc:proof:v2` proofs (jurisdiction `zkc:proof:jurisdiction:v2`, KYC-where-required `zkc:proof:kyc:v2`, instance-attestation `afp.telemetry.instance_attestation.v2`). The APR requests `zkc:presentation:scoped:v1` with `scopePolicy = protocol:afp:<introduction-policy-hash>` and the accepted instance-attestation root classes and root authorities; the proof satisfies the AID/APR/session/purpose binding of §5.9 and the selected §6.3.1 branch. Anonymous downgrade is forbidden because these presentations become the credential basis of the provisional agreement. Linkable v1 is permitted only after explicit holder consent. Each side verifies the other against *its own* policy. Failure only declines the interaction; it never gates tenant state.
- **NEGOTIATING.** The two sides converge on a scoped envelope — the intersection of offered/required credentials plus a mutually acceptable {permitted assets, per-interaction limit, cumulative-outstanding limit, collateral requirement, rotation policy, credential validity expiries, agreement expiry}. [AFP-0032] Either side MAY counter; either side MAY abort unconditionally (Safeguard 5).
- **BONDING.** Collateral is posted **against exposure**, which may be asymmetric. Whichever side(s) the negotiated envelope extends credit to — the side that could be left owing if a non-atomic settlement fails — posts the required bond into the pre-agreed escrow (the §12.5 2-of-3 / arbiter-co-signed escrow). A symmetric envelope bonds both sides; an asymmetric one bonds only the credit-taking side. A trustless-ZKA-direct-only envelope skips bonding entirely: settlement is atomic, so neither side is exposed and no credit is extended.
- **ACTIVE.** Both parties sign an `afp:provisional-agreement:v1` with the §12.6.1 bilateral, KEL-anchored signature machinery. The provisional agreement is now a valid, narrowly-scoped §5.5 federation agreement carrying an `afp:introduction-policy:v1` block. Subsequent value interactions run as ordinary work (§5) / VXP sessions *scoped by this agreement*, each bounded by the envelope and the posted bond.

Terminal states: `DECLINED` (credential or negotiation failure; no agreement is formed), `ABORTED` (unconditional exit, §12.8 Safeguard 5), and from `ACTIVE`: `DOWNGRADED` (the envelope contracts, then the session returns to `ACTIVE` under the new terms; §14.7), `TERMINATED` (§14.7), and `GRADUATED` (replaced by a standard §5.5 agreement; §14.6).

### 14.4 The provisional agreement and the introduction policy block

```typescript
interface AfpProvisionalAgreement {         // afp:provisional-agreement:v1
  kind: 'afp:provisional-agreement:v1';
  tier: 'introduction';                     // distinguishes it from a standard §5.5 agreement

  // §5.5 agreement core: mutually signed by both tenant root (or delegated) AIDs,
  // using the §12.6.1 bilateral-signature shape.
  initiator_signature: AfpCommitSignature;  // §12.6.1: signed_by, kel_event_dig, signature, signed_at
  responder_signature: AfpCommitSignature;

  policy: AfpIntroductionPolicy;            // afp:introduction-policy:v1

  reputation_state: {                       // the running, signed basis for §14.6 growth
    settled_interactions: number;
    cumulative_settled_value: string;
    slash_events: number;
    last_commitment_ref?: string;           // chains into the §12.6.1 commitment history
  };
}

interface AfpIntroductionPolicy {           // afp:introduction-policy:v1
  permitted_entities: string[];
  permitted_assets: string[];
  max_per_interaction: string;
  max_cumulative_outstanding: string;
  bond_ref?: string;                        // escrow reference; absent only for a trustless-ZKA-direct-only envelope
  accepted_credentials: { class: string; valid_until: string }[];
  accepted_instance_attestation_roots: {
    root_class: 'root:build-provenance' | 'root:tee-attestation' | 'root:publisher-manifest';
    root_authority_identifier: string;
  }[];                                      // signed v2 verifier policy; empty only when v2 is not required
  rotation_policy: string;                  // KEL rotation expectations (§4.6)
  growth_curve: object;                     // negotiated step / cap / decay (§14.6) — not protocol-fixed
  agreement_expires_at: string;
}
```

A provisional agreement is a **specialization** of the §5.5 federation agreement, distinguished by `tier: 'introduction'` and a reputation state — and, **for a bonded envelope**, a bond reference (`bond_ref` is absent for a trustless-ZKA-direct-only envelope, §14.5). [AFP-0033] When `accepted_credentials` contains `afp.telemetry.instance_attestation.v2`, `accepted_instance_attestation_roots` MUST contain at least one pair, and the verifier MUST accept only a proof whose public `root_class` and `root_authority_identifier` exactly match one signed pair. [AFP-0034] If v2 is not required the array MUST be empty; it MUST NOT silently authorize an attestation predicate. A pair that a party's implementation ships as a default entry has no different status here: it is signed into the agreement by that party or it does not apply. An empty array means the predicate is not required — never that a shipped default applies. Like every §5.5 agreement the complete policy is **private to the two tenants**, bilaterally signed, not published, and not discoverable. It is referenced by the `afp.work.request` (§5.3) / VXP intent messages of the value interactions it scopes.

**Signed agreement content (normative).** The `afp:provisional-agreement:v1` record is an AFP-authored JSON artifact under §6.3.1 of the core. [AFP-0508] An implementation MUST form its **agreement content** as the JSON object with exactly the members `kind`, `tier`, `policy`, `reputation_state`, `initiator_signature`, and `responder_signature`. The first four carry their wire values. Each of the last two is the object `{"signed_by": <AID>}`, which holds only that signature's `signed_by` value, so `kel_event_dig`, `signature`, and `signed_at` are outside the content. The content therefore binds both signers in their roles. [AFP-0509] Both parties MUST fix both `signed_by` values before the first signature; a change to either value changes the content and needs both signatures again. [AFP-0510] Both signatures MUST cover the same bytes, computed as follows:

```text
content_hash = "D_" || lowercase_hex(SHA-256(RFC8785_JCS_UTF8(agreement_content)))
signed_bytes = ASCII(content_hash)                       // exactly 66 octets
signature    = lowercase_hex(Ed25519(signer_key, signed_bytes))
```

[AFP-0511] The `AfpCommitSignature.signature` member MUST be exactly 128 lowercase hexadecimal characters, made with the key that the signature's `kel_event_dig` pins. [AFP-0512] An optional member that is absent from the wire record, such as `policy.bond_ref` or `reputation_state.last_commitment_ref`, MUST be absent from the agreement content too; JSON `null` does not encode an absent member. [AFP-0513] Implementations MUST hash each string as it is carried, and MUST NOT re-encode, normalize, or translate a string before hashing. RFC 8785 serializes a string as its JSON string token. This includes `policy.accepted_credentials[].valid_until` and `policy.agreement_expires_at`: core §1.6.1 leaves their spelling unresolved, the content hash covers each string exactly as it was signed, and this rule fixes no spelling. Numbers, including the `reputation_state` counts and any number inside `growth_curve`, are IEEE 754 binary64 values: the block above declares them `number`, and RFC 8785 serializes each one as its binary64 value in the RFC 8785 number form. A number token with a fraction or exponent part is read as RFC 8785 reads it, as the nearest binary64 value, so `2e-3` and `0.002` give the same content. An integer token, which has neither part, stands for a binary64 value only when it writes that value exactly or is its RFC 8785 spelling, and an integer made in memory only when it is that value exactly. For example, `1152921504606846976` and `1152921504606847000` both stand for 2^60 and hash as `1152921504606847000`. The two `reputation_state` counts are non-negative integral values, so a reader that holds a count as an integer holds the integer that its binary64 value equals: `1000000000000000000000` and the RFC 8785 spelling `1e+21` both give 10^21. [AFP-0514] A party MUST NOT sign an agreement whose content holds any other integer, such as `9007199254740993`, which no binary64 value represents, or a string that is not valid Unicode, because such content has no RFC 8785 serialization that keeps its value, and a verifier MUST reject such an agreement. This adds no limit to the record: a value outside binary64 was never a `number`.

**Domain separation.** The signed bytes are the ASCII content hash alone, as for the §12.2.1 stable session content and the §15.3 quote content of the core. They satisfy AFP-0104 as follows. A KEL controller signature or witness receipt signs a preimage that starts with an `afp:kel-` prefix (§4.4.2 of the core), and no 66-octet `D_` string equals such a preimage. The other `D_` content hashes that AFP keys sign are digests of JSON objects whose `kind` member is not `afp:provisional-agreement:v1` (AFP-0213), so a signature over one of them verifies as an agreement signature only through a SHA-256 collision. [AFP-0515] A verifier MUST verify each agreement signature over these signed bytes only, and MUST NOT accept a signature over the raw SHA-256 digest, over the agreement's wire bytes, or over any other preimage.

**Signers and roles.** The agreement does not name its introduction session, so a verifier takes the expected parties from the authenticated introduction session in which the agreement is formed (§14.3). Because the content binds both `signed_by` values, a signature moved into the other role's member, or a member whose `signed_by` is changed, no longer verifies. [AFP-0516] `initiator_signature.signed_by` MUST be the tenant root AID or the delegated entity AID that the session's authenticated `initiator` party reference names (§12.2.1 of the core), and `responder_signature.signed_by` MUST name the responder party in the same way. [AFP-0517] A verifier MUST reject a signature whose `signed_by` names the other party, including a signature in the other role's member, and a signature whose `signed_by` names neither party. [AFP-0518] A verifier MUST resolve the signer's key from the signer's KEL, through the delegation chain to its tenant root and the §4.5 witness policies for a delegated entity AID, and MUST reject a `kel_event_dig` that is not the signer's latest establishment event (§12.6.1 of the core). [AFP-0519] A verifier MUST accept an agreement only when both signatures verify under the strict profile of §4.4.1 of the core. `signed_at` is observational metadata outside the signed bytes, as for the quote signatures of §15.3 of the core (AFP-0419). [AFP-0520] Changing it neither invalidates nor strengthens an agreement signature, and a verifier MUST NOT use it for freshness or authority.

### 14.5 Settlement safety floor

[AFP-0035] Every value interaction under an introduction-tier agreement MUST be either:

- **(a) trustless ZKA-direct** — settled atomically on the ZKA rail with no credit extended (the safe default), or
- [AFP-0036] **(b) bonded** — outstanding exposure MUST NOT exceed the collateral posted in the pre-agreed escrow.

[AFP-0037] A conforming implementation **MUST NOT** allow uncollateralized credit at the introduction tier. Credentials gate *which* counterparties and assets are eligible; the bond is what bounds loss. *(Instance identity is not sybil resistance; collateral prices the risk.)*

**Enforcement location.** The floor is enforced at the **agreement / channel-policy layer**: the provisional agreement's envelope populates the channel policy block (the APL channel policy block for bonded and graduated channels), and the layer that authorizes or opens a value channel enforces "ZKA-direct, or bonded ≤ collateral" before any interaction. This section defines the conformance property; the channel-policy layer implements it. A value profile (e.g. VXP) is **not** special-cased to carry introduction-tier validation — cross-cutting policy lives at the core/agreement layer (§13.2 rule 4).

### 14.6 Progressive limit growth and graduation

**Mechanism (normative).** [AFP-0038] A party MAY present an `afp:reputation-proof` — a zero-knowledge proof of *N settled interactions and cumulative settled value with zero slash/default events*, bound to **this** agreement and counterparty and **non-replayable** (bound to the agreement id and a monotonic counter, mirroring the §12.6.1 chaining). On verification, the presenter proposes an `afp:limit-adjustment:v1` raising the envelope; **both parties sign** it with the §12.6.1 machinery. A rejected, stale, or slash-bearing proof yields no adjustment — never a freeze.

**Curve (policy, not protocol).** The growth curve — step size, caps, decay on inactivity — is a negotiated parameter in the `afp:introduction-policy:v1` block. AFP fixes the *predicate and the adjustment handshake*; the *numbers* are the bilateral choice. This mirrors the house rule that the mechanism is normative and the parameters are negotiated (cf. §8.2).

**Graduation.** When the parties choose, they replace the provisional agreement with a **standard §5.5 agreement** — no `introduction` tier, no mandatory bond, eligible for fast APL channels. Graduation is itself a bilateral signed act; the §12.6.1 chained-commitment history carries forward as the relationship's provable basis. The reputation proof and the on-chain escrow are lower-layer constructs (§14.9); this section owns the predicate's *interface* and the adjustment/graduation *handshake*, not the circuit.

### 14.7 Downgrade and termination

Both are safeguard-compatible: nothing here freezes, claws back, or redirects tenant state (Safeguard 3), and exit is unconditional (Safeguard 5).

**Downgrade.** The go-forward envelope contracts — lower limits, higher collateral, narrower assets. Triggers include a lapsed credential validity (the policy-block expiry), a late or missed settlement, a signed dispute-divergence record (§12.5), partial collateral consumption, or reputation decay. [AFP-0039] A downgrade is realized **either** as a re-negotiation both parties sign (an `afp:downgrade:v1` followed by a new `afp:limit-adjustment:v1`) **or** as a *unilateral protective contraction*: a party MAY always decline to extend further credit or offer a *smaller* envelope (declining an interaction is always permitted, §5.4 / Safeguard 5). A party can never unilaterally compel the counterparty to act.

**Termination.** [AFP-0040] Recorded as an `afp:termination:v1`; either party MAY terminate unconditionally and with no protocol penalty (Safeguard 5). Residual obligations settle **against the pre-posted escrow only** — the §12.5 arbiter-co-signed release, bounded by what was escrowed, never against base-layer custody (Safeguard 5). Any unsettled dispute leaves a signed divergence record (§12.5).

**Default consequence.** Financial recourse for a default is limited to the pre-posted escrow; the §12.5 dispute and arbiter procedures and the downgrade and termination paths above are unchanged. AFP defines no portable record of a default for use as reputation with future counterparties.

### 14.8 Composition and Freedom Safeguards

- **OB-2 (§8).** The introduction handshake and every subsequent interaction are routed through the §8 mixnet. The willingness directory (§14.1) reveals *openness*, never *pairing*; the coordination graph is never operator-visible.
- **APL channel policy block.** The envelope's {permitted assets, limits, collateral} populate the channel policy block under which bonded and graduated channels run (§14.5).
- **Freedom Safeguards (§12.8).** The introduction profile inherits all six by running over the core and weakens none:
  - **Predicate Pluralism (1)** — AFP privileges no credential issuer or set; the required credentials are each tenant's bilateral choice recorded in the agreement.
  - **Minimal Disclosure (2)** — credentials are atomic ZKC proofs, one predicate per proof.
  - **No Revocability (3)** — bond slashing is bounded to pre-escrowed funds with the pre-agreed arbiter co-signature (§12.5); it never touches tenant state or a ZKA note.
  - [AFP-0041] **Open-Source Predicates (4)** — the credential and reputation circuits MUST be open-source, versioned, and published with a public review period (ZKC §1.4).
  - **Agent Exit Rights (5)** — decline, abort, and terminate are all unconditional and penalty-free.
  - **Verifier Accountability (6)** — every credential or reputation-proof request is authenticated under the requester's stable identity and leaves the holder a portable receipt (§5.8); no anonymous proof demand is accepted.

### 14.9 Open seams and honest disclosure

The introduction tier is the AFP-owned protocol contract; several lower layers it composes are owned and tracked elsewhere. AFP owns the handshake, the provisional-agreement object, the introduction policy block, and the conformance properties of this section. It **references** — and does not redefine — the following:

| Construct | Owner / status |
|---|---|
| Trustless ZKA-direct settlement rail | ZKA (transfer + unconditional withdrawal); operational. |
| Native credential-only presentation carriage | AFP `afp:credential-envelope:v1` (§12.7.2), carrying the ZKC-owned native proof/presentation envelope and exact signed APR. No ZKA bundle, transaction or Coord proof is constructed. ZKA §5.4 still rejects compliance-only bundles with `EMPTY_BUNDLE`. |
| ZK reputation-proof circuit (§14.6) | ZKA/Reputation — companion requirement; **not yet operational**. |
| On-chain bilateral escrow with mutually-chosen arbiter (§14.5, §14.7) | Companion requirement (ADAMAS.Network / ZKA escrow contract); **not yet operational**. |
| Instance-attestation predicate (§14.2) | §6.3 `afp.telemetry.instance_attestation.v2`; AFP fixes the public statement and root-specific verifier obligations. The separately versioned ZKC machine build/runtime credential schema and issuer-adapter registry entry are companion work; raw provenance bundles and TEE quotes remain provider-side. An authority's key ceremony, published trust material, and the out-of-band AID↔legal-entity binding (§6.3.1) are likewise companion work owned by that authority rather than by AFP; for the ADAMAS product line these are Pyramidal Inc.'s and are **not yet operational**. |

**Honest disclosure.** [AFP-0042] A deployment whose selected §6.3.1 v2 root path, escrow, or ZK-reputation lower layer is not yet operational MUST disclose the introduction tier as *spec-available but not fully operational* rather than claim it, exactly as §3.5 and §8.9 require for OB-1/OB-2. The profile descriptor's `status: experimental` (§14.2) reflects this until the lower layers are operational federation-wide. Claiming a fully operational introduction tier without a realized v2 credential/circuit/verifier path, the reputation circuit, and the bonded-escrow rail in place is a conformance violation, independent of the correctness of any one available component.

---
