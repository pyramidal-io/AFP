# KERI ↔ AFP Identity Mapping

**Version:** 0.1.0-draft  
**Date:** February 2026  
**Context:** Decentralizing ADAMAS.network identity via KERI semantics

---

## 1. Conceptual Mapping

### 1.1 Core Primitives

| KERI Concept | AFP Identity Equivalent | Notes |
|--------------|------------------------|-------|
| **AID** (Autonomic Identifier) | `identity_id` | Both are self-certifying, derived from genesis key |
| **Inception Event** | Agent registration + `genesis_nkey` | Creates the identifier |
| **Rotation Event** | `NKeyRotation` | Key update with signed authorization |
| **Interaction Event** | Task execution, attestations | Non-key-change events that reference the AID |
| **Delegated AID** | `DelegateGrant` | Hierarchical identifier relationship |
| **KEL** (Key Event Log) | `nkey_history[]` + identity events stream | Append-only signed log |
| **Witness** | Guardian (extended role) | Receipts and replicates events |
| **Watcher** | Federation peers | Monitors KELs for inconsistencies |

### 1.2 Identifier Derivation

**KERI:**
```
AID = Base64(public_key_prefix + public_key)
```

**AFP (current):**
```typescript
identity_id = `aid_${blake3(genesis_nkey + created_at + provider).slice(0, 32)}`
```

**Aligned approach:**
```typescript
// Self-certifying: identity IS the key (for basic AIDs)
identity_id = `aid_${base64url(genesis_nkey)}`

// Or with derivation code prefix (KERI style)
identity_id = `B${base64url(ed25519_pubkey)}`  // 'B' = Ed25519 non-transferable
identity_id = `D${base64url(ed25519_pubkey)}`  // 'D' = Ed25519 transferable (can rotate)
```

The advantage: Anyone can verify `identity_id` derives from `genesis_nkey` without external lookup.

---

## 2. Key Event Log (KEL) Structure

### 2.1 Event Types

```typescript
// KERI-aligned event types for AFP
type AFPKeyEvent = 
  | InceptionEvent      // icp - identity creation
  | RotationEvent       // rot - key rotation
  | InteractionEvent    // ixn - non-key operations (attestations, delegations)
  | DelegatedInception  // dip - delegated identity creation
  | DelegatedRotation   // drt - delegated key rotation

interface BaseEvent {
  // KERI fields
  v: string;            // Version string
  t: string;            // Event type (icp, rot, ixn, dip, drt)
  d: string;            // SAID (Self-Addressing Identifier) - hash of event
  i: string;            // AID this event belongs to
  s: number;            // Sequence number (0 for inception, incrementing)
  
  // Signatures
  signatures: string[]; // Controller signatures: rot/drt by the revealed key(s), others by the current key(s) (AFP §4.4)
}

interface InceptionEvent extends BaseEvent {
  t: 'icp';
  s: 0;                 // Always 0 for inception
  
  kt: number;           // Signing threshold (1 for single key)
  k: string[];          // Current public key(s)
  
  nt: number;           // Next threshold
  n: string[];          // Next key digest(s) - pre-commitment to rotation keys
  
  bt: number;           // Witness threshold
  b: string[];          // Witness AIDs
  
  // AFP extensions
  afp: {
    provider: ProviderInfo;
    capabilities: string[];
    recovery_config: RecoveryConfig;
  }
}

interface RotationEvent extends BaseEvent {
  t: 'rot';
  
  kt: number;           // New signing threshold
  k: string[];          // New public key(s)
  
  nt: number;           // Next threshold  
  n: string[];          // Next key digest(s) - pre-commitment for future rotation
  
  bt: number;           // Witness threshold (can change)
  br: string[];         // Witnesses to remove
  ba: string[];         // Witnesses to add
  
  // AFP extensions
  afp: {
    reason: 'scheduled' | 'compromise' | 'upgrade' | 'recovery';
    grace_period_ends?: datetime;
  }
}

interface InteractionEvent extends BaseEvent {
  t: 'ixn';
  
  a: AnchoredData[];    // Data anchored to this event
  
  // AFP: attestations, delegation grants, etc. anchored here
}

interface AnchoredData {
  d: string;            // SAID of anchored content
  type: 'attestation' | 'delegation' | 'task_result' | 'reputation_update';
  payload: object;      // The actual content
}
```

### 2.2 Pre-rotation (Key Pre-commitment)

KERI's key innovation: You commit to your *next* key at rotation time, before you need it.

```
Inception:  k=[key1], n=[hash(key2)]     ← "my next key will hash to this"
Rotation 1: k=[key2], n=[hash(key3)]     ← key2 matches previous commitment
Rotation 2: k=[key3], n=[hash(key4)]     ← key3 matches previous commitment
```

**Why this matters:**
- Attacker who compromises `key1` cannot rotate—they don't know `key2`
- You generated `key2` at inception, stored it offline
- Even if attacker gets `key1`, they can't forge a valid rotation

**AFP integration:**
```typescript
interface RecoveryConfig {
  // Existing
  method: 'social' | 'timelock' | 'threshold';
  guardians?: string[];
  
  // Add pre-rotation
  next_key_digest: string;    // blake3(next_public_key)
  next_key_threshold: number; // For multi-sig identities
}
```

---

## 3. Witnesses

### 3.1 What Witnesses Do

Witnesses provide **receipts** - signed acknowledgments that they observed an event:

```typescript
interface WitnessReceipt {
  // Event reference
  event_said: string;       // SAID of the event being witnessed
  event_aid: string;        // AID the event belongs to
  event_sequence: number;   // Sequence number
  
  // Witness attestation
  witness_aid: string;      // Witness's own AID
  witnessed_at: datetime;
  signature: string;        // Witness signs the event SAID
}
```

An event is considered **established** when it has receipts from a threshold of witnesses.

```
Event created by Agent → Sent to Witnesses → Witnesses return receipts
                                          → Event + receipts = established
```

### 3.2 Witness Selection Criteria

**Who makes good witnesses?**

| Criterion | Why It Matters | ADAMAS.network Examples |
|-----------|---------------|------------------------|
| **Availability** | Must be online to receipt events | Long-running servers, not laptops |
| **Independence** | Witnesses shouldn't collude | Different operators, jurisdictions |
| **Stake** | Something to lose if they misbehave | Reputation in the network, business relationship |
| **Competence** | Must correctly validate events | Technical operators, not end users |
| **Persistence** | Should store receipts long-term | Servers with reliable storage |

**For ADAMAS.network specifically:**

| Witness Type | Example | Trust Basis |
|--------------|---------|-------------|
| **Your infrastructure** | OVH server, Mac Mini | You control, high availability |
| **Client infrastructure** | Client's ADAMAS instance | Mutual business interest |
| **Neutral third party** | Another ADAMAS operator | Reputation stake |
| **Public witness service** | GLEIF witnesses, others | Institutional credibility |

**Recommended setup for personal ADAMAS:**

```
Witness threshold: 2 of 3

Witness 1: Big ADAMAS (OVH)        ← Your primary infra
Witness 2: Mini ADAMAS (Mac Mini) ← Your secondary infra  
Witness 3: [Future client/partner] ← Independence
```

Even with just your two machines, you get geographic and hardware diversity. Add a third independent witness when you onboard a trusted partner.

### 3.3 What Witnesses Validate

Witnesses don't blindly sign anything. They verify:

```typescript
interface WitnessValidation {
  // Structural validity
  event_well_formed: boolean;       // Schema compliance
  said_matches_content: boolean;    // SAID correctly computed
  sequence_correct: boolean;        // s = previous.s + 1
  
  // Cryptographic validity  
  signatures_valid: boolean;        // Event signed by its authorizing keys (AFP §4.4)
  threshold_met: boolean;           // Enough signatures per kt
  
  // For rotations
  key_commitment_honored: boolean;  // New key matches previous n[]
  
  // Consistency
  no_duplicates: boolean;           // Haven't seen different event at this sequence
  no_forks: boolean;                // KEL is linear, no branches
}
```

**Critical rule:** If a witness sees two different events at the same sequence number (a fork), they:
1. Refuse to receipt either
2. Raise an alarm to watchers
3. The AID is considered **duplicitous** and untrusted

This is how KERI achieves consensus without a blockchain—forks are detectable and punished socially.

### 3.4 Witness vs Guardian

> The AFP specification defines no guardian event. Tenant-root recovery after loss of the pre-rotated keys is an open item (AFP §10), and entities are recovered by tenant revocation and re-delegation (AFP §4.2, §4.6). The comparison below is exploratory design material, not a description of AFP.

| Role | AFP Guardian | KERI Witness |
|------|--------------|--------------|
| **Purpose** | Recovery authorization | Event receipting |
| **When active** | Key loss/compromise | Every key event |
| **Trust model** | Threshold of humans/agents you trust | Threshold of available servers |
| **Can forge identity?** | Yes (that's the point for recovery) | No (just observes) |

**In ADAMAS, you likely want both:**
- Witnesses for normal operations (automated, fast)
- Guardians for recovery (human-in-loop, slower, higher trust)

---

## 4. NATS Integration for KERI-style Events

### 4.1 Subjects

```
# Key Event Log operations
afp.{org}.kel.{aid}.event          # Publish new event
afp.{org}.kel.{aid}.query          # Query KEL for an AID
afp.{org}.kel.{aid}.receipt        # Witness receipts

# Witness coordination  
afp.{org}.witness.{witness_aid}.inbox     # Events for this witness
afp.{org}.witness.{witness_aid}.receipts  # Receipts from this witness

# Watcher alerts
afp.{org}.watcher.duplicity        # Fork detection alerts
afp.{org}.watcher.escrow           # Events pending witness threshold
```

### 4.2 JetStream Streams

```bash
# Immutable KEL storage (per org)
nats stream add AFP_KEL \
  --subjects "afp.*.kel.*.event" \
  --retention limits \
  --max-age unlimited \      # KELs are forever
  --storage file \
  --replicas 3 \
  --deny-delete \            # Append-only
  --deny-purge

# Witness receipts
nats stream add AFP_RECEIPTS \
  --subjects "afp.*.kel.*.receipt" \
  --retention limits \
  --max-age unlimited \
  --storage file \
  --replicas 3
```

---

## 5. Certificate Authorities: The Centralization Problem

### 5.1 How TLS/CAs Work

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Website    │────▶│  CA (e.g.   │────▶│  Browser    │
│  wants cert │     │  Let's      │     │  trusts CA  │
│             │     │  Encrypt)   │     │  root cert  │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    Signs cert for
                    "example.com"
```

Your browser ships with ~150 trusted root CAs. Any of them can sign a cert for any domain.

### 5.2 CA Compromise Vectors

| Attack | Description | Real Examples |
|--------|-------------|---------------|
| **CA compromise** | Attacker gets CA's signing key | DigiNotar (2011) - fraudulent Google certs |
| **Rogue employee** | Insider issues unauthorized cert | Symantec employees (2015) |
| **Government coercion** | State compels CA to issue certs | Suspected in multiple countries |
| **Validation bypass** | Trick CA's domain verification | Various ACME bugs |
| **BGP hijack + validation** | Intercept validation traffic | Demonstrated in research |

**The DigiNotar incident:**
1. Iranian attackers compromised DigiNotar (Dutch CA)
2. Issued fraudulent cert for *.google.com
3. Used for MITM attacks on Iranian Gmail users
4. DigiNotar went bankrupt after trust revocation

### 5.3 Why People Accept This

| Reason | Reality |
|--------|---------|
| "It works" | True—for most threat models |
| "Certificate Transparency helps" | CT logs detect mis-issuance *after the fact* |
| "Revocation exists" | CRL/OCSP is broken in practice, browsers often skip it |
| "Let's Encrypt is trustworthy" | Probably, but still a single point of failure |
| "No alternative" | **This is what KERI addresses** |

### 5.4 KERI vs CA Model

| Aspect | CA/PKI Model | KERI Model |
|--------|--------------|------------|
| **Trust root** | 150 CAs in your browser | The identifier itself (self-certifying) |
| **Can any authority forge?** | Yes, any CA can cert any domain | No—only key holder can sign events |
| **Key rotation** | Reissue cert from CA | Self-issued rotation event |
| **Revocation** | CA publishes CRL (often ignored) | Rotation event in KEL (append-only) |
| **Detection of compromise** | CT logs (after the fact) | Duplicity detection (real-time) |
| **Single point of failure** | Each CA is one | Witness threshold (n of m) |

**The fundamental difference:**

```
CA model:    Identity ← certified by → Trusted Third Party
KERI model:  Identity = Cryptographic Key (self-certifying)
```

In KERI, there's no third party who can forge your identity. The worst witnesses can do is *refuse to receipt*—they can't *create* events for you.

---

## 6. Hybrid Approach for ADAMAS.network

### 6.1 Recommended Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ADAMAS.network                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Agent Identity Layer (KERI-style)                         │
│   ├── Self-certifying AIDs (NKey-derived)                   │
│   ├── KEL stored in JetStream (append-only)                 │
│   ├── Witness network (your infra + partners)               │
│   └── Pre-rotation for key security                         │
│                                                             │
│   External Interface (Traditional TLS)                      │
│   ├── Let's Encrypt certs for HTTPS endpoints               │
│   ├── A2A Agent Cards served over TLS                       │
│   └── mTLS optional for agent-to-agent (defense in depth)   │
│                                                             │
│   Trust Bridge                                              │
│   ├── Agent Card includes AID + current public key          │
│   ├── Verifiers can check KEL for key validity              │
│   └── TLS gets you to the endpoint, KERI verifies the agent │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 What This Gives You

| Layer | Protects Against |
|-------|------------------|
| TLS/Let's Encrypt | Network eavesdropping, casual MITM |
| KERI identity | CA compromise, identity forgery, key theft (via pre-rotation) |
| Witness threshold | Single point of failure, undetected key events |

You're not replacing TLS—you're adding a layer that doesn't trust the CA system for *identity*, only for *transport*.

---

## 7. Implementation Path

### Phase 1: KERI-aligned KEL (No External Witnesses Yet)

- [ ] Update `identity_id` to be self-certifying (derivable from `genesis_nkey`)
- [ ] Add `next_key_digest` to registration (pre-rotation)
- [ ] Structure key events as KERI-compatible (icp, rot, ixn)
- [ ] Store KEL in append-only JetStream stream

### Phase 2: Internal Witnesses

- [ ] Big ADAMAS and Mini ADAMAS witness each other
- [ ] Implement receipt generation and validation
- [ ] Add witness threshold checking before event acceptance
- [ ] Implement duplicity detection

### Phase 3: External Witnesses

- [ ] Define witness onboarding protocol
- [ ] Add first external witness (client or partner)
- [ ] Implement witness discovery for ADAMAS.network participants

### Phase 4: Optional Blockchain Anchoring

- [ ] Periodic KEL root hash anchored to Bitcoin/Ethereum
- [ ] Provides catastrophic recovery if all witnesses lost
- [ ] Not required for normal operation

---

## References

- [KERI Whitepaper](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
- [KERI Protocol Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [WebOfTrust (KERI implementation)](https://github.com/WebOfTrust)
- [GLEIF vLEI (KERI in production)](https://www.gleif.org/en/lei-solutions/gleifs-digital-strategy-for-the-lei/introducing-the-verifiable-lei)
- [Certificate Transparency](https://certificate.transparency.dev/)

---

*Self-certifying identity removes the need to trust third parties. Witnesses provide availability and consistency, not authority.*
