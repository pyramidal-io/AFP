# AFP Agent Identity Addendum

> **SUPERSEDED — Historical reference only.** This addendum extends AFP v0.2.0 with NKey-based identity lifecycle (rotation, recovery, delegation, succession). Both documents are superseded by **AFP v0.3.14-draft** (`docs/afp_specification.md` §4), which replaces NKey-based identity with **KERI Autonomic Identifiers (AIDs)** and Key Event Logs. Do **not** implement against this document. See §4 of `docs/afp_specification.md` for the current normative identity model.

**Version:** 0.1.1-draft  
**Date:** March 2026  
**Status:** Superseded — see docs/afp_specification.md §4
**Parent Document:** Agent_Federation_Protocol_AFP.md (v0.2.0)  
**Authors:** Michael Beddows, Claude (Anthropic)  
**License:** Apache 2.0

---

## Abstract

This addendum extends the Agent Federation Protocol (AFP) with comprehensive agent identity management. While AFP v0.2.0 establishes NKey-based authentication and registration, this document specifies the complete identity lifecycle: establishment, rotation, delegation, recovery, and succession.

**Design principle:** Identity is the foundation of federation. Every AFP operation—registration, discovery, task delegation, reputation—depends on verifiable, durable agent identity.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Identity Model](#2-identity-model)
3. [Key Lifecycle](#3-key-lifecycle)
4. [Identity Delegation](#4-identity-delegation)
5. [Recovery Mechanisms](#5-recovery-mechanisms)
6. [Agent Succession](#6-agent-succession)
7. [Identity Attestations](#7-identity-attestations)
8. [NATS Integration](#8-nats-integration)
9. [Security Considerations](#9-security-considerations)
10. [Implementation Checklist](#10-implementation-checklist)

---

## 1. Introduction

### 1.1 The Problem

AFP v0.2.0 establishes that agents authenticate via NKeys (Ed25519 keypairs). However, several identity scenarios remain unspecified:

- **Key compromise:** What happens when an agent's private key is exposed?
- **Key rotation:** How do agents update keys without losing reputation?
- **Delegation:** Can Agent A act on behalf of Agent B?
- **Recovery:** How does an agent recover from key loss?
- **Succession:** What happens when an agent is retired or replaced?

Without answers to these questions, AFP identities are fragile—a single key loss can orphan accumulated reputation and break established trust relationships.

### 1.2 Design Goals

| Goal | Approach |
|------|----------|
| **Continuity** | Identity persists across key rotations |
| **Recoverability** | Lost keys don't mean lost identity |
| **Delegation** | Hierarchical agent relationships supported |
| **Auditability** | All identity operations are signed and logged |
| **Minimal trust** | No central identity authority required |

### 1.3 Relationship to Other Protocols

| Protocol | Identity Role |
|----------|---------------|
| **AFP** | Identity establishment and authentication |
| **ZKA** | Privacy-preserving identity proofs |
| **VXP** | Identity as party to value exchanges |
| **APL** | Identity tied to payment addresses |

---

## 2. Identity Model

### 2.1 Identity Structure

An AFP agent identity consists of:

```typescript
interface AgentIdentity {
  // === Immutable Core ===
  identity_id: string;              // Content-addressed ID (hash of genesis key + metadata)
  genesis_nkey: string;             // Original public NKey (never changes)
  created_at: datetime;
  
  // === Mutable State ===
  current_nkey: string;             // Active public NKey (can rotate)
  nkey_history: NKeyRotation[];     // Signed chain of key transitions
  
  // === Delegation ===
  delegates: DelegateGrant[];       // Agents authorized to act on behalf
  delegated_from?: string;          // If this identity is a delegate
  
  // === Recovery ===
  recovery_config: RecoveryConfig;
  
  // === Metadata ===
  display_name: string;
  provider: ProviderInfo;
  
  // === Attestations ===
  attestations: Attestation[];      // Third-party identity claims
}

// Content-addressed identity ID
function computeIdentityId(genesis_nkey: string, created_at: datetime, provider: ProviderInfo): string {
  const payload = canonicalize({ genesis_nkey, created_at, provider });
  return `aid_${blake3(payload).slice(0, 32)}`;  // "aid_" prefix for Agent Identity
}
```

### 2.2 Identity vs. Keys

A critical distinction:

| Concept | Description | Lifetime |
|---------|-------------|----------|
| **Identity** | The persistent "who" of an agent | Permanent (until succession) |
| **NKey** | The cryptographic "how" of authentication | Rotatable |
| **Reputation** | Accumulated trust from behavior | Tied to identity, not key |

An agent can rotate keys while maintaining the same identity. Reputation follows identity, not keys.

### 2.3 Identity States

```
┌─────────────┐
│   Genesis   │  Initial registration
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Active    │  Normal operation
└──────┬──────┘
       │
       ├───────────────┬───────────────┐
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Rotating   │ │  Suspended  │ │  Delegated  │
└──────┬──────┘ └──────┬──────┘ └─────────────┘
       │               │
       ▼               ▼
┌─────────────┐ ┌─────────────┐
│   Active    │ │  Recovered  │
└─────────────┘ └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │   Active    │
                └─────────────┘

       │
       ▼ (explicit succession)
┌─────────────┐
│  Succeeded  │  Identity terminated, successor designated
└─────────────┘
```

---

## 3. Key Lifecycle

### 3.1 Key Rotation

Agents can rotate their NKey while preserving identity:

```typescript
interface NKeyRotation {
  // New key
  new_nkey: string;
  
  // Rotation metadata
  rotated_at: datetime;
  reason: 'scheduled' | 'compromise' | 'upgrade' | 'recovery';
  
  // Authorization chain
  authorized_by: {
    method: 'current_key' | 'recovery' | 'delegate';
    signature: string;              // Signed by authorizing key
  };
  
  // Previous key acknowledgment
  previous_key_signature?: string;  // Old key signs transition (if available)
  
  // Transition period
  grace_period_ends?: datetime;     // Both keys valid until this time
}
```

**NATS Subject:** `afp.{org}.identity.rotate`

```typescript
// Request
interface RotationRequest {
  identity_id: string;
  new_nkey: string;
  reason: string;
  
  // Proof of authorization
  current_key_signature: string;    // Current key signs the rotation
  new_key_signature: string;        // New key proves possession
  
  // Optional: grace period request
  grace_period_hours?: number;      // Default: 24 hours
}

// Response
interface RotationResponse {
  success: boolean;
  rotation_id: string;
  grace_period_ends: datetime;
  
  // Updated NATS credentials (if applicable)
  new_credentials?: NATSCredentials;
}
```

### 3.2 Rotation Best Practices

| Scenario | Recommended Approach |
|----------|---------------------|
| **Scheduled rotation** | 90-day cycle, 24-hour grace period |
| **Suspected compromise** | Immediate rotation, 0 grace period |
| **Hardware upgrade** | Rotate before migration, 48-hour grace |
| **Organizational change** | Coordinate with succession planning |

### 3.3 Key Revocation

Immediate key invalidation (without rotation):

```typescript
// NATS Subject: afp.{org}.identity.revoke
interface RevocationRequest {
  identity_id: string;
  
  // Authorization (one of)
  current_key_signature?: string;   // Self-revocation
  recovery_proof?: RecoveryProof;   // Recovery-based revocation
  delegate_signature?: string;      // Delegate with revocation permission
  
  reason: string;
  
  // What happens next
  suspend_identity: boolean;        // If true, identity enters suspended state
}
```

Revocation is instant—the NATS account configuration is updated immediately, and the revoked NKey loses all access.

---

## 4. Identity Delegation

### 4.1 Delegate Model

Delegation allows Agent A to authorize Agent B to act on its behalf:

```typescript
interface DelegateGrant {
  delegate_identity_id: string;     // Who is being delegated to
  
  // Scope of delegation
  permissions: DelegatePermission[];
  
  // Constraints
  constraints: {
    expires_at?: datetime;
    max_tasks?: number;
    allowed_capabilities?: string[];
    budget_limit?: number;          // VXP budget constraint
  };
  
  // Authorization
  granted_at: datetime;
  granted_by_signature: string;     // Principal signs the grant
  accepted_by_signature?: string;   // Delegate acknowledges
  
  // Revocation
  revoked_at?: datetime;
  revocation_signature?: string;
}

enum DelegatePermission {
  // Task operations
  ACCEPT_TASKS = 'accept_tasks',        // Accept tasks on behalf of principal
  DELEGATE_TASKS = 'delegate_tasks',    // Further delegate to others
  
  // Identity operations
  ROTATE_KEYS = 'rotate_keys',          // Rotate principal's keys
  REVOKE_KEYS = 'revoke_keys',          // Emergency key revocation
  
  // Reputation operations
  VOUCH = 'vouch',                      // Vouch for others using principal's reputation
  
  // Value operations (VXP)
  TRANSACT = 'transact',                // Make value exchanges
  SIGN_COMMITMENTS = 'sign_commitments' // Sign binding agreements
}
```

### 4.2 Delegation Chains

Delegation can be transitive (if permitted):

```
Principal Agent
    │
    │ grants ACCEPT_TASKS, DELEGATE_TASKS
    ▼
Sub-Agent A
    │
    │ grants ACCEPT_TASKS (no DELEGATE_TASKS)
    ▼
Sub-Agent B (leaf delegate)
```

**Constraint:** A delegate cannot grant permissions it doesn't have. Chains are verified by tracing back to the principal.

### 4.3 Delegation Protocol

```typescript
// NATS Subject: afp.{org}.identity.delegate
interface DelegationRequest {
  principal_identity_id: string;
  delegate_identity_id: string;
  permissions: DelegatePermission[];
  constraints: DelegateConstraints;
  
  // Principal authorizes
  principal_signature: string;
}

// NATS Subject: afp.{org}.identity.delegate.accept
interface DelegationAcceptance {
  grant_id: string;
  delegate_signature: string;       // Delegate accepts responsibility
}

// NATS Subject: afp.{org}.identity.delegate.revoke
interface DelegationRevocation {
  grant_id: string;
  
  // Either party can revoke
  revoked_by: 'principal' | 'delegate';
  signature: string;
  reason?: string;
}
```

---

## 5. Recovery Mechanisms

### 5.1 Recovery Configuration

Set during registration or updated later:

```typescript
interface RecoveryConfig {
  // Method 1: Social recovery (n-of-m guardians)
  social_recovery?: {
    guardians: GuardianConfig[];
    threshold: number;              // n guardians required
  };
  
  // Method 2: Time-locked recovery
  timelock_recovery?: {
    recovery_nkey: string;          // Pre-registered recovery key
    delay_hours: number;            // Mandatory waiting period
  };
  
  // Method 3: Organization recovery (for org-owned agents)
  org_recovery?: {
    org_id: string;
    authorized_roles: string[];     // Roles that can initiate recovery
  };
  
  // Last resort: No recovery configured
  // If all methods fail, identity is unrecoverable
}

interface GuardianConfig {
  guardian_identity_id: string;
  guardian_nkey: string;
  weight: number;                   // For weighted threshold schemes
}
```

### 5.2 Social Recovery Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Social Recovery Flow                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Agent loses access to current NKey                             │
│                                                                     │
│  2. Agent (via new NKey) initiates recovery:                       │
│     POST afp.{org}.identity.recover.initiate                       │
│     { identity_id, new_nkey, reason }                              │
│                                                                     │
│  3. Guardians are notified:                                        │
│     PUB afp.{org}.identity.recover.request.{guardian_id}           │
│                                                                     │
│  4. Each guardian reviews and signs (or rejects):                  │
│     POST afp.{org}.identity.recover.approve                        │
│     { recovery_id, guardian_signature }                            │
│                                                                     │
│  5. Once threshold reached, recovery executes:                     │
│     - New NKey becomes active                                      │
│     - Old NKey is revoked                                          │
│     - Identity state: Recovered → Active                           │
│                                                                     │
│  6. Recovery event logged to identity history                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Time-Locked Recovery

For self-sovereign recovery without guardians:

```typescript
// NATS Subject: afp.{org}.identity.recover.timelock.initiate
interface TimelockRecoveryRequest {
  identity_id: string;
  new_nkey: string;
  
  // Signed by pre-registered recovery key
  recovery_key_signature: string;
}

// Response includes mandatory delay
interface TimelockRecoveryResponse {
  recovery_id: string;
  executes_at: datetime;            // Now + delay_hours
  
  // During delay, current key holder can cancel
  cancellation_subject: string;
}
```

The delay allows the legitimate key holder to cancel if the recovery was initiated by an attacker who obtained the recovery key.

---

## 6. Agent Succession

### 6.1 Succession Model

When an agent is permanently retired, its identity can designate a successor:

```typescript
interface SuccessionDeclaration {
  predecessor_identity_id: string;
  successor_identity_id: string;
  
  // What transfers
  transfer_config: {
    reputation: boolean;            // Transfer accumulated trust
    delegates: boolean;             // Transfer delegation grants (as principal)
    active_tasks: boolean;          // Transfer in-progress tasks
    channels: boolean;              // Transfer payment channels (VXP/APL)
  };
  
  // Authorization
  declared_at: datetime;
  predecessor_signature: string;
  successor_acceptance?: string;
  
  // Execution
  effective_at?: datetime;          // Scheduled succession
  executed_at?: datetime;
}
```

### 6.2 Succession Protocol

```typescript
// NATS Subject: afp.{org}.identity.succession.declare
interface SuccessionRequest {
  predecessor_identity_id: string;
  successor_identity_id: string;
  transfer_config: TransferConfig;
  effective_at?: datetime;
  
  predecessor_signature: string;
}

// NATS Subject: afp.{org}.identity.succession.accept
interface SuccessionAcceptance {
  succession_id: string;
  successor_signature: string;
}

// NATS Subject: afp.{org}.identity.succession.execute
// Triggered automatically at effective_at, or manually if immediate
interface SuccessionExecution {
  succession_id: string;
  
  // Results
  reputation_transferred: number;
  delegates_transferred: number;
  tasks_transferred: number;
  channels_transferred: number;
  
  // Predecessor state
  predecessor_final_state: 'succeeded';  // Identity is now historical
}
```

### 6.3 Reputation Transfer

Reputation transfer is not 1:1—it decays based on the succession context:

| Context | Reputation Transfer Rate |
|---------|-------------------------|
| Planned succession (same provider) | 90% |
| Planned succession (different provider) | 70% |
| Unplanned succession | 50% |
| Forced succession (guardian-initiated) | 30% |

This prevents reputation laundering while preserving continuity value.

---

## 7. Identity Attestations

### 7.1 Attestation Model

Third parties can make claims about an identity:

```typescript
interface Attestation {
  attestation_id: string;           // Content-addressed
  
  // Subject
  subject_identity_id: string;
  
  // Claim
  claim_type: AttestationType;
  claim_data: object;               // Type-specific payload
  
  // Attestor
  attestor_identity_id: string;
  attestor_signature: string;
  
  // Validity
  issued_at: datetime;
  expires_at?: datetime;
  revoked_at?: datetime;
}

enum AttestationType {
  // Organizational
  EMPLOYEE_OF = 'employee_of',              // "Agent X works for Org Y"
  CERTIFIED_BY = 'certified_by',            // "Agent X is certified by Authority Z"
  
  // Capability
  CAPABILITY_VERIFIED = 'capability_verified', // TVF validation result
  
  // Reputation vouching
  VOUCHED_BY = 'vouched_by',                // AFP cross-org reputation vouching
  
  // Compliance
  KYC_VERIFIED = 'kyc_verified',            // For regulated contexts
  AUDIT_PASSED = 'audit_passed',            // Security audit attestation
  
  // Custom
  CUSTOM = 'custom'
}
```

### 7.2 ZKA Integration

Attestations can be proven without revealing details via ZKA:

```typescript
// Prove: "I have a CAPABILITY_VERIFIED attestation for 'code_review' 
//         from an attestor with reputation > 0.8"
// Without revealing: attestor identity, exact score, other capabilities

interface AttestationProof {
  proof_type: 'zka_attestation';
  
  // What's being proven
  claim_type: AttestationType;
  claim_predicate: string;          // "capability = 'code_review'"
  attestor_predicate: string;       // "reputation > 0.8"
  
  // ZKA proof (UltraHonk/Barretenberg — BN254, ZKA spec v0.5.0)
  zka_proof: UltraHonkProof;
  
  // Verification
  verifiable_at: string;            // ZKA verification endpoint
}
```

---

## 8. NATS Integration

### 8.1 Identity Subjects

```
# Identity lifecycle
afp.{org}.identity.register              # Initial registration (extends AFP register)
afp.{org}.identity.rotate                # Key rotation
afp.{org}.identity.revoke                # Key revocation
afp.{org}.identity.query                 # Query identity state

# Delegation
afp.{org}.identity.delegate              # Create delegation
afp.{org}.identity.delegate.accept       # Accept delegation
afp.{org}.identity.delegate.revoke       # Revoke delegation
afp.{org}.identity.delegate.query        # Query delegations

# Recovery
afp.{org}.identity.recover.initiate      # Start recovery
afp.{org}.identity.recover.approve       # Guardian approval
afp.{org}.identity.recover.cancel        # Cancel recovery (by current key holder)
afp.{org}.identity.recover.execute       # Execute recovery

# Succession
afp.{org}.identity.succession.declare    # Declare succession
afp.{org}.identity.succession.accept     # Accept succession
afp.{org}.identity.succession.execute    # Execute succession

# Attestations
afp.{org}.identity.attest                # Issue attestation
afp.{org}.identity.attest.revoke         # Revoke attestation
afp.{org}.identity.attest.query          # Query attestations
```

### 8.2 JetStream Streams

```bash
# Identity events stream (per org)
nats stream add AFP_IDENTITY_ORG_ACME \
  --subjects "afp.org_acme.identity.>" \
  --retention limits \
  --max-age 365d \
  --storage file \
  --replicas 3

# Immutable identity history
nats stream add AFP_IDENTITY_HISTORY \
  --subjects "afp.*.identity.rotate,afp.*.identity.recover.*,afp.*.identity.succession.*" \
  --retention limits \
  --max-age unlimited \
  --storage file \
  --replicas 3
```

---

## 9. Security Considerations

### 9.1 Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Key theft | Immediate revocation, recovery mechanisms |
| Recovery abuse | Time delays, threshold requirements, cancellation windows |
| Delegation abuse | Explicit permissions, constraints, revocation |
| Reputation laundering | Decayed transfer rates for succession |
| Guardian collusion | Diverse guardian selection, weighted thresholds |
| Identity impersonation | Cryptographic signatures on all operations |

### 9.2 Key Storage Recommendations

| Environment | Recommendation |
|-------------|----------------|
| Cloud agents | Hardware Security Module (HSM) or cloud KMS |
| Edge agents | Secure enclave (SGX, TrustZone) |
| Development | Encrypted keystore with passphrase |
| Recovery keys | Offline, geographically distributed |

### 9.3 Audit Requirements

All identity operations MUST be logged:

```typescript
interface IdentityAuditEntry {
  timestamp: datetime;
  identity_id: string;
  operation: string;
  
  // Authorization
  authorized_by: {
    method: 'self' | 'delegate' | 'recovery' | 'guardian';
    authorizer_id: string;
    signature: string;
  };
  
  // Outcome
  success: boolean;
  error?: string;
  
  // Immutable reference
  stream_sequence: number;          // JetStream sequence for verification
}
```

---

## 10. Implementation Checklist

### 10.1 For AFP Implementations

**Phase 1: Core Identity**
- [ ] Extend registration to create full identity structure
- [ ] Implement identity_id computation
- [ ] Add identity state machine
- [ ] Create identity query endpoints

**Phase 2: Key Rotation**
- [ ] Implement rotation request/response
- [ ] Add grace period handling
- [ ] Update NATS credentials on rotation
- [ ] Maintain rotation history

**Phase 3: Delegation**
- [ ] Implement delegation grants
- [ ] Add permission checking to all operations
- [ ] Support delegation chains with verification
- [ ] Handle delegation revocation

**Phase 4: Recovery**
- [ ] Implement social recovery with guardians
- [ ] Add time-locked recovery
- [ ] Create recovery cancellation flow
- [ ] Handle recovery execution

**Phase 5: Succession**
- [ ] Implement succession declaration
- [ ] Add reputation transfer with decay
- [ ] Handle task and channel transfers
- [ ] Archive predecessor identity

### 10.2 For Agent Developers

- [ ] Generate and securely store NKey
- [ ] Implement key rotation schedule
- [ ] Configure recovery mechanism (guardians or timelock)
- [ ] Handle delegation if supporting hierarchical agents
- [ ] Plan succession strategy for long-lived agents

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1.0-draft | 2026-01 | Claude + Michael | Initial specification |
| 0.1.1-draft | 2026-03 | Claude + Michael | §7.2: `Halo2Proof` → `UltraHonkProof` (ZKA v0.5.0 alignment) |

---

*Identity is the foundation of trust. AFP Identity ensures agents can build lasting relationships across the federation.*
