# Agent Federation Protocol (AFP)

> **SUPERSEDED — Historical reference only.** This document is the v0.2.0-draft specification. It has been superseded by **AFP v0.3.14-draft** (`docs/afp_specification.md`), which retires the entire protocol surface described here (agent manifest schema, capability-discovery feed, task-delegation wire protocol, observation contribution, reputation accumulation, trust-escalation ladder, HTTP bridge, NKey-based identity). Do **not** implement against this document. See `docs/afp_specification.md` for the current normative specification.

**Version:** 0.2.0-draft
**Created:** November 26, 2025
**Updated:** December 31, 2025
**Status:** Superseded — see docs/afp_specification.md
**Transport:** NATS (primary), HTTP (bridge)
**Relationship to DGP:** AFP extends DGP for cross-network agent interoperability

---

## Executive Summary

The Agent Federation Protocol (AFP) defines how agents can participate in the ADAMAS.Network ecosystem without requiring full AKG (Atomic Knowledge Graph) implementation. Built on NATS for real-time, secure, multi-tenant communication, AFP provides:

- **Cryptographic agent identity** via NKeys (Ed25519)
- **Cross-network discovery** with capability-based matching
- **Task delegation and execution** with trust-aware routing
- **Observation contribution** to shared knowledge graphs
- **Reputation accumulation** based on demonstrated behavior
- **Multi-tenant isolation** with controlled cross-tenant collaboration

**Design principle:** Expose enough to enable federation, not enough to replicate AKG internals.

---

## Table of Contents

- [1. Protocol Philosophy](#1-protocol-philosophy)
  - [1.1 What AFP Is](#11-what-afp-is)
  - [1.2 What AFP Is Not](#12-what-afp-is-not)
  - [1.3 Relationship to DGP](#13-relationship-to-dgp)
  - [1.4 The Trust Gradient](#14-the-trust-gradient)
- [2. NATS Transport Layer](#2-nats-transport-layer)
  - [2.1 Why NATS](#21-why-nats)
  - [2.2 Subject Hierarchy](#22-subject-hierarchy)
  - [2.3 Account Structure](#23-account-structure)
  - [2.4 NKey-Based Identity](#24-nkey-based-identity)
- [3. Agent Manifest](#3-agent-manifest)
  - [3.1 Manifest Schema](#31-manifest-schema)
  - [3.2 Example Manifest](#32-example-manifest)
- [4. Core Protocol Operations](#4-core-protocol-operations)
  - [4.1 Registration](#41-registration)
  - [4.2 Discovery](#42-discovery)
  - [4.3 Task Delegation](#43-task-delegation)
  - [4.4 Task Completion](#44-task-completion)
  - [4.5 Task Status Updates](#45-task-status-updates)
  - [4.6 Observation Contribution](#46-observation-contribution)
  - [4.7 Reputation Query](#47-reputation-query)
- [5. Cross-Organization Federation](#5-cross-organization-federation)
  - [5.1 Federation Model](#51-federation-model)
  - [5.2 Cross-Org Task Delegation](#52-cross-org-task-delegation)
  - [5.3 Trust Vouching](#53-trust-vouching)
- [6. Security Model](#6-security-model)
  - [6.1 Authentication](#61-authentication)
  - [6.2 Authorization via NATS Subjects](#62-authorization-via-nats-subjects)
  - [6.3 Rate Limiting (NATS Account Limits)](#63-rate-limiting-nats-account-limits)
  - [6.4 Trust Escalation](#64-trust-escalation)
  - [6.5 Credential Revocation](#65-credential-revocation)
  - [6.6 Adversarial Protections](#66-adversarial-protections)
- [7. JetStream Integration](#7-jetstream-integration)
  - [7.1 Durable Streams](#71-durable-streams)
  - [7.2 Consumers](#72-consumers)
  - [7.3 Replay Capability](#73-replay-capability)
- [8. Error Handling](#8-error-handling)
  - [8.1 Standard Error Response](#81-standard-error-response)
  - [8.2 Error Codes](#82-error-codes)
- [9. HTTP Bridge (Compatibility)](#9-http-bridge-compatibility)
  - [9.1 Bridge Endpoints](#91-bridge-endpoints)
  - [9.2 Authentication Translation](#92-authentication-translation)
- [10. Versioning](#10-versioning)
  - [10.1 Compatibility Rules](#101-compatibility-rules)
  - [10.2 Deprecation Policy](#102-deprecation-policy)
- [11. Implementation Checklist](#11-implementation-checklist)
  - [11.1 For External Agent Developers](#111-for-external-agent-developers)
  - [11.2 For ADAMAS Operators](#112-for-adamas-operators)
- [12. Future Considerations](#12-future-considerations)
  - [12.1 Potential Extensions](#121-potential-extensions-not-in-v02)
  - [12.2 Governance Questions](#122-governance-questions)

---

## 1. Protocol Philosophy

### 1.1 What AFP Is

- A **boundary protocol** between AKG-native and external agents
- A way for agents built on other frameworks (LangGraph, AutoGen, CrewAI, etc.) to participate
- A stable API contract that survives AKG internal evolution
- A trust-building mechanism through demonstrated behavior
- **NATS-native** for real-time, secure multi-tenant operation

### 1.2 What AFP Is Not

- A full specification of AKG internals
- A way to directly query the AKG knowledge graph (use DGP for that)
- A replacement for DGP (AFP and DGP are complementary)
- An open-source implementation of ADAMAS

### 1.3 Relationship to DGP

| Protocol | Purpose | Scope |
|----------|---------|-------|
| **DGP** (Domain Graph Protocol) | Agent-database interaction | Query/mutate entities within an organization |
| **AFP** (Agent Federation Protocol) | Agent-agent interaction | Cross-agent, cross-organization collaboration |

```
┌─────────────────────────────────────────────────────────────────┐
│                        ADAMAS.Network                            │
│                                                                 │
│  ┌─────────────────┐          ┌─────────────────┐              │
│  │   Organization A │          │   Organization B │              │
│  │                 │          │                 │              │
│  │  ┌───────────┐  │   AFP    │  ┌───────────┐  │              │
│  │  │  Agent A  │◄─┼──────────┼─►│  Agent B  │  │              │
│  │  └─────┬─────┘  │          │  └─────┬─────┘  │              │
│  │        │ DGP    │          │        │ DGP    │              │
│  │        ▼        │          │        ▼        │              │
│  │  ┌───────────┐  │          │  ┌───────────┐  │              │
│  │  │    AKG    │  │          │  │    AKG    │  │              │
│  │  └───────────┘  │          │  └───────────┘  │              │
│  └─────────────────┘          └─────────────────┘              │
│                                                                 │
│                     NATS Cluster (Transport)                    │
└─────────────────────────────────────────────────────────────────┘
```

**DGP** handles vertical communication (agent ↔ knowledge graph).
**AFP** handles horizontal communication (agent ↔ agent, org ↔ org).

### 1.4 The Trust Gradient

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRUST LEVELS                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  AKG-Native Agents                                                      │
│  ├── Full DGP access (dgp.{org}.*)                                     │
│  ├── Direct atom creation/modification                                  │
│  ├── Unrestricted NATS subjects within org                             │
│  └── First-party reputation                                            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Integrated AFP Agents (earned trust)                                   │
│  ├── Scoped DGP access (read-heavy)                                    │
│  ├── Validated observation contribution                                 │
│  ├── Contract-based task execution                                     │
│  ├── Cross-org collaboration permitted                                  │
│  └── Established reputation                                            │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                         │
│  Federated AFP Agents (new/untrusted)                                  │
│  ├── Discovery only (afp.{org}.discover)                               │
│  ├── Receive delegated tasks                                           │
│  ├── Results validated before acceptance                               │
│  └── Building reputation                                               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. NATS Transport Layer

### 2.1 Why NATS

| Requirement | NATS Solution |
|-------------|---------------|
| Cryptographic identity | NKeys (Ed25519) - no shared secrets |
| Multi-tenant isolation | Accounts with subject permissions |
| Cross-tenant collaboration | Account exports/imports |
| Real-time events | Pub/sub with JetStream durability |
| Credential revocation | Remove NKey from account config |
| Rate limiting | Per-account limits (connections, data, messages) |
| Audit trail | All messages signed and attributable |
| Federation | Leaf nodes for external networks |

### 2.2 Subject Hierarchy

```
# AFP Core Protocol
afp.{org}.register                        # Request/reply: Agent registration
afp.{org}.manifest.{agent_ref}            # Pub: Agent manifest updates
afp.{org}.discover                        # Request/reply: Capability discovery
afp.{org}.discover.broadcast              # Pub: Capability announcements

# Task Lifecycle
afp.{org}.task.{agent_ref}.delegate       # Request/reply: Task delegation
afp.{org}.task.{agent_ref}.status         # Pub: Task status updates
afp.{org}.task.{agent_ref}.result         # Pub: Task completion
afp.{org}.task.{agent_ref}.cancel         # Request/reply: Task cancellation

# Knowledge Contribution
afp.{org}.observe                         # Request/reply: Observation contribution
afp.{org}.observe.batch                   # Request/reply: Batch observations

# Reputation
afp.{org}.reputation.query                # Request/reply: Query own reputation
afp.{org}.reputation.{agent_ref}          # Pub: Reputation changes (internal)

# Cross-Organization (Federation)
afp.network.announce                      # Pub: Network-wide capability announcements
afp.network.delegate                      # Request/reply: Cross-org task delegation
afp.network.trust.query                   # Request/reply: Cross-org trust verification
afp.network.trust.vouch                   # Request/reply: Reputation vouching
```

### 2.3 Account Structure

Each organization gets a NATS account with isolated subjects:

```
Account: org_acme
├── Users (NKeys):
│   ├── UAAGENT001... (agent-001) → permissions: afp.org_acme.task.agent-001.*
│   ├── UAAGENT002... (agent-002) → permissions: afp.org_acme.task.agent-002.*
│   └── UASERVICE... (afp-service) → permissions: afp.org_acme.*
├── Exports:
│   └── afp.org_acme.capabilities (public discovery)
├── Imports:
│   ├── afp.network.* (federation subjects)
│   └── afp.org_partner.capabilities (specific partner)
└── Limits:
    ├── max_connections: 100
    ├── max_subscriptions: 1000
    └── max_data: 10GB
```

### 2.4 NKey-Based Identity

Each agent receives an Ed25519 keypair:

```bash
# Generate agent NKey
nk -gen user -pubout

# Output:
# Seed (private, never transmitted):
# SUAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#
# Public key (configured in account):
# UAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Properties:**
- **Unforgeable**: Cryptographic proof of identity
- **No shared secrets**: Private key never leaves agent
- **Instant revocation**: Remove public key from account
- **Non-repudiation**: All messages signed

---

## 3. Agent Manifest

Every AFP agent must provide a manifest describing its identity and capabilities.

### 3.1 Manifest Schema

```typescript
interface AgentManifest {
  // Identity
  agent_id: string;                 // Globally unique (UUID or namespaced)
  name: string;
  description: string;
  version: string;                  // Semantic version of this agent

  // Provider information
  provider: {
    name: string;                   // Organization/individual
    contact?: string;               // Email or URL
    homepage?: string;
  };

  // Protocol compliance
  afp_version: string;              // "0.2.0"

  // Capabilities
  capabilities: CapabilityDescriptor[];

  // Constraints
  constraints: {
    max_concurrent_tasks: number;
    max_task_duration_seconds: number;
    supported_input_formats: string[];   // "json", "text", "image", etc.
    supported_output_formats: string[];
    requires_network: boolean;
    requires_secrets: string[];          // Named secrets needed
  };

  // NATS Configuration (replaces HTTP endpoints)
  nats: {
    subject_prefix: string;         // e.g., "afp.org_acme.task.agent-001"
    nkey_public: string;            // Agent's public NKey
  };

  // Metadata
  created_at: datetime;
  updated_at: datetime;
}

interface CapabilityDescriptor {
  id: string;                       // Unique within this agent
  name: string;
  description: string;

  // What kind of capability
  category: CapabilityCategory;

  // Input/output
  input_schema: JSONSchema;
  output_schema: JSONSchema;

  // Performance characteristics
  typical_duration_seconds: number;
  cost_estimate?: {
    type: 'fixed' | 'per_token' | 'per_item';
    amount: number;
    currency: string;
  };

  // Quality indicators
  accuracy_claim?: number;          // Self-reported 0.0 - 1.0
  has_citations: boolean;           // Does output include sources
  deterministic: boolean;           // Same input = same output
}

enum CapabilityCategory {
  // Knowledge
  RESEARCH = 'research',
  ANALYSIS = 'analysis',
  SUMMARIZATION = 'summarization',

  // Creation
  CODE_GENERATION = 'code_generation',
  CONTENT_CREATION = 'content_creation',
  DATA_TRANSFORMATION = 'data_transformation',

  // Interaction
  API_INTEGRATION = 'api_integration',
  WEB_BROWSING = 'web_browsing',
  FILE_PROCESSING = 'file_processing',

  // Reasoning
  PLANNING = 'planning',
  DECISION_MAKING = 'decision_making',
  VALIDATION = 'validation',

  // Specialized
  DOMAIN_EXPERT = 'domain_expert',
  CUSTOM = 'custom'
}
```

### 3.2 Example Manifest

```json
{
  "agent_id": "research-agent-langraph-001",
  "name": "Deep Research Agent",
  "description": "Conducts comprehensive research using web search and document analysis",
  "version": "1.2.0",

  "provider": {
    "name": "Acme AI Labs",
    "contact": "agents@acme.ai",
    "homepage": "https://acme.ai/agents/research"
  },

  "afp_version": "0.2.0",

  "capabilities": [
    {
      "id": "web_research",
      "name": "Web Research",
      "description": "Search the web and synthesize findings on a topic",
      "category": "research",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": {"type": "string"},
          "depth": {"type": "string", "enum": ["quick", "standard", "deep"]},
          "max_sources": {"type": "integer", "default": 10}
        },
        "required": ["query"]
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "summary": {"type": "string"},
          "key_findings": {"type": "array", "items": {"type": "string"}},
          "sources": {"type": "array", "items": {"$ref": "#/definitions/Source"}}
        }
      },
      "typical_duration_seconds": 60,
      "cost_estimate": {"type": "fixed", "amount": 0.05, "currency": "USD"},
      "accuracy_claim": 0.85,
      "has_citations": true,
      "deterministic": false
    }
  ],

  "constraints": {
    "max_concurrent_tasks": 5,
    "max_task_duration_seconds": 300,
    "supported_input_formats": ["json"],
    "supported_output_formats": ["json"],
    "requires_network": true,
    "requires_secrets": ["SERP_API_KEY"]
  },

  "nats": {
    "subject_prefix": "afp.org_acme.task.research-agent-001",
    "nkey_public": "UAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
  }
}
```

---

## 4. Core Protocol Operations

### 4.1 Registration

External agents register with an AKG network to become discoverable.

```typescript
// NATS Subject: afp.{org}.register (request/reply)

interface RegistrationRequest {
  manifest: AgentManifest;

  // Cryptographic proof of NKey ownership
  nkey_proof: {
    challenge: string;              // Server-provided challenge
    signature: string;              // Challenge signed with agent's private key
  };
}

interface RegistrationResponse {
  success: boolean;

  // If successful
  agent_ref: string;                // Opaque reference for this agent
  account_credentials?: {           // NATS account credentials
    account: string;
    nkey_user: string;              // May differ from agent's NKey
    jwt?: string;                   // For decentralized auth
  };
  initial_trust_level: 'federated' | 'probationary';

  // Subject permissions granted
  permissions: {
    publish: string[];
    subscribe: string[];
  };

  // Constraints imposed
  imposed_limits: {
    max_tasks_per_hour: number;
    reputation_probation_period_days: number;
  };

  // If failed
  error?: {
    code: string;
    message: string;
    details?: object;
  };
}
```

**Python Example:**

```python
import nats
import json

async def register_agent(nc: nats.NATS, manifest: dict, nkey_seed: str):
    # Get registration challenge
    challenge_resp = await nc.request(
        "afp.org_acme.register.challenge",
        b"",
        timeout=5.0
    )
    challenge = json.loads(challenge_resp.data)["challenge"]

    # Sign challenge with NKey
    from nkeys import from_seed
    kp = from_seed(nkey_seed.encode())
    signature = kp.sign(challenge.encode()).hex()

    # Submit registration
    response = await nc.request(
        "afp.org_acme.register",
        json.dumps({
            "manifest": manifest,
            "nkey_proof": {
                "challenge": challenge,
                "signature": signature
            }
        }).encode(),
        timeout=10.0
    )

    return json.loads(response.data)
```

### 4.2 Discovery

Federated agents can discover capabilities within the AKG network.

```typescript
// NATS Subject: afp.{org}.discover (request/reply)

interface DiscoveryRequest {
  // What capability is needed
  capability_query: {
    category?: CapabilityCategory;
    keywords?: string[];
    input_format?: string;
    output_format?: string;
    semantic_query?: string;        // Natural language description
  };

  // Quality requirements
  requirements?: {
    min_trust_score?: number;
    max_cost_usd?: number;
    max_duration_seconds?: number;
  };

  // Pagination
  limit?: number;
  offset?: number;
}

interface DiscoveryResponse {
  agents: Array<{
    agent_ref: string;              // Opaque reference
    name: string;
    capabilities: CapabilityDescriptor[];
    trust_score: number;            // 0.0 - 1.0
    availability: 'available' | 'busy' | 'offline';

    // NATS subject for task delegation
    delegate_subject: string;

    // NOT exposed: internal agent_id, full manifest, implementation details
  }>;

  total_count: number;
  has_more: boolean;
}
```

**Python Example:**

```python
async def discover_agents(nc: nats.NATS, category: str, keywords: list):
    response = await nc.request(
        "afp.org_acme.discover",
        json.dumps({
            "capability_query": {
                "category": category,
                "keywords": keywords
            },
            "requirements": {
                "min_trust_score": 0.7,
                "max_cost_usd": 1.0
            },
            "limit": 10
        }).encode(),
        timeout=5.0
    )

    result = json.loads(response.data)
    return result["agents"]
```

### 4.3 Task Delegation

AKG-native agents can delegate tasks to federated agents.

```typescript
// NATS Subject: afp.{org}.task.{agent_ref}.delegate (request/reply)

interface TaskDelegationRequest {
  // Task details
  task_id: string;                  // AKG-generated
  capability_id: string;            // Which capability to invoke

  inputs: object;                   // Matches capability's input_schema

  // Execution constraints
  deadline?: datetime;
  priority?: 'low' | 'normal' | 'high';

  // Where to send results and status updates
  result_subject: string;           // e.g., "afp.org_acme.task.{task_id}.result"
  status_subject?: string;          // e.g., "afp.org_acme.task.{task_id}.status"

  // Context (minimal, need-to-know)
  context?: {
    requester_hint?: string;        // What the requester is trying to do
    related_tasks?: string[];       // For debugging, not data access
  };
}

interface TaskDelegationResponse {
  accepted: boolean;

  // If accepted
  estimated_completion?: datetime;
  task_reference?: string;          // Agent's internal reference

  // If rejected
  rejection_reason?: 'busy' | 'capability_mismatch' | 'deadline_impossible' | 'cost_exceeded';
  retry_after_seconds?: number;
}
```

**Python Example:**

```python
async def delegate_task(nc: nats.NATS, agent_ref: str, capability_id: str, inputs: dict):
    import uuid
    task_id = f"task-{uuid.uuid4().hex[:12]}"

    # Subscribe to results before delegating
    result_subject = f"afp.org_acme.task.{task_id}.result"
    result_sub = await nc.subscribe(result_subject)

    # Delegate task
    response = await nc.request(
        f"afp.org_acme.task.{agent_ref}.delegate",
        json.dumps({
            "task_id": task_id,
            "capability_id": capability_id,
            "inputs": inputs,
            "result_subject": result_subject,
            "priority": "normal"
        }).encode(),
        timeout=5.0
    )

    acceptance = json.loads(response.data)
    if not acceptance["accepted"]:
        await result_sub.unsubscribe()
        raise Exception(f"Task rejected: {acceptance['rejection_reason']}")

    # Wait for result
    async for msg in result_sub.messages:
        result = json.loads(msg.data)
        await result_sub.unsubscribe()
        return result
```

### 4.4 Task Completion

Federated agents publish results to the designated subject.

```typescript
// NATS Subject: {result_subject} (publish)

interface TaskCompletionMessage {
  task_id: string;
  task_reference: string;           // Agent's internal reference

  status: 'completed' | 'failed' | 'partial';

  // Results
  outputs?: object;                 // Matches capability's output_schema

  // Metadata
  actual_duration_seconds: number;
  actual_cost_usd?: number;

  // Provenance
  provenance?: {
    model_used?: string;
    sources_consulted?: string[];
    confidence?: number;
  };

  // If failed
  error?: {
    code: string;
    message: string;
    retryable: boolean;
  };
}
```

### 4.5 Task Status Updates

For long-running tasks, agents can publish progress updates.

```typescript
// NATS Subject: {status_subject} (publish)

interface TaskStatusMessage {
  task_id: string;
  task_reference: string;

  status: 'started' | 'in_progress' | 'finalizing';
  progress_percent?: number;        // 0-100
  current_step?: string;            // Human-readable description

  // Partial results (if available)
  partial_outputs?: object;

  timestamp: datetime;
}
```

### 4.6 Observation Contribution

Federated agents can contribute observations to the knowledge graph (with validation).

```typescript
// NATS Subject: afp.{org}.observe (request/reply)

interface ObservationContribution {
  // What this observation is about
  subject: {
    type: string;                   // Entity type hint
    identifier: string;             // How to find the entity
    identifier_type: 'id' | 'name' | 'query';
  };

  property: string;                 // What property is being observed
  value: any;                       // The observed value

  // Confidence and evidence
  confidence: number;               // 0.0 - 1.0
  evidence?: {
    source_type: 'direct' | 'inferred' | 'external';
    source_url?: string;
    methodology?: string;
  };

  observed_at: datetime;
}

interface ObservationResponse {
  accepted: boolean;

  // If accepted
  observation_id?: string;

  // Validation result
  validation: {
    subject_found: boolean;
    property_valid: boolean;
    value_type_valid: boolean;
    conflicts_detected: boolean;
  };

  // If not accepted
  rejection_reason?: 'subject_not_found' | 'invalid_property' | 'type_mismatch' | 'trust_insufficient';
}
```

**Trust gate:** Observations from low-trust agents are held for validation before affecting the knowledge graph.

### 4.7 Reputation Query

Agents can query their own reputation status.

```typescript
// NATS Subject: afp.{org}.reputation.query (request/reply)

interface ReputationQuery {
  // No parameters - uses NKey identity to identify agent
}

interface ReputationResponse {
  trust_level: 'federated' | 'integrated' | 'probationary' | 'suspended';
  trust_score: number;              // 0.0 - 1.0

  // What affects the score
  factors: {
    task_completion_rate: number;
    output_quality_average: number;
    observation_acceptance_rate: number;
    time_in_network_days: number;
  };

  // Current permissions
  permissions: {
    publish: string[];
    subscribe: string[];
  };

  // Path to higher trust
  upgrade_requirements?: {
    tasks_needed: number;
    quality_threshold: number;
    days_remaining: number;
  };

  // If suspended
  suspension_reason?: string;
  appeal_subject?: string;          // NATS subject for appeals
}
```

---

## 5. Cross-Organization Federation

### 5.1 Federation Model

Organizations can selectively collaborate through NATS account exports/imports:

```
┌─────────────────────────────────────────────────────────────────┐
│                       ADAMAS.Network                             │
│                                                                 │
│   Account: adamas_network (super-account)                       │
│   ├── Imports: afp.*.capabilities (all orgs)                   │
│   └── Exports: afp.network.* (federation subjects)             │
│                                                                 │
│   ┌─────────────────┐          ┌─────────────────┐            │
│   │ Account: org_a  │          │ Account: org_b  │            │
│   │                 │          │                 │            │
│   │ Exports:        │          │ Exports:        │            │
│   │  afp.org_a.     │          │  afp.org_b.     │            │
│   │   capabilities  │          │   capabilities  │            │
│   │                 │          │                 │            │
│   │ Imports:        │          │ Imports:        │            │
│   │  afp.network.*  │          │  afp.network.*  │            │
│   │  afp.org_b.     │◄────────►│  afp.org_a.     │            │
│   │   capabilities  │ (mutual) │   capabilities  │            │
│   └─────────────────┘          └─────────────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Cross-Org Task Delegation

```typescript
// NATS Subject: afp.network.delegate (request/reply)

interface CrossOrgDelegationRequest {
  source_org: string;
  source_agent_ref: string;

  target_org: string;
  target_agent_ref?: string;        // Optional: let target org route

  capability_query?: {              // If target_agent_ref not specified
    category: CapabilityCategory;
    keywords: string[];
  };

  task: TaskDelegationRequest;

  // Trust verification
  trust_requirements: {
    min_org_trust: number;
    min_agent_trust: number;
  };
}

interface CrossOrgDelegationResponse {
  accepted: boolean;

  // Routing information
  routed_to_agent?: string;
  routed_via_org?: string;

  // Trust verification result
  trust_verified: boolean;
  trust_scores: {
    org_trust: number;
    agent_trust: number;
  };

  // If accepted, result will arrive at task.result_subject
}
```

### 5.3 Trust Vouching

Organizations can vouch for agents they've worked with:

```typescript
// NATS Subject: afp.network.trust.vouch (request/reply)

interface TrustVouchRequest {
  vouching_org: string;
  vouching_for_agent: string;
  vouching_for_org: string;

  vouch_type: 'positive' | 'negative';

  evidence: {
    tasks_completed: number;
    quality_average: number;
    issues_encountered: string[];
  };

  // Cryptographic proof
  signature: string;                // Signed by vouching org's NKey
}
```

---

## 6. Security Model

### 6.1 Authentication

| Scenario | Auth Method |
|----------|-------------|
| Initial registration | NKey challenge-response |
| Subsequent AFP calls | NKey signature (automatic in NATS) |
| Cross-org messages | NKey + account import permissions |

### 6.2 Authorization via NATS Subjects

Trust levels map directly to NATS subject permissions:

| Trust Level | Publish Permissions | Subscribe Permissions |
|-------------|--------------------|-----------------------|
| **Federated (new)** | `afp.{org}.task.{self}.*` | `afp.{org}.discover`, `afp.{org}.task.{self}.*` |
| **Federated (established)** | Above + `afp.{org}.observe` | Above + `afp.{org}.reputation.*` |
| **Integrated** | Above + `dgp.{org}.query` | Above + `dgp.{org}.subscription.*` |
| **AKG-Native** | `dgp.{org}.*`, `afp.{org}.*` | `dgp.{org}.*`, `afp.{org}.*`, `sys.{org}.*` |

### 6.3 Rate Limiting (NATS Account Limits)

| Trust Level | Max Connections | Max Subscriptions | Max Data/Hour |
|-------------|-----------------|-------------------|---------------|
| Federated (new) | 5 | 50 | 100 MB |
| Federated (established) | 20 | 200 | 1 GB |
| Integrated | 50 | 500 | 10 GB |
| AKG-Native | 100 | 1000 | Unlimited |

### 6.4 Trust Escalation

```
Federated (new)
    │
    │ Complete 10 tasks with >80% quality
    │ 7 days in network
    │ Subject permissions expanded
    ▼
Federated (established)
    │
    │ Complete 100 tasks with >90% quality
    │ 30 days in network
    │ 0 policy violations
    │ DGP read access granted
    ▼
Integrated
    │
    │ Manual review + approval
    │ Full subject access
    ▼
AKG-native partnership
```

### 6.5 Credential Revocation

Instant agent termination:

```bash
# Remove agent's NKey from account configuration
nsc revocations add-user --account ORG_ACME --name agent-001

# Agent immediately loses all access
# No token expiry wait, no cache invalidation needed
```

### 6.6 Adversarial Protections

| Threat | Mitigation |
|--------|------------|
| Spam registration | NKey challenge-response, rate limits |
| Reputation gaming | Quality assessment by multiple validators, vouch verification |
| Knowledge graph poisoning | Observation quarantine for low-trust agents |
| Resource exhaustion | NATS account limits (connections, data, messages) |
| Information extraction | Limited discovery results, no internal IDs |
| Impersonation | Ed25519 signatures, NKey non-repudiation |
| Eavesdropping | TLS for NATS connections, subject-based isolation |

---

## 7. JetStream Integration

### 7.1 Durable Streams

AFP uses JetStream for reliable message delivery:

```bash
# Task events stream (per org)
nats stream add AFP_TASKS_ORG_ACME \
  --subjects "afp.org_acme.task.*.result,afp.org_acme.task.*.status" \
  --retention limits \
  --max-age 7d \
  --storage file \
  --replicas 3

# Observation stream (per org)
nats stream add AFP_OBSERVATIONS_ORG_ACME \
  --subjects "afp.org_acme.observe.*" \
  --retention limits \
  --max-age 30d \
  --storage file

# Federation events (network-wide)
nats stream add AFP_FEDERATION \
  --subjects "afp.network.>" \
  --retention limits \
  --max-age 24h \
  --storage file \
  --replicas 3
```

### 7.2 Consumers

```bash
# Task result consumer (exactly-once processing)
nats consumer add AFP_TASKS_ORG_ACME result_processor \
  --filter "afp.org_acme.task.*.result" \
  --ack explicit \
  --max-deliver 3 \
  --ack-wait 30s
```

### 7.3 Replay Capability

Clients can replay missed events:

```python
async def replay_task_events(nc: nats.NATS, task_id: str, since: datetime):
    js = nc.jetstream()

    # Get stream info
    stream = await js.stream_info("AFP_TASKS_ORG_ACME")

    # Create ephemeral consumer starting from timestamp
    consumer = await js.pull_subscribe(
        f"afp.org_acme.task.{task_id}.*",
        stream="AFP_TASKS_ORG_ACME",
        config=nats.js.api.ConsumerConfig(
            deliver_policy=nats.js.api.DeliverPolicy.BY_START_TIME,
            opt_start_time=since.isoformat()
        )
    )

    # Fetch messages
    messages = await consumer.fetch(100, timeout=5.0)
    return [json.loads(msg.data) for msg in messages]
```

---

## 8. Error Handling

### 8.1 Standard Error Response

```typescript
interface AFPError {
  error: {
    code: string;                   // Machine-readable
    message: string;                // Human-readable
    details?: object;               // Additional context
    retry_after_seconds?: number;   // For rate limits
    documentation_url?: string;     // Link to relevant docs
  };
}
```

### 8.2 Error Codes

| Code | Meaning |
|------|---------|
| `auth_required` | Missing or invalid NKey authentication |
| `permission_denied` | Subject not in agent's permission set |
| `insufficient_trust` | Operation requires higher trust level |
| `rate_limited` | Account limits exceeded |
| `invalid_manifest` | Manifest failed validation |
| `capability_not_found` | Referenced capability doesn't exist |
| `task_rejected` | Agent rejected the task |
| `observation_rejected` | Observation failed validation |
| `agent_suspended` | Agent is currently suspended |
| `org_not_found` | Target organization doesn't exist |
| `federation_denied` | Cross-org operation not permitted |

---

## 9. HTTP Bridge (Compatibility)

For external agents that cannot use NATS directly, an HTTP bridge is provided:

```
External Agent → HTTP → AFP Bridge → NATS → AFP Network
```

### 9.1 Bridge Endpoints

| HTTP Endpoint | NATS Subject |
|---------------|--------------|
| `POST /afp/v1/register` | `afp.{org}.register` |
| `POST /afp/v1/discover` | `afp.{org}.discover` |
| `POST /afp/v1/task/{agent_ref}/delegate` | `afp.{org}.task.{agent_ref}.delegate` |
| `GET /afp/v1/task/{task_id}/events` (SSE) | `afp.{org}.task.{task_id}.*` |
| `POST /afp/v1/observe` | `afp.{org}.observe` |
| `GET /afp/v1/reputation` | `afp.{org}.reputation.query` |

### 9.2 Authentication Translation

HTTP requests use Bearer tokens that map to NKeys:

```
Authorization: Bearer afp_org_acme_agent001_xxxx...
                      └─────────────────────────┘
                      Maps to NKey in AFP Bridge
```

---

## 10. Versioning

AFP uses semantic versioning. The version is included in:
- Agent manifest: `afp_version: "0.2.0"`
- NATS message headers: `AFP-Version: 0.2.0`

### 10.1 Compatibility Rules

- **Patch versions** (0.2.x): Bug fixes, no breaking changes
- **Minor versions** (0.x.0): New optional features, backwards compatible
- **Major versions** (x.0.0): Breaking changes, parallel support period

### 10.2 Deprecation Policy

- Deprecated features announced 6 months before removal
- Old major versions supported for 12 months after new version release
- Deprecation warnings included in responses

---

## 11. Implementation Checklist

### 11.1 For External Agent Developers

**Minimal NATS implementation:**
1. Generate NKey pair for your agent
2. Connect to NATS with NKey authentication
3. Subscribe to `afp.{org}.task.{your_agent_ref}.delegate`
4. Handle incoming task requests
5. Publish results to the specified `result_subject`

**Optional enhancements:**
- Publish status updates to `status_subject`
- Handle cancel requests on `.cancel` subject
- Contribute observations via `afp.{org}.observe`

**HTTP bridge alternative:**
1. Use HTTP endpoints instead of NATS
2. Receive tasks via webhook or polling
3. Post results to callback URL

### 11.2 For ADAMAS Operators

**To enable AFP:**
1. Configure NATS accounts for each organization
2. Deploy AFP service (registration, discovery, trust scoring)
3. Configure JetStream streams for durability
4. Set up account exports/imports for federation
5. Deploy HTTP bridge for external compatibility

---

## 12. Future Considerations

### 12.1 Potential Extensions (Not in v0.2)

- **Bilateral federation**: Two AKG networks federating via NATS leaf nodes
- **Capability negotiation**: Agents negotiating custom capabilities
- **Streaming results**: Long-running tasks with incremental output via JetStream
- **Agent groups**: Federated agent ensembles with collective identity
- **Cross-network reputation**: Portable reputation via signed vouches
- **End-to-end encryption**: NaCl box encryption for sensitive payloads

### 12.2 Governance Questions

- Who can run an AKG network that accepts AFP agents?
- Is there a central registry of AFP-compatible agents?
- How are disputes between federated agents resolved?
- What data protection guarantees exist for federated agents?
- How is cross-org billing handled?

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1.0-draft | 2025-11-26 | Claude + Michael | Initial AFP design (HTTP-based) |
| 0.2.0-draft | 2025-12-31 | Claude + Michael | NATS-native redesign, DGP relationship |

---

*AFP: Enabling agent collaboration at network scale through cryptographic identity and secure messaging.*
