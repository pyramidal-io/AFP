# AFP Federation Mixnet

**Interface version:** 0.3.14-draft
**Document revision:** 4 (2026-11-17)
**Specification set:** AFP, listed in `docs/afp_specification.md` §11
**Scope:** §8.3–§8.8 of the AFP specification. §8.1, §8.2, §8.9 and §8.10 stay in `docs/afp_specification.md`.

---

### 8.3 The AFP Federation Mixnet

AFP's baseline satisfies §8.2 with a **self-contained, consortium-operated mix network of the Loopix family**. "Self-contained" means the mixnet is operated by and for the federation; it is not a dependency on any public, token-incentivized, third-party anonymity network. "Loopix family" means the design class characterized by the Sphinx packet format, a stratified mix topology, continuous-time (exponential-delay) mixing, and mandatory cover traffic — the class with published anonymity analyses against a global passive adversary (formal for a single mix, empirical end to end).

**Reference implementation.** The preliminary reference implementation is **Katzenpost** (`katzenpost/katzenpost`, AGPLv3), a Loopix-family mixnet using client-selected exponential mixing delays, a stratified topology, configurable-geometry Sphinx packets, post-quantum cryptographic agility, and a decentralized directory-authority system. Katzenpost is the **reference implementation for development**, not a frozen normative dependency; it is evolving toward the Echomix design and has no confirmed large-scale production deployment as of this writing. Accordingly, **§8 binds to the Loopix-family architecture (§8.2 properties), not to a specific Katzenpost version**. An implementation tracks a named Katzenpost release; the AFP conformance test remains §8.2.

**Reference maturity rule.** [AFP-0001] A deployment that uses Katzenpost MUST publish the exact release, commit, configuration profile, and any local patches in its AFP conformance statement. Echomix is tracked as the expected next-generation Katzenpost protocol, but it is not a normative AFP dependency until AFP publishes a successor mixnet profile. [AFP-0002] A deployment MAY pilot Echomix-derived behavior only if the deployed behavior still satisfies §8.2 and the conformance statement identifies the deviation from `afp.mixnet.profile.ob2-baseline.v1`.

**Why a mixnet and not a lighter relay.** Simpler designs — VPNs with rotating exits, onion-routed relays without mixing, or queue-relay systems without cover traffic — defeat single-relay and IP-level correlation but do **not** defeat §8.2 property 3 against a link observer: a burst of real traffic leaving tenant A still correlates, by timing and volume, with the burst arriving at tenant B, regardless of how the source address is obscured. Only mixing delay plus cover traffic breaks that correlation. This is the property that selects the Loopix family.

### 8.4 Topology and packet format

The AFP baseline implementation profile is `afp.mixnet.profile.ob2-baseline.v1`. [AFP-0003] A deployment MAY define a stricter profile, but it MUST disclose any deviation and still satisfy §8.2.

| Parameter | `ob2-baseline-v1` value | Conformance rule |
|---|---|---|
| Packet format | Sphinx, fixed-size packets | Every coordination packet has identical observable size and form. |
| [AFP-0004] Hop geometry | 3 mix hops, one hop per layer | A deployment MUST NOT use fewer than 3 hops for OB-2 claims. |
| Layers | 3 stratified layers | No operator may control all nodes in any layer or enough adjacent-layer positions to observe a full path: every layer has nodes of at least two operators, and no operator has a node in every layer. |
| Payload class | 4 KiB encrypted AFP payload fragment per packet | Larger AFP messages are fragmented and padded into indistinguishable packets. |
| Per-hop delay | Exponential delay, mean 30 s | The delay is independently sampled per hop by the sender. |
| Maximum packet TTL | 15 min | Expired packets are dropped without revealing whether they were real or cover packets. |
| Tenant cover rate | At least 1 packet every 10 s per federated tenant | Real traffic is slotted into the same schedule; deployments may raise but not lower the rate. |
| Mix-node loop cover | At least 1 loop packet every 10 s per mix node per adjacent layer | Loop cover is independent of tenant activity. |
| [AFP-0005] Directory epoch | At most 24 h | Tenants MUST reject expired directories unless an emergency extension is KERI-witnessed. |

- **Packet format.** All coordination traffic is carried as fixed-size **Sphinx** packets. Every packet is identical in size and form; a mix node decrypts exactly one layer and learns only the immediately preceding and following hop. This delivers §8.2 properties 1 and 2 at the packet layer. `ob2-baseline-v1` fixes the hop geometry and payload class above so implementers do not pick weaker deployment defaults.
- **Stratified topology.** Mix nodes are arranged in ordered layers; a packet traverses one node per layer. [AFP-0006] Three layers are REQUIRED for `ob2-baseline-v1`, so no single mix node sees both endpoints; §8.1 states what a coalition of mix nodes learns.
- **Route selection and operator diversity.** [AFP-0504] For each tenant-originated packet, real or cover, the sender MUST choose one node in each layer such that the three nodes carry three different `operator_aid` values in the verified directory (§8.7), and MUST choose uniformly at random among all such paths, independently for each packet. The rule uses only the `layer_index` and `operator_aid` fields that the directory already carries. Choosing one node per layer uniformly and independently, and drawing the whole path again whenever two of its nodes share an `operator_aid`, meets the rule. Choosing each next hop uniformly among the nodes that remain eligible does not in general give a uniform distribution over whole paths. The valid paths are the paths that meet this rule through nodes the sender can currently reach, and the §8.1 fraction is taken over that set. A directory that meets the "Layers" constraints above always contains a valid path when every node is reachable. If unreachable nodes leave no valid path, the sender does not relax the rule; it has no OB-2 route until a valid path exists. The rule does not govern mix-node loop cover (§8.5).
- **Continuous-time mixing.** Each mix node delays each packet by an independent, exponentially distributed random delay (client-selected per hop). This decouples the timing of a packet's arrival from its departure and is the core of §8.2 property 3. The baseline trades multi-hop latency for correlation resistance, a trade that suits work which tolerates delay, such as §5 work requests. The `pay` profile is latency-sensitive: a quote settles only through a transaction included before its signed `expires_at` (§15.6), and §15.5 recommends a dispatch admission check before a payer begins an execution attempt.

**Transport budget.** The figures below are ideal model outputs for the `ob2-baseline-v1` delay at exactly the minimum schedule of one packet every 10 s. They assume no loss, no retry, no queueing at the sender or at a relay, independent per-hop delays, and, where a slot wait appears, a slot phase that is uniform. They are not a delivery promise, and this profile defines no retry behaviour. A tail probability here is the chance that the modelled time exceeds a bound. It is not the failure rate of any flow; that depends on which legs fall inside the flow's deadline and on everything else on its critical path.

| Quantity | Model | Mean | Median | 95th percentile | 99th percentile |
|---|---|---|---|---|---|
| One leg: one packet, three hops | Erlang, shape 3, scale 30 s | 90 s | 80.2 s | 188.9 s | 252.2 s |
| Two sequential legs | Erlang, shape 6, scale 30 s | 180 s | 170.1 s | 315.4 s | 393.3 s |
| Slot wait before a packet leaves | uniform over one 10 s slot | 5 s | 5 s | 9.5 s | 9.9 s |

- Mixing alone takes longer than 300 s with probability 0.0671 for two sequential legs. Mixing plus an independent uniform slot wait before each leg takes longer than 300 s with probability 0.0810. Mixing alone would carry one packet past the 900 s TTL with probability about 4.5 × 10⁻¹¹. That is a tail of the model, not a fraction of deliveries; the TTL is a drop limit, not a delivery promise.
- **Fragments mix in parallel.** Take a message of n packets, all ready at once, sent in consecutive free slots. Fragment j, for j = 0, …, n − 1, leaves at W + 10j seconds, where W is the slot wait, and mixes independently of the others. The message has arrived when its last fragment arrives, at the maximum over j of W + 10j + Xⱼ, each Xⱼ Erlang(3, 30 s). Given W, its distribution function is the product over j of F₃(t − W − 10j), where F₃ is the one-leg distribution function and F₃(u) = 0 for u ≤ 0. Reassembly and delivery are omitted. The fragment that leaves last need not arrive last. With a uniform slot wait, four packets (16 KiB of padded payload class) have all arrived by 264.6 s with probability 0.95, and sixteen packets (64 KiB) by 399.7 s. A user message of 16 KiB need not fit in four packets, because framing takes space in each.
- **Payload ceiling.** At exactly one slot every 10 s a tenant sends 8,640 packets a day: one 4,096-byte payload class per slot, which is 409.6 bytes per second or 35,389,440 bytes (33.75 MiB) a day. This is the tenant's gross outgoing payload-class capacity, shared by all its counterparties and by its cover traffic. It is not a promised throughput: framing, retries and backlog lower the useful amount. A higher fixed schedule for all traffic is allowed and shortens slot waits and fragment spacing, but not the mixing delay. Extra emissions triggered by `pay` traffic would break the workload-independent schedule of §8.5.
- **A faster class for one profile.** Lower mixing delay for `pay` traffic alone could make that traffic a statistically distinguishable timing class. Such a class is a separate privacy design that owes its own §8.2 evidence; it is not a parameter change of `ob2-baseline-v1`.

### 8.5 Mandatory cover traffic

[AFP-0007] Cover traffic is **REQUIRED**, not optional, and is the property on which OB-2 against a link observer depends.

- [AFP-0008] Every tenant MUST emit coordination-plane traffic into the mixnet at a constant, scheduled rate at all times while federated, **whether or not it has real coordination traffic to send**. Real `afp.*` messages (§5.3) are slotted into this constant stream; when there is no real message, a cover (loop) message is sent instead. Cover and real packets are indistinguishable to any relay or observer (identical Sphinx form, §8.4).
- [AFP-0009] Mix nodes MUST additionally emit loop cover traffic, so that link-level traffic between mix nodes is constant independent of tenant activity.
- [AFP-0010] The cover schedule MUST be derived from the active mixnet directory epoch and the tenant's local scheduler, not from the presence of application work. [AFP-0011] Missed cover slots are an OB-2 health failure and MUST be disclosed in operator telemetry without identifying counterparties.
- **Exploiting the bounded tenant set.** Because the federation membership is bounded and enumerable (unlike an open consumer network), AFP can *mandate* constant emission from every participant. Each tenant's scheduled emission rate is independent of whether it has real work to send; mixing and cover traffic provide the correlation-resistance mechanism required by §8.2. This does not establish that an adversary's full observation is identical in every world: membership remains visible, and long-horizon statistical disclosure is mitigated but not eliminated, especially in small federations (§8.10). [AFP-0012] A conforming deployment MUST run cover traffic at a fixed rate at every tenant and every mix node; a deployment that does not is not OB-2-conforming and MUST disclose this per §3.5.

### 8.6 Relay operation — no single trusted relay

- Mix nodes are operated by **mutually distrusting parties** — federated tenants, designated independent operators, or both — such that no single operator controls enough of any path to correlate endpoints.
- [AFP-0013] **The operator (e.g. Pyramidal) MUST NOT occupy a position on the mix path from which the coordination graph is observable.** [AFP-0014] Consistent with §7.3, the operator publishes the (source-available) mixnet software and MAY run a directory authority or witness, but MUST NOT be the sole operator of any mix layer, and MUST NOT run a mix node in a topological position that, alone, reveals a pairing. This is the §3.2 capability standard applied to the operator's own infrastructure.
- **The operator role and the §6.3.1 attestation-authority role are independent.** Where the same legal entity is both an AFP operator (§2.1) and a §6.3.1 attestation root authority — as Pyramidal Inc. is — neither role confers anything on the other: standing as an attestation authority confers no operator privilege and no relaxation of the constraint above or of §3, and operating a transport confers no standing as an authority and no claim on any verifier's policy. A verifier's acceptance of an authority is not a judgment about that party's infrastructure, and §3's operator-blindness invariant is a capability standard that no attestation reputation can substitute for.
- The mixnet uses **no token and no cryptocurrency.** Relay operation is a federation membership obligation or a flat contractual arrangement, not a speculative incentive. The federation is a bounded set of identified institutions, not an open population of anonymous relay operators; the token-and-incentive layer that public mixnets require to recruit untrusted relays is therefore unnecessary, and is deliberately excluded.

### 8.7 Mix-node directory

[AFP-0015] The set of mix nodes, their layer assignment, and their public keys MUST be published as a **directory** that every tenant can verify without trusting any single party.

- [AFP-0016] The directory MUST be a tamper-evident structure verifiable against the federation's existing KERI substrate (§4): directory documents are signed by a quorum of consortium witnesses, so a tenant — including an appliance with no operator contact — verifies the mix-node set the same way it verifies a peer's KEL. AFP introduces no new trust authority for the **mix-node directory**; it reuses §4. (The §6.3.1 attestation root authority is unrelated to this section: it is a verifier-elective trust root for instance attestation, plays no part in directory verification, and confers nothing here.)
- A reference Loopix-family implementation supplies its own decentralized directory-authority mechanism (a quorum-voting protocol). [AFP-0017] A conforming deployment MAY use that mechanism provided its trust model meets §8.2 property 4 — no single directory authority can forge the mix-node set — and provided the directory is bound into the consortium's KERI-witnessed structure so directory trust and federation identity share one root.

The directory document has the following verifier-facing shape:

```typescript
interface AfpMixnetDirectory {
  kind: 'afp:mixnet-directory:v1';
  profile: 'afp.mixnet.profile.ob2-baseline.v1';
  epoch: number;
  valid_from: datetime;
  valid_until: datetime;
  keri_anchor_event_dig: string;
  sphinx: {
    packet_payload_bytes: 4096;
    hop_count: 3;
  };
  mixing: {
    delay_distribution: 'exponential';
    mean_delay_seconds: 30;
    packet_ttl_seconds: 900;
  };
  cover: {
    tenant_packet_interval_seconds: 10;
    mix_loop_interval_seconds: 10;
  };
  layers: Array<{
    layer_index: number;
    nodes: Array<{
      mix_node_aid: string;
      operator_aid: string;
      endpoint: string;
      sphinx_public_key: string;
      directory_signing_key: string;
      software_ref: string;
    }>;
  }>;
  quorum_signatures: Array<{
    witness_aid: string;
    signature: string;
  }>;
}
```

[AFP-0018] A tenant MUST reject a directory if the KERI anchor is absent, the witness quorum is below the federation threshold, the profile parameters are weaker than `ob2-baseline-v1`, any layer is empty, or the operator-control constraints of §8.6 are violated.

**What the directory establishes about operators.** A directory that passes these checks lets a tenant verify, as the witness quorum asserts them, each node's layer and `operator_aid`, the number of nodes and of different `operator_aid` values in each layer, and the §8.4 "Layers" constraints. For any set of `operator_aid` values that the tenant chooses to treat as one coalition, it can compute the fraction of valid paths that the set holds (§8.1). The directory does not let a tenant verify that different `operator_aid` values belong to different or independent parties. An AID costs nothing to create, and a distinct AID does not by itself establish independence (§6.4 states the same for external sources). Nor does the directory show whether operators share hosting, a network provider or a jurisdiction, whether they collude, or whether a node runs the software its `software_ref` names. Operator independence therefore rests on how the federation admits mix-node operators, not on anything the directory proves. A tenant that doubts the independence of the listed operators can decline to rely on OB-2 for that directory.

### 8.8 Private route resolution

§5.2 step 1 requires an initiating entity to resolve a counterparty tenant AID to a transport route. This subsection specifies how, without any party learning the pairing.

- **No directory of tenants.** AFP defines no global, queryable directory mapping tenant AIDs to routes; such a directory would itself be the coordination graph (the same reason §5 defines no capability-discovery feed). Open federation (§5.8) defines trust establishment, not discovery, and adds no directory. Mixnet route resolution is possible only between tenants that **already share rendezvous data** — bootstrapped from a bilateral federation agreement (§5.5) for the known-counterparty path, or established out-of-band and then in-protocol for the open-federation path (see the last bullet).
- **Rendezvous data is carried in the federation agreement.** When two tenants establish a §5.5 agreement, that agreement carries — or bootstraps — the rendezvous information each needs to reach the other through the mixnet: mixnet ingress points and the information needed to establish per-session destination values. Because the agreement is held only by the two tenant principals it concerns, the artifact that maps the A↔B pairing to that information exists nowhere except with A and B. A terminal relay handles an opaque per-session destination value, but it receives neither this mapping nor either tenant AID.
- [AFP-0019] **Rendezvous handles MUST NOT be stable cleartext identifiers** of the tenant pair (§8.2 property 2). The parties derive or rotate the opaque destination value at least once per session. Later Sphinx layers hide it from intermediate relays; the terminal relay necessarily recovers it to perform delivery. [AFP-0020] The value MUST expose neither tenant AID in cleartext. [AFP-0021] An unkeyed digest can still be tested offline if an observer learns or can guess its inputs; implementations claiming resistance to candidate testing MUST derive destination values with bilateral secret material. The bundled clean-room helper is intentionally unkeyed and demonstrates only per-session non-stability and absence of a cleartext AID encoding. This privacy property is not secrecy from the terminal relay.
- **Finding a counterparty that you cannot yet reach** is out of AFP scope. Open federation specifies *trust establishment* (§5.8: two strangers can establish trust by ZKC attestation with no prior agreement), not *discovery or rendezvous*. A queryable directory of who-can-reach-whom is exactly the coordination graph OB-2 (§3.1) exists to deny. Therefore:
  - For the **known-counterparty** path, rendezvous data is carried in the §5.5 agreement (above); route resolution begins once that agreement exists.
  - For the **open-federation** path (§5.8), the two tenants have no agreement to carry rendezvous data. **First contact must be established out-of-band** — a real-world decision, optionally assisted by a separate tenant-discovery layer outside this specification — after which the parties establish a per-relationship rendezvous handle and proceed exactly as the known-counterparty path does. AFP provides the trust-by-attestation and the session; it does **not** provide the find-each-other step.
  - **The genuine unresolved tension** is routing first contact *through the mixnet* for parties who have no agreement from which to bootstrap rendezvous data. This is tracked as an open item (§10) and is the one place where open federation is not yet self-contained.
  - [AFP-0022] Any discovery layer, if one exists, MUST NOT have visibility into coordination traffic and is **not** part of the AFP trust boundary.
