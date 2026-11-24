# AFP Key Derivation Core (AFP-KDC)

**KDC Version:** 1.0.3
**Document revision:** 2 (2026-11-17)
**Specification set:** AFP, listed in `docs/afp_specification.md` §11

---

## Appendix A: Key Derivation Core (KDC)

**Module:** Key Derivation Core
**KDC Version:** 1.0.3
**Status:** Stable
**Owning specification:** AFP (AFP.dev), as a member of the AFP specification set (`docs/afp_specification.md` §11)
**Referenced normatively by:** ZKA v0.9.2-draft (§2.1–2.2), ZKC v0.4.1-draft (§1.3, §2.1, §5.9), ZKM v0.1.0-draft (§2), AFP 0.3.14-draft (§2.2, §4.3, §5.9)

This appendix specifies the **Key Derivation Core (KDC)** — the master-seed derivation, hash-and-domain-separation scheme, domain-tag registry, and per-entity sub-derivation shared by ZKA, ZKC, ZKM, and AFP. It is a self-contained module: it is published as part of the AFP specification for packaging reasons (AFP is the identity protocol of the family and carries the most complete derivation model), but it depends on **no other section of this specification** and on **no construct specific to AFP, ZKA, ZKC, or ZKM**. Sibling protocols reference this appendix without thereby depending on the remainder of AFP.

KDC carries its **own version line**, independent of the AFP specification version. The active module is **AFP-KDC v1.0.3**, and a dependent specification cites that version rather than an AFP version. Sections A.3–A.7 and their normative artifacts completely specify its field-domain derivation, Poseidon2 instance, sponge, hierarchy, and conformance vectors. AFP-KDC v1.0.3 reuses the v1.0.2 Poseidon2 parameter and conformance artifacts and defines the external fixed-byte ownership boundary; it changes no KDC-owned tag, derivation, value, vector, hash, proof, circuit, verification key, or wire record.

### A.1 Scope

**In scope (normative for KDC):**

- the master seed (§A.2);
- the hash function and domain-separation scheme (§A.3);
- the KDC domain-tag registry (§A.4);
- the per-entity HKDF sub-derivation (§A.5);
- the key-derivation functions producing the spending, viewing, proof, and credential-binding keys, the address, and the credential commitment (§A.6).

**Out of scope (owned by the referencing specifications):**

- ZKA note structure, commitments, nullifier *semantics*, Merkle trees, and the `zka/nullifier` operational tag (ZKA §2);
- ZKC credential structure, issuance, revocation, and accumulators (ZKC §2–§4);
- ZKM mandate structure, issuance, consumption, delegation, revocation, and its mandate-specific `zkm/*` operational tags (ZKM §2–§7);
- AFP KERI machinery — AIDs, KELs, witnesses, delegated inception (AFP §4);
- key *rotation and recovery* mechanics, including on-chain re-binding of artifacts after a seed rotation (ZKA §5.7). KDC defines how keys are derived from a seed; it does not define how a rotation re-binds artifacts derived from a prior seed.

KDC defines derivation. It does not know what the derived keys are used for.

### A.2 Master Seed

A **master seed** is a 256-bit (32-byte) secret. [KDC-0001] It is the root of a key hierarchy and MUST be generated from a cryptographically secure random source and stored securely.

A master seed may be:

- a **standalone master seed**, used directly as the input to §A.6 (e.g. a standalone ZKA deployment with no AFP entity hierarchy); or
- a **per-entity sub-seed** `M'`, derived from a tenant master seed `M` via §A.5 and then used as the §A.6 input. Under AFP entity identity (AFP §4.3), the §A.6 input is always a per-entity sub-seed.

The two cases are interchangeable as far as §A.6 is concerned: §A.6 takes a 256-bit seed and does not distinguish how that seed was obtained. This is what makes a sub-seed `M'` a drop-in master seed for the key-derivation functions.

### A.3 Hash Function and Domain Separation

KDC uses **Poseidon2** over the **BN254 scalar field** for all key-derivation hashing. Poseidon2 is the hash provided by Noir's standard library (`std::hash::poseidon2`) and is optimized for UltraHonk constraints, so derivations are efficiently provable inside circuits — required because the ZKA identity-binding circuit (ZKA §5.2) re-derives keys from a seed in-circuit.

The BN254 scalar field modulus is

```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

All KDC hashes use **domain separation** via a leading domain-tag field element:

```
H(domain, x...) = Poseidon2( deriveFieldTag(domain), x... )
```

`deriveFieldTag` is the one field-domain algorithm for both KDC derivation tags and protocol-owned operational tags:

```text
deriveFieldTag(tag) =
  LEInteger(Blake2b-512(UTF8("ZKA-Domain-") || UTF8(tag))) mod r
```

The 64-byte digest is interpreted as a **little-endian** non-negative integer before reduction. [KDC-0002] Implementations MUST NOT substitute direct UTF-8-to-integer encoding, big-endian digest interpretation, a different Blake2 variant, or an unprefixed hash. The byte prefix `ZKA-Domain-` is frozen compatibility material; it does not assign ownership of an operational tag to ZKA.

`encodeFixedTag(tag)` is a separate non-field operation. [KDC-0003] Its input domain is a non-empty string whose UTF-8 encoding is 1–32 bytes and whose first encoded byte is non-zero; implementations MUST reject a leading NUL byte so left-zero-padding remains injective. After validation, left-zero-pad the encoding to exactly 32 bytes. It is used for the §A.5 HKDF salt. [KDC-0004] A field tag MUST NOT be substituted as HKDF salt. [KDC-0005] A fixed byte tag MUST NOT be interpreted as a circuit field separator, with exactly one exception: the fixed-byte fold-tag class carved out in §A.4, whose externally-owned tags are consumed directly as field-element domain separators by their owning specification.

A 256-bit seed supplied as a hash input is interpreted as a big-endian integer and reduced modulo `r` before use as a field element.

> **Behavioral-identity requirement.** [KDC-0006] Every consumer MUST implement the exact §A.3 permutation, sponge, tag derivation, and §A.6 hierarchy and reproduce all normative vectors. The pinned field constants, seeds-to-keys outputs, proofs, verification keys, hashes, and HKDF vectors are immutable within AFP-KDC v1.0.3.

#### A.3.1 Poseidon2 Instance

KDC uses exactly one Poseidon2 instance. Any other parameterization is non-conformant even if it is also called “Poseidon2 over BN254.”

| Parameter | Normative value |
|---|---|
| Field | BN254 scalar field `Fr` with modulus `r` above |
| State width | `t = 4` |
| Rate | 3, lanes 0–2 |
| Capacity | 1, lane 3 |
| S-box | `x^5` |
| Full rounds | 8, split 4 before and 4 after the partial rounds |
| Partial rounds | 56 |
| External matrix | `[[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]` |
| Internal matrix | all-ones plus the pinned diagonal-minus-one values |

Treat the state as a column vector and reduce every operation modulo `r`. Apply the external matrix once before round 0. In rounds 0–3, add all four round constants, apply `x^5` to all lanes, then apply the external matrix. In rounds 4–59, add the lane-0 round constant, apply `x^5` only to lane 0, then apply the internal matrix. In rounds 60–63, repeat the full-round operation.

`docs/kdc_v1_0_2_poseidon2_parameters.json` is the normative, self-contained parameter artifact. It fixes all 64 four-lane constant rows, the four internal diagonal-minus-one values, both matrices, and operation order. Its canonical constant encoding concatenates every constant row in round/lane order, followed by the four internal diagonal-minus-one values, with each field encoded as canonical 32-byte big-endian. [KDC-0007] The encoding contains 260 fields and 8,320 bytes and MUST have SHA-256:

```text
8cb18652f4afeac5b6819b156c13fbbc327deacba568b9d8d961ab134123214c
```

[KDC-0008] An implementation that imports, embeds, or loads an explicit parameter table MUST verify this digest before use. [KDC-0009] An opaque backend intrinsic MUST be immutably identified and reproduce every §A.3.3 KAT.

#### A.3.2 Sponge Mode

Let `P(x[0], …, x[n-1])` be the raw length-bound sponge. Its input is a sequence of canonical `Fr` elements with `0 <= n <= 2^32 - 1`. Initialize `[0, 0, 0, n * 2^64]`; the length IV is in capacity lane 3. For each complete three-element chunk, add it to rate lanes 0–2 and permute. Add any one- or two-element remainder to the corresponding leading rate lanes. Apply one final permutation if and only if `n = 0` or `n mod 3 != 0`. Return lane 0. There is no delimiter or padding field, and a positive multiple of three receives no additional trailing permutation.

Absorption is additive. `P` accepts canonical field elements rather than arbitrary integers or bytes. KDC semantic domain separation is explicit and is not supplied merely by arity:

```text
H(domain, x...) = P(deriveFieldTag(domain), x...)
```

#### A.3.3 Conformance Known-Answer Tests

[KDC-0010] For raw inputs consisting of the field elements `1, 2, 3, ...` in order, a conforming implementation MUST reproduce:

| `n` | Input | `P` output |
|---|---|---|
| 0 | `[]` | `0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e` |
| 1 | `[1]` | `0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373` |
| 2 | `[1,2]` | `0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383` |
| 3 | `[1,2,3]` | `0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8` |
| 4 | `[1,2,3,4]` | `0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9` |
| 6 | `[1,2,3,4,5,6]` | `0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a` |
| 7 | `[1,2,3,4,5,6,7]` | `0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238` |

`n = 0, 3, 6` exercise the conditional trailing-permutation branch in both directions. `n = 2, 3, 4` cover the H2/H3/H4 raw-wrapper arities used by consuming runtimes.

`docs/kdc_v1_0_2_conformance_vectors.json` is the normative machine-readable package. Its `rawSponge` section contains the table above. Its `kdc` section covers seed values 0, 1, `r-1`, `r`, `r+1`, the high bit, and an asymmetric 32-byte seed, and pins all six §A.6 outputs. The `r`/zero and `r+1`/one aliases are intentional consequences of the normative big-endian reduction.

[KDC-0011] Every conforming runtime MUST reproduce every shared vector applicable to its published interface. [KDC-0012] Solidity conformance is limited to the raw arities its published interface implements; it MUST NOT claim unsupported higher arities. [KDC-0013] Noir, Rust, ZKC, ZKM, and Aztec runners MUST execute every applicable vector rather than merely copying the expected values.

### A.4 Domain-Tag Registry

The following are the **complete** KDC-owned derivation tags in v1.0.3:

| Domain tag | Used in | Purpose |
|---|---|---|
| `zka/spending` | §A.6 | Derive spending key from seed |
| `zka/viewing` | §A.6 | Derive viewing key from spending key |
| `zka/proof` | §A.6 | Derive proof key from spending key |
| `zka/address` | §A.6 | Derive address from viewing key |
| `zkc/credential` | §A.6 | Derive credential binding key from seed |
| `zkc/binding` | §A.6 | Derive credential commitment from credential binding key |

The `zka/` and `zkc/` prefixes in these six frozen tag strings do not imply ownership by ZKA or ZKC. KDC owns all six derivation tags.

**Ownership and collision rule.** A tag string is owned by the specification that defines its operation, irrespective of its prefix. [KDC-0014] A referencing specification MAY define additional operational tags. Every such tag:

- [KDC-0015] MUST derive its field value with §A.3 `deriveFieldTag`, unless it is a fixed-byte fold tag under the carve-out below;
- [KDC-0016] MUST NOT collide with any KDC derivation tag or any published operational tag in the ZK protocol family;
- is owned by the defining specification, not by KDC.

**Fixed-byte fold-tag carve-out.** The ZKA `zka/pay/*` and `zka/coord/*` tag families are raw **fixed byte tags**: each tag's UTF-8 bytes right-aligned in a 32-byte word and consumed directly as a field element, never derived through `deriveFieldTag`. [KDC-0017] Like ZKC's frozen aggregation literals below, they are deliberate compatibility constants outside the `deriveFieldTag` regime and MUST NOT be reinterpreted through it. They are owned by ZKA as the specification defining their folds. [KDC-0018] A new tag in this class MUST NOT collide with any registered tag string, and collision checking for the class is against ZKA's `protocol-family/poseidon2-operational-domains-v1.json` (`active_fixed_byte` rows) in addition to the 27-tag snapshot below. ZKA's registry contains `zka/pay/interaction-context/v1` as the `pay-interaction-context` row, and AFP vendors that registry under the canonical family manifest. The manifest binds both registry copies and both copies of the frozen interaction-context KAT. This ownership boundary changes no KDC-owned tag, derivation, value, or vector.

The active machine-readable interoperability snapshot `docs/kdc_v1_0_3_domain_registry.json` pins all 27 currently tagged field constants: six KDC derivation tags, four ZKA operational tags, eight ZKC operational tags, and nine ZKM operational tags. It is a KAT and collision registry, not a transfer of tag-string ownership to KDC. [KDC-0019] A new tag MUST be checked against the complete snapshot before publication. [KDC-0020] ZKC's frozen aggregation seed/verify literals are not string tags; they remain explicit compatibility constants outside this registry and MUST NOT be reinterpreted through `deriveFieldTag`. Replacing them with tagged constants requires a versioned circuit/VK migration.

ZKA, ZKC, and ZKM operational **field tags** — the `deriveFieldTag` class — all use the same §A.3 derivation; ZKA's `pay`/`coord` fixed-byte fold tags sit outside that class under the carve-out above. The v1.0.3 registry is the active 27-tag KAT and collision snapshot.

### A.5 Per-Entity Sub-Derivation

A tenant with master seed `M` derives a distinct sub-seed `M'` for each entity:

```
M' = HKDF(M, "entity/{name}")
```

KDC is the authoritative definition of this sub-derivation, which supplies the per-entity seed used by the AFP entity model (§4.3).

**Concrete construction.** The sub-derivation uses **HKDF** per RFC 5869 with SHA-256:

```
M' = HKDF-SHA256(
        IKM  = M,                            // 32-byte tenant master seed
        salt = encodeFixedTag("kdc/entity-subseed"), // fixed 32-byte domain salt
        info = utf8("entity/" || name),       // entity name, UTF-8
        L    = 32                             // output length in bytes
     )
```

The output `M'` is a 32-byte value and is itself a valid §A.2 master seed: it is supplied directly to the §A.6 derivation functions. `name` is the entity's name as used in its AFP delegated-AID label (AFP §4.2).

> **Rationale — two primitives by design.** KDC deliberately uses **HKDF-SHA256** for the seed-tree derivation (`M → M'`) and **Poseidon2/BN254** for the key derivation (`M'/seed → keys`, §A.6). The seed-tree derivation is never performed inside a zero-knowledge circuit — it is wallet- and key-management-layer work — so the well-audited RFC 5869 standard KDF is the appropriate, conservative choice. The key derivation of §A.6 *is* performed in-circuit (ZKA §5.2 re-derives keys from a seed as circuit constraints), so it must use the circuit-efficient Poseidon2. The boundary between the two primitives is exactly the boundary between non-circuit and circuit derivation. [KDC-0021] An implementation MUST NOT substitute one primitive for the other.

> **Implementation note.** `HKDF-SHA256` is fixed and normative. `docs/kdc_v1_0_0_test_vectors.json` pins the required sub-seed vectors, and `encodeFixedTag("kdc/entity-subseed")` is exactly the byte encoding used by those vectors.

### A.6 Key-Derivation Functions

Given a 256-bit seed (a standalone master seed per §A.2, or a per-entity sub-seed `M'` per §A.5), KDC derives the key hierarchy:

```
                    +-----------------+
                    |   Seed (256b)   |   standalone master seed,
                    +--------+--------+   or per-entity M' (§A.5)
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
  +--------------+   +--------------+   +--------------+
  | Spending key |   | Viewing key  |   |  Proof key   |
  |     (sk)     |   |     (vk)     |   |     (pk)     |
  +--------------+   +--------------+   +--------------+
         |                   |
         |                   v
         |            +--------------+
         |            |   Address    |
         |            |    (addr)    |
         |            +--------------+
         v
  +-----------------------+
  | Credential binding    |
  | key (cbk)             |
  +-----------+-----------+
              |
              v
  +-----------------------+
  | Credential commitment |
  | (holderCommitment)    |
  +-----------------------+
```

```typescript
interface KeyHierarchy {
  seed:                 Uint8Array;  // 256 bits — store securely
  spendingKey:          Hash;        // sk
  viewingKey:           Hash;        // vk
  proofKey:             Hash;        // pk
  address:              Hash;        // addr
  credentialBindingKey: Hash;        // cbk
  credentialCommitment: Hash;        // public — holderCommitment in ZKC binding
}

// AFP-KDC key derivation. All hashes use the exact §A.3 Poseidon2 sponge
// and §A.3 domain separation.
function kdcDeriveKeys(seed: Uint8Array): KeyHierarchy {
  const sk   = H("zka/spending",  seed);   // from seed
  const vk   = H("zka/viewing",   sk);     // from sk
  const pk   = H("zka/proof",     sk);     // from sk
  const addr = H("zka/address",   vk);     // from vk
  const cbk  = H("zkc/credential", seed);  // from seed — NOT from sk
  const cc   = H("zkc/binding",   cbk);    // credential commitment

  return { seed, spendingKey: sk, viewingKey: vk, proofKey: pk,
           address: addr, credentialBindingKey: cbk,
           credentialCommitment: cc };
}
```

Two derivation facts are normative and load-bearing for the referencing specifications:

1. **`cbk` derives from the seed, not from `sk`.** The credential binding key is `H("zkc/credential", seed)`, a sibling of the spending key, not a descendant of it. This is what lets a holder prove credential ownership without exposing spending authority.
2. **Address and credential commitment are derived along separate paths.** `address = H("zka/address", H("zka/viewing", H("zka/spending", seed)))` and `credentialCommitment = H("zkc/binding", H("zkc/credential", seed))` share only the seed. Given one, the other cannot be computed or linked **without the seed**. ZKA's identity-binding circuit (ZKA §5.2) proves the link in zero knowledge precisely *because* the link is otherwise unrecoverable. [KDC-0022] A KDC implementation MUST preserve this separation.

The names of the derived keys are KDC's; how each key is *used* — `sk` to spend ZKA notes, `vk` to decrypt incoming notes, `cbk` to bind ZKC credentials — is specified by the referencing protocols, not here.

### A.7 Conformance and Versioning

A **conforming AFP-KDC v1.0.3 implementation**:

- implements the exact Poseidon2 permutation, constants digest, raw sponge `P`, tagged wrapper `H`, and all KATs of §A.3;
- implements exactly the domain-tag registry of §A.4 for derivation, and honors the tag-collision rule;
- implements the HKDF-SHA256 sub-derivation of §A.5;
- implements `kdcDeriveKeys` per §A.6, preserving the two normative derivation facts;
- reproduces every raw and KDC case in `docs/kdc_v1_0_2_conformance_vectors.json` exactly;
- reproduces every `field_hex` in `docs/kdc_v1_0_3_domain_registry.json` with `deriveFieldTag`, enforces its external fixed-byte ownership contract, and rejects any cross-family collision.

**Test vectors.** `docs/kdc_v1_0_0_test_vectors.json` is normative for HKDF entity sub-seeds. `docs/kdc_v1_0_3_domain_registry.json` is normative for field tags, the external fixed-byte ownership contract, and the complete cross-protocol collision scan. `docs/kdc_v1_0_2_poseidon2_parameters.json` and `docs/kdc_v1_0_2_conformance_vectors.json` are normative for Poseidon2 and the complete KDC hierarchy. All four artifacts are required for v1.0.3 conformance.

**Versioning.** AFP-KDC v1.0.3 immutably pins the derivation surface specified by §A.3–§A.6 and its normative artifacts. It requires the four artifacts listed above. Any change that alters a derived field, seed, key, proof, verification key, or hash requires a **major** KDC version bump and an explicit compatibility and migration plan across every consumer. A referencing specification cites a specific AFP-KDC version and may assume its derived values are immutable.

---
