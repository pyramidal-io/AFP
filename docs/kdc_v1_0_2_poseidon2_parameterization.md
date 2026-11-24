# AFP-KDC v1.0.2 Poseidon2 Parameterization Record

**Status:** Adopted by AFP-KDC (`docs/kdc_specification.md`, formerly Appendix A of `docs/afp_specification.md`) §A.3.1–§A.3.3 and §A.7.
**Normative artifacts:** `docs/kdc_v1_0_2_poseidon2_parameters.json` and `docs/kdc_v1_0_2_conformance_vectors.json`.
**Version:** **v1.0.2 — non-breaking clarification.** Not a major bump. See §2.
**Author's provenance:** every value below was recomputed from the deployed implementations on 2026-08-12 and cross-toolchain edge verification was completed on 2026-08-14 (§6); no value was transcribed from documentation.

---

## 1. The gap this closes

Appendix A currently names Poseidon2 ten times and never parameterizes it. §A.3 says only that KDC "uses **Poseidon2** over the **BN254 scalar field**," identified as "the hash provided by Noir's standard library (`std::hash::poseidon2`)."

That leaves five things unpinned:

1. **Permutation width.** t=3 and t=4 Poseidon2 instances both exist for BN254 and are widely published. Nothing in Appendix A selects one.
2. **Round parameters.** RF/RP are not stated. (Public tutorials commonly quote "8 full + 60 partial" — the **t=5** instance — which a good-faith implementer could reasonably adopt.)
3. **Sponge mode.** The absorption rule, capacity IV, padding behavior, and output lane are undefined, yet `H(domain, x...)` is written variadically.
4. **Round constants.** Delegated to an external library reference, which is mutable (see §5).
5. **Domain-separation semantics of arity.** Undefined, which invites the assumption that `H2` and `H3` are separated *because* their arities differ.

**Consequence:** a conformance claim under §A.7 ("uses Poseidon2 over BN254 with the domain separation of §A.3") is satisfiable today by mutually incompatible implementations. The published KAT vectors — not the prose — are currently the only real pin, and vectors are a check, not a specification.

**Secondary consequence.** The in-flight correction requiring implementations to "reproduce authoritative AFP-KDC/ZKC vectors byte-for-byte" is only enforceable if the specification states which permutation produced those vectors. This pin is therefore a **precondition** for that requirement's acceptance criteria to have force, which is why it should land first.

---

## 2. Why this is v1.0.2 and not a major bump

§A.9 requires a major KDC version bump for any change that alters a derived field, key, proof, VK, or hash.

**This change alters none of them.** It documents the instance that ZKA, ZKC, and ZKM already share. Verified: the three reference KATs reproduce bit-identically across two independent implementations (ZKA's Noir `zka_lib` and ZKC's pure-Python `zkc_crypto`), and ZKM pins the same values. No known deployed KDC consumer is invalidated by this pin.

It is therefore additive documentation, and it is compatible with the standing **behavioral-identity requirement** in §A.3: existing field constants, seed→key derivations, proofs, verification keys, hashes, and HKDF vectors all remain byte-for-byte unchanged.

**Note on sequencing (correcting a prior recommendation).** An earlier assessment suggested bundling this with the `cbk`/holder-commitment correction into one coordinated version change. That was wrong on inspection: **AFP §A.6 is already correct** on `cbk = H("zkc/credential", seed)` and `holderCommitment = H("zkc/binding", cbk)`. The defect is in ZKA's *implementation*, which contradicts AFP, ZKC, ZKM, and ZKA's own specification. No AFP change is required for it, so there is no major bump to bundle into. This pin is cleanly separable and should ship on its own.

---

## 3. Adopted normative design

> ### A.3.1 Poseidon2 Instance (normative)
>
> KDC uses exactly one Poseidon2 instance. Implementations MUST use these parameters; any other parameterization is non-conformant regardless of whether it is also called "Poseidon2 over BN254."
>
> | Parameter | Value |
> |---|---|
> | Field | BN254 scalar field `Fr` |
> | Modulus `r` | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
> | State width `t` | **4** |
> | Rate | **3** (state lanes 0, 1, 2) |
> | Capacity | **1** (state lane 3) |
> | S-box | `x⁵` |
> | External (full) rounds `R_F` | **8** — 4 before and 4 after the internal rounds |
> | Internal (partial) rounds `R_P` | **56** |
> | Total rounds | 64 |
> | External linear layer `M_E` | `[[5,7,1,3], [4,6,1,1], [1,3,5,7], [1,1,4,6]]` |
> | Internal linear layer `M_I` | all-ones plus the diagonal fixed by `INTERNAL_DIAG_MINUS_ONE` below |
>
> This is the Barretenberg/`aztec-packages` t=4 BN254 parameter set that Noir's `poseidon2_permutation` builtin implements. **The width is 4, not 3.** Implementations MUST NOT substitute the t=3 or t=5 instances, and MUST NOT adopt round counts quoted for other widths.
>
> The permutation operates over `Fr`; every addition, multiplication, and exponentiation below is reduced modulo `r`. Let `RC[q][i]` denote lane `i` of round-constant row `q`, and let `D[i]` denote `INTERNAL_DIAG_MINUS_ONE[i]`. The exact permutation is:
>
> ```text
> permutation(state):
>     state = M_E · state
>
>     for q with 0 ≤ q < 4:
>         for i with 0 ≤ i < 4:
>             state[i] = (state[i] + RC[q][i])⁵
>         state = M_E · state
>
>     for q with 4 ≤ q < 60:
>         state[0] = (state[0] + RC[q][0])⁵
>         total = state[0] + state[1] + state[2] + state[3]
>         for i with 0 ≤ i < 4:
>             state[i] = total + D[i] · state[i]
>
>     for q with 60 ≤ q < 64:
>         for i with 0 ≤ i < 4:
>             state[i] = (state[i] + RC[q][i])⁵
>         state = M_E · state
>
>     return state
> ```
>
> Thus the internal matrix is `M_I = J + diag(D)`, where `J` is the 4×4 all-ones matrix. Equivalently, its diagonal entries are `D[i] + 1` and its off-diagonal entries are `1`. The initial multiplication by `M_E` occurs before round 0 and is not itself a round.
>
> **Normative parameter artifact.** `docs/kdc_v1_0_2_poseidon2_parameters.json` publishes the exact `M_E`, all 64 `RC` rows, all four `D` values, and the operation order above. The artifact is part of AFP-KDC v1.0.2, not an informative implementation aid. A clean-room implementation can therefore be produced without recovering constants from an upstream repository.
>
> **Constant digest.** Because an upstream Git tag is mutable, this specification additionally pins the artifact's 64 round-constant quadruples and 4 internal-diagonal-minus-one values by content. The canonical encoding is:
>
> ```text
> canonicalConstantEncoding =
>     concatenate BE32(RC[q][i]) in row-major order
>       for 0 ≤ q < 64 and, within each row, 0 ≤ i < 4
>  || concatenate BE32(D[i]) for 0 ≤ i < 4
>
> where BE32(x) is the 32-byte big-endian encoding of the canonical
> representative of x in [0, r).
>
> length  = 8320 bytes  (260 field elements)
> SHA-256 = 8cb18652f4afeac5b6819b156c13fbbc327deacba568b9d8d961ab134123214c
> ```
>
> An implementation MAY obtain the constants from any source. An implementation that imports, embeds, or loads an explicit parameter table MUST verify that table against this digest before use. A backend exposing only an opaque Poseidon2 intrinsic MUST immutably identify the backend artifact it relies on and MUST reproduce every §A.3.3 known-answer test; it is not required to extract a table that the backend does not expose.
>
> ### A.3.2 Sponge Mode (normative)
>
> Let `P(x₀, …, xₙ₋₁)` denote the length-bound sponge below — the `Poseidon2::hash` construction of `noir-lang/poseidon`. `P` absorbs no delimiter or semantic domain tag: unused rate lanes remain zero, while message length is encoded in the capacity lane. Semantic domain separation is supplied by the tagged KDC wrapper already defined in §A.3:
>
> ```text
> H(domain, x...) = P(deriveFieldTag(domain), x...)
> ```
>
> `P` and `H` are distinct functions. In particular, the raw conformance vectors of §A.3.3 test `P`; KDC derivations call `H`.
>
> The domain of `P` is a sequence `x[0], …, x[n-1]` of typed, canonical `Fr` elements, where `n` is the number of absorbed elements and `0 ≤ n ≤ 2³²−1`:
>
> ```text
> state[0] = state[1] = state[2] = state[3] = 0
> state[3] = n · 2⁶⁴                     # capacity lane carries the length IV
>
> full = n - (n mod 3)
> for chunk in 0, 3, 6, ..., full-3:
>     for i with 0 ≤ i < 3:
>         state[i] = (state[i] + x[chunk+i]) mod r
>     state = permutation(state)
>
> rem = n mod 3
> if rem ≠ 0:
>     for i with 0 ≤ i < rem:
>         state[i] = (state[i] + x[n-rem+i]) mod r
>
> if n = 0 or rem ≠ 0:
>     state = permutation(state)
>
> return state[0]
> ```
>
> Four properties are normative and are the ones implementations most often get wrong:
>
> 1. **The length IV occupies capacity lane 3**, as `n · 2⁶⁴`. Under the `u32` bound this integer is smaller than `r`, so its image in `Fr` is exact. This is what makes `P(m₁, …, m_k)` differ from `P(m₁, …, m_k, 0)`. It avoids the same Poseidon-v1 variable-length zero-padding collision demonstrated by CVE-2026-32129 in `soroban-poseidon`'s `PoseidonSponge`; that CVE does not affect KDC or Noir's Poseidon2 construction. Removing or relocating the IV would reintroduce the collision class.
> 2. **Absorption is additive** into the rate lanes, not overwriting.
> 3. **The trailing permutation is conditional.** It runs when `n = 0` or `n mod 3 ≠ 0`, and **does not run** when `n` is a positive multiple of 3. An implementation that always permutes at the end produces correct results for `n ∈ {1,2,4,5,…}` and **wrong** results for `n ∈ {3,6,9,…}`. §A.3.3 includes vectors on both sides of this branch specifically to catch it.
> 4. **The output is lane 0** of the final state.
>
> `n` MUST equal the number of field elements absorbed and MUST fit in the `u32` message-length type of the deployed Noir `Poseidon2::hash` API. No KDC call site approaches this bound.
>
> `P` accepts `Fr` elements, not arbitrary integers or byte strings. A value enters `P` only after the owning construction has converted it to its canonical representative in `[0, r)`; for example, §A.3's seed rule performs its specified reduction before hashing. Passing a non-canonical integer directly is outside the domain of `P` and is not a conforming invocation. Host APIs MAY expose separately named decoding or reduction helpers, but MUST NOT describe a reducing integer API as the primitive `P` itself.
>
> **Arity separation is not semantic domain separation.** The length IV makes `P₂(x, y)` differ from `P₃(x, y, 0)` even though the extra absorbed value is zero; in that comparison, the IV is the only differing pre-permutation input. But two distinct protocol contexts with the same arity still invoke the same raw function on the same inputs. Implementations MUST use an explicit leading domain tag through `H` and MUST NOT use arity as a substitute for context separation.
>
> ### A.3.3 Conformance Known-Answer Tests (normative)
>
> An implementation is conformant with §A.3.1–§A.3.2 only if it reproduces every value below. Inputs are the field elements `1, 2, 3, …` in order.
>
> | `n` | Input | `P` output |
> |---|---|---|
> | 0 | `[]` | `0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e` |
> | 1 | `[1]` | `0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373` |
> | 2 | `[1,2]` | `0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383` |
> | 3 | `[1,2,3]` | `0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8` |
> | 4 | `[1,2,3,4]` | `0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9` |
> | 6 | `[1,2,3,4,5,6]` | `0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a` |
> | 7 | `[1,2,3,4,5,6,7]` | `0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238` |
>
> The `n ∈ {0, 3, 6}` rows are not redundant: they exercise the conditional trailing permutation of §A.3.2(3) in both directions. `n ∈ {2,3,4}` are the historical raw `H2`/`H3`/`H4` wrapper vectors—called `P₂`/`P₃`/`P₄` here to distinguish them from KDC's tagged `H`—and are unchanged from v1.0.0.

---

## 4. Adopted §A.7 conformance amendment

Replace the Poseidon2 clause of the conformance statement with:

> An implementation claiming AFP-KDC v1.0.2 conformance MUST implement the exact Poseidon2 permutation and parameter artifact of §A.3.1, implement the raw sponge `P` and tagged wrapper `H` of §A.3.2, reproduce all §A.3.3 known-answer tests, and apply the semantic domain separation of §A.3–§A.4. An implementation with an explicit parameter table MUST also reproduce the pinned constant digest.

Rationale: the current clause can be satisfied by an implementation using a different width. This makes the claim mechanically checkable.

---

## 5. Design note — why constants are pinned by digest

Every consumer (`ZKA/noir/zka_lib`, `ZKC/noir/zkc_lib`, `ZKM/noir/zkm_lib`) declares `poseidon = { tag = "v0.3.0", git = "…/noir-lang/poseidon" }`. A Git tag is mutable, and the toolchain in use silently ignores `rev`/`commit` and emits no lockfile, so immutability **cannot be expressed in the manifests**. Pinning by upstream reference would import that weakness into the normative specification.

The normative parameter artifact publishes the constant values and complete permutation metadata; the content digest authenticates the constant table. Together they make Appendix A self-contained: the specification does not depend on an external repository's tag continuing to mean what it meant, nor does a clean-room implementer need to recover a digest preimage from elsewhere. Combined with the domain registry Appendix A already hosts, this makes AFP the single conformance anchor for both "which permutation" and "which tags."

Implementations should continue to verify their upstream fetch independently; the digest is the specification-level backstop, not a replacement for supply-chain checks.

---

## 6. Verification performed (2026-08-12; extended 2026-08-14)

Every normative value was recomputed rather than transcribed:

- **Parameter artifact and constant digest** — `docs/kdc_v1_0_2_poseidon2_parameters.json` was generated from the ZKC table and then checked against the current ZKA Rust and ZKM Python tables and directly against Barretenberg `poseidon2_params.hpp` at `aztec-packages` commit `e44e98dce68e7d5fbe2c93f700da924bb2963004` (tag `v4.3.0`). Every source contains the same 260 field elements and produces the same 8320-byte encoding and SHA-256 stated in §A.3.1.
- **Round parameters** — `R_F = 8`, `R_P = 56` confirmed independently in `ZKA/src/zka-crypto/src/hash/poseidon2_bn254.rs:39,41` and in the ZKC Python permutation.
- **Sponge mode** — transcribed from the executable reference `ZKC/python/zkc_crypto/poseidon2.py:91-118`, including the conditional trailing permutation.
- **KAT cross-validation** — the historical raw `H2`/`H3`/`H4` wrappers (`P₂`/`P₃`/`P₄` in this proposal) computed by the ZKC Python implementation match `ZKA/noir/zka_lib/src/lib.nr:438-459` exactly (`0x038682aa…7383`, `0x23864adb…3dd8`, `0x130bf204…b1b9`). Two independent implementations, two languages.
- **Existing edge corroboration** — `P₁(1)` already appears with the same value in ZKA's published `tests/vectors/crypto/poseidon_hash.json`; `P₇(1,…,7)` already appears with the same value in ZKM's Noir `zkm_lib` KAT. Before the 2026-08-14 run below, `n = 0` and `n = 6` were the only rows without an independent counterpart.
- **Cross-toolchain edge verification (2026-08-14)** — one isolated Noir KAT asserted all four proposed edge rows, `n ∈ {0,1,6,7}`, against `Poseidon2::hash`. It passed under both `nargo` 1.0.0-beta.22 and `aztec-nargo` 1.0.0-beta.21. This independently corroborates `P₀()` and `P₆(1,…,6)` and closes the known Aztec-toolchain KAT gap.

---

## 7. Independently completed companion corrections

- **ZKA `cbk`/holderCommitment.** ZKA now implements AFP's existing `cbk = H("zkc/credential", seed)` and `holderCommitment = H("zkc/binding", cbk)` contract.
- **Seed→field aliases and decoding.** AFP now explicitly preserves the big-endian modulo-`r` mapping; ZKC publishes strict 32-byte decoders and boundary vectors for 0, 1, `r-1`, `r`, `r+1`, the high bit, and an asymmetric seed.
- **Operational tags.** ZKA, ZKC, and ZKM now share the §A.3 Blake2b-512 little-endian reduction and the complete v1.0.2 collision registry, whose tag values are unchanged from v1.0.1.

---

## 8. Adoption checklist

- [x] **Regenerate `P₀()` and `P₆(1,…,6)` under both `nargo` and `aztec-nargo`.** The 2026-08-14 isolated KAT included all four new edge rows and passed under `nargo` 1.0.0-beta.22 and `aztec-nargo` 1.0.0-beta.21.
- [x] Confirm the constant digest against the current ZKA `poseidon2_bn254_constants.rs`, ZKM `_poseidon2_constants.py`, and Barretenberg `poseidon2_params.hpp` at `aztec-packages` commit `e44e98dce68e7d5fbe2c93f700da924bb2963004`, not only the ZKC Python extraction. All four sources produce 260 elements, 8320 bytes, and `8cb18652…123214c`.
- [x] Align the input-length bound with the deployed Noir `u32` message-length API.
- [x] Specify the exact external matrix, internal diagonal convention, initial layer, and per-round operation order, and publish the complete parameter table as a normative artifact.
- [x] Publish §A.3.3 vectors as an AFP-owned required conformance gate for every consumer repository.
- [x] Publish `docs/kdc_v1_0_2_domain_registry.json` as the active registry while retaining the byte-value-identical v1.0.1 artifact as historical compatibility evidence.
