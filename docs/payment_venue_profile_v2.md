# Payment venue v2: published profile rationale and executable reference

**Status:** Published experimental interface in AFP 0.3.12-draft §15.9; offline reference implementation; no activated settlement route.
**Date:** 2026-09-06

## Decision and compatibility

Keep the published `pay` profile, its Base-only `Settlement` and
`PaymentDeployment`, and every v1 quote, policy and receipt encoding unchanged.
Introduce a separate, opt-in `pay_venue` profile with
`afp:payment-quote:v2`, `afp:payment-policy:v2`, and `afp:payment-receipt:v2`.
The reference descriptor has version `2.0` and status `experimental`.
`venue_profile_descriptor()` returns it and `default_registry()` recognizes it
as part of the published profile set. Registration is not activation: the
acceptance API does not consult a registry. Bilateral acceptance requires a `pay_venue` session and the exact v2 policy
hash. A legacy `pay` session cannot accept a v2 quote, or vice versa.

AFP 0.3.12-draft §15.9 is the normative authority. This document records the
design rationale and executable-reference boundaries. Publication advances the
AFP interface identity and coordinated protocol-family epoch but does not
qualify a manifest, deployment, holder path, receipt verifier, or APL route.
Consumers that only understand v1 reject v2; there is no conversion or fallback.

The design follows ZKA ADR 0006 (Aztec native pay), ADR 0010 (flagship and
production gates), and ADR 0011 (Ethereum exit and Base reachability).
ADR 0010 places the quote design before V6 qualification. ADR 0011 accepts
Ethereum L1 ingress/egress architecturally and requires exact destination-bound
quotes. V6 adoption, qualified manifests, holder execution, independent audits,
and explicit activation remain separate gates. Synthetic vectors are not
evidence that any deployment satisfies them.

## Venue and deployment identity

The first v2 validator is `zka:aztec:native-pay:v1`. Unknown venue identifiers
fail closed; no validator is inferred from address length. The existing Base
rail remains expressible through v1 rather than being silently translated.

`VenueDeployment` is a frozen, trusted policy descriptor with exactly these
required members:

| Field | Encoding and meaning |
|---|---|
| `venue_profile` | Exact supported venue identifier above |
| `network_id` | Lowercase `aztec:<reference>` execution-network identifier |
| `anchor_chain_id` | `eip155:<positive decimal>` L1 identifier, no leading zero |
| `asset_id` | `<anchor_chain_id>/erc20:<lowercase 20-byte 0x address>` |
| `asset_commitment` | Canonical nonzero BN254 scalar binding the ZKA asset projection |
| `contract_class_id` | Canonical nonzero BN254 scalar identifying the immutable Aztec class |
| `contract_instance_id` | Canonical nonzero BN254 scalar identifying the Aztec instance |
| `settlement_portal_id` | Nonzero lowercase 20-byte 0x address on the anchor chain |
| `manifest_hash` | `sha256:` followed by 64 lowercase hex digits of the pinned manifest artifact |
| `fee_route` | `aztec-protocol-fee-v1` |
| `receipt_profile` | `zka:aztec:pay-receipt:v1` |
| `nullifier_semantics` | `aztec-app-siloed-v1` |
| `max_note_value` | Decimal string `340282366920938463463374607431768211455` (`u128::MAX`) |
| `asset_risk_profile` | `zka:asset-risk:s3-hard:v1`, with the venue-specific evidence below |

Scalars use lowercase `0x` plus exactly 64 hex digits and integers in `1..r-1`,
where `r` is the §15.4 BN254 modulus. Network references use the restricted
lowercase CAIP-2 spelling `[a-z0-9][a-z0-9._-]{0,31}`. Asset identifiers use the
CAIP-19 chain/namespace/reference structure, restricted here to ERC-20 assets.
No URI resolution or registry lookup is performed on quote input.

A deployment owner must obtain this tuple from trusted, tenant-scoped
configuration after checking the exact immutable manifest bytes, class and
instance, constructor-fixed portal/underlying asset, asset commitment mapping,
and chain identity. A manifest digest supplied by a quote is only a comparison
value, never a source of trust. The reference code checks schema and exact
policy equality; it does not attest a manifest, query chain state, or establish
production eligibility. An unqualified or ambiguous target must remain disabled.

The asset identifier names the L1 asset backing the one-asset portal. Ethereum
L1 WETH and Base WETH9 are different assets even if another address happens to
have matching bytes. Atomic units are the pinned asset's smallest units; for
WETH these are wei. Other ERC-20 assets need their own immutable portal, exact
asset projection, rate and risk evidence. Syntactic acceptance is not asset
approval. An adapter must never infer decimals or replace a signed amount.

The hard-S3 identifier means constructor-fixed one-asset custody, an ownerless
immutable Aztec pay class with no reachable update path, and unconditional
transfer/withdrawal under the selected protocol. It does not inherit evidence
from the Base deployment. Token freeze/admin behavior, portal authority and
host proving/finality assumptions must be assessed for the exact asset/venue;
an asset failing those requirements is ineligible. Other risk claims require a
separately specified validator rather than an arbitrary accepted string.

## Settlement, arithmetic and hashes

`VenueSettlement` has exactly these required fields:

```text
venue_profile, network_id, anchor_chain_id, asset_id,
contract_instance_id, settlement_portal_id, manifest_hash,
recipient_id, amount_atomic, asset_risk_profile
```

Shared deployment fields have the encodings above and must equal the policy
exactly. `recipient_id` is the canonical nonzero Aztec recipient address scalar.
It identifies the private payment recipient, not an L1 withdrawal beneficiary.
`amount_atomic` is a positive canonical decimal string at most `u128::MAX`.
Every target, recipient, asset, amount, or manifest change requires a newly
signed and accepted quote. There is no Base hop in this settlement object.

`AfpPaymentQuoteV2` retains the v1 top-level field names: `kind`, `quote_id`,
`session_ref`, `session_context`, `obligation`, `settlement`, `rate`, `quoted_at`,
`expires_at`, `max_slippage_bps`, `quote_nonce`, and the two optional signature
objects, and adds the required canonical `D_` digest `policy_hash`. Its kind is
v2, settlement is the object above, and rate has exactly
`source`, `usd_minor`, `asset_atomic`, `reference_usd_minor`, and
`reference_asset_atomic`. Obligation remains USD minor units. All rate amounts
are positive canonical decimal strings. Arithmetic is exact:

```text
amount_atomic = ceil(obligation.amount_minor * rate.asset_atomic / rate.usd_minor)
```

The §15.2 cross-multiplied slippage inequality applies with the asset-atomic
denominators replacing WETH-wei denominators. Protocol fees/fee juice are not
subtracted from the signed payment amount and are not priced as private WETH
fees. FPCs require a different profile. Quote timestamps remain whole-second
UTC; nonce is any canonical 32-byte hex value; `session_context` is exactly the
base-defined `X_` digest. Unknown, missing, noncanonical or extra wire fields
are rejected rather than normalized.

`AfpPaymentPolicyV2` keeps the v1 policy fields with a v2 kind and
`VenueDeployment` in `deployment`. Accepted sources, quote lifetime, slippage,
and required finality retain their validation rules. The session policy hash
commits to the complete descriptor, including class, asset commitment, fee,
receipt and nullifier profiles. It is not interchangeable with a v1 policy.

Canonicalization uses the same RFC 8785 JCS bytes and SHA-256 as §15.3:
`quote_hash = qb64("D", SHA-256(RFC8785_JCS_UTF8(quote_content)))`.
Only the two signature objects are omitted from quote content. All new
settlement fields are included. The complete signed-record acceptance hash
still covers both full signatures. The unchanged §15.4 digest-to-field mapping
and `zka/pay/interaction-context/v1` fold consume this quote hash and the
session context. The producer derives the fold before signature exchange and
rejects zero reductions. ZKA receives that exact context without reinterpretation.

[The synthetic conformance vector](payment_venue_v2_conformance.json) pins full
canonical quote bytes, quote hash, interaction context, policy, and policy hash.
The existing Base canonical vectors remain byte-identical. Neither the synthetic
asset address nor the manifest digest asserts a real asset registry entry.

## Authentication, receipts and finality

The shared signing/acceptance functions authenticate both KEL-current session
principals, reparse the exact version, require the matching live session and
policy hash, and reserve the quote ID/nonce/full signed-record hash in the same
durable replay ledger. Sealed `AcceptedPaymentQuote` capabilities retain v2
wire data and revalidate it on use. The required `policy_hash` in v2 quote
content commits the entire accepted policy, including deployment fields and
required finality; subsequent verification rejects policy substitution. No v2 route can be created from an unsigned
or unreserved quote.

Route dispatch keeps the AFP §15.5 dispatch window. `route_from_accepted`
requires the live `pay_venue` session capability and the verification
context's deployment-owned clock. It refuses a claim at or after `expires_at`,
before `quoted_at`, after the session ends, or for another session or profile,
and a refused claim does not consume the route claim. The finality verifier
receives the quote's `expires_at`; `safe` or `finalized` evidence must prove
inclusion strictly before it, so a late transaction leaves the obligation
unsettled. [The dispatch vectors](payment_venue_v2_dispatch_conformance_v1.json)
pin these cases.

A party that learns of a transaction outside the dispatch window, for example
after `expires_at` or after the session ends, claims it through
`route_from_observation` (AFP §15.5). That call needs no live session and
reads no clock. It requires the accepted policy, a receipt that echoes the
exact route, finality at the policy's `required_finality`, and verified
evidence of inclusion strictly before `expires_at`. Only then does it claim
the transaction, and a rejected observation does not consume the claim. A
transaction included at or after `expires_at` can never be claimed this way,
so the path gives the payer no option to settle late. Through either path, one
Aztec transaction settles at most one v2 quote.

`PaymentRouteEvidenceV2` has exactly `quote_ref`, `quote_hash`,
`interaction_context`, the full nested `settlement`, and `transaction_id`.
`AfpPaymentReceiptV2` adds `kind`, `output_note_hash`,
`private_event_log_position`, `observed_at`, `finality`, and
`finality_evidence`, retaining the v1 observation formats and monotonic
`pending` → `safe` → `finalized` model. `PaymentReceiptVerificationContext`
chooses the route type from the authenticated quote version. The receipt must
echo every settlement field exactly; a matching transaction identifier alone
is insufficient. The ledger still permits only one transaction claim per
accepted quote, and one accepted quote per transaction, with retry/reconciliation retaining that identity.
One Aztec transaction therefore settles at most one v2 quote: the ledger refuses a
`transaction_id` that a different accepted quote has claimed.

The output note hash is a canonical BN254 field encoding and may be zero. The private
event log position is a nonnegative JSON-safe integer (at most 2^53 - 1, a wire
encoding bound rather than a network limit). The trusted verifier authenticates
both occurrence fields. The tracker pins the first verified occurrence and
rejects a different note or log position during finality advancement, even if
the replacement observation verifies independently.

For Aztec, a trusted deployment-specific finality verifier must verify the
holder-authorized disclosure of the constrained encrypted receipt: exact
recipient output-note binding, contract instance and receipt-profile domain,
interaction context, transaction, amount, asset and recipient, plus the pinned
network/finality evidence. A public Base batch receipt, unconstrained log,
matching note hash, or arbitrary nonempty evidence is not proof of settlement.
The reference tracker requires the injected verifier to return exactly `True`;
it implements no Aztec chain verifier. Level names acquire meaning only through
that pinned verifier and finality policy. Private pay completion is distinct
from L1 withdrawal/Outbox completion.

Receipt disclosure stays within the holder-authorized private application
boundary. This AFP observation does not make the interaction context a public
Aztec argument, log, note field, nullifier input, or withdrawal predicate.
Ciphertext size/count, timing and discovery metadata remain disclosed residuals.
Equal cross-environment note commitments do not establish nullifier equality
or authorize duplicate spending.

Direct L1 withdrawal remains unconditional under ZKA. A later Base bridge hop
requires separately accepted route/asset/conversion/recipient/finality terms;
failure of that hop must not block or reverse direct withdrawal. Route
qualification and activation are owned by the existing ZKA holder and APL
target-route requirements, not by this profile.
