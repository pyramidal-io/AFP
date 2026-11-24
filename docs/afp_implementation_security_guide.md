# AFP Implementation-Security Guide

**Document revision:** 2 (2026-11-17)
**Status:** Informative. This guide is not part of the AFP specification.
**Applies to:** the standard-library Python reference packages in `python/` (`afp_session`, `afp_payment`)
**Specification:** `docs/afp_specification.md`, interface version 0.3.14-draft, document revision 54

## 1. Status and scope

This guide describes how the AFP reference implementation meets some requirements of the AFP specification, and where its in-process protections end. It covers §12.7.1, §12.7.2 and §15.5.

The guide is informative. It adds no requirement and creates no exception. The specification states each outcome that an implementation must reach. This guide describes one way to reach it, in one language. An implementation in another language can meet the same outcome with different mechanisms. If this guide and the specification disagree, the specification controls (§11).

Each section below names the specification rule it serves, with its requirement identifiers (specification §1.5), then describes the reference mechanism. The names of classes, functions and stores are those of the reference packages at the specification revision above.

## 2. Native credential receive (§12.7.2)

**Serves:** AFP-0369.

**Specification outcome.** A successful receive records exactly one accepted-credential effect before it returns. Any later use of an accepted credential confirms that this receiver accepted that exact, unchanged record and that its session is still live. The receiver's record of an accepted credential is not a proof, wire artifact, durable attestation or settlement authority.

**Reference mechanism.**

- A successful receive returns an `AcceptedCredentialEnvelope` (`python/afp_session/credential.py`). It is a frozen object that only the receive path can construct: the constructor requires a module-private mint token.
- The object holds a detached copy of the envelope wire, the verified presentation, the evidence and the verified public statement. Each accessor returns a copy.
- The object records its issuing `Instance`. `require_verified_native_credential` rejects an object that the receive path did not issue, an object whose issuer changed, and an object whose session is no longer live. Every accessor calls it.
- The object refuses serialization (`__reduce__` raises). It is a process-local capability, not durable evidence.
- The reference has no built-in persistence for native credentials or sessions. `Instance.sessions`, `Instance.credential_inbox`, the seen-credential replay set and the issued-result registry are in-memory structures, so none of them survives a restart. The Coord completion store of §3 does not cover native credentials. A deployment that needs these effects to survive a restart supplies its own durable storage.

These checks are API-misuse hardening inside a trusted process. Section 5 states their limit.

## 3. Coord v2 completion store (§12.7.1)

**Serves:** AFP-0357, AFP-0358.

**Specification outcome.** The durable completion record survives a restart of the receiving instance. Storage that can lose records on restart does not hold it. A workflow instance's completion is therefore applied at most once, including across a restart.

**Reference mechanism.**

- `SqliteCoordCompletionStore` (`python/afp_session/coord.py`) writes the replay record and the completion effect in one SQLite transaction. The `workflow_instance_id` column is the primary key.
- The store refuses paths that SQLite would back with memory or a temporary file: an empty path, `:memory:`, and any `file:` URI, which could select `mode=memory`. A refused path fails with the replay code. The store does not try to detect every non-durable backing. For example, it cannot detect a path on a RAM-backed file system. Choosing durable storage stays a deployment decision.
- `InMemoryCoordCompletionStore` exists for tests. It is not durable and does not meet the specification outcome.

## 4. `pay` acceptance and route execution (§15.5)

### 4.1 Live-session handle

**Serves:** AFP-0436 (item 3), AFP-0437, AFP-0447.

**Specification outcome.** Item 3 of §15.5 is evaluated against the instance's own current session state, normal-activation provenance and clock each time it is relied on. After a restart, a stored or transferred token cannot stand in for that state.

**Reference mechanism.**

- `Instance.verified_live_session(fsm)` (`python/afp_session/session.py`) returns a `VerifiedLiveSession` only after a normal ACTIVE transition. Construction requires a module-private mint token.
- The handle stays bound to its owning `Instance`. Each access rechecks the exact owned FSM, its activation provenance and expiry against the owner's clock. Close, abort, expiry or replacement of the FSM invalidates every handle minted for it.
- The handle refuses serialization. The reference keeps session state in memory. A deployment that needs sessions to survive a restart rehydrates the durable session and FSM state, restores lifecycle provenance, and mints a new handle. It does not persist or restore the handle.

### 4.2 Accepted capability: `AcceptedPaymentQuote`

**Serves:** AFP-0442, AFP-0444.

**Specification outcome.** The accepted capability is created only after every acceptance check succeeds. It uses a recomputed `quote_hash`, never one supplied by the caller or the counterparty. The durable ledger reservation, not the in-memory capability, is the authorization source.

**Reference mechanism.**

- `accept_payment_quote` (`python/afp_payment/authentication.py`) is the only issuer of `AcceptedPaymentQuote`. The class is defined inside a closure. Its `__new__` requires a private authority object, so direct construction raises. The class has no public constructor that takes a quote hash.
- The issuing path canonically reconstructs the detached quote and recomputes `quote_hash` before it retains the quote ID, nonce, `acceptance_record_hash`, interaction context, the session's `profile_policy_hash` and the canonical quote wire.
- The capability refuses serialization. Long-running receipt observation persists its route and receipt state, not the capability.

### 4.3 Process-local seal

**Serves:** AFP-0443, AFP-0444.

The reference seals each `AcceptedPaymentQuote` with HMAC-SHA-256. The seal covers the retained `profile_policy_hash` and the canonical accepted wire. The key is 32 random bytes from `secrets.token_bytes`, created when the module loads and held only by the closure.

On each use (`to_quote`), the reference:

1. compares the seal in constant time (`hmac.compare_digest`);
2. reparses the sealed wire;
3. recomputes `quote_hash`, `acceptance_record_hash` and `interaction_context`;
4. matches them and the quote ID and nonce against the retained fields;
5. for a v2 quote, requires the signed `policy_hash` to equal the retained `profile_policy_hash`.

The seal detects in-process tampering with the object's fields. It is **not authorization**. A new process has a new key, so a capability cannot outlive its process. The authorization source is the durable ledger reservation of §4.5.

### 4.4 Composition root: `PaymentReceiptVerificationContext`

**Serves:** AFP-0451.

**Specification outcome.** The acceptance ledger, the finality-evidence verifier and the trusted clock are fixed by the deployment's configuration. Request data and received records cannot select, replace or supply any of them.

**Reference mechanism.**

- The deployment builds one `PaymentReceiptVerificationContext` (`python/afp_payment/receipt.py`) at its composition root. The context binds three things: a store-issued limited acceptance authority, the deployment's finality-evidence verifier, and the deployment's trusted clock.
- The constructor rejects the writer store itself, an object that only looks like an authority view, a missing verifier and a missing clock.
- `route_from_accepted`, `route_from_observation`, `route_from_dict` (route decoding) and `tracker` use only the bound context. None of these request-facing calls takes a verifier or a time parameter.
- This boundary prevents request data from substituting a new attacker-controlled ledger. Each deployment still chooses its own trusted composition root.

### 4.5 Store-issued limited authority and the issued-instance set

**Serves:** AFP-0452, AFP-0454, AFP-0455.

**Specification outcome.** Route and receipt processing needs only exact-tuple verification and the atomic route claim from the ledger. It never reserves a quote.

**Reference mechanism.**

- A replay store issues a limited authority view (`_AcceptanceVerifierView`, `python/afp_payment/replay.py`). The view exposes `verify_reservation`, `claim_route` and `verify_route`, and no quote reservation.
- The view class and its issuing function are defined inside a closure. Construction requires a closure-held token. The closure also holds a weak set of issued views. `PaymentReceiptVerificationContext` accepts only a view that is in that set. Direct construction, nominal construction through `object.__new__`, and objects that only have the same methods are therefore rejected.
- `SQLiteReplayStore` opens a separate read-write connection for the view (`verifier_view`). That connection serves only exact-tuple verification and the atomic route claim. The store uses WAL journaling and `synchronous=FULL`. Each quote has one row with one claimed-transaction column, and the atomic first-claim operation enforces one transaction per quote. A unique index over `claimed_transaction_id` enforces one quote per transaction. The store fails closed at start-up when existing rows violate that index.
- `InMemoryReplayStore` exposes the same limited operations under its store lock. It is for tests and is not durable.

### 4.6 Restart

**Serves:** AFP-0464, AFP-0465.

**Specification outcome.** An accepted quote executes at most once, including across a restart.

**Reference mechanism.** `SQLiteReplayStore` keeps the reservation and the route claim across a restart. In-memory capabilities and handles do not survive a restart, and the reference provides no path to recreate an `AcceptedPaymentQuote` for a quote already in the ledger. A deployment that adds a recovery path verifies a durable accepted record and keeps replay protection unchanged. An existing claim stays bound. If no transaction is claimed yet, the recovered quote gets its first claim only through dispatch or the observation claim.

## 5. In-process trust boundary

**Serves:** AFP-0466.

**Specification outcome.** The §15.5 rules assume that the code holding the acceptance ledger and route authority is trusted. AFP defines no isolation against code that already runs with that authority. A deployment does not run tenant code, plugins or other untrusted extensions with that authority.

**Limits of the reference.** The mint tokens, closures, issued-instance sets, seals and serialization refusals in this guide protect against API misuse by trusted code. They are not a sandbox. Code that runs in the same Python interpreter can introspect closures, monkey-patch functions and classes, or read storage credentials. Such code can defeat every in-process guard in this guide.

**Deployment options.** A deployment that keeps request data, tenant code, plugins and other untrusted extensions out of the authority process can rely on the reference guards against misuse. A deployment whose threat model includes code in the same process places the acceptance and route authority behind a stronger boundary. Examples are a separate process, a signer backed by a KMS or an HSM, or an isolated service. The in-process reference objects are not sufficient for that threat model. No capability or handle in this guide crosses a process boundary.
