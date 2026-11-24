# Public snapshot provenance

This document accompanies the public [AFP snapshot](../README.md). Its source
selection policy is itself published as [PUBLIC_ALLOWLIST](../PUBLIC_ALLOWLIST).

This repository is constructed by default-deny source selection: only the
literal paths in `PUBLIC_ALLOWLIST` and the explicit public-only paths in
`PUBLIC_SURFACE` may be tracked. The selected source blobs and overlay inputs
are taken from one immutable reviewed revision.

Publication creates fresh orphan history. It does not inherit, expose, or
otherwise reuse private commit graph history. The included surface checker
requires the complete tracked tree to equal the two manifests and accepts only
regular file modes. Public CI also requires every workflow action reference to
use a complete immutable commit SHA.

`LICENSE_INVENTORY.json` is canonical machine-readable exported-source license
metadata. Its public CI checker assigns every tracked file exactly one reviewed
scope and verifies the root license/notice, vendored Poseidon provenance, and
the exact Nargo manifests. A separate dependency gate rejects any manifest
outside that reviewed set, rejects non-path Noir dependencies, and requires all
dependency paths to resolve inside the snapshot. Public CI executes the
vendored Noir KATs with checksum-pinned Nargo `1.0.0-beta.22`; the Python
packages remain standard-library-only. The private cross-repository Rust
harness is not part of this self-contained snapshot.

The vendored protocol-family bundle intentionally retains its canonical
repository authority identifiers and immutable revision pins. Those fields are
approved protocol provenance; private pull requests, CI runs, rollout records,
and AFP source-history identifiers are excluded.

The public provenance gate reads every tracked blob and fails generically on
private-source GitHub URLs, pull-request or Actions-run URLs, internal tracker
identifiers and paths, private authority-document references, self-hosted runner
configuration, selected private credential names, or Git LFS pointers. Its
output never includes a matching path or value.

The public changelog begins at this snapshot's first public baseline. It does
not expose or reconstruct private development history. Public tag validation
is read-only: a `v<spec-version>` tag must match the normative specification
and a dated public changelog heading, but CI does not create releases or write
repository state.

Snapshot construction runs secret scanners with an exporter-owned Gitleaks
policy. Post-export validation also runs the public `.gitleaks.toml` policy;
both policies enable the default rules. The public policy limits its reviewed,
line-and-path-scoped `generic-api-key` false-positive exceptions to public
mixnet verifier-call fixtures, KDC conformance output-field shapes, the
exact pinned Coord v2 recursive verification-key field hash, and exact public
APR verification keys in the synthetic native credential-carriage fixture.
Scanner success and exact-tree checks reduce
publication risk, but they cannot prove the absence of every sensitive fact,
establish operational safety, or turn this snapshot into a source of private
history or production access.
