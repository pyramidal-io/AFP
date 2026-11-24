# AFP protocol-family interfaces

This directory contains AFP's machine-readable composition boundary with ZKA,
ZKC, ZKM, and AFP-KDC.

The interface manifest, schema, golden vectors, snapshot lock, and validator
form a vendored canonical bundle. Their repository authority identifiers and
immutable revision pins are intentional public protocol provenance. They do
not grant access to source repositories or carry pull-request, CI-run, runner,
credential, or private-history data.

`afp-interface-surface-v1.json` is AFP-owned and records the wire/interface
surface composed by that bundle. `poseidon2-operational-domains-v1.json` is the
vendored fixed-byte operational-domain inventory required by AFP-KDC v1.0.3.

Run the self-contained checks from the repository root:

```text
python3.12 scripts/validate_protocol_family.py validate --repo afp --root .
python3.12 scripts/check_afp_interface_surface.py
python3.12 scripts/validate_kdc_conformance.py
```

The public snapshot intentionally omits cross-repository audit orchestration,
rollout records, and historical migration worklists.
