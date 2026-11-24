#!/usr/bin/env python3
"""Fail-closed checks for AFP's published interface surface.

WHY THIS EXISTS
===============
AFP publishes two independent version axes. The *interface version* names the
wire surface -- envelope, message classes, telemetry predicates, typed wire
records, presentation profiles, published profiles, subject namespace, and the
sibling versions AFP composes with. The *document revision* identifies the
current publication of the normative prose. A document-only revision does not
move the interface version, interface digest, family manifest, or family epoch.

`protocol-family/afp-interface-surface-v1.json` separates those axes, and this
script enforces the separation. On every CI run it re-derives the current
surface claims from their sources:

  * message classes from the specification's own section 5.3 table;
  * telemetry predicates from the section 6.3 catalog rows, including the
    frozen status of `afp.telemetry.instance_attestation.v1`;
  * typed wire records from the specification's own `kind: 'afp:...'`
    declarations -- in BOTH directions, so an undeclared new record fails;
  * published profiles and their reference/experimental status from the
    section 13.3 table;
  * the envelope identifier, presentation profiles, composed-with versions and
    family epoch from the vendored family manifest and snapshot lock;
  * the interface version and its short form from the specification
    front matter, the section 2.2 layering diagram and the Appendix A
    back-reference;
  * `interface_set_id` recomputed from the prose-excluding projection; and
  * the family's pin on AFP -- which must name a published interface version,
    must not lag `last_breaking_interface_version`, must never pin this file
    *or the specification* by whole-file digest, and must never reference the
    document-revision axis.

WHAT `interface_set_id` DOES AND DOES NOT COVER
==============================================
The digest commits to the interface surface at IDENTIFIER granularity: which
message classes, telemetry predicates, typed wire records, presentation
profiles and published profiles exist; each message class's subject subtree;
each predicate's frozen status and the *name* of its public-input structure;
the envelope identifier, the NATS subject root and the composed sibling
versions. That is exactly the scope `version_discipline.interface_change`
declares, and it is what makes the digest stable across prose.

It deliberately does NOT cover the FIELD CONTENT of those records -- adding a
field to `interface AfpEnvelope { ... }` or to
`AfpInstanceAttestationPublicInputsV2` leaves `interface_set_id` unchanged.
Field content is gated separately, by the byte-identical `FROZEN_*` pins in
`tests/python/test_instance_attestation_spec.py` and
`tests/python/test_interface_surface.py`. Two gates, two granularities: do not
read a green `interface_set_id` as evidence that no record gained a field.
Record bodies are excluded because their inline `//` comments would put prose
in the digest preimage and re-couple editorial revisions to the interface
digest.

The family validator asserts equality only, so this AFP-local gate enforces the
lower-bound invariant that the family pin covers AFP's last breaking interface
version.

`--self-test` mutates the surface and its sources and requires every check to
fail closed, and requires every prose-only mutation to leave `interface_set_id`
untouched. A gate that only catches the careless spelling is not a gate.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SURFACE_PATH = ROOT / "protocol-family" / "afp-interface-surface-v1.json"
SPEC_PATH = ROOT / "docs" / "afp_specification.md"
MANIFEST_PATH = ROOT / "protocol-family" / "interface-manifest-v1.json"
LOCK_PATH = ROOT / "protocol-family" / "snapshot-lock.json"

SURFACE_FORMAT = "afp:interface-surface:v1"
INTERFACE_SET_DOMAIN = b"afp:interface-surface:v1"

SPEC_RELATIVE = "docs/afp_specification.md"
SURFACE_RELATIVE = "protocol-family/afp-interface-surface-v1.json"

# ADR-0013: the AFP specification is an ordered set of normative documents.
# `authority.specification_set` lists them, core first. Every other member is
# incorporated into the core by exactly one include block, which keeps the
# frozen section numbering and lets the website assemble the set in section
# order.
MEMBER_PATH = re.compile(r"^docs/[a-z0-9_]+\.md$")
INCLUDE_CLOSE = "<!-- afp-set:end -->"
INCLUDE_MARKER_LINE = re.compile(r"^<!-- afp-set:(?:include \S+|end) -->$", re.M)
CANONICAL_SET_HEADING = "## 11. Canonical Specification"

# The four snapshot-lock digest targets and the lock itself are byte-identical
# mirrors of the canonical ZKA protocol-family package. The operational-domain
# inventory is also a byte-identical ZKA mirror, but is bound separately by the
# manifest rather than by snapshot-lock. The surface file MUST NOT become one
# of them: an AFP-owned artifact that ZKA mirrors byte-for-byte could not move
# on an AFP interface change without breaking the whole-family snapshot audit.
MIRRORED_PATHS = frozenset(
    {
        "protocol-family/interface-manifest-v1.json",
        "protocol-family/interface-manifest-v1.schema.json",
        "protocol-family/golden-vectors-v1.json",
        "protocol-family/snapshot-lock.json",
        "scripts/validate_protocol_family.py",
        "protocol-family/poseidon2-operational-domains-v1.json",
    }
)

# --- the digest partition ---------------------------------------------------
#
# `interface_set_id` commits to the interface surface and to nothing else. The
# exclusion of prose is BY CONSTRUCTION, in three layers:
#
#   1. the preimage is a whitelist of SECTIONS, so a field of this file that is
#      not named here cannot enter the digest at all -- including the
#      `interface_version` label itself, `document_revision` and `family_epoch`;
#   2. each member is projected onto a fixed `digested` tuple, and any member
#      key that is in neither `digested` nor `annotation` fails the run, so a
#      newly added field cannot silently land on either side of the line
#      without an author choosing a side; and
#   3. `check_digest_construction` refuses to digest a field whose NAME is
#      prose-shaped, so the partition cannot be edited into uselessness later.
#
# If prose could ever leak into the digest input, the coupling this file exists
# to remove would simply reappear one layer down -- and be harder to see,
# because it would look like a cryptographic surface change.
PROSE_KEYS = frozenset(
    {
        "note",
        "notes",
        "description",
        "rationale",
        "summary",
        "purpose",
        "comment",
        "reason",
        "spec_reference",
    }
)
PROSE_KEY_SHAPE = re.compile(r"(^|_)(note|notes|summary|reason|row|reference|prose|text)$")

SECTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "message_classes": {
        "digested": ("id", "subject_subtree"),
        "annotation": ("note",),
    },
    "telemetry_predicates": {
        "digested": ("id", "status", "public_inputs_interface"),
        "annotation": ("note",),
    },
    "wire_records": {
        "digested": ("id",),
        "annotation": ("note",),
    },
    "profiles": {
        "digested": ("name", "status"),
        "annotation": ("note", "spec_reference"),
    },
}
COMPOSES_WITH_FIELDS = ("zka", "zkc", "kdc")
SCALAR_DIGESTED = ("envelope", "nats_subject_root")

# Every top-level key of the surface file, partitioned. `digest_input` names the
# sections that reach the digest; everything else is a label, a declaration
# about the family pin, or prose. An unclassified top-level key fails the run.
TOP_LEVEL_DIGESTED = frozenset(
    set(SECTIONS) | set(SCALAR_DIGESTED) | {"composes_with", "presentation_profiles"}
)
TOP_LEVEL_EXCLUDED = frozenset(
    {
        "format",
        "authority",
        "purpose",
        "interface_version",
        "interface_version_short",
        "superseded_interface_versions",
        "last_breaking_interface_version",
        "document_revision",
        "published",
        "family_epoch",
        "interface_set_id",
        "interface_set_id_derivation",
        "digest_scope",
        "document_axis",
        "version_discipline",
        "family_pin",
        "consumer_gate",
    }
)

LABEL_PIN_FORMS = ("spec_header_text_contains", "surface_field_json_pointer")

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class Failure(AssertionError):
    """One deterministic interface-surface conformance failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def canonical_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def project(entry: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: entry.get(field) for field in fields}


def interface_set_id(
    surface: dict[str, Any], sections: dict[str, dict[str, tuple[str, ...]]] | None = None
) -> str:
    """Re-derive the identity of the interface surface, prose excluded."""

    sections = SECTIONS if sections is None else sections
    preimage: dict[str, Any] = {
        name: [project(entry, spec["digested"]) for entry in surface.get(name, [])]
        for name, spec in sections.items()
    }
    for field in SCALAR_DIGESTED:
        preimage[field] = surface.get(field)
    preimage["presentation_profiles"] = surface.get("presentation_profiles", [])
    preimage["composes_with"] = project(
        surface.get("composes_with", {}), COMPOSES_WITH_FIELDS
    )
    digest = hashlib.sha256(
        INTERFACE_SET_DOMAIN + canonical_json(preimage).encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def parse_version(label: str) -> tuple[str, tuple[int, int, int, int]]:
    """Split a version label into its base string and comparable key.

    A family pin may legitimately carry a qualifier -- ZKM is pinned as
    `0.1.0-draft (rev 10)` -- so a trailing parenthetical is stripped before
    the base is parsed.

    The comparable key is `(major, minor, patch, release_rank)`, where a
    prerelease qualifier ranks *below* the corresponding release, per SemVer
    §11.3. This keeps the current `0.3.12-draft` label correctly ordered below
    `0.3.12` and lets the superseded-version and family-lag checks compare both
    forms without flattening the qualifier.
    """

    base = label.split(" (")[0].strip()
    match = _VERSION.match(base)
    require(match is not None, f"unparseable version label: {label!r}")
    assert match is not None
    release_rank = 0 if match.group(4) else 1
    return base, (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        release_rank,
    )


def spec_section(spec: str, start_heading: str, end_heading: str) -> str:
    start = spec.find(start_heading)
    require(start != -1, f"specification has no {start_heading!r} heading")
    end = spec.find(end_heading, start)
    require(end != -1, f"specification has no {end_heading!r} heading after {start_heading!r}")
    return spec[start:end]


def table_rows(section: str) -> list[list[str]]:
    """Parse a markdown table into rows of stripped cells, separators dropped."""

    rows: list[list[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if all(set(cell) <= set("-: ") and cell for cell in cells):
            continue
        rows.append(cells)
    return rows


def specification_set(surface: dict[str, Any]) -> list[Any]:
    """The declared normative set, core first, exactly as the surface lists it."""

    declared = surface.get("authority", {}).get("specification_set")
    return list(declared) if isinstance(declared, list) else []


def load_sources(surface: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load every source of truth the surface's claims are re-derived from."""

    if surface is None:
        surface = json.loads(SURFACE_PATH.read_bytes())
    members: dict[str, str] = {}
    for relative in specification_set(surface)[1:]:
        if isinstance(relative, str) and MEMBER_PATH.match(relative):
            path = ROOT / relative
            if path.is_file():
                members[relative] = path.read_text(encoding="utf-8")
    return {
        "spec": SPEC_PATH.read_text(encoding="utf-8"),
        "members": members,
        "manifest": json.loads(MANIFEST_PATH.read_bytes()),
        "lock": json.loads(LOCK_PATH.read_bytes()),
        "sections": copy.deepcopy(SECTIONS),
    }


def set_text(sources: dict[str, Any]) -> str:
    """The core followed by every other member: where a construct may live."""

    return "\n".join([sources["spec"], *sources.get("members", {}).values()])


INCLUDE_BLOCK = re.compile(
    r"^<!-- afp-set:include (\S+) -->\n(?P<stub>(?:.*\n)*?)<!-- afp-set:end -->\n(?:\n|\Z)",
    re.MULTILINE,
)


def member_body(relative: str, text: str) -> str:
    """A member's text after its front-matter rule and the blank lines after it."""

    lines = text.splitlines(keepends=True)
    stripped = [line.rstrip("\n") for line in lines]
    require("---" in stripped, f"{relative} has no front-matter rule")
    return "".join(lines[stripped.index("---") + 1 :]).lstrip("\n")


def assemble_set(core: str, members: dict[str, str]) -> str:
    """The core with each include block replaced by its member's body.

    Only standalone marker lines delimit blocks. Inline examples remain prose.
    """

    included: list[str] = []

    def substitute(match: re.Match[str]) -> str:
        relative = match.group(1)
        require(relative in members, f"the core includes {relative}, which is not in the set")
        require(
            INCLUDE_MARKER_LINE.search(match.group("stub")) is None,
            "an afp-set include block is malformed or nested",
        )
        text = members[relative]
        require(
            INCLUDE_MARKER_LINE.search(text) is None,
            f"{relative} carries an afp-set include marker; only the core may",
        )
        included.append(relative)
        return member_body(relative, text)

    assembled = INCLUDE_BLOCK.sub(substitute, core)
    require(
        INCLUDE_MARKER_LINE.search(assembled) is None,
        "an afp-set include block is malformed or nested",
    )
    for relative in members:
        require(
            included.count(relative) == 1,
            f"the core must include {relative} exactly once",
        )
    return assembled


def specification_text() -> str:
    """The assembled normative set at this checkout, for tests and tools."""

    sources = load_sources()
    return assemble_set(sources["spec"], sources["members"])


def front_matter(document: str) -> list[str]:
    lines = document.splitlines()
    require("---" in lines, "a specification document has no front-matter rule")
    return lines[: lines.index("---")]


def canonical_set_table(spec: str) -> list[str]:
    """The member paths that the core's section 11 table names, in order."""

    start = spec.find(CANONICAL_SET_HEADING)
    require(start != -1, f"specification has no {CANONICAL_SET_HEADING!r} heading")
    end = spec.find("\n## ", start + len(CANONICAL_SET_HEADING))
    section = spec[start : end if end != -1 else len(spec)]
    paths: list[str] = []
    for cells in table_rows(section):
        match = re.search(r"`(docs/[^`]+\.md)`", " | ".join(cells))
        if match is not None:
            paths.append(match.group(1))
    return paths or [SPEC_RELATIVE]


# --- checks -----------------------------------------------------------------


def check_shape(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    require(surface.get("format") == SURFACE_FORMAT, "wrong surface format")

    unclassified = set(surface) - TOP_LEVEL_DIGESTED - TOP_LEVEL_EXCLUDED
    require(
        not unclassified,
        "unclassified top-level field(s) "
        f"{sorted(unclassified)}: every field must be declared either part of "
        "the digested interface surface or outside it",
    )
    missing = (TOP_LEVEL_DIGESTED | TOP_LEVEL_EXCLUDED) - set(surface)
    require(not missing, f"surface is missing declared field(s) {sorted(missing)}")

    authority = surface["authority"]
    require(authority.get("protocol") == "afp", "surface is not AFP-owned")
    require(
        authority.get("repository") == "pyramidal-io/AFP.dev",
        "surface authority is not the AFP repository",
    )
    require(
        authority.get("mirrored_from_zka") is False,
        "the surface is AFP-owned and MUST NOT be declared a ZKA mirror",
    )
    for key in (
        "surface_path",
        "specification_path",
        "validator_path",
        "rollout_note_path",
    ):
        relative = authority.get(key)
        require(isinstance(relative, str) and relative, f"authority.{key} missing")
        require((ROOT / relative).is_file(), f"authority.{key} does not exist: {relative}")
    require(
        authority["surface_path"] not in MIRRORED_PATHS,
        "the surface MUST NOT be published at a ZKA-mirrored snapshot path",
    )
    require(
        SURFACE_PATH == ROOT / authority["surface_path"],
        "authority.surface_path does not name this file",
    )
    require(
        authority["specification_path"] == SPEC_RELATIVE,
        "authority.specification_path does not name the AFP specification",
    )

    base, triple = parse_version(surface["interface_version"])
    require(
        base == surface["interface_version"],
        "interface_version MUST be a bare version, with no revision qualifier: "
        "qualifiers belong to the document-revision axis",
    )
    require(
        surface["interface_version_short"] == "v" + base.split("-")[0],
        "interface_version_short is not the short form of interface_version",
    )
    require(_DATE.match(str(surface["published"])) is not None, "published is not a date")
    require(
        isinstance(surface["document_revision"], int)
        and surface["document_revision"] >= 1,
        "document_revision must be a positive integer",
    )
    require(
        _DIGEST.match(str(surface["interface_set_id"])) is not None,
        "interface_set_id is not a sha256:<64 hex> digest",
    )

    superseded = surface["superseded_interface_versions"]
    require(isinstance(superseded, list), "superseded_interface_versions must be a list")
    for label in superseded:
        older_base, older = parse_version(label)
        require(
            older < triple,
            f"superseded interface version {older_base} is not older than {base}",
        )
    breaking_base, breaking = parse_version(surface["last_breaking_interface_version"])
    require(
        breaking_base in published_versions(surface),
        f"last_breaking_interface_version {breaking_base} is not a published AFP interface version",
    )
    require(
        breaking <= triple,
        "last_breaking_interface_version is ahead of the published interface version",
    )


def check_specification_set(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """ADR-0013: the declared normative set, its section 11 table, and each member."""

    declared = specification_set(surface)
    require(
        declared and declared[0] == SPEC_RELATIVE,
        "authority.specification_set must list the core specification first",
    )
    require(
        len(set(map(str, declared))) == len(declared),
        "authority.specification_set lists a document twice",
    )
    for relative in declared[1:]:
        require(
            isinstance(relative, str) and MEMBER_PATH.match(relative) is not None,
            f"specification_set member {relative!r} is not a docs/<name>.md path",
        )
        require(
            relative in sources["members"],
            f"specification_set member {relative} does not exist",
        )
    require(
        sorted(sources["members"]) == sorted(declared[1:]),
        "the loaded specification members do not match authority.specification_set",
    )
    table = canonical_set_table(sources["spec"])
    require(
        table == declared,
        f"authority.specification_set {declared} does not match the section 11 "
        f"table {table}",
    )

    assemble_set(sources["spec"], sources["members"])

    interface_line = f"**Interface version:** {surface['interface_version']}"
    for relative, text in sources["members"].items():
        front = front_matter(text)
        require(
            not any(line.startswith("**Version:**") for line in front),
            f"{relative} carries a **Version:** line; only the core may",
        )
        revisions = [line for line in front if line.startswith("**Document revision:**")]
        require(
            len(revisions) == 1
            and re.match(
                r"^\*\*Document revision:\*\* (\d+) \((\d{4}-\d{2}-\d{2})\)$",
                revisions[0],
            )
            is not None,
            f"{relative} must carry exactly one **Document revision:** N (date) line",
        )
        if any(line.startswith("**KDC Version:**") for line in front):
            continue
        require(
            front.count(interface_line) == 1
            and sum(line.startswith("**Interface version:**") for line in front) == 1,
            f"{relative} must carry exactly one {interface_line!r} line",
        )


def published_versions(surface: dict[str, Any]) -> set[str]:
    return {surface["interface_version"], *surface["superseded_interface_versions"]}


def check_digest_construction(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """The digest partition itself, before anything is digested with it."""

    sections = sources["sections"]
    require(set(sections) == set(SECTIONS), "the digested section set has moved")
    for name, spec in sections.items():
        digested = tuple(spec["digested"])
        annotation = tuple(spec["annotation"])
        require(digested, f"{name}: the digested field tuple is empty")
        overlap = set(digested) & set(annotation)
        require(
            not overlap,
            f"{name}: field(s) {sorted(overlap)} are both digested and annotation",
        )
        for field in digested:
            require(
                field not in PROSE_KEYS and PROSE_KEY_SHAPE.search(field) is None,
                f"{name}: prose-shaped field {field!r} MUST NOT be part of the "
                "interface_set_id preimage -- prose is excluded by construction",
            )
        entries = surface.get(name)
        require(isinstance(entries, list) and entries, f"{name}: no entries")
        known = set(digested) | set(annotation)
        seen: set[str] = set()
        for entry in entries:
            require(isinstance(entry, dict), f"{name}: entry is not an object")
            unclassified = set(entry) - known
            require(
                not unclassified,
                f"{name}: entry {entry.get('id', entry.get('name'))} carries "
                f"unclassified field(s) {sorted(unclassified)} -- classify them as "
                "digested surface or as annotation before publishing",
            )
            absent = set(digested) - set(entry)
            require(
                not absent,
                f"{name}: entry {entry.get('id', entry.get('name'))} omits digested "
                f"field(s) {sorted(absent)}",
            )
            key = str(entry.get("id", entry.get("name")))
            require(key not in seen, f"{name}: duplicate entry {key}")
            seen.add(key)

    for field in SCALAR_DIGESTED:
        require(isinstance(surface.get(field), str) and surface[field], f"{field} missing")
    require(
        set(surface.get("composes_with", {})) == set(COMPOSES_WITH_FIELDS),
        "composes_with must carry exactly the projected sibling versions",
    )

    # `presentation_profiles` is the one digested section that enters the
    # preimage unprojected, so it needs its own construction guard: if an entry
    # were ever enriched into an object it would carry its annotation prose into
    # the digest input, which is the exact failure mode this file exists to
    # prevent. Bare identifiers, or nothing.
    profiles = surface.get("presentation_profiles")
    require(
        isinstance(profiles, list) and profiles,
        "presentation_profiles: no entries",
    )
    require(
        all(isinstance(profile, str) and profile for profile in profiles),
        "presentation_profiles entries MUST be bare identifier strings: the "
        "section enters the interface_set_id preimage unprojected, so an entry "
        "carrying an annotation field would put prose in the digest input. "
        "Promote it to a projected SECTIONS member before adding structure.",
    )
    require(
        len(set(profiles)) == len(profiles),
        "presentation_profiles: duplicate entry",
    )


def check_interface_set_id(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    recomputed = interface_set_id(surface, sources["sections"])
    require(
        recomputed == surface["interface_set_id"],
        f"interface_set_id is stale: declared {surface['interface_set_id']}, "
        f"recomputed {recomputed}",
    )


def check_family_agreement(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    manifest = sources["manifest"]
    lock = sources["lock"]

    require(
        surface["family_epoch"] == manifest["epoch"],
        "family_epoch does not match the vendored manifest epoch",
    )
    require(
        surface["family_epoch"] == lock["epoch"],
        "family_epoch does not match the vendored snapshot lock epoch",
    )
    require(
        surface["envelope"] == manifest["interfaces"]["afp_envelope"],
        "envelope does not match the manifest's declared AFP envelope interface",
    )
    require(
        sorted(surface["presentation_profiles"])
        == sorted(manifest["interfaces"]["presentation_profiles"]),
        "presentation_profiles do not match the manifest's declared profiles",
    )
    for protocol in COMPOSES_WITH_FIELDS:
        require(
            surface["composes_with"][protocol] == manifest["protocols"][protocol]["version"],
            f"composes_with.{protocol} does not match the manifest's pinned "
            f"{protocol} version",
        )


def check_spec_front_matter(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """The two axes, as the specification front matter actually carries them."""

    spec = sources["spec"]
    lines = spec.splitlines()
    try:
        end = lines.index("---")
    except ValueError:  # pragma: no cover - the spec always has a rule
        raise Failure("specification has no front-matter rule") from None
    front = lines[:end]

    version_line = f"**Version:** {surface['interface_version']}"
    require(
        front.count(version_line) == 1,
        f"specification front matter must carry exactly one {version_line!r} line: "
        "the vendored family manifest asserts that exact string, so the "
        "document-revision split MUST be additive",
    )
    interface_line = f"**Interface version:** {surface['interface_version']}"
    require(
        front.count(interface_line) == 1,
        f"specification front matter must carry exactly one {interface_line!r} line",
    )

    revisions = [line for line in front if line.startswith("**Document revision:**")]
    require(
        len(revisions) == 1,
        "specification front matter must carry exactly one **Document revision:** line",
    )
    match = re.match(
        r"^\*\*Document revision:\*\* (\d+) \((\d{4}-\d{2}-\d{2})\)$",
        revisions[0],
    )
    require(match is not None, f"unparseable document-revision line: {revisions[0]!r}")
    assert match is not None
    require(
        int(match.group(1)) == surface["document_revision"],
        f"document_revision {surface['document_revision']} does not match the "
        f"specification front matter ({match.group(1)})",
    )
    require(
        match.group(2) == surface["published"],
        f"published date {surface['published']} does not match the document-revision "
        f"date ({match.group(2)})",
    )
    date_line = f"**Date:** {surface['published']}"
    require(
        front.count(date_line) == 1,
        f"specification front matter must carry exactly one {date_line!r} line",
    )
    require(
        surface["interface_version"] not in revisions[0],
        "the document-revision line MUST NOT restate the interface version: the "
        "two axes are separate or they are not split at all",
    )


def check_version_stamps(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """The exact current interface version in its pinned prose locations."""

    spec = set_text(sources)
    interface_version = surface["interface_version"]

    layering = spec_section(sources["spec"], "### 2.2 Layering", "### 2.3 Transport")
    stamps = [
        line for line in layering.splitlines() if f"AFP {interface_version}" in line
    ]
    require(
        len(stamps) == 1,
        f"section 2.2 layering diagram must stamp {interface_version!r} exactly once "
        f"(found {len(stamps)})",
    )

    appendix = [
        line
        for line in spec.splitlines()
        if line.startswith("**Referenced normatively by:**")
    ]
    require(len(appendix) == 1, "Appendix A has no single back-reference line")
    require(
        f"AFP {interface_version} " in appendix[0],
        f"Appendix A back-reference does not cite AFP {interface_version}",
    )
    require(
        f"AFP-KDC v{surface['composes_with']['kdc']}" in spec,
        "the specification does not cite the composed AFP-KDC version",
    )
    require(
        f"**KDC Version:** {surface['composes_with']['kdc']}" in spec,
        "Appendix A does not carry the composed AFP-KDC version line",
    )


def check_message_classes(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    section = spec_section(
        sources["spec"], "### 5.3 Message classes", "### 5.4 Work artifacts"
    )
    declared = [entry["id"] for entry in surface["message_classes"]]
    observed: list[str] = []
    for cells in table_rows(section):
        if cells[0] == "Class":
            continue
        observed.extend(re.findall(r"`(afp\.[A-Za-z0-9_.]+)`", cells[0]))
    require(
        sorted(declared) == sorted(observed),
        "declared message classes do not match the section 5.3 table: "
        f"declared {sorted(declared)}, specified {sorted(observed)}",
    )
    for entry in surface["message_classes"]:
        expected = (
            "afp.{tenant}.session"
            if entry["id"].startswith("afp.session.")
            else "afp.{tenant}.work"
        )
        require(
            entry["subject_subtree"] == expected,
            f"{entry['id']}: subject_subtree {entry['subject_subtree']!r} is not the "
            f"section 12.4 subtree {expected!r}",
        )
    for subtree in ("afp.{tenant}.session", "afp.{tenant}.work"):
        require(
            f"`{subtree}.*`" in section,
            f"section 5.3 does not address its classes under `{subtree}.*`",
        )
    require(
        f"`{surface['nats_subject_root']}.*`" in set_text(sources),
        "the specification does not carry the declared NATS subject root",
    )


def check_telemetry_predicates(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    spec = set_text(sources)
    declared = [entry["id"] for entry in surface["telemetry_predicates"]]
    observed = list(
        dict.fromkeys(
            re.findall(r"^\| `(afp\.telemetry\.[a-z_]+\.v\d+)` \|", spec, flags=re.M)
        )
    )
    require(
        sorted(declared) == sorted(observed),
        "declared telemetry predicates do not match the section 6.3 catalog: "
        f"declared {sorted(declared)}, specified {sorted(observed)}",
    )
    for entry in surface["telemetry_predicates"]:
        require(
            entry["status"] in {"frozen", "current"},
            f"{entry['id']}: unknown status {entry['status']!r}",
        )
        if entry["status"] == "frozen":
            require(
                f"`{entry['id']}` is frozen" in spec,
                f"{entry['id']} is declared frozen but the specification does not "
                "freeze it",
            )
        else:
            require(
                f"`{entry['id']}` is frozen" not in spec,
                f"{entry['id']} is declared current but the specification freezes it",
            )
        interface = entry["public_inputs_interface"]
        if interface is not None:
            require(
                f"interface {interface} {{" in spec,
                f"{entry['id']}: public-input interface {interface} is not declared "
                "in the specification",
            )


def check_wire_records(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    spec = set_text(sources)
    declared = [entry["id"] for entry in surface["wire_records"]]
    observed = list(dict.fromkeys(re.findall(r"kind: '(afp:[^']+)'", spec)))
    require(
        sorted(declared) == sorted(observed),
        "declared wire records do not match the specification's typed `kind:` "
        f"declarations: declared {sorted(declared)}, specified {sorted(observed)}",
    )
    require(
        surface["envelope"] in declared,
        "the session envelope is not among the declared wire records",
    )


def check_profiles(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    section = spec_section(
        sources["spec"], "### 13.3 Published profiles", "### 13.4 Profile conformance"
    )
    observed: dict[str, str] = {}
    for cells in table_rows(section):
        if cells[0].startswith("Profile"):
            continue
        match = re.search(r"`([A-Za-z0-9_.]+)`", cells[0])
        require(match is not None, f"unparseable section 13.3 profile row: {cells[0]!r}")
        assert match is not None
        observed[match.group(1)] = cells[-1]
    declared = {entry["name"]: entry["status"] for entry in surface["profiles"]}
    require(
        declared == observed,
        "declared profiles do not match the section 13.3 table: "
        f"declared {declared}, specified {observed}",
    )


def check_composition(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """The fragile prose target sentence, derived rather than transcribed."""

    spec = sources["spec"]
    composes = surface["composes_with"]
    sentence = (
        f"This specification targets **ZKA v{composes['zka']}**, "
        f"**ZKC v{composes['zkc']}**, and **AFP-KDC v{composes['kdc']}**."
    )
    require(
        sentence in spec,
        "the specification's composition sentence does not match composes_with: "
        f"expected {sentence!r}",
    )
    everywhere = set_text(sources)
    for profile in surface["presentation_profiles"]:
        require(
            f"`{profile}`" in everywhere,
            f"the specification does not carry presentation profile {profile}",
        )
    require(
        f"`{surface['envelope']}`" in everywhere,
        "the specification does not carry the declared session envelope identifier",
    )


def afp_assertions(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return list(manifest["projections"]["afp"]["assertions"])


def check_document_axis_is_unpinned(
    surface: dict[str, Any], sources: dict[str, Any]
) -> None:
    """The negative guard: nothing in the family may touch the prose axis."""

    manifest = sources["manifest"]
    axis = surface["document_axis"]
    require(
        axis["field"] == "**Document revision:**",
        "document_axis.field does not name the specification's revision line",
    )
    offenders = [
        assertion["id"]
        for assertion in afp_assertions(manifest)
        if isinstance(assertion.get("expected"), str)
        and (
            "Document revision" in assertion["expected"]
            or "document_revision" in str(assertion.get("pointer", ""))
        )
    ]
    require(
        not offenders,
        f"family manifest assertion(s) {offenders} reference AFP's document-revision "
        "axis. Re-coupling the editorial axis to the family manifest reintroduces the "
        "exact friction the surface file removes: a prose edit would again force a "
        "family epoch action.",
    )
    require(
        axis["pinned_by_family"] is False,
        "document_axis.pinned_by_family MUST be false: the document revision is "
        "never a protocol-family pin",
    )

    # Neither the surface file nor the specification may be family-pinned by
    # whole-file digest: prose edits would otherwise force a non-protocol
    # family-epoch action.
    UNPINNABLE_FILES = {
        SURFACE_RELATIVE: (
            "Pin /interface_set_id instead: the file digest moves on prose edits "
            "and trains reviewers to re-bless a digest that moved for "
            "non-protocol reasons."
        ),
        SPEC_RELATIVE: (
            "The specification carries the document-revision axis, so a "
            "whole-file digest on it makes every prose edit a family epoch "
            "action. Pin /interface_version and /interface_set_id of "
            f"{SURFACE_RELATIVE} instead."
        ),
    }
    for relative in specification_set(surface)[1:]:
        UNPINNABLE_FILES[str(relative)] = (
            "Every member of the normative set carries its own document-revision "
            "axis, so a whole-file digest on it makes every prose edit a family "
            "epoch action."
        )
    for relative, rationale in UNPINNABLE_FILES.items():
        file_pins = [
            assertion["id"]
            for projection in manifest["projections"].values()
            for assertion in projection["assertions"]
            if assertion.get("path") == relative
            and assertion.get("kind") == "sha256_equals"
        ]
        require(
            not file_pins,
            f"family manifest assertion(s) {file_pins} pin the FILE digest of "
            f"{relative}. {rationale}",
        )
        bound = [
            binding["id"]
            for binding in manifest["artifact_bindings"]
            if binding.get("path") == relative
        ]
        require(
            not bound,
            f"artifact_bindings entr(ies) {bound} pin the file digest of "
            f"{relative}. {rationale}",
        )


def check_family_pin(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """The bidirectional binding between AFP's surface and the family's pin."""

    manifest = sources["manifest"]
    assertions = afp_assertions(manifest)
    pin = surface["family_pin"]

    declared_version = pin["declared_version"]
    require(
        declared_version == manifest["protocols"]["afp"]["version"],
        f"family_pin.declared_version {declared_version!r} is not the manifest's "
        f"pinned AFP version {manifest['protocols']['afp']['version']!r}",
    )
    pinned_base, pinned = parse_version(declared_version)
    require(
        pinned_base in published_versions(surface),
        f"the family pins interface version {pinned_base}, which AFP has not published",
    )
    _, current = parse_version(surface["interface_version"])
    _, breaking = parse_version(surface["last_breaking_interface_version"])
    require(
        pinned >= breaking,
        f"the family pins {pinned_base}, which lags AFP's last breaking interface "
        f"version {surface['last_breaking_interface_version']}: a breaking AFP "
        "interface change MUST NOT be silently combined with an older epoch",
    )
    require(
        pinned <= current,
        f"the family pins {pinned_base}, which is ahead of AFP's published interface "
        f"version {surface['interface_version']}",
    )

    label = pin["interface_version_label"]
    require(label["pinned"] is True, "the family MUST pin AFP's interface version")
    require(
        label["form"] in LABEL_PIN_FORMS,
        f"unknown interface-version pin form {label['form']!r}",
    )
    header_form = [
        assertion["id"]
        for assertion in assertions
        if assertion.get("kind") == "text_contains"
        and assertion.get("path") == SPEC_RELATIVE
        and assertion.get("expected") == f"**Version:** {surface['interface_version']}"
    ]
    pointer_form = [
        assertion["id"]
        for assertion in assertions
        if assertion.get("kind") == "json_pointer_equals"
        and assertion.get("path") == SURFACE_RELATIVE
        and assertion.get("pointer") == "/interface_version"
        and assertion.get("expected") == surface["interface_version"]
    ]
    observed_forms = {
        "spec_header_text_contains": header_form,
        "surface_field_json_pointer": pointer_form,
    }
    matching = observed_forms[label["form"]]
    require(
        len(matching) == 1,
        f"the manifest carries {len(matching)} assertion(s) of the declared "
        f"interface-version pin form {label['form']!r}; expected exactly one",
    )
    require(
        label["pinned_by"] == f"assertion:{matching[0]}",
        f"family_pin.interface_version_label.pinned_by does not name the assertion "
        f"that pins it (assertion:{matching[0]})",
    )

    digest = pin["interface_digest"]
    require(
        digest["pin"]["kind"] == "json_pointer_equals"
        and digest["pin"]["path"] == SURFACE_RELATIVE
        and digest["pin"]["pointer"] == "/interface_set_id",
        "family_pin.interface_digest.pin MUST describe a json_pointer_equals on "
        "/interface_set_id -- the field, never the file",
    )
    observed_digest = [
        assertion
        for assertion in assertions
        if assertion.get("kind") == "json_pointer_equals"
        and assertion.get("path") == SURFACE_RELATIVE
        and assertion.get("pointer") == "/interface_set_id"
    ]
    if digest["pinned"] is True:
        require(
            len(observed_digest) == 1,
            "family_pin.interface_digest declares the surface digest pinned, but the "
            "vendored manifest carries no /interface_set_id assertion",
        )
        require(
            observed_digest[0]["expected"] == surface["interface_set_id"],
            "the family pins a stale interface_set_id: "
            f"{observed_digest[0]['expected']} vs {surface['interface_set_id']}",
        )
        require(
            digest["pinned_by"] == f"assertion:{observed_digest[0]['id']}",
            "family_pin.interface_digest.pinned_by does not name the pinning assertion",
        )
    else:
        require(
            not observed_digest,
            "the vendored manifest pins /interface_set_id but the surface still "
            "declares it unpinned; flip family_pin.interface_digest.pinned in the "
            "same commit that vendors the manifest",
        )
        require(
            digest["pinned_by"] is None,
            "family_pin.interface_digest.pinned_by must be null while unpinned",
        )



CHECKS = (
    check_shape,
    check_specification_set,
    check_digest_construction,
    check_interface_set_id,
    check_family_agreement,
    check_spec_front_matter,
    check_version_stamps,
    check_message_classes,
    check_telemetry_predicates,
    check_wire_records,
    check_profiles,
    check_composition,
    check_document_axis_is_unpinned,
    check_family_pin,
)


def run_checks(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    for check in CHECKS:
        check(surface, sources)


# --- self-test --------------------------------------------------------------


def _reseal(surface: dict[str, Any]) -> None:
    """Re-derive the digest after a mutation, as a diligent-but-wrong editor would.

    A resealed mutation defeats the recomputation check by construction, so it
    can only be caught by the check that re-derives that specific claim from the
    specification. Every surface mutation is therefore tested resealed.
    """

    surface["interface_set_id"] = interface_set_id(surface)


def _prose_fields(surface: dict[str, Any]) -> int:
    """Rewrite every free-text field in place; return how many were rewritten."""

    rewritable = PROSE_KEYS
    rewritten = 0

    def walk(node: Any) -> None:
        nonlocal rewritten
        if isinstance(node, dict):
            for key, value in node.items():
                if key in rewritable and isinstance(value, str):
                    node[key] = "Editorially rewritten during the self-test."
                    rewritten += 1
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(surface)
    return rewritten


def _adopt_surface_label_pin(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Phase 2: ZKA re-points the version pin off the specification header."""

    manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
    assertions = manifest["projections"]["afp"]["assertions"]
    for index, assertion in enumerate(assertions):
        if assertion.get("expected") == f"**Version:** {surface['interface_version']}":
            assertions[index] = {
                "id": "afp-interface-version",
                "kind": "json_pointer_equals",
                "path": SURFACE_RELATIVE,
                "pointer": "/interface_version",
                "expected": surface["interface_version"],
            }
    surface["family_pin"]["interface_version_label"].update(
        {"form": "surface_field_json_pointer", "pinned_by": "assertion:afp-interface-version"}
    )


def _adopt_digest_pin(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Phase 2: ZKA additionally pins /interface_set_id, declared on both sides."""

    manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
    assertions = manifest["projections"]["afp"]["assertions"]
    if not any(
        assertion.get("kind") == "json_pointer_equals"
        and assertion.get("path") == SURFACE_RELATIVE
        and assertion.get("pointer") == "/interface_set_id"
        for assertion in assertions
    ):
        assertions.append(
            {
                "id": "afp-interface-set-id",
                "kind": "json_pointer_equals",
                "path": SURFACE_RELATIVE,
                "pointer": "/interface_set_id",
                "expected": surface["interface_set_id"],
            }
        )
    surface["family_pin"]["interface_digest"].update(
        {"pinned": True, "pinned_by": "assertion:afp-interface-set-id", "form": "surface_field_json_pointer"}
    )


def _promote_draft_to_final(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Dropping the `-draft` qualifier MUST NOT need a numeric bump.

    This exercises the prerelease ordering in `parse_version`: a flattened
    triple would make `0.3.12-draft` neither older than nor different from
    `0.3.12`, so `check_shape` would reject the superseded label.
    """

    draft = surface["interface_version"]
    final = draft.split("-")[0]
    revision = surface["document_revision"] + 1
    old_published = surface["published"]
    new_published = "2026-09-01"

    surface["interface_version"] = final
    surface["superseded_interface_versions"] = [
        *surface["superseded_interface_versions"],
        draft,
    ]
    surface["last_breaking_interface_version"] = final
    surface["document_revision"] = revision
    surface["published"] = new_published
    surface["family_pin"]["declared_version"] = final

    sources["spec"] = (
        sources["spec"]
        .replace(f"**Version:** {draft}", f"**Version:** {final}")
        .replace(f"**Interface version:** {draft}", f"**Interface version:** {final}")
        .replace(
            f"**Document revision:** {revision - 1} ({old_published})",
            f"**Document revision:** {revision} ({new_published})",
        )
        .replace(f"**Date:** {old_published}", f"**Date:** {new_published}")
        .replace(f"AFP {draft}", f"AFP {final}")
    )
    # Every member restates the interface version it requires, and the KDC
    # member's back-reference cites it: an interface release moves them all.
    sources["members"] = {
        relative: text.replace(
            f"**Interface version:** {draft}", f"**Interface version:** {final}"
        ).replace(f"AFP {draft}", f"AFP {final}")
        for relative, text in sources["members"].items()
    }

    manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
    manifest["protocols"]["afp"]["version"] = final
    for assertion in manifest["projections"]["afp"]["assertions"]:
        if assertion.get("expected") == f"**Version:** {draft}":
            assertion["expected"] = f"**Version:** {final}"


SELFTEST_MEMBER = "docs/afp_selftest_member.md"

# ADR-0013 section 1: (member, first heading of the range, heading after the
# range, whether the member is AFP-KDC). Listed last range first.
ADR_0013_RANGES: tuple[tuple[str, str, str, bool], ...] = (
    ("docs/kdc_specification.md", "## Appendix A: Key Derivation Core", "## License", True),
    ("docs/afp_pay_profile.md", "## 15. ", "## Appendix A", False),
    ("docs/afp_introduction_profile.md", "## 14. ", "## 15. ", False),
    ("docs/afp_routing_specification.md", "### 8.3 ", "### 8.9 ", False),
)


def _include_spans(spec: str) -> list[tuple[int, int]]:
    return [(match.start(), match.end()) for match in INCLUDE_BLOCK.finditer(spec)]


def _outside_includes(spec: str, needle: str, start: int = 0) -> int:
    """The first `needle` at or after `start` that no include block holds, or -1."""

    spans = _include_spans(spec)
    index = spec.find(needle, start)
    while index != -1 and any(low <= index < high for low, high in spans):
        index = spec.find(needle, index + 1)
    return index


def _range_end(spec: str, needle: str, start: int) -> int:
    """Where a moved range ends: at `needle`, or at the stub block that holds it."""

    candidates = [
        low for low, high in _include_spans(spec) if low >= start and needle in spec[low:high]
    ]
    direct = _outside_includes(spec, needle, start)
    if direct != -1:
        candidates.append(direct)
    require(bool(candidates), f"self-test: no {needle!r} after the moved range")
    return min(candidates)


def _append_set_row(spec: str, relative: str) -> str:
    """Add `relative` as the last row of the section 11 table, creating it if absent."""

    start = spec.index(CANONICAL_SET_HEADING)
    section_end = spec.index("\n## ", start + len(CANONICAL_SET_HEADING))
    row = f"| Member | `{relative}` | that range |\n"
    has_table = any(
        re.search(r"`docs/[^`]+\.md`", " | ".join(cells))
        for cells in table_rows(spec[start:section_end])
    )
    if not has_table:
        row = (
            "| Document | Path | Normative for |\n|---|---|---|\n"
            f"| AFP Specification | `{SPEC_RELATIVE}` | the core |\n" + row
        )
    return spec[:section_end] + "\n\n" + row + spec[section_end:]


def _add_set_table_rows(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Give every declared member that the section 11 table lacks its row."""

    for relative in specification_set(surface)[1:]:
        if relative not in canonical_set_table(sources["spec"]):
            sources["spec"] = _append_set_row(sources["spec"], relative)


def move_into_member(
    surface: dict[str, Any],
    sources: dict[str, Any],
    relative: str,
    start_heading: str,
    end_heading: str,
    *,
    kdc: bool = False,
    table: bool = True,
) -> bool:
    """Move one core range verbatim into a new member, as an ADR-0013 stage does.

    The core keeps a stub block that names the member and, for a top-level
    range, repeats its heading. With `table`, the section 11 table gains a
    row. Returns False when the range is no longer in the core.
    """

    spec = sources["spec"]
    begin = _outside_includes(spec, start_heading)
    if begin == -1:
        return False
    end = _range_end(spec, end_heading, begin)
    body = spec[begin:end]
    first_line = body.split("\n", 1)[0]
    heading = f"{first_line}\n\n" if first_line.startswith("## ") else ""
    stub = (
        f"<!-- afp-set:include {relative} -->\n{heading}"
        f"This section is specified in `{relative}`.\n{INCLUDE_CLOSE}\n\n"
    )
    spec = spec[:begin] + stub + spec[end:]

    if table:
        spec = _append_set_row(spec, relative)

    version = (
        f"**KDC Version:** {surface['composes_with']['kdc']}"
        if kdc
        else f"**Interface version:** {surface['interface_version']}"
    )
    sources["spec"] = spec
    sources["members"] = {
        **sources["members"],
        relative: (
            f"# {first_line.lstrip('#').strip()}\n\n{version}\n"
            f"**Document revision:** 1 ({surface['published']})\n\n---\n\n" + body
        ),
    }
    surface["authority"]["specification_set"] = [*specification_set(surface), relative]
    return True


def split_adr_0013(
    surface: dict[str, Any],
    sources: dict[str, Any],
    *,
    ranges: tuple[tuple[str, str, str, bool], ...] = ADR_0013_RANGES,
    table: bool = True,
) -> list[str]:
    """Move every ADR-0013 range that is still in the core into its member.

    Ranges already moved by a real stage are left alone, so this yields the
    ADR-0013 end state from any checkout.
    """

    return [
        relative
        for relative, start, end, kdc in ranges
        if relative not in sources["members"]
        and move_into_member(surface, sources, relative, start, end, kdc=kdc, table=table)
    ]


def _split_out_member(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Move section 12.6 verbatim into a fixture member.

    Section 12.6 stays in the core under ADR-0013, so this fixture remains a
    valid shape after every real stage. It carries typed `kind:` declarations,
    so the move proves that records are found across the set.
    """

    require(
        move_into_member(surface, sources, SELFTEST_MEMBER, "### 12.6 ", "### 12.7 "),
        "self-test: section 12.6 is no longer in the core",
    )


def _accepted_variants() -> list[tuple[str, Any]]:
    """States that MUST keep passing: prose churn, and the Phase 2-5 end state."""

    def prose_rewritten(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        before = surface["interface_set_id"]
        rewritten = _prose_fields(surface)
        require(rewritten >= 20, f"self-test rewrote only {rewritten} prose fields")
        require(
            interface_set_id(surface) == before,
            "prose leaked into the interface_set_id preimage: an editorial edit moved "
            "the digest, which is precisely the coupling this file removes",
        )

    def spec_prose_added(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = sources["spec"] + (
            "\n\nAn additional clarifying sentence, published without any wire change.\n"
        )

    def document_revision_advanced(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        """The whole point: a prose revision moves alone."""

        before = surface["interface_set_id"]
        old_revision = surface["document_revision"]
        old_published = surface["published"]
        new_revision = old_revision + 1
        new_published = "2026-09-01"
        surface["document_revision"] = new_revision
        surface["published"] = new_published
        sources["spec"] = (
            sources["spec"]
            .replace(
                f"**Document revision:** {old_revision} ({old_published})",
                f"**Document revision:** {new_revision} ({new_published})",
            )
            .replace(f"**Date:** {old_published}", f"**Date:** {new_published}")
        )
        require(
            interface_set_id(surface) == before,
            "a document-revision-only change moved interface_set_id",
        )

    def split_out_member(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        before = surface["interface_set_id"]
        _split_out_member(surface, sources)
        require(
            interface_set_id(surface) == before,
            "moving specification text into a member moved interface_set_id",
        )

    def full_split(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        before = assemble_set(sources["spec"], sources["members"])
        split_adr_0013(surface, sources, table=False)
        require(
            assemble_set(sources["spec"], sources["members"]) == before,
            "the ADR-0013 split did not assemble to the same text",
        )
        _add_set_table_rows(surface, sources)

    return [
        ("prose fields rewritten throughout the surface", prose_rewritten),
        ("a sentence added to the specification", spec_prose_added),
        ("a prose-only document revision published", document_revision_advanced),
        ("the draft qualifier dropped without a numeric bump", _promote_draft_to_final),
        ("phase 2: the version pin moves to the surface field", _adopt_surface_label_pin),
        ("phase 2: the family pins /interface_set_id", _adopt_digest_pin),
        ("ADR-0013: a section moves verbatim into a second member", split_out_member),
        ("ADR-0013: the full document set", full_split),
    ]


def _mutations() -> list[tuple[str, Any]]:
    """Drift that MUST fail closed, in both the careless and resealed spellings."""

    def rename_message_class(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["message_classes"][0]["id"] = "afp.session.begin"

    def rename_message_class_resealed(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        rename_message_class(surface, sources)
        _reseal(surface)

    def drop_wire_record(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["wire_records"] = surface["wire_records"][:-1]
        _reseal(surface)

    def invent_wire_record(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["wire_records"].append({"id": "afp:invented:v1", "note": "not specified"})
        _reseal(surface)

    def unfreeze_v1(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        for entry in surface["telemetry_predicates"]:
            if entry["status"] == "frozen":
                entry["status"] = "current"
        _reseal(surface)

    def promote_experimental_profile(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        for entry in surface["profiles"]:
            if entry["status"] == "experimental":
                entry["status"] = "reference"
        _reseal(surface)

    def move_composed_version(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["composes_with"]["zkc"] = "0.5.0-draft"
        _reseal(surface)

    def move_envelope(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["envelope"] = "afp:envelope:v2"
        _reseal(surface)

    def move_subtree(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["message_classes"][-1]["subject_subtree"] = "afp.{tenant}.session"
        _reseal(surface)

    def move_interface_version(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        major, minor, patch, _ = parse_version(surface["interface_version"])[1]
        surface["interface_version"] = f"{major}.{minor}.{patch + 1}-draft"
        surface["interface_version_short"] = f"v{major}.{minor}.{patch + 1}"

    def move_short_form(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["interface_version_short"] = "v0.4.0"

    def qualify_interface_version(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["interface_version"] = f"{surface['interface_version']} (editorial note)"

    def move_document_revision(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["document_revision"] = surface["document_revision"] + 1

    def move_document_publication_date(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        surface["published"] = "2026-09-01"

    def drop_version_header(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = sources["spec"].replace(
            f"**Version:** {surface['interface_version']}\n",
            f"**Version:** {surface['interface_version']} (editorial note)\n",
            1,
        )

    def drop_document_revision_line(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        lines = sources["spec"].splitlines(keepends=True)
        sources["spec"] = "".join(
            line for line in lines if not line.startswith("**Document revision:**")
        )

    def pin_the_document_revision(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["projections"]["afp"]["assertions"].append(
            {
                "id": "afp-spec-document-revision",
                "kind": "text_contains",
                "path": SPEC_RELATIVE,
                "expected": f"**Document revision:** {surface['document_revision']}",
            }
        )

    def pin_the_surface_file(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["projections"]["afp"]["assertions"].append(
            {
                "id": "afp-interface-surface-digest",
                "kind": "sha256_equals",
                "path": SURFACE_RELATIVE,
                "expected": "sha256:" + "0" * 64,
            }
        )

    def bind_the_surface_file(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["artifact_bindings"].append(
            {
                "id": "afp-interface-surface",
                "repository": "afp",
                "path": SURFACE_RELATIVE,
                "sha256": "sha256:" + "0" * 64,
            }
        )

    def pin_the_specification_file(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        """The prose axis lives in the spec; a file digest on it re-couples it."""

        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["projections"]["afp"]["assertions"].append(
            {
                "id": "afp-spec-digest",
                "kind": "sha256_equals",
                "path": SPEC_RELATIVE,
                "expected": "sha256:" + "0" * 64,
            }
        )

    def bind_the_specification_file(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["artifact_bindings"].append(
            {
                "id": "afp-specification",
                "repository": "afp",
                "path": SPEC_RELATIVE,
                "sha256": "sha256:" + "0" * 64,
            }
        )

    def enrich_presentation_profiles(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        """The unprojected section: structure here would drag prose into the digest."""

        surface["presentation_profiles"] = [
            {"id": profile, "note": "An editorial annotation."}
            for profile in surface["presentation_profiles"]
        ]
        _reseal(surface)

    def remove_the_declared_digest_pin(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        manifest = sources["manifest"] = copy.deepcopy(sources["manifest"])
        manifest["projections"]["afp"]["assertions"] = [
            assertion
            for assertion in manifest["projections"]["afp"]["assertions"]
            if not (
                assertion.get("kind") == "json_pointer_equals"
                and assertion.get("path") == SURFACE_RELATIVE
                and assertion.get("pointer") == "/interface_set_id"
            )
        ]

    def family_lags_a_breaking_change(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        """AFP moved its surface; the family epoch never followed."""

        old_version = surface["interface_version"]
        major, minor, _, _ = parse_version(old_version)[1]
        next_version = f"{major}.{minor + 1}.0-draft"
        surface["interface_version"] = next_version
        surface["interface_version_short"] = f"v{major}.{minor + 1}.0"
        surface["last_breaking_interface_version"] = next_version
        surface["superseded_interface_versions"] = [
            *surface["superseded_interface_versions"], old_version,
        ]
        sources["spec"] = (
            sources["spec"]
            .replace(f"**Version:** {old_version}", f"**Version:** {next_version}")
            .replace(f"**Interface version:** {old_version}", f"**Interface version:** {next_version}")
            .replace(f"AFP {old_version}", f"AFP {next_version}")
        )

    def move_family_epoch(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["family_epoch"] = "zka:protocol-family:2026-09-01.1"

    def unclassified_field(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["message_classes"][0]["stability"] = "stable"
        _reseal(surface)

    def unclassified_top_level_field(
        surface: dict[str, Any], sources: dict[str, Any]
    ) -> None:
        surface["wire_format_notes"] = "unclassified"

    def digest_a_prose_field(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        """The construction guard: prose may never be added to the preimage."""

        sources["sections"]["message_classes"]["digested"] = ("id", "subject_subtree", "note")
        sources["sections"]["message_classes"]["annotation"] = ()

    def move_diagram_stamp(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        current = surface["interface_version"]
        major, minor, patch, _ = parse_version(current)[1]
        sources["spec"] = sources["spec"].replace(
            f"|                AFP {current}", f"|                AFP {major}.{minor}.{patch + 1}-draft"
        )
    return [
        ("a message class renamed", rename_message_class),
        ("a message class renamed and resealed", rename_message_class_resealed),
        ("a specified wire record dropped", drop_wire_record),
        ("an unspecified wire record invented", invent_wire_record),
        ("the frozen v1 predicate unfrozen", unfreeze_v1),
        ("an experimental profile promoted", promote_experimental_profile),
        ("a composed sibling version moved", move_composed_version),
        ("the session envelope revised", move_envelope),
        ("a message class moved between subject subtrees", move_subtree),
        ("the interface version moved without the specification", move_interface_version),
        ("the short version form desynchronized", move_short_form),
        ("a document-revision qualifier smuggled into the interface version", qualify_interface_version),
        ("the document revision moved without the specification", move_document_revision),
        ("the document publication date moved without the specification", move_document_publication_date),
        ("the specification header string mutated", drop_version_header),
        ("the document-revision line removed", drop_document_revision_line),
        ("the family manifest pins the document revision", pin_the_document_revision),
        ("the family manifest pins the surface file digest", pin_the_surface_file),
        ("artifact_bindings pins the surface file digest", bind_the_surface_file),
        ("the family manifest pins the specification file digest", pin_the_specification_file),
        ("artifact_bindings pins the specification file digest", bind_the_specification_file),
        ("presentation_profiles enriched with prose", enrich_presentation_profiles),
        ("the manifest digest pin removed while the surface still claims it", remove_the_declared_digest_pin),
        ("the family pin lags a breaking interface change", family_lags_a_breaking_change),
        ("the family epoch drifted from the vendored manifest", move_family_epoch),
        ("an unclassified field added to a digested member", unclassified_field),
        ("an unclassified top-level field added", unclassified_top_level_field),
        ("a prose field added to the digest preimage", digest_a_prose_field),
        ("the section 2.2 diagram stamp moved", move_diagram_stamp),
        *_set_mutations(),
    ]


def _set_mutations() -> list[tuple[str, Any]]:
    """ADR-0013 set drift, each applied to a valid two-member set."""

    member = SELFTEST_MEMBER

    def split_then(edit: Any) -> Any:
        def mutate(surface: dict[str, Any], sources: dict[str, Any]) -> None:
            _split_out_member(surface, sources)
            edit(surface, sources)

        return mutate

    def edit_member(old: str, new: str) -> Any:
        def edit(surface: dict[str, Any], sources: dict[str, Any]) -> None:
            text = sources["members"][member]
            require(old in text, f"self-test: {old!r} not in the fixture member")
            sources["members"][member] = text.replace(old, new, 1)

        return edit

    def not_included(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = (
            sources["spec"]
            .replace(f"<!-- afp-set:include {member} -->\n", "")
            .replace(f"{INCLUDE_CLOSE}\n", "", 1)
        )

    def unlisted_include(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = sources["spec"].replace(
            f"<!-- afp-set:include {member} -->", "<!-- afp-set:include docs/afp_other.md -->"
        )

    def unclosed_include(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = sources["spec"].replace(f"{INCLUDE_CLOSE}\n", "", 1)

    def member_missing(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        del sources["members"][member]

    def core_not_first(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["authority"]["specification_set"].reverse()

    def path_escapes(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        surface["authority"]["specification_set"][-1] = "../outside.md"

    def table_omits_member(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["spec"] = sources["spec"].replace(
            f"| Member | `{member}` |", "| Member | elsewhere |"
        )

    def pin_member(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["manifest"]["projections"]["afp"]["assertions"].append(
            {
                "id": "afp-member-digest",
                "kind": "sha256_equals",
                "path": member,
                "expected": "sha256:" + "0" * 64,
            }
        )

    def member_record_dropped(surface: dict[str, Any], sources: dict[str, Any]) -> None:
        sources["members"][member] = re.sub(
            r"kind: '(afp:[^']+)'", "kind: 'omitted'", sources["members"][member]
        )

    return [
        ("a member is not included by the core", split_then(not_included)),
        ("the core includes an undeclared member", split_then(unlisted_include)),
        ("an include block is not closed", split_then(unclosed_include)),
        ("a declared member does not exist", split_then(member_missing)),
        ("the specification set does not list the core first", split_then(core_not_first)),
        ("a member path escapes docs/", split_then(path_escapes)),
        ("the section 11 table omits a member", split_then(table_omits_member)),
        ("the family manifest pins a member file digest", split_then(pin_member)),
        ("a member's typed records vanish from the set", split_then(member_record_dropped)),
        (
            "a member carries a **Version:** line",
            split_then(edit_member("**Interface version:**", "**Version:** 9.9.9\n**Interface version:**")),
        ),
        (
            "a member's interface version drifts",
            split_then(edit_member("**Interface version:** ", "**Interface version:** 9.")),
        ),
        (
            "a member has no document revision",
            split_then(edit_member("**Document revision:** 1", "**Revision:** 1")),
        ),
    ]


def self_test(surface: dict[str, Any], sources: dict[str, Any]) -> None:
    """Prove every check has teeth by reintroducing the drift it must catch."""

    run_checks(copy.deepcopy(surface), copy.deepcopy(sources))
    for name, mutate in _accepted_variants():
        variant_surface = copy.deepcopy(surface)
        variant_sources = copy.deepcopy(sources)
        mutate(variant_surface, variant_sources)
        try:
            run_checks(variant_surface, variant_sources)
        except Failure as failure:
            raise Failure(
                f"self-test: accepted variant rejected -- {name}: {failure}"
            ) from None
    for name, mutate in _mutations():
        mutated_surface = copy.deepcopy(surface)
        mutated_sources = copy.deepcopy(sources)
        mutate(mutated_surface, mutated_sources)
        try:
            run_checks(mutated_surface, mutated_sources)
        except Failure:
            continue
        raise Failure(f"self-test: mutation not caught -- {name}")
    print(
        "AFP interface surface self-test: OK "
        f"({len(_mutations())} mutations caught, "
        f"{len(_accepted_variants())} accepted variants still pass)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="mutate the surface and its sources and require every check to fail closed",
    )
    args = parser.parse_args(argv)

    surface = json.loads(SURFACE_PATH.read_bytes())
    sources = load_sources()
    try:
        if args.self_test:
            self_test(surface, sources)
        else:
            run_checks(surface, sources)
            print(
                "AFP interface surface: OK "
                f"(interface {surface['interface_version']}, document revision "
                f"{surface['document_revision']}, {surface['interface_set_id']})"
            )
    except Failure as failure:
        print(f"AFP interface surface FAILED: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
