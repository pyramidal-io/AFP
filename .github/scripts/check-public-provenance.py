#!/usr/bin/env python3
"""Reject private operational provenance from every tracked public blob."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any


REPORT_FORMAT = "afp:public-provenance-report:v1"
FORBIDDEN_PATTERNS = (
    re.compile(rb"https://github\.com/[^\s]+/actions/runs/\d+"),
    re.compile(rb"https://github\.com/[^\s]+/pull/\d+"),
    re.compile(rb"\b(?:req|epic)_[a-z0-9_]{6,}\b"),
    re.compile(rb"\bPyramidal\.Authority\b"),
    re.compile(rb"\bdocs/(?:internal|operations|superpowers)/"),
    re.compile(rb"\bPOSEIDON_CONFORMANCE_APP_(?:CLIENT_ID|PRIVATE_KEY)\b"),
)
SELF_HOSTED_RUNNER = re.compile(rb"\bself-hosted\b")
PYRAMIDAL_REPOSITORY_URL = re.compile(
    rb"https://github\.com/pyramidal-io/([A-Za-z0-9_.-]+)"
)
APPROVED_PUBLIC_REPOSITORY_URLS = frozenset({b"AFP"})
PRIVATE_PROTOCOL_REPOSITORY = re.compile(rb"\bpyramidal-io/[A-Za-z0-9_.-]+\.dev\b")
APPROVED_PROTOCOL_REPOSITORIES = frozenset(
    {
        b"pyramidal-io/AFP.dev",
        b"pyramidal-io/ZKA.dev",
        b"pyramidal-io/ZKC.dev",
        b"pyramidal-io/ZKM.dev",
    }
)
APPROVED_PROTOCOL_PROVENANCE_PATHS = frozenset(
    {
        ".github/scripts/check-public-provenance.py",
        "protocol-family/afp-interface-surface-v1.json",
        "protocol-family/interface-manifest-v1.json",
        "protocol-family/interface-manifest-v1.schema.json",
        "protocol-family/snapshot-lock.json",
        "scripts/check_afp_interface_surface.py",
        "scripts/validate_protocol_family.py",
        "tests/python/test_interface_surface.py",
    }
)
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"
COORD_PROVENANCE_PATH = "docs/afp_coord_v2_cross_org_conformance_v1.json"
COORD_PROTOCOL_REPOSITORY = "pyramidal-io/ZKA.dev"


class ProvenancePolicyError(Exception):
    """Raised when a tracked blob crosses the public provenance boundary."""


def reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def provenance_scan_blob(path: str, blob: bytes) -> bytes:
    if path != COORD_PROVENANCE_PATH:
        return blob
    try:
        document = json.loads(blob, object_pairs_hook=reject_duplicate_json_members)
        if not isinstance(document, dict):
            raise ValueError("Coord provenance document is not an object")
        source_pins = document.get("source_pins")
        if (
            not isinstance(source_pins, dict)
            or source_pins.get("repository") != COORD_PROTOCOL_REPOSITORY
        ):
            raise ValueError("Coord provenance repository is not exact")
        del source_pins["repository"]
        return canonical_json(document)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ProvenancePolicyError(
            "tracked public Coord provenance document is invalid"
        ) from error


def git(*args: str) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise ProvenancePolicyError("cannot read the tracked public tree")
    return result.stdout


def validate() -> dict[str, Any]:
    raw_paths = git("ls-files", "-z")
    paths = [path for path in raw_paths.split(b"\0") if path]
    if not paths:
        raise ProvenancePolicyError("tracked public tree is empty")
    for raw_path in paths:
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProvenancePolicyError("tracked public path is not valid UTF-8") from error
        blob = git("show", f"HEAD:{path}")
        if blob.startswith(LFS_POINTER_PREFIX):
            raise ProvenancePolicyError("tracked public blob is a Git LFS pointer")
        scan_blob = provenance_scan_blob(path, blob)
        if any(pattern.search(scan_blob) for pattern in FORBIDDEN_PATTERNS):
            raise ProvenancePolicyError("tracked public blob contains private operational provenance")
        if path.startswith(".github/workflows/") and SELF_HOSTED_RUNNER.search(scan_blob):
            raise ProvenancePolicyError("tracked public workflow uses private runner topology")
        repository_urls = set(PYRAMIDAL_REPOSITORY_URL.findall(scan_blob))
        if not repository_urls.issubset(APPROVED_PUBLIC_REPOSITORY_URLS):
            raise ProvenancePolicyError("tracked public blob links to a private repository")
        protocol_repositories = set(PRIVATE_PROTOCOL_REPOSITORY.findall(scan_blob))
        if protocol_repositories and (
            path not in APPROVED_PROTOCOL_PROVENANCE_PATHS
            or not protocol_repositories.issubset(APPROVED_PROTOCOL_REPOSITORIES)
        ):
            raise ProvenancePolicyError(
                "tracked public blob contains unapproved protocol provenance"
            )
    return {"format": REPORT_FORMAT, "scanned_file_count": len(paths), "status": "clean"}


def main() -> int:
    try:
        report = validate()
    except (OSError, ProvenancePolicyError) as error:
        print(f"PUBLIC_PROVENANCE invalid: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
