#!/usr/bin/env python3
"""Validate an exact-file AFP public policy against an immutable Git commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


SAFE_GIT_MODES = {"100644", "100755"}
REPORT_FORMAT = "afp:public-allowlist-report:v1"
FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
VERSION_HEADER = re.compile(r"^\*\*Version:\*\*\s+([^\s]+)\s*$", re.MULTILINE)
SPEC_PATH = "docs/afp_specification.md"
SURFACE_PATH = "protocol-family/afp-interface-surface-v1.json"
MEMBER_PATH = re.compile(r"docs/[a-z0-9_]+\.md\Z")


class PolicyError(Exception):
    """A policy or immutable-object validation failure."""


def parse_policy(contents: str) -> tuple[str, ...]:
    """Parse and validate literal, normalized POSIX allowlist paths."""
    entries: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(contents.splitlines(), start=1):
        if not raw or raw.startswith("#"):
            continue
        path = pathlib.PurePosixPath(raw)
        unsafe = (
            raw != raw.strip()
            or path.is_absolute()
            or "\\" in raw
            or raw.endswith("/")
            or any(char in raw for char in "*?[]")
            or raw != path.as_posix()
            or any(part in {".", "..", ".git"} for part in path.parts)
        )
        if unsafe or raw in seen:
            raise PolicyError(f"unsafe or duplicate allowlist entry at line {number}")
        seen.add(raw)
        entries.append(raw)
    return tuple(entries)


def git_output(root: pathlib.Path, *args: str) -> bytes:
    """Read Git output without exposing Git diagnostics to policy callers."""
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise PolicyError("Git object lookup failed") from error
    if result.returncode:
        raise PolicyError("Git object lookup failed")
    return result.stdout


def resolve_commit(root: pathlib.Path, revision: str) -> str:
    try:
        object_type = git_output(root, "cat-file", "-t", revision).decode("ascii").strip()
        resolved = git_output(root, "rev-parse", "--verify", revision)
        commit = resolved.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PolicyError("Git object lookup failed") from error
    if object_type != "commit" or commit != revision:
        raise PolicyError("Git object lookup failed")
    return commit


def git_object_type(root: pathlib.Path, object_id: str) -> str:
    try:
        return git_output(root, "cat-file", "-t", object_id).decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PolicyError("Git tree contains an invalid object reference") from error


def raw_tree_entries(
    root: pathlib.Path, tree: str, object_id_bytes: int
) -> tuple[tuple[str, str, str], ...]:
    """Parse one raw tree object without allowing Git to flatten its namespace."""
    contents = git_output(root, "cat-file", "tree", tree)
    entries: list[tuple[str, str, str]] = []
    names: set[str] = set()
    offset = 0
    while offset < len(contents):
        mode_end = contents.find(b" ", offset)
        if mode_end <= offset:
            raise PolicyError("Git tree contains a malformed raw entry")
        raw_mode = contents[offset:mode_end]
        name_end = contents.find(b"\0", mode_end + 1)
        object_end = name_end + 1 + object_id_bytes
        if (
            name_end < 0
            or object_end > len(contents)
            or not raw_mode
            or any(byte not in b"01234567" for byte in raw_mode)
        ):
            raise PolicyError("Git tree contains a malformed raw entry")
        raw_name = contents[mode_end + 1 : name_end]
        try:
            mode = raw_mode.decode("ascii")
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PolicyError("Git tree is not a valid UTF-8 file inventory") from error
        if not name or "/" in name or name in {".", ".."}:
            raise PolicyError("Git tree contains a malformed raw entry")
        if name in names:
            raise PolicyError("Git tree contains a duplicate raw entry name")
        names.add(name)
        entries.append((mode, name, contents[name_end + 1 : object_end].hex()))
        offset = object_end
    return tuple(entries)


def tracked_files(root: pathlib.Path, commit: str) -> dict[str, tuple[str, str, str]]:
    """Recursively validate raw Git trees before producing a flat file inventory."""
    try:
        root_tree = git_output(root, "rev-parse", "--verify", f"{commit}^{{tree}}")
        tree = root_tree.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise PolicyError("Git object lookup failed") from error
    object_id_bytes = len(tree) // 2
    if (
        len(tree) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in tree)
    ):
        raise PolicyError("Git object lookup failed")

    entries: dict[str, tuple[str, str, str]] = {}

    def walk(tree_id: str, prefix: str) -> None:
        if git_object_type(root, tree_id) != "tree":
            raise PolicyError("Git tree recursion referenced a non-tree object")
        for mode, name, object_id in raw_tree_entries(root, tree_id, object_id_bytes):
            object_type = git_object_type(root, object_id)
            path = f"{prefix}/{name}" if prefix else name
            if object_type == "tree":
                if mode != "40000":
                    raise PolicyError("Git tree contains a malformed raw entry")
                walk(object_id, path)
                continue
            if mode == "40000":
                raise PolicyError("Git tree recursion referenced a non-tree object")
            if path in entries:
                raise PolicyError("Git tree contains a duplicate path")
            entries[path] = (mode, object_type, object_id)

    walk(tree, "")
    return entries


def read_blob(
    root: pathlib.Path, tracked: dict[str, tuple[str, str, str]], path: str
) -> str:
    mode, object_type, object_id = tracked.get(path, ("", "", ""))
    if mode not in SAFE_GIT_MODES or object_type != "blob":
        raise PolicyError(f"allowlist entry is not a tracked regular file: {path}")
    try:
        return git_output(root, "cat-file", "blob", object_id).decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError(f"required source file is not UTF-8: {path}") from error


def read_afp_version(
    root: pathlib.Path, tracked: dict[str, tuple[str, str, str]]
) -> str:
    match = VERSION_HEADER.search(read_blob(root, tracked, SPEC_PATH))
    if match is None:
        raise PolicyError("AFP version header is missing")
    return match.group(1)


def specification_set(surface: bytes | str) -> tuple[str, ...]:
    """The normative AFP document set that the interface surface declares (ADR-0013)."""
    try:
        declared = json.loads(surface)["authority"]["specification_set"]
    except (ValueError, KeyError, TypeError) as error:
        raise PolicyError("interface surface declares no specification_set") from error
    if (
        not isinstance(declared, list)
        or declared[:1] != [SPEC_PATH]
        or any(not isinstance(path, str) or MEMBER_PATH.match(path) is None for path in declared)
        or len(set(declared)) != len(declared)
    ):
        raise PolicyError("interface surface specification_set is malformed")
    return tuple(declared)


def require_specification_set(
    root: pathlib.Path, tracked: dict[str, tuple[str, str, str]], inventory: tuple[str, ...]
) -> None:
    """A public snapshot carries the whole normative set or fails closed.

    The interface surface is the only source of set membership, so it must be
    a tracked regular file and itself allowlisted; there is no fallback.
    """
    if SURFACE_PATH not in inventory:
        raise PolicyError(f"the interface surface is not in PUBLIC_ALLOWLIST: {SURFACE_PATH}")
    members = specification_set(read_blob(root, tracked, SURFACE_PATH))
    for path in members:
        if path not in inventory:
            raise PolicyError(f"specification_set member is not in PUBLIC_ALLOWLIST: {path}")


def build_report(root: pathlib.Path, revision: str) -> dict[str, object]:
    """Build a deterministic public-inventory report for one immutable commit."""
    if FULL_COMMIT.fullmatch(revision) is None:
        raise PolicyError("revision must be a full immutable Git object ID")
    commit = resolve_commit(root, revision)
    tracked = tracked_files(root, commit)
    inventory = parse_policy(read_blob(root, tracked, "PUBLIC_ALLOWLIST"))
    if "PUBLIC_ALLOWLIST" not in inventory:
        raise PolicyError("PUBLIC_ALLOWLIST must include itself")
    for path in inventory:
        mode, object_type, _object_id = tracked.get(path, ("", "", ""))
        if mode not in SAFE_GIT_MODES or object_type != "blob":
            raise PolicyError(f"allowlist entry is not a tracked regular file: {path}")
    require_specification_set(root, tracked, inventory)
    ordered = sorted(inventory)
    digest = hashlib.sha256(("\n".join(ordered) + "\n").encode()).hexdigest()
    return {
        "format": REPORT_FORMAT,
        "revision": commit,
        "inventory": ordered,
        "inventory_count": len(ordered),
        "inventory_sha256": digest,
        "afp_version": read_afp_version(root, tracked),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.root, args.revision)
    except (OSError, UnicodeDecodeError, PolicyError) as error:
        print(f"PUBLIC_ALLOWLIST invalid: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
