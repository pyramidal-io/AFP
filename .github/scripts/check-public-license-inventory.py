#!/usr/bin/env python3
"""Fail closed unless the exported AFP tree has reviewed license metadata."""

from __future__ import annotations

import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


INVENTORY_NAME = "LICENSE_INVENTORY.json"
INVENTORY_FORMAT = "afp:public-license-inventory:v1"
REPORT_FORMAT = "afp:public-license-inventory-report:v1"
SAFE_GIT_MODES = {"100644", "100755"}
EXPECTED_LICENSE_INVENTORY_SHA256 = "0f867aac0b754de74fe867e3e4cb6a3b5aa8409fd86516c46aec0be249269004"

ROOT_LICENSE_SHA256 = "4458503dd48e88c4e0b945fb252a08b93c40ec757309b8ffa7c594dfa1e35104"
ROOT_NOTICE_SHA256 = "2339bf6c4b5741a6b955ddef95140d42c10a4392989e767046abbd5ef07a0015"
POSEIDON_LICENSE_SHA256 = ROOT_LICENSE_SHA256
POSEIDON_UPSTREAM_SHA256 = "7c2e52ab271e1cdeec36ce028636638d115571539359ad13bac4a8cb2939ff84"
POSEIDON_SOURCE_SHA256 = "727ab4c68338938edb3d300c1f7949395beda882f6b06456bc21e8917102b507"

AFP_SCOPE = "afp-apache-2.0"
POSEIDON_SCOPE = "noir-poseidon-apache-2.0"
POSEIDON_ROOT = "conformance/noir/vendor/poseidon"
POSEIDON_LICENSE = f"{POSEIDON_ROOT}/LICENSE"
POSEIDON_UPSTREAM = f"{POSEIDON_ROOT}/UPSTREAM.json"
POSEIDON_SOURCE = f"{POSEIDON_ROOT}/src/poseidon2.nr"

EXPECTED_SCOPES = {
    AFP_SCOPE: {
        "license": "LICENSE",
        "notice": "NOTICE",
        "spdx": "Apache-2.0",
    },
    POSEIDON_SCOPE: {
        "license": POSEIDON_LICENSE,
        "spdx": "Apache-2.0",
        "upstream": POSEIDON_UPSTREAM,
    },
}
EXPECTED_UPSTREAM = {
    "format": "afp-vendored-noir-source-v1",
    "license": {
        "file": "LICENSE",
        "spdx": "Apache-2.0",
    },
    "source": {
        "path": "src/poseidon2.nr",
        "sha256": POSEIDON_SOURCE_SHA256,
        "upstreamBlobSha1": "d152ab207cc056eb58d0fb9a7d1f754504621ea0",
    },
    "upstreamCommit": "f249446e6e01f7b607ad35351cebe0cc20068cb7",
    "upstreamRepository": "https://github.com/noir-lang/poseidon",
}
EXPECTED_MANIFESTS = {
    "conformance/noir/Nargo.toml": {
        "format": "nargo-toml",
        "scope": AFP_SCOPE,
        "sha256": "5d6f5b379f299d04ff1fd3c63f9f8077ae2390b1f728711209897ed74f5e4845",
    },
    "conformance/noir/kdc_poseidon2/Nargo.toml": {
        "format": "nargo-toml",
        "scope": AFP_SCOPE,
        "sha256": "debde93da6322b1c7941d7e03800946655a6c672b12be28f3076eb5f486e3376",
    },
    f"{POSEIDON_ROOT}/Nargo.toml": {
        "format": "nargo-toml",
        "scope": POSEIDON_SCOPE,
        "sha256": "646424b1836a4a5bfea47310ce38555296c1c7db8556f4d3593302947b8c52f1",
    },
}
EXPECTED_LICENSE_LIKE_FILES = {
    "LICENSE",
    "NOTICE",
    INVENTORY_NAME,
    POSEIDON_LICENSE,
    POSEIDON_UPSTREAM,
}
EXPECTED_VENDOR_ROOTS = {POSEIDON_ROOT}
LICENSE_NOTICE_TOKENS = frozenset(
    {
        "license",
        "licenses",
        "licence",
        "licences",
        "notice",
        "notices",
        "copying",
        "copyright",
        "spdx",
    }
)
METADATA_COMPONENT_TOKENS = frozenset(
    LICENSE_NOTICE_TOKENS | {"provenance", "upstream", "reuse"}
)
METADATA_DIRECTORY_SEQUENCES = frozenset(
    {(token,) for token in METADATA_COMPONENT_TOKENS}
    | {
        ("third", "party", "license"),
        ("third", "party", "licenses"),
        ("third", "party", "licence"),
        ("third", "party", "licences"),
        ("third", "party", "notice"),
        ("third", "party", "notices"),
    }
)
METADATA_LEAF_SEQUENCES = frozenset(
    {(token,) for token in METADATA_COMPONENT_TOKENS}
    | {
        ("third", "party"),
        ("license", "inventory"),
        ("spdx", "license", "identifier"),
        ("third", "party", "license"),
        ("third", "party", "licenses"),
        ("third", "party", "licence"),
        ("third", "party", "licences"),
        ("third", "party", "notice"),
        ("third", "party", "notices"),
    }
)
COMPACT_METADATA_TOKEN_ALIASES = {
    "thirdparty": ("third", "party"),
    "thirdpartylicense": ("third", "party", "license"),
    "thirdpartylicenses": ("third", "party", "licenses"),
    "thirdpartylicence": ("third", "party", "licence"),
    "thirdpartylicences": ("third", "party", "licences"),
    "thirdpartynotice": ("third", "party", "notice"),
    "thirdpartynotices": ("third", "party", "notices"),
    "agpl2": ("agpl", "2"),
    "agpl3": ("agpl", "3"),
    "gpl2": ("gpl", "2"),
    "gpl3": ("gpl", "3"),
    "lgpl2": ("lgpl", "2"),
    "lgpl3": ("lgpl", "3"),
}
METADATA_TEXT_SUFFIXES = frozenset(
    {".json", ".md", ".rst", ".toml", ".txt", ".xml", ".yaml", ".yml"}
)
LICENSE_IDENTIFIER_TOKENS = frozenset(
    {
        "agpl",
        "apache",
        "apache2",
        "artistic",
        "bsd",
        "cc",
        "cc0",
        "epl",
        "gpl",
        "inventory",
        "isc",
        "lgpl",
        "lib",
        "lesser",
        "mit",
        "mozilla",
        "mpl",
        "ofl",
        "unlicense",
        "zlib",
    }
)
LICENSE_QUALIFIER_TOKENS = frozenset(
    {
        "and",
        "by",
        "clause",
        "exception",
        "later",
        "nc",
        "nd",
        "only",
        "or",
        "sa",
        "with",
    }
)
NUMERIC_LICENSE_VERSION_PREFIXES = frozenset({"license", "licence", "copying"})
RECOGNIZED_BUILD_MANIFEST_NAMES = frozenset(
    {
        ".bazelrc",
        ".terraform.lock.hcl",
        "build",
        "build.bazel",
        "build.gradle",
        "build.gradle.kts",
        "build.zig",
        "build.zig.zon",
        "bun.lock",
        "bun.lockb",
        "bunfig.toml",
        "bower.json",
        "bower.lock",
        "cabal.project",
        "cabal.project.freeze",
        "cargo.lock",
        "cargo.toml",
        "cmakepresets.json",
        "cmakeuserpresets.json",
        "cmakelists.txt",
        "composer.json",
        "composer.lock",
        "conanfile.py",
        "conanfile.txt",
        "configure",
        "configure.ac",
        "containerfile",
        "default.nix",
        "deno.json",
        "deno.jsonc",
        "deno.lock",
        "directory.build.props",
        "directory.build.targets",
        "directory.packages.props",
        "dockerfile",
        "dune-project",
        "environment.yaml",
        "environment.yml",
        "flake.lock",
        "flake.nix",
        "gemfile",
        "gemfile.lock",
        "global.json",
        "gnumakefile",
        "go.mod",
        "go.sum",
        "go.work",
        "gradle.properties",
        "gradlew",
        "gradlew.bat",
        "makefile",
        "manifest.in",
        "meson.build",
        "meson_options.txt",
        "mix.exs",
        "mix.lock",
        "module.bazel",
        "nargo.lock",
        "nargo.toml",
        "npm-shrinkwrap.json",
        "nuget.config",
        "package-lock.json",
        "package.json",
        "package.resolved",
        "package.swift",
        "packages.config",
        "packages.lock.json",
        "paket.dependencies",
        "paket.lock",
        "pdm.lock",
        "pdm.toml",
        "pipfile",
        "pipfile.lock",
        "podfile",
        "podfile.lock",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "poetry.lock",
        "poetry.toml",
        "pom.xml",
        "project.assets.json",
        "pubspec.lock",
        "pubspec.yaml",
        "pyproject.toml",
        "rebar.config",
        "rebar.lock",
        "sconstruct",
        "sconscript",
        "settings.gradle",
        "settings.gradle.kts",
        "setup.cfg",
        "setup.py",
        "shell.nix",
        "stack.lock",
        "stack.yaml",
        "stack.yml",
        "uv.lock",
        "uv.toml",
        "vcpkg-configuration.json",
        "vcpkg.json",
        "workspace",
        "workspace.bazel",
        "yarn.lock",
        "cartfile",
        "cartfile.resolved",
    }
)
RECOGNIZED_BUILD_MANIFEST_PATTERNS = (
    re.compile(r"dockerfile(?:\.[a-z0-9][a-z0-9._-]*)?\Z"),
    re.compile(r"containerfile(?:\.[a-z0-9][a-z0-9._-]*)?\Z"),
    re.compile(r"pipfile(?:\.[a-z0-9][a-z0-9._-]*)?\Z"),
    re.compile(r"requirements(?:[-_.][a-z0-9][a-z0-9._-]*)?\.(?:in|txt)\Z"),
    re.compile(r"[a-z0-9][a-z0-9._-]*\.(?:cabal|opam)\Z"),
    re.compile(r"[a-z0-9][a-z0-9._-]*\.gemspec\Z"),
    re.compile(r"[a-z0-9][a-z0-9._-]*\.(?:csproj|fsproj|vbproj|vcxproj|sln)\Z"),
)


class PolicyError(Exception):
    """Raised when public license metadata cannot be verified."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise PolicyError("JSON contains a duplicate object key")
        value[key] = member
    return value


def reject_json_constant(_constant: str) -> None:
    raise PolicyError("JSON contains a non-standard numeric constant")


def read_canonical_json(path: pathlib.Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be a JSON object")
    if raw != canonical_json(value):
        raise PolicyError(f"{label} is not canonical JSON")
    return value, raw


def tracked_files(root: pathlib.Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-s", "-z"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise PolicyError("cannot read the public Git index") from error
    if result.returncode:
        raise PolicyError("cannot read the public Git index")

    paths: set[str] = set()
    for raw_record in result.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, _object_id, stage = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise PolicyError("public Git index has a malformed entry") from error
        pure_path = pathlib.PurePosixPath(path)
        if (
            stage != "0"
            or mode not in SAFE_GIT_MODES
            or not path
            or pure_path.is_absolute()
            or path != pure_path.as_posix()
            or any(part in {"", ".", "..", ".git"} for part in pure_path.parts)
        ):
            raise PolicyError("public Git index has an unsupported entry")
        if path in paths:
            raise PolicyError("public Git index has a duplicate path")
        paths.add(path)
    if not paths:
        raise PolicyError("public Git index is empty")
    return tuple(sorted(paths))


def sha256_file(root: pathlib.Path, relative_path: str) -> str:
    try:
        return hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
    except OSError as error:
        raise PolicyError(f"required reviewed file is unavailable: {relative_path}") from error


def expect_digest(root: pathlib.Path, relative_path: str, expected: str, label: str) -> None:
    if sha256_file(root, relative_path) != expected:
        raise PolicyError(f"{label} digest does not match the reviewed value")


def normalized_component_tokens(component: str) -> tuple[str, ...]:
    """Return tokens after stripping only reviewed text-metadata suffixes."""
    stem = component.casefold()
    suffix = pathlib.PurePosixPath(stem).suffix
    if suffix in METADATA_TEXT_SUFFIXES:
        stem = stem[: -len(suffix)]
    return tuple(
        normalized
        for token in re.findall(r"[a-z0-9]+", stem)
        for normalized in COMPACT_METADATA_TOKEN_ALIASES.get(token, (token,))
    )


def is_qualified_license_metadata_leaf(tokens: tuple[str, ...]) -> bool:
    """Recognize finite identifier/metadata combinations in either token order."""
    token_set = set(tokens)
    if not token_set & LICENSE_NOTICE_TOKENS:
        return False
    allowed = LICENSE_NOTICE_TOKENS | LICENSE_IDENTIFIER_TOKENS | LICENSE_QUALIFIER_TOKENS
    if token_set & LICENSE_IDENTIFIER_TOKENS:
        return all(token in allowed or token.isdecimal() for token in tokens)
    return (
        tokens[0] in NUMERIC_LICENSE_VERSION_PREFIXES
        and len(tokens) > 2
        and all(token.isdecimal() for token in tokens[1:])
    )


def is_recognized_license_metadata_path(path: str) -> bool:
    """Recognize finite metadata directory and leaf forms without broad phrases."""
    parts = path.split("/")
    for index, component in enumerate(parts):
        tokens = normalized_component_tokens(component)
        is_leaf = index == len(parts) - 1
        if not tokens:
            continue
        if not is_leaf:
            if tokens in METADATA_DIRECTORY_SEQUENCES:
                return True
            continue
        if tokens in METADATA_LEAF_SEQUENCES:
            return True
        if is_qualified_license_metadata_leaf(tokens):
            return True
    return False


def is_recognized_build_manifest(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1].casefold()
    return basename in RECOGNIZED_BUILD_MANIFEST_NAMES or any(
        pattern.fullmatch(basename) for pattern in RECOGNIZED_BUILD_MANIFEST_PATTERNS
    )


def recognized_special_path_kind(path: str) -> str | None:
    """Classify common compliance metadata and build/package forms fail closed."""
    if is_recognized_license_metadata_path(path):
        return "license/notice/provenance"
    if is_recognized_build_manifest(path):
        return "build/package manifest"
    return None


def reject_unreviewed_special_paths(paths: tuple[str, ...]) -> None:
    for path in paths:
        parts = path.split("/")
        if "vendor" in parts:
            vendor_index = parts.index("vendor")
            if vendor_index + 1 >= len(parts):
                raise PolicyError("unreviewed vendor root")
            vendor_root = "/".join(parts[: vendor_index + 2])
            if vendor_root not in EXPECTED_VENDOR_ROOTS:
                raise PolicyError(f"unreviewed vendor root: {vendor_root}")
        kind = recognized_special_path_kind(path)
        if kind == "license/notice/provenance" and path not in EXPECTED_LICENSE_LIKE_FILES:
            raise PolicyError(f"unreviewed recognized license/notice/provenance file: {path}")
        if kind == "build/package manifest" and path not in EXPECTED_MANIFESTS:
            raise PolicyError(f"unreviewed recognized build/package manifest: {path}")


def validate_inventory(paths: tuple[str, ...], inventory: dict[str, Any]) -> None:
    if set(inventory) != {"files", "format", "manifests", "scopes"}:
        raise PolicyError("license inventory has an unsupported schema")
    if inventory["format"] != INVENTORY_FORMAT:
        raise PolicyError("license inventory format is not recognized")
    files = inventory["files"]
    scopes = inventory["scopes"]
    manifests = inventory["manifests"]
    if not isinstance(files, dict) or not isinstance(scopes, dict) or not isinstance(manifests, dict):
        raise PolicyError("license inventory members must be objects")
    if scopes != EXPECTED_SCOPES:
        raise PolicyError("license inventory scopes do not match reviewed Apache-2.0 scopes")
    if manifests != EXPECTED_MANIFESTS:
        raise PolicyError("license inventory manifests do not match reviewed Cargo/Nargo manifests")
    tracked = set(paths)
    assigned = set(files)
    if assigned != tracked:
        difference = sorted((assigned - tracked) or (tracked - assigned))
        raise PolicyError(f"license inventory does not assign every tracked file exactly once: {difference[0]}")
    for path, scope in files.items():
        if not isinstance(path, str) or not isinstance(scope, str) or scope not in scopes:
            raise PolicyError("license inventory has an invalid file scope")
        expected_scope = POSEIDON_SCOPE if path.startswith(f"{POSEIDON_ROOT}/") else AFP_SCOPE
        if scope != expected_scope:
            raise PolicyError(f"license inventory assigns an incorrect scope: {path}")


def validate_reviewed_content(root: pathlib.Path) -> None:
    expect_digest(root, "LICENSE", ROOT_LICENSE_SHA256, "root LICENSE")
    expect_digest(root, "NOTICE", ROOT_NOTICE_SHA256, "root NOTICE")
    expect_digest(root, POSEIDON_LICENSE, POSEIDON_LICENSE_SHA256, "Poseidon LICENSE")
    expect_digest(root, POSEIDON_UPSTREAM, POSEIDON_UPSTREAM_SHA256, "Poseidon UPSTREAM")
    upstream, _raw = read_canonical_json(root / POSEIDON_UPSTREAM, "Poseidon UPSTREAM")
    if upstream != EXPECTED_UPSTREAM:
        raise PolicyError("Poseidon UPSTREAM does not match reviewed SPDX, upstream, and source metadata")
    expect_digest(root, POSEIDON_SOURCE, POSEIDON_SOURCE_SHA256, "Poseidon source")
    for path, metadata in EXPECTED_MANIFESTS.items():
        expect_digest(root, path, metadata["sha256"], f"reviewed manifest {path}")


def build_report(root: pathlib.Path) -> dict[str, Any]:
    paths = tracked_files(root)
    inventory, inventory_bytes = read_canonical_json(root / INVENTORY_NAME, INVENTORY_NAME)
    inventory_digest = hashlib.sha256(inventory_bytes).hexdigest()
    if inventory_digest != EXPECTED_LICENSE_INVENTORY_SHA256:
        raise PolicyError("LICENSE_INVENTORY digest does not match the reviewed value")
    reject_unreviewed_special_paths(paths)
    validate_inventory(paths, inventory)
    validate_reviewed_content(root)
    scope_counts = collections.Counter(inventory["files"].values())
    return {
        "format": REPORT_FORMAT,
        "inventory_sha256": inventory_digest,
        "scopes": dict(sorted(scope_counts.items())),
        "tracked_file_count": len(paths),
    }


def main() -> int:
    try:
        report = build_report(pathlib.Path.cwd())
    except (OSError, PolicyError) as error:
        print(f"PUBLIC_LICENSE_INVENTORY invalid: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
