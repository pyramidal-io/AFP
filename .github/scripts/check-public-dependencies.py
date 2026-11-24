#!/usr/bin/env python3
"""Fail closed unless the public snapshot has only reviewed local dependencies."""

from __future__ import annotations

import json
import pathlib
import runpy
import subprocess
import sys
import tomllib
from typing import Any


REPORT_FORMAT = "afp:public-dependency-report:v1"
PINNED_NARGO_VERSION = "1.0.0-beta.22"
EXPECTED_MANIFESTS = {
    "conformance/noir/Nargo.toml",
    "conformance/noir/kdc_poseidon2/Nargo.toml",
    "conformance/noir/vendor/poseidon/Nargo.toml",
}
LICENSE_CHECKER = pathlib.PurePosixPath(".github/scripts/check-public-license-inventory.py")


class DependencyPolicyError(Exception):
    """Raised when the exported dependency boundary is not self-contained."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def tracked_paths(root: pathlib.Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        raise DependencyPolicyError("cannot enumerate the public Git index")
    try:
        return tuple(sorted(path.decode("utf-8") for path in result.stdout.split(b"\0") if path))
    except UnicodeDecodeError as error:
        raise DependencyPolicyError("public Git paths are not valid UTF-8") from error


def read_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DependencyPolicyError("reviewed Nargo manifest is invalid") from error
    if not isinstance(value, dict):
        raise DependencyPolicyError("reviewed Nargo manifest is not a table")
    return value


def manifest_classifier(root: pathlib.Path):
    checker = root / LICENSE_CHECKER
    try:
        namespace = runpy.run_path(str(checker), run_name="public_license_inventory_policy")
    except (OSError, RuntimeError, SyntaxError) as error:
        raise DependencyPolicyError("reviewed manifest classifier cannot be loaded") from error
    classifier = namespace.get("is_recognized_build_manifest")
    if not callable(classifier):
        raise DependencyPolicyError("reviewed manifest classifier is unavailable")
    return classifier


def validate(root: pathlib.Path) -> dict[str, Any]:
    paths = tracked_paths(root)
    is_recognized_build_manifest = manifest_classifier(root)
    manifests = {path for path in paths if is_recognized_build_manifest(path)}
    if manifests != EXPECTED_MANIFESTS:
        raise DependencyPolicyError("tracked dependency manifests do not match the reviewed set")

    workspace = read_toml(root / "conformance/noir/Nargo.toml")
    if workspace != {"workspace": {"members": ["kdc_poseidon2"]}}:
        raise DependencyPolicyError("Noir workspace does not match the reviewed package set")

    path_dependencies = 0
    for relative_path in sorted(EXPECTED_MANIFESTS - {"conformance/noir/Nargo.toml"}):
        manifest_path = root / relative_path
        manifest = read_toml(manifest_path)
        package = manifest.get("package")
        if not isinstance(package, dict) or "compiler_version" in package:
            raise DependencyPolicyError(
                "Noir prerelease compiler selection must use the reviewed external pin"
            )
        dependencies = manifest.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise DependencyPolicyError("Noir dependencies must be a table")
        for dependency in dependencies.values():
            if not isinstance(dependency, dict) or set(dependency) != {"path"}:
                raise DependencyPolicyError("Noir dependency is not an exact local path dependency")
            raw_path = dependency["path"]
            if not isinstance(raw_path, str) or not raw_path:
                raise DependencyPolicyError("Noir dependency path is invalid")
            target = (manifest_path.parent / raw_path).resolve()
            try:
                target.relative_to(root.resolve())
            except ValueError as error:
                raise DependencyPolicyError("Noir dependency escapes the public snapshot") from error
            if not (target / "Nargo.toml").is_file():
                raise DependencyPolicyError("Noir dependency target is absent")
            path_dependencies += 1

    return {
        "external_dependency_count": 0,
        "format": REPORT_FORMAT,
        "manifest_count": len(manifests),
        "nargo_version": PINNED_NARGO_VERSION,
        "path_dependency_count": path_dependencies,
    }


def main() -> int:
    try:
        report = validate(pathlib.Path.cwd())
    except (OSError, DependencyPolicyError) as error:
        print(f"PUBLIC_DEPENDENCIES invalid: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
