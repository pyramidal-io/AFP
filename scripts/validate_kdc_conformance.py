#!/usr/bin/env python3
"""Validate the AFP-KDC v1.0.3 registry and v1.0.2 cryptographic profile."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from afp_session.kdc import BN254_SCALAR_MODULUS, load_domain_registry  # noqa: E402
from afp_session.poseidon2 import (  # noqa: E402
    derive_kdc_keys,
    hash_fields,
    load_profile,
    seed_to_field,
)


PROFILE_PATH = ROOT / "docs" / "kdc_v1_0_2_poseidon2_parameters.json"
VECTORS_PATH = ROOT / "docs" / "kdc_v1_0_2_conformance_vectors.json"
REGISTRY_PATH = ROOT / "docs" / "kdc_v1_0_3_domain_registry.json"

_EXPECTED_PROVENANCE = {
    "parameterSource": "docs/kdc_v1_0_2_poseidon2_parameters.json",
    "noirPoseidonRepository": "https://github.com/noir-lang/poseidon",
    "noirPoseidonTag": "v0.3.0",
    "noirPoseidonCommit": "0880c371e88e583d39515fd3f877538657ac41eb",
    "independentRuntimes": [
        "AFP standard-library Python reference",
        "ZKA Rust",
        "ZKA/ZKC/ZKM Noir mirrors",
        "ZKC Python",
        "ZKM Python",
        "aztec-nargo",
        "ZKA Solidity H2",
    ],
}
_EXPECTED_KDC_ALIASES = {"r": "zero", "r_plus_1": "one"}


class ConformanceError(RuntimeError):
    """A consumer no longer matches the AFP-owned conformance authority."""


def _fail(message: str) -> NoReturn:
    raise ConformanceError(message)


def _profile_constants(profile: dict[str, Any]) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    rounds = tuple(
        tuple(int(value, 16) for value in row)
        for row in profile["permutation"]["round_constants"]
    )
    diagonal = tuple(
        int(value, 16)
        for value in profile["permutation"]["internal_matrix"]["diagonal_minus_one"]
    )
    return rounds, diagonal


def _python_assignment(path: Path, name: str) -> Any:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise ConformanceError(f"cannot parse {path}: {exc}") from exc
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError) as exc:
                raise ConformanceError(f"{path}:{name} is not literal data") from exc
    _fail(f"{path} omits {name}")


def _rust_constants(path: Path) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    source = path.read_text(encoding="utf-8")
    try:
        round_start = source.index("pub(crate) const ROUND_CONSTANTS_HEX")
        round_start = source.index("= [", round_start)
        round_block = source[round_start : source.index("\n];", round_start)]
        diagonal_start = source.index("pub(crate) const INTERNAL_DIAG_MINUS_ONE_HEX")
        diagonal_start = source.index("= [", diagonal_start)
        diagonal_block = source[diagonal_start : source.index("\n];", diagonal_start)]
    except ValueError as exc:
        raise ConformanceError(f"{path} does not expose both constant tables") from exc
    rounds_flat = [int(value, 16) for value in re.findall(r'"(0x[0-9a-f]{64})"', round_block)]
    diagonal = tuple(
        int(value, 16)
        for value in re.findall(r'"(0x[0-9a-f]{64})"', diagonal_block)
    )
    if len(rounds_flat) != 256 or len(diagonal) != 4:
        _fail(
            f"{path} constant layout drift: {len(rounds_flat)} round values, "
            f"{len(diagonal)} diagonal values"
        )
    rounds = tuple(tuple(rounds_flat[index : index + 4]) for index in range(0, 256, 4))
    return rounds, diagonal


def _assert_constants(label: str, actual: tuple[Any, Any], expected: tuple[Any, Any]) -> None:
    if actual != expected:
        _fail(f"{label} Poseidon2 constant table differs from AFP-KDC v1.0.2")


def _run_json(command: list[str], cwd: Path) -> Any:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConformanceError(f"runtime command timed out in {cwd}") from exc
    if result.returncode != 0:
        _fail(f"runtime command failed in {cwd}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConformanceError(f"runtime in {cwd} emitted invalid JSON") from exc


def _validate_vector_shape(vectors: Any) -> None:
    if not isinstance(vectors, dict) or set(vectors) != {
        "format",
        "profile",
        "parameterArtifact",
        "parameterDigest",
        "fieldModulus",
        "provenance",
        "rawSponge",
        "kdc",
    }:
        _fail("shared-vector root violates the v1 schema")
    if vectors.get("format") != "afp-kdc-poseidon2-conformance-v1":
        _fail("shared vectors identify the wrong format")
    if vectors.get("parameterArtifact") != "docs/kdc_v1_0_2_poseidon2_parameters.json":
        _fail("shared vectors identify the wrong parameter artifact")
    if vectors.get("fieldModulus") != f"0x{BN254_SCALAR_MODULUS:064x}":
        _fail("shared vectors identify the wrong field modulus")
    if vectors.get("provenance") != _EXPECTED_PROVENANCE:
        _fail("shared-vector provenance violates the v1 schema")
    raw = vectors.get("rawSponge")
    kdc = vectors.get("kdc")
    if not isinstance(raw, list) or not isinstance(kdc, list):
        _fail("shared-vector cases must be arrays")
    expected_raw_cases = {
        ("empty", 0),
        ("one", 1),
        ("two-h2", 2),
        ("three-h3-exact-rate", 3),
        ("four-h4-remainder", 4),
        ("six-two-full-rate-blocks", 6),
        ("seven-two-blocks-and-remainder", 7),
    }
    if len(raw) != 7:
        _fail("shared vectors must contain exactly seven raw sponge cases")
    field_hex = re.compile(r"0x[0-9a-f]{64}\Z")
    for case in raw:
        if not isinstance(case, dict) or set(case) != {
            "name",
            "inputLength",
            "inputs",
            "output",
        }:
            _fail("raw sponge case violates the v1 schema")
        if (
            not isinstance(case["name"], str)
            or isinstance(case["inputLength"], bool)
            or not isinstance(case["inputLength"], int)
            or not isinstance(case["inputs"], list)
            or not isinstance(case["output"], str)
        ):
            _fail("raw sponge case uses invalid JSON types")
        if case["inputLength"] != len(case["inputs"]):
            _fail(f"raw sponge length mismatch in {case['name']}")
        if not field_hex.fullmatch(case["output"]) or any(
            not isinstance(value, str) or not field_hex.fullmatch(value)
            for value in case["inputs"]
        ):
            _fail(f"raw sponge case {case['name']} has noncanonical field hex")
        if int(case["output"], 16) >= BN254_SCALAR_MODULUS or any(
            int(value, 16) >= BN254_SCALAR_MODULUS for value in case["inputs"]
        ):
            _fail(f"raw sponge case {case['name']} is outside BN254 Fr")
    if {(case["name"], case["inputLength"]) for case in raw} != expected_raw_cases:
        _fail("shared vectors do not contain the seven required raw sponge cases")
    derived_keys = {
        "spendingKey",
        "viewingKey",
        "proofKey",
        "address",
        "credentialBindingKey",
        "holderCommitment",
    }
    expected_kdc_names = {
        "zero",
        "one",
        "r_minus_1",
        "r",
        "r_plus_1",
        "high_bit",
        "asymmetric",
    }
    if len(kdc) != 7:
        _fail("shared vectors must contain exactly seven KDC seed cases")
    for case in kdc:
        if not isinstance(case, dict) or set(case) not in (
            {"name", "seed", "kdcInput", "derived"},
            {"name", "seed", "kdcInput", "kdcAliasOf", "derived"},
        ):
            _fail("KDC case violates the v1 schema")
        if (
            not isinstance(case["name"], str)
            or not isinstance(case["seed"], str)
            or not isinstance(case["kdcInput"], str)
            or not isinstance(case["derived"], dict)
        ):
            _fail("KDC case uses invalid JSON types")
        expected_alias = _EXPECTED_KDC_ALIASES.get(case["name"])
        if expected_alias is None and "kdcAliasOf" in case:
            _fail(f"KDC case {case['name']} has an unexpected alias")
        if expected_alias is not None and case.get("kdcAliasOf") != expected_alias:
            _fail(f"KDC case {case['name']} has the wrong alias")
        if set(case["derived"]) != derived_keys:
            _fail(f"KDC case {case['name']} has the wrong branch set")
        if not field_hex.fullmatch(case["seed"]) or not field_hex.fullmatch(
            case["kdcInput"]
        ) or any(
            not isinstance(value, str) or not field_hex.fullmatch(value)
            for value in case["derived"].values()
        ):
            _fail(f"KDC case {case['name']} has noncanonical field or seed hex")
        if int(case["kdcInput"], 16) >= BN254_SCALAR_MODULUS or any(
            int(value, 16) >= BN254_SCALAR_MODULUS
            for value in case["derived"].values()
        ):
            _fail(f"KDC case {case['name']} has a value outside BN254 Fr")
        if seed_to_field(bytes.fromhex(case["seed"][2:])) != int(
            case["kdcInput"], 16
        ):
            _fail(f"KDC case {case['name']} has the wrong seed reduction")
    if {case["name"] for case in kdc} != expected_kdc_names:
        _fail("shared vectors do not contain the seven required KDC seed cases")


def validate_local() -> tuple[dict[str, Any], dict[str, Any]]:
    profile = load_profile(PROFILE_PATH)
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    _validate_vector_shape(vectors)
    registry = load_domain_registry(REGISTRY_PATH)
    if len(registry) != 27:
        _fail("AFP-KDC v1.0.3 registry must contain exactly 27 collision-free tags")
    if vectors.get("profile") != "afp-kdc:poseidon2:v1.0.2":
        _fail("shared vectors identify the wrong profile")
    if vectors.get("parameterDigest") != profile["canonical_constant_encoding"]["sha256"]:
        _fail("shared vectors do not bind the normative parameter digest")
    for case in vectors["rawSponge"]:
        actual = hash_fields([int(value, 16) for value in case["inputs"]], profile)
        if actual != int(case["output"], 16):
            _fail(f"AFP reference raw sponge drift in {case['name']}")
    for case in vectors["kdc"]:
        actual = derive_kdc_keys(bytes.fromhex(case["seed"][2:]), profile)
        expected = {name: int(value, 16) for name, value in case["derived"].items()}
        if actual != expected:
            _fail(f"AFP reference KDC drift in {case['name']}")
    return profile, vectors


def validate_zka(root: Path, profile: dict[str, Any], vectors: dict[str, Any]) -> None:
    expected_constants = _profile_constants(profile)
    actual_constants = _rust_constants(
        root / "src" / "zka-crypto" / "src" / "hash" / "poseidon2_bn254_constants.rs"
    )
    _assert_constants("ZKA Rust", actual_constants, expected_constants)

    zka_vectors = json.loads(
        (root / "tests" / "vectors" / "crypto" / "key_derivation.json").read_text(
            encoding="utf-8"
        )
    )
    zero = next((case for case in vectors["kdc"] if case["name"] == "zero"), None)
    if zero is None:
        _fail("shared vectors omit the zero-seed KDC case")
    if not isinstance(zka_vectors, dict) or not isinstance(
        zka_vectors.get("vectors"), list
    ):
        _fail("ZKA key_derivation.json violates its vector schema")
    zka_case = next(
        (
            case
            for case in zka_vectors["vectors"]
            if isinstance(case, dict) and case.get("master_seed") == zero["seed"]
        ),
        None,
    )
    if zka_case is None:
        _fail(f"ZKA key_derivation.json omits the AFP zero seed {zero['seed']}")
    zka_zero = zka_case.get("expected_keys")
    if not isinstance(zka_zero, dict):
        _fail("ZKA key_derivation.json omits expected zero-seed keys")
    mapping = {
        "spendingKey": "spending_key",
        "viewingKey": "viewing_key",
        "proofKey": "proof_key",
        "address": "address",
        "credentialBindingKey": "credential_binding_key",
        "holderCommitment": "credential_commitment",
    }
    for shared_name, zka_name in mapping.items():
        zka_value = zka_zero.get(zka_name)
        if not isinstance(zka_value, str) or re.fullmatch(
            r"0x[0-9a-f]{64}", zka_value
        ) is None:
            _fail(f"ZKA key_derivation.json has noncanonical {zka_name}")
        if int(zero["derived"][shared_name], 16) != int(zka_value, 16):
            _fail(f"ZKA key_derivation.json contradicts AFP {shared_name}")


def validate_zkc(root: Path, profile: dict[str, Any], vectors: dict[str, Any]) -> None:
    expected_constants = _profile_constants(profile)
    constants_path = root / "python" / "zkc_crypto" / "_poseidon2_constants.py"
    actual_constants = (
        tuple(tuple(row) for row in _python_assignment(constants_path, "ROUND_CONSTANTS")),
        tuple(_python_assignment(constants_path, "INTERNAL_DIAG_MINUS_ONE")),
    )
    _assert_constants("ZKC Python", actual_constants, expected_constants)

    program = "\n".join(
        (
            "import json, sys",
            "sys.path.insert(0, 'python')",
            "from zkc_crypto.poseidon2 import hash_fields",
            "from zkc_crypto.kdc import (",
            "    derive_credential_binding_key,",
            "    derive_holder_commitment,",
            ")",
            "with open(sys.argv[1], encoding='utf-8') as handle:",
            "    vectors = json.load(handle)",
            "raw = [",
            "    f'0x{hash_fields([int(value, 16) for value in case[\"inputs\"]]):064x}'",
            "    for case in vectors['rawSponge']",
            "]",
            "kdc = []",
            "for case in vectors['kdc']:",
            "    seed = bytes.fromhex(case['seed'][2:])",
            "    binding_key = derive_credential_binding_key(seed)",
            "    kdc.append({",
            "        'credentialBindingKey': f'0x{binding_key:064x}',",
            "        'holderCommitment': f'0x{derive_holder_commitment(binding_key):064x}',",
            "    })",
            "print(json.dumps({'raw': raw, 'kdc': kdc}))",
        )
    )
    actual = _run_json([sys.executable, "-c", program, str(VECTORS_PATH)], root)
    expected_raw = [case["output"] for case in vectors["rawSponge"]]
    expected_kdc = [
        {
            "credentialBindingKey": case["derived"]["credentialBindingKey"],
            "holderCommitment": case["derived"]["holderCommitment"],
        }
        for case in vectors["kdc"]
    ]
    if actual != {"raw": expected_raw, "kdc": expected_kdc}:
        _fail("ZKC runtime contradicts AFP raw or holder-binding vectors")


def validate_zkm(root: Path, profile: dict[str, Any], vectors: dict[str, Any]) -> None:
    expected_constants = _profile_constants(profile)
    constants_path = root / "scripts" / "_poseidon2_constants.py"
    actual_constants = (
        tuple(tuple(row) for row in _python_assignment(constants_path, "ROUND_CONSTANTS")),
        tuple(_python_assignment(constants_path, "INTERNAL_DIAG_MINUS_ONE")),
    )
    _assert_constants("ZKM Python", actual_constants, expected_constants)
    program = (
        "import json,sys;"
        "from poseidon2 import hash_fields;"
        "v=json.load(open(sys.argv[1]));"
        "print(json.dumps([f'0x{hash_fields([int(x,16) for x in c[\"inputs\"]]):064x}' for c in v[\"rawSponge\"]]))"
    )
    actual = _run_json([sys.executable, "-c", program, str(VECTORS_PATH)], root / "scripts")
    if actual != [case["output"] for case in vectors["rawSponge"]]:
        _fail("ZKM runtime contradicts AFP raw sponge vectors")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zka", type=Path)
    parser.add_argument("--zkc", type=Path)
    parser.add_argument("--zkm", type=Path)
    args = parser.parse_args()
    try:
        profile, vectors = validate_local()
        if args.zka:
            validate_zka(args.zka.resolve(), profile, vectors)
        if args.zkc:
            validate_zkc(args.zkc.resolve(), profile, vectors)
        if args.zkm:
            validate_zkm(args.zkm.resolve(), profile, vectors)
    except (ConformanceError, OSError, ValueError, KeyError) as exc:
        print(f"KDC conformance failed: {exc}", file=sys.stderr)
        return 1
    checked = [name for name in ("ZKA" if args.zka else "", "ZKC" if args.zkc else "", "ZKM" if args.zkm else "") if name]
    suffix = f" and {', '.join(checked)}" if checked else ""
    print(
        "AFP-KDC v1.0.3 registry with v1.0.2 Poseidon2 profile and vectors"
        f"{suffix} is conformant"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
