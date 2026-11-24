"""Normative AFP-KDC v1.0.2 Poseidon2 profile implementation.

The parameter artifact is the authority: this module deliberately contains no
independent copy of the round constants.  Loading the artifact validates its
shape and canonical constant digest before any conformance calculation runs.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .kdc import BN254_SCALAR_MODULUS, derive_field_tag


PROFILE_FORMAT = "afp-kdc-poseidon2-parameters-v1"
PROFILE_VERSION = "1.0.2"
_CANONICAL_CONSTANT_SHA256 = (
    "8cb18652f4afeac5b6819b156c13fbbc327deacba568b9d8d961ab134123214c"
)
_CANONICAL_FIELD = re.compile(r"0x[0-9a-f]{64}\Z")
_INITIAL_STATE = {
    "lanes_0_to_2": "0",
    "lane_3": {
        "operation": "multiply",
        "left_operand": "input_length",
        "right_operand": {"base": 2, "exponent": 64},
    },
}


class Poseidon2ProfileError(ValueError):
    """The AFP-KDC Poseidon2 profile is malformed or has drifted."""


def _canonical_field(value: Any, label: str) -> int:
    if not isinstance(value, str) or _CANONICAL_FIELD.fullmatch(value) is None:
        raise Poseidon2ProfileError(f"{label} must be canonical 32-byte lowercase hex")
    parsed = int(value, 16)
    if parsed >= BN254_SCALAR_MODULUS:
        raise Poseidon2ProfileError(f"{label} is outside BN254 Fr")
    return parsed


def _parameters(profile: dict[str, Any]) -> tuple[list[list[int]], list[int]]:
    try:
        permutation = profile["permutation"]
        constants = permutation["round_constants"]
        diagonal = permutation["internal_matrix"]["diagonal_minus_one"]
    except (KeyError, TypeError) as exc:
        raise Poseidon2ProfileError("profile omits Poseidon2 parameters") from exc

    expected = {
        "state_width": 4,
        "rate": 3,
        "capacity": 1,
        "capacity_lane": 3,
        "s_box_exponent": 5,
        "full_rounds": 8,
        "partial_rounds": 56,
        "full_round_split": [4, 4],
        "external_matrix": [
            [5, 7, 1, 3],
            [4, 6, 1, 1],
            [1, 3, 5, 7],
            [1, 1, 4, 6],
        ],
    }
    for key, value in expected.items():
        if permutation.get(key) != value:
            raise Poseidon2ProfileError(f"unexpected Poseidon2 parameter {key}")
    field = profile.get("field")
    if not isinstance(field, dict) or field.get("modulus") != str(
        BN254_SCALAR_MODULUS
    ):
        raise Poseidon2ProfileError("unexpected BN254 scalar-field modulus")
    if not isinstance(constants, list) or len(constants) != 64:
        raise Poseidon2ProfileError("round constants must have 64 rows")
    if not isinstance(diagonal, list) or len(diagonal) != 4:
        raise Poseidon2ProfileError("internal diagonal must have four elements")

    parsed_constants: list[list[int]] = []
    for row_index, row in enumerate(constants):
        if not isinstance(row, list) or len(row) != 4:
            raise Poseidon2ProfileError(
                f"round constant row {row_index} must have four lanes"
            )
        parsed_constants.append(
            [
                _canonical_field(value, f"round_constants[{row_index}][{lane}]")
                for lane, value in enumerate(row)
            ]
        )
    parsed_diagonal = [
        _canonical_field(value, f"diagonal_minus_one[{index}]")
        for index, value in enumerate(diagonal)
    ]

    for row_index in range(4, 60):
        if parsed_constants[row_index][1:] != [0, 0, 0]:
            raise Poseidon2ProfileError(
                f"partial-round row {row_index} has a non-zero unused lane"
            )
    return parsed_constants, parsed_diagonal


def validate_constant_digest(profile: dict[str, Any]) -> None:
    """Validate the canonical 260-field, 8,320-byte parameter commitment."""
    constants, diagonal = _parameters(profile)
    values = [value for row in constants for value in row] + diagonal
    encoding = b"".join(value.to_bytes(32, "big") for value in values)
    metadata = profile.get("canonical_constant_encoding")
    if not isinstance(metadata, dict):
        raise Poseidon2ProfileError("profile omits canonical constant encoding metadata")
    if metadata.get("field_element_count") != 260 or len(values) != 260:
        raise Poseidon2ProfileError("constant encoding element count drift")
    if metadata.get("byte_length") != 8320 or len(encoding) != 8320:
        raise Poseidon2ProfileError("constant encoding byte length drift")
    actual = hashlib.sha256(encoding).hexdigest()
    if metadata.get("sha256") != _CANONICAL_CONSTANT_SHA256:
        raise Poseidon2ProfileError(
            "constant digest mismatch: canonical digest metadata has drifted"
        )
    if actual != _CANONICAL_CONSTANT_SHA256:
        raise Poseidon2ProfileError(
            f"constant digest mismatch: canonical digest is "
            f"{_CANONICAL_CONSTANT_SHA256}, got {actual}"
        )


def _validate_profile(profile: dict[str, Any]) -> None:
    if not isinstance(profile, dict):
        raise Poseidon2ProfileError("profile root must be an object")
    if profile.get("format") != PROFILE_FORMAT:
        raise Poseidon2ProfileError("unknown Poseidon2 profile format")
    if profile.get("kdc_version") != PROFILE_VERSION:
        raise Poseidon2ProfileError("profile must identify AFP-KDC v1.0.2")
    if profile.get("status") != "normative":
        raise Poseidon2ProfileError("profile is not normative")
    sponge = profile.get("sponge")
    if not isinstance(sponge, dict) or sponge.get("initial_state") != _INITIAL_STATE:
        raise Poseidon2ProfileError("unexpected sponge initial state")
    validate_constant_digest(profile)


def load_profile(path: str | Path) -> dict[str, Any]:
    """Load and fully validate the normative AFP-KDC v1.0.2 profile."""
    try:
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Poseidon2ProfileError("profile must be readable canonical JSON") from exc
    _validate_profile(profile)
    return profile


def _sbox(value: int) -> int:
    square = value * value % BN254_SCALAR_MODULUS
    fourth = square * square % BN254_SCALAR_MODULUS
    return fourth * value % BN254_SCALAR_MODULUS


def permutation(state: Iterable[int], profile: dict[str, Any]) -> tuple[int, ...]:
    """Apply the exact width-four Poseidon2 permutation pinned by the profile."""
    _validate_profile(profile)
    constants, diagonal = _parameters(profile)
    values = list(state)
    if len(values) != 4 or any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < BN254_SCALAR_MODULUS
        for value in values
    ):
        raise Poseidon2ProfileError("permutation state must be four canonical fields")

    external = profile["permutation"]["external_matrix"]

    def apply_external(current: list[int]) -> list[int]:
        return [
            sum(coefficient * current[lane] for lane, coefficient in enumerate(row))
            % BN254_SCALAR_MODULUS
            for row in external
        ]

    def apply_internal(current: list[int]) -> list[int]:
        total = sum(current) % BN254_SCALAR_MODULUS
        return [
            (total + diagonal[lane] * current[lane]) % BN254_SCALAR_MODULUS
            for lane in range(4)
        ]

    values = apply_external(values)
    for round_index in range(4):
        values = [
            _sbox((values[lane] + constants[round_index][lane]) % BN254_SCALAR_MODULUS)
            for lane in range(4)
        ]
        values = apply_external(values)
    for round_index in range(4, 60):
        values[0] = _sbox((values[0] + constants[round_index][0]) % BN254_SCALAR_MODULUS)
        values = apply_internal(values)
    for round_index in range(60, 64):
        values = [
            _sbox((values[lane] + constants[round_index][lane]) % BN254_SCALAR_MODULUS)
            for lane in range(4)
        ]
        values = apply_external(values)
    return tuple(values)


def hash_fields(inputs: Iterable[int], profile: dict[str, Any]) -> int:
    """Compute the profile's length-bound, rate-three Poseidon2 sponge."""
    _validate_profile(profile)
    values = list(inputs)
    if len(values) > 2**32 - 1:
        raise Poseidon2ProfileError("message exceeds the normative length bound")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < BN254_SCALAR_MODULUS
        for value in values
    ):
        raise Poseidon2ProfileError("sponge inputs must be canonical fields")
    state = [0, 0, 0, len(values) << 64]
    complete_length = len(values) - len(values) % 3
    for start in range(0, complete_length, 3):
        for lane in range(3):
            state[lane] = (state[lane] + values[start + lane]) % BN254_SCALAR_MODULUS
        state = list(permutation(state, profile))
    remainder = len(values) % 3
    if remainder:
        for lane in range(remainder):
            state[lane] = (state[lane] + values[complete_length + lane]) % BN254_SCALAR_MODULUS
    if not values or remainder:
        state = list(permutation(state, profile))
    return state[0]


def seed_to_field(seed: bytes) -> int:
    """Interpret exactly 32 bytes big-endian and reduce modulo BN254 Fr."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise Poseidon2ProfileError("master seed must be exactly 32 bytes")
    return int.from_bytes(seed, "big") % BN254_SCALAR_MODULUS


def derive_kdc_keys(seed: bytes, profile: dict[str, Any]) -> dict[str, int]:
    """Derive every AFP-KDC §A.6 branch from one canonical master seed."""
    _validate_profile(profile)
    seed_field = seed_to_field(seed)

    def derive(tag: str, value: int) -> int:
        return hash_fields([derive_field_tag(tag), value], profile)

    spending = derive("zka/spending", seed_field)
    viewing = derive("zka/viewing", spending)
    proof = derive("zka/proof", spending)
    address = derive("zka/address", viewing)
    credential = derive("zkc/credential", seed_field)
    commitment = derive("zkc/binding", credential)
    return {
        "spendingKey": spending,
        "viewingKey": viewing,
        "proofKey": proof,
        "address": address,
        "credentialBindingKey": credential,
        "holderCommitment": commitment,
    }


__all__ = [
    "PROFILE_FORMAT",
    "PROFILE_VERSION",
    "Poseidon2ProfileError",
    "derive_kdc_keys",
    "hash_fields",
    "load_profile",
    "permutation",
    "seed_to_field",
    "validate_constant_digest",
]
