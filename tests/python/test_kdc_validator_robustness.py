"""Fail-closed behavior for cross-repository AFP-KDC runtime probes."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _path  # noqa: F401

from scripts.validate_kdc_conformance import (
    ConformanceError,
    _run_json,
    validate_zka,
)


class KdcValidatorRobustnessTests(unittest.TestCase):
    def test_runtime_probe_timeout_is_a_conformance_error(self):
        with mock.patch(
            "scripts.validate_kdc_conformance.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["probe"], 300),
        ) as run:
            with self.assertRaisesRegex(ConformanceError, "timed out"):
                _run_json(["probe"], Path("."))
        self.assertEqual(run.call_args.kwargs["timeout"], 300)

    def test_zka_missing_zero_cases_fail_without_stop_iteration(self):
        cases = (
            ({"kdc": []}, {"vectors": []}, "shared vectors omit"),
            (
                {
                    "kdc": [
                        {
                            "name": "zero",
                            "seed": "0x" + "00" * 32,
                            "derived": {},
                        }
                    ]
                },
                {"vectors": []},
                "ZKA key_derivation.json omits",
            ),
        )
        for shared, zka, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                vector_path = root / "tests" / "vectors" / "crypto"
                vector_path.mkdir(parents=True)
                (vector_path / "key_derivation.json").write_text(
                    json.dumps(zka), encoding="utf-8"
                )
                with (
                    mock.patch(
                        "scripts.validate_kdc_conformance._profile_constants",
                        return_value=((), ()),
                    ),
                    mock.patch(
                        "scripts.validate_kdc_conformance._rust_constants",
                        return_value=((), ()),
                    ),
                ):
                    with self.assertRaisesRegex(ConformanceError, message):
                        validate_zka(root, {}, shared)

    def test_zka_consumer_fields_must_be_canonical(self):
        seed = "0x" + "00" * 32
        shared = {
            "kdc": [
                {
                    "name": "zero",
                    "seed": seed,
                    "derived": {"spendingKey": "0x" + "00" * 32},
                }
            ]
        }
        zka = {
            "vectors": [
                {
                    "master_seed": seed,
                    "expected_keys": {"spending_key": "0X" + "00" * 32},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vector_path = root / "tests" / "vectors" / "crypto"
            vector_path.mkdir(parents=True)
            (vector_path / "key_derivation.json").write_text(
                json.dumps(zka), encoding="utf-8"
            )
            with (
                mock.patch(
                    "scripts.validate_kdc_conformance._profile_constants",
                    return_value=((), ()),
                ),
                mock.patch(
                    "scripts.validate_kdc_conformance._rust_constants",
                    return_value=((), ()),
                ),
            ):
                with self.assertRaisesRegex(ConformanceError, "noncanonical"):
                    validate_zka(root, {}, shared)


if __name__ == "__main__":
    unittest.main()
