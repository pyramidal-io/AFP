"""Ed25519 (RFC 8032) reference tests, including the canonical KAT vector."""

import _path  # noqa: F401

import ast
import hashlib
import re
import unittest
from pathlib import Path

from afp_session import ed25519

pytestmark = None

# Canonical E[8] encodings from Taming the many EdDSAs. Source:
# novifinancial/ed25519-speccheck@65519336fda78a3d016e947df6d82848aca0c9da,
# src/main.rs.
# Paper: https://eprint.iacr.org/2020/1244
_TORSION_VECTORS = tuple(
    (bytes.fromhex(encoded), order)
    for encoded, order in (
        ("00" * 32, 4),
        ("00" * 31 + "80", 4),
        ("01" + "00" * 31, 1),
        ("ec" + "ff" * 30 + "7f", 2),
        (
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            8,
        ),
        (
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            8,
        ),
        (
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            8,
        ),
        (
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            8,
        ),
    )
)
_TORSION_ENCODINGS = tuple(encoded for encoded, _order in _TORSION_VECTORS)

_IDENTITY = b"\x01" + b"\x00" * 31
_BASE_POINT = b"\x58" + b"\x66" * 31
_POINT_42B = bytes.fromhex(
    "ce1a32994e835c193e2bf33909f44373ae2cf94ddef0fd922035c483670637c2"
)

# Canonical suite vector 3: both A and R are mixed-order and the signature
# succeeds unless full-order membership is checked.
# Source: novifinancial/ed25519-speccheck at the revision above, cases.json.
_MIXED_ORDER_MESSAGE = bytes.fromhex(
    "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79"
)
_MIXED_ORDER_PUBLIC_KEY = bytes.fromhex(
    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d"
)
_MIXED_ORDER_SIGNATURE = bytes.fromhex(
    "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
    "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"
)
_MIXED_ORDER_R = bytes.fromhex(
    "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f"
)

_RFC8032_MESSAGE = b""
_RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
    "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
_RFC8032_NONEMPTY_MESSAGE = bytes.fromhex("72")
_RFC8032_NONEMPTY_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
_RFC8032_NONEMPTY_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)
_SHORT_KEY_PADDING_MESSAGE = b"afp-ed25519-short-key-padding"
_SHORT_KEY_PADDING_PUBLIC_KEY = bytes.fromhex(
    "6745500eda4ab1ad47d2ce855c4a9f4604f89abca2a4561cf0d9ccaacb0c0700"
)
_SHORT_KEY_PADDING_SIGNATURE = bytes.fromhex(
    "269cf83488cf0526154c7d28691690e1f207bc7e458413e182a87c761c6c720b"
    "96bd2ea7f8b51b35c2612b71732461511dda569ff249ca887fe24e266d7f0c0c"
)
_RFC8032_SIGNATURE_S_PLUS_L = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901554"
    "c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b"
)

# A mixed-order public key paired with a prime-order R. The equation succeeds
# for a verifier that omits full-order validation of A.
_MIXED_ORDER_A_ONLY_MESSAGE = b"afp-ed25519-mixed-order-a:\x02\x00"
_MIXED_ORDER_A_ONLY_PUBLIC_KEY = bytes.fromhex(
    "16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5"
)
_MIXED_ORDER_A_ONLY_SIGNATURE = bytes.fromhex(
    "ce1a32994e835c193e2bf33909f44373ae2cf94ddef0fd922035c483670637c2"
    "5f4146805d928192fd9ba6909fc0c1db061f91cefe0d08138d9be32ea6765406"
)

# A mixed-order R paired with the RFC vector's prime-order A. This equation
# succeeds under cofactored verification unless R is rejected first.
_MIXED_ORDER_R_ONLY_MESSAGE = b"afp-ed25519-mixed-order-r:v1"
_MIXED_ORDER_R_ONLY_SIGNATURE = bytes.fromhex(
    "1fe5cd66b17ca3e6c1d40cc6f60bbc8c51d306b2210f026ddfca3b7c98f9c83d"
    "69e340dbfd61f1f4b40e79cc72b8d9acdd2b23d7c640a11a4516f7b8ae08b80a"
)

_NONCANONICAL_A_MESSAGE = b"afp-ed25519-noncanonical-a:\x14\x00"
_NONCANONICAL_A = b"\xed" + b"\xff" * 30 + b"\x7f"
_NONCANONICAL_R_MESSAGE = b"afp-ed25519-noncanonical-r:y=p+1"
_NONCANONICAL_R = b"\xee" + b"\xff" * 30 + b"\x7f"
_NONCANONICAL_R_SCALAR = bytes.fromhex(
    "5cff36833def3514e2eb5c3c6419792e6585d5a8bc2bc56a886c32ba00b70903"
)
_NEGATIVE_ZERO_R_MESSAGE = b"afp-negative-zero-r-conformance-gap"
_NEGATIVE_ZERO_R_SIGNATURE = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000080"
    "7f5e42127c9f1d8870b3c2704f8f31436a10e7eb9422b7bc7d7dde36ac2cef0a"
)

_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_STRICT_VERIFY_CALLS = {
    "python/afp_ceremony/authority.py": 2,
    "python/afp_mixnet/directory.py": 1,
    "python/afp_payment/authentication.py": 1,
    "python/afp_session/channel.py": 4,
    "python/afp_session/commitment.py": 1,
    "python/afp_session/dispute.py": 2,
    "python/afp_session/keri.py": 2,
    "python/afp_session/session.py": 1,
}


def _inspect_strict_boundary_calls(source, filename):
    """Count direct strict calls and reject alternate verifier references."""
    tree = ast.parse(source, filename=filename)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    strict_calls = 0
    forbidden = []
    valid_binding_count = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                local_name = imported.asname or imported.name.split(".", 1)[0]
                if local_name == "ed25519" or imported.name.endswith(".ed25519"):
                    forbidden.append(
                        f"{filename}:{node.lineno}: unsupported ed25519 import"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for imported in node.names:
                local_name = imported.asname or imported.name
                valid_relative_import = (
                    Path(filename).parent == Path("python/afp_session")
                    and node.level == 1
                    and module == ""
                    and imported.name == "ed25519"
                    and local_name == "ed25519"
                )
                valid_absolute_import = (
                    node.level == 0
                    and module == "afp_session"
                    and imported.name == "ed25519"
                    and local_name == "ed25519"
                )
                if valid_relative_import or valid_absolute_import:
                    valid_binding_count += 1
                    continue
                if imported.name == "*":
                    forbidden.append(
                        f"{filename}:{node.lineno}: wildcard import can replace "
                        "the ed25519 binding"
                    )
                if module.endswith("ed25519") and imported.name in {
                    "verify",
                    "verify_strict",
                }:
                    forbidden.append(
                        f"{filename}:{node.lineno}: imported verifier alias"
                    )
                if local_name == "ed25519" or imported.name == "ed25519":
                    forbidden.append(
                        f"{filename}:{node.lineno}: unsupported ed25519 import"
                    )

        if (
            isinstance(node, ast.Name)
            and node.id == "ed25519"
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            forbidden.append(
                f"{filename}:{node.lineno}: rebound ed25519 module"
            )
        if isinstance(node, ast.arg) and node.arg == "ed25519":
            forbidden.append(
                f"{filename}:{node.lineno}: shadowed ed25519 module"
            )
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "ed25519":
                forbidden.append(
                    f"{filename}:{node.lineno}: shadowed ed25519 module"
                )
        if isinstance(node, ast.ExceptHandler) and node.name == "ed25519":
            forbidden.append(
                f"{filename}:{node.lineno}: shadowed ed25519 module"
            )

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Name) and value.id == "ed25519":
                forbidden.append(
                    f"{filename}:{node.lineno}: captured ed25519 module alias"
                )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if (
                node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "ed25519"
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in {"verify", "verify_strict"}
            ):
                forbidden.append(
                    f"{filename}:{node.lineno}: dynamically selected verifier"
                )

        if not (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "ed25519"
            and node.attr in {"verify", "verify_strict"}
        ):
            continue
        parent = parents.get(node)
        is_direct_call = isinstance(parent, ast.Call) and parent.func is node
        if node.attr == "verify_strict" and is_direct_call:
            strict_calls += 1
        else:
            forbidden.append(
                f"{filename}:{node.lineno}: non-strict or captured verifier"
            )

    if strict_calls and valid_binding_count != 1:
        forbidden.append(
            f"{filename}: strict verifier calls require exactly one supported "
            "afp_session.ed25519 import"
        )

    return strict_calls, forbidden


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_test_vector_1(self):
        # RFC 8032 Section 7.1, TEST 1 (empty message).
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        pk = ed25519.public_key_from_seed(seed)
        self.assertEqual(pk, _RFC8032_PUBLIC_KEY)
        sig = ed25519.sign(_RFC8032_MESSAGE, seed)
        self.assertEqual(sig, _RFC8032_SIGNATURE)
        self.assertTrue(
            ed25519.verify(_RFC8032_MESSAGE, _RFC8032_SIGNATURE, pk)
        )

    def test_sign_verify_roundtrip(self):
        seed = ed25519.generate_seed()
        pk = ed25519.public_key_from_seed(seed)
        msg = b"afp session core"
        sig = ed25519.sign(msg, seed)
        self.assertTrue(ed25519.verify(msg, sig, pk))

    def test_tampered_message_rejected(self):
        seed = ed25519.generate_seed()
        pk = ed25519.public_key_from_seed(seed)
        sig = ed25519.sign(b"original", seed)
        self.assertFalse(ed25519.verify(b"tampered", sig, pk))

    def test_tampered_signature_rejected(self):
        seed = ed25519.generate_seed()
        pk = ed25519.public_key_from_seed(seed)
        sig = bytearray(ed25519.sign(b"msg", seed))
        sig[0] ^= 0x01
        self.assertFalse(ed25519.verify(b"msg", bytes(sig), pk))

    def test_wrong_key_rejected(self):
        seed1 = ed25519.generate_seed()
        seed2 = ed25519.generate_seed()
        pk2 = ed25519.public_key_from_seed(seed2)
        sig = ed25519.sign(b"msg", seed1)
        self.assertFalse(ed25519.verify(b"msg", sig, pk2))

    def test_malformed_inputs_return_false_not_raise(self):
        seed = ed25519.generate_seed()
        pk = ed25519.public_key_from_seed(seed)
        sig = ed25519.sign(b"m", seed)

        class BytesSubclass(bytes):
            pass

        self.assertFalse(ed25519.verify(b"m", b"too-short", pk))
        self.assertFalse(ed25519.verify(b"m", b"\x00" * 64, b"short-key"))
        self.assertFalse(ed25519.verify(None, sig, pk))
        self.assertFalse(ed25519.verify(b"m", None, pk))
        self.assertFalse(ed25519.verify(b"m", b"\x00" * 64, None))
        self.assertFalse(ed25519.verify(bytearray(b"m"), sig, pk))
        self.assertFalse(ed25519.verify(b"m", bytearray(sig), pk))
        self.assertFalse(ed25519.verify(BytesSubclass(b"m"), sig, pk))
        self.assertFalse(ed25519.verify(b"m", BytesSubclass(sig), pk))

    def test_seed_size_validation(self):
        with self.assertRaises(ValueError):
            ed25519.public_key_from_seed(b"\x00" * 16)
        with self.assertRaises(ValueError):
            ed25519.sign(b"m", b"\x00" * 16)

    def test_public_key_ingestion_validation(self):
        seed = b"\x07" * 32
        public_key = ed25519.public_key_from_seed(seed)
        self.assertIsNone(ed25519.validate_public_key(public_key))

        class AliasedBytes(bytes):
            def __new__(cls, value, alias):
                instance = super().__new__(cls, value)
                instance.alias = alias
                return instance

            def __hash__(self):
                return hash(self.alias)

            def __eq__(self, other):
                return self.alias == other

        message = b"public-key-subclass"
        signature = ed25519.sign(message, seed)
        self.assertFalse(
            ed25519.verify(
                message, signature, AliasedBytes(public_key, public_key)
            )
        )

        invalid_keys = (
            None,
            bytearray(public_key),
            AliasedBytes(_IDENTITY, public_key),
            b"\x00" * 31,
            b"\x00" * 33,
            *_TORSION_ENCODINGS,
            _MIXED_ORDER_PUBLIC_KEY,
            _MIXED_ORDER_R,
            ed25519._P.to_bytes(32, "little"),
            b"\x01" + b"\x00" * 30 + b"\x80",
        )
        for invalid_key in invalid_keys:
            with self.subTest(public_key=invalid_key), self.assertRaises(ValueError):
                ed25519.validate_public_key(invalid_key)

    def test_decode_point_rejects_noncanonical_y_coordinates(self):
        for y in (ed25519._P, ed25519._P + 1, (1 << 255) - 1):
            with self.subTest(y=y), self.assertRaisesRegex(
                ValueError, "non-canonical y-coordinate"
            ):
                ed25519._decode_point(y.to_bytes(32, "little"))

    def test_decode_point_rejects_noncanonical_negative_zero(self):
        encoded = b"\x01" + b"\x00" * 30 + b"\x80"
        with self.assertRaisesRegex(ValueError, "non-canonical sign for x=0"):
            ed25519._decode_point(encoded)

    def test_decode_point_rejects_all_torsion_points(self):
        self.assertEqual(len(set(_TORSION_ENCODINGS)), 8)
        for encoded in _TORSION_ENCODINGS:
            with self.subTest(encoded=encoded.hex()), self.assertRaisesRegex(
                ValueError, "small order"
            ):
                ed25519._decode_point(encoded)

    def test_verify_rejects_all_identity_public_key_forgeries(self):
        self.assertEqual(
            _POINT_42B, ed25519._encode_point(ed25519._scalarmult(ed25519._B, 42))
        )
        for name, message, signature in (
            (
                "R=identity,S=0",
                b"afp-ed25519-identity-forgery:identity-R-S0:0000",
                _IDENTITY + b"\x00" * 32,
            ),
            (
                "R=42B,S=42",
                b"afp-ed25519-identity-forgery:R-42B-S42:0000",
                _POINT_42B + (42).to_bytes(32, "little"),
            ),
            (
                "R=B,S=1",
                b"afp-ed25519-identity-forgery:R-B-S1:0000",
                _BASE_POINT + (1).to_bytes(32, "little"),
            ),
        ):
            with self.subTest(name=name):
                self.assertFalse(ed25519.verify(message, signature, _IDENTITY))

    def test_verify_rejects_all_torsion_points_in_a_and_r(self):
        scalar = (1).to_bytes(32, "little")
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        for encoded in _TORSION_ENCODINGS:
            with self.subTest(location="A", encoded=encoded.hex()):
                self.assertFalse(
                    ed25519.verify(b"any message", _BASE_POINT + scalar, encoded)
                )
            with self.subTest(location="R", encoded=encoded.hex()):
                self.assertFalse(
                    ed25519.verify(b"any message", encoded + scalar, public_key)
                )

    def test_verify_rejects_grindable_torsion_key_forgeries(self):
        signature = _BASE_POINT + (1).to_bytes(32, "little")
        for index, (public_key, order) in enumerate(_TORSION_VECTORS):
            for counter in range(256):
                message = (
                    f"afp-ed25519-torsion-key-forgery:{index}:".encode("ascii")
                    + counter.to_bytes(4, "big")
                )
                k = int.from_bytes(
                    hashlib.sha512(signature[:32] + public_key + message).digest(),
                    "little",
                ) % ed25519._L
                if k % order == 0:
                    break
            else:
                self.fail(f"no torsion forgery found for order {order}")

            with self.subTest(
                public_key=public_key.hex(), order=order, counter=counter
            ):
                self.assertFalse(ed25519.verify(message, signature, public_key))

    def test_verify_rejects_mixed_order_public_key(self):
        point = ed25519._decode_point(_MIXED_ORDER_PUBLIC_KEY)
        self.assertNotEqual(ed25519._scalarmult(point, ed25519._L), (0, 1))
        self.assertFalse(
            ed25519.verify(
                _MIXED_ORDER_MESSAGE,
                _MIXED_ORDER_SIGNATURE,
                _MIXED_ORDER_PUBLIC_KEY,
            )
        )

    def test_prime_order_decoder_rejects_mixed_order_point(self):
        for encoded in (_MIXED_ORDER_PUBLIC_KEY, _MIXED_ORDER_R):
            with self.subTest(encoded=encoded.hex()), self.assertRaisesRegex(
                ValueError, "prime-order subgroup"
            ):
                ed25519._decode_prime_order_point(encoded)

    def test_signature_scalar_canonicality_boundary(self):
        scalar_l_minus_one = (ed25519._L - 1).to_bytes(32, "little")
        scalar_l = ed25519._L.to_bytes(32, "little")
        self.assertTrue(ed25519._is_canonical_scalar(scalar_l_minus_one))
        self.assertFalse(ed25519._is_canonical_scalar(scalar_l))

        original_s = int.from_bytes(_RFC8032_SIGNATURE[32:], "little")
        self.assertEqual(
            _RFC8032_SIGNATURE_S_PLUS_L[32:],
            (original_s + ed25519._L).to_bytes(32, "little"),
        )
        self.assertTrue(
            ed25519.verify(
                _RFC8032_MESSAGE, _RFC8032_SIGNATURE, _RFC8032_PUBLIC_KEY
            )
        )
        self.assertFalse(
            ed25519.verify(
                _RFC8032_MESSAGE,
                _RFC8032_SIGNATURE_S_PLUS_L,
                _RFC8032_PUBLIC_KEY,
            )
        )

    def test_verify_rejects_noncanonical_points_in_a_and_r(self):
        signature = _BASE_POINT + (1).to_bytes(32, "little")
        self.assertFalse(
            ed25519.verify(
                _NONCANONICAL_A_MESSAGE, signature, _NONCANONICAL_A
            )
        )

        self.assertFalse(
            ed25519.verify(
                _NONCANONICAL_R_MESSAGE,
                _NONCANONICAL_R + _NONCANONICAL_R_SCALAR,
                _RFC8032_PUBLIC_KEY,
            )
        )


class VerifierBackendBoundaryTest(unittest.TestCase):
    @staticmethod
    def _outcomes():
        cases = ed25519.STRICT_VERIFICATION_CASES
        return {
            (case.message, case.signature, case.public_key): case.expected
            for case in cases
        }

    def test_legacy_verify_name_is_the_strict_boundary(self):
        self.assertIs(ed25519.verify, ed25519.verify_strict)

    def test_strict_cases_cover_each_required_semantic(self):
        cases = ed25519.STRICT_VERIFICATION_CASES
        self.assertIsInstance(cases, tuple)
        observed = {
            (case.message, case.signature, case.public_key, case.expected)
            for case in cases
        }
        required = {
            (
                _RFC8032_MESSAGE,
                _RFC8032_SIGNATURE,
                _RFC8032_PUBLIC_KEY,
                True,
            ),
            (
                _RFC8032_NONEMPTY_MESSAGE,
                _RFC8032_NONEMPTY_SIGNATURE,
                _RFC8032_NONEMPTY_PUBLIC_KEY,
                True,
            ),
            (
                _RFC8032_MESSAGE,
                _RFC8032_SIGNATURE + b"\x00",
                _RFC8032_PUBLIC_KEY,
                False,
            ),
            (
                _RFC8032_NONEMPTY_MESSAGE,
                _RFC8032_NONEMPTY_SIGNATURE[:-1],
                _RFC8032_NONEMPTY_PUBLIC_KEY,
                False,
            ),
            (
                _SHORT_KEY_PADDING_MESSAGE,
                _SHORT_KEY_PADDING_SIGNATURE,
                _SHORT_KEY_PADDING_PUBLIC_KEY[:-1],
                False,
            ),
            (
                _RFC8032_MESSAGE,
                _RFC8032_SIGNATURE,
                _RFC8032_PUBLIC_KEY + b"\x00",
                False,
            ),
            (
                _NONCANONICAL_A_MESSAGE,
                _BASE_POINT + (1).to_bytes(32, "little"),
                _NONCANONICAL_A,
                False,
            ),
            (
                _NONCANONICAL_R_MESSAGE,
                _NONCANONICAL_R + _NONCANONICAL_R_SCALAR,
                _RFC8032_PUBLIC_KEY,
                False,
            ),
            (
                _NEGATIVE_ZERO_R_MESSAGE,
                _NEGATIVE_ZERO_R_SIGNATURE,
                _RFC8032_PUBLIC_KEY,
                False,
            ),
            (
                _MIXED_ORDER_A_ONLY_MESSAGE,
                _MIXED_ORDER_A_ONLY_SIGNATURE,
                _MIXED_ORDER_A_ONLY_PUBLIC_KEY,
                False,
            ),
            (
                _MIXED_ORDER_R_ONLY_MESSAGE,
                _MIXED_ORDER_R_ONLY_SIGNATURE,
                _RFC8032_PUBLIC_KEY,
                False,
            ),
            (
                _RFC8032_MESSAGE,
                _RFC8032_SIGNATURE_S_PLUS_L,
                _RFC8032_PUBLIC_KEY,
                False,
            ),
        }
        self.assertTrue(required <= observed)
        self.assertTrue(
            any(
                case.signature == _BASE_POINT + (1).to_bytes(32, "little")
                and case.public_key == _IDENTITY
                and case.expected is False
                for case in cases
            ),
            "strict cases omit the valid-equation identity-key forgery",
        )
        self.assertEqual(len(cases), len(observed))
        self.assertEqual(len(cases), len({case.name for case in cases}))
        for case in cases:
            with self.subTest(case=case.name):
                self.assertIs(type(case.name), str)
                self.assertIs(type(case.message), bytes)
                self.assertIs(type(case.signature), bytes)
                self.assertIs(type(case.public_key), bytes)
                self.assertIs(type(case.expected), bool)

    def test_reference_backend_passes_and_constant_backends_fail(self):
        self.assertIsNone(
            ed25519.validate_verifier_backend(ed25519.verify_strict)
        )
        with self.assertRaises(ValueError):
            ed25519.validate_verifier_backend(lambda *_args: False)
        with self.assertRaises(ValueError):
            ed25519.validate_verifier_backend(lambda *_args: True)

    def test_every_strict_case_is_enforced(self):
        cases = ed25519.STRICT_VERIFICATION_CASES
        outcomes = self._outcomes()
        self.assertEqual(len(outcomes), len(cases))

        for target in cases:
            target_input = (target.message, target.signature, target.public_key)

            def wrong_for_target(message, signature, public_key):
                inputs = (message, signature, public_key)
                expected = outcomes[inputs]
                return not expected if inputs == target_input else expected

            with self.subTest(case=target.name), self.assertRaisesRegex(
                ValueError, re.escape(target.name)
            ):
                ed25519.validate_verifier_backend(wrong_for_target)

    def test_backend_must_return_exact_bool_and_must_not_raise(self):
        outcomes = self._outcomes()

        with self.assertRaises(TypeError):
            ed25519.validate_verifier_backend(None)

        def integer_backend(message, signature, public_key):
            return int(outcomes[(message, signature, public_key)])

        with self.assertRaisesRegex(ValueError, "bool"):
            ed25519.validate_verifier_backend(integer_backend)

        def raising_backend(_message, _signature, _public_key):
            raise RuntimeError("backend unavailable")

        first_case = ed25519.STRICT_VERIFICATION_CASES[0]
        with self.assertRaisesRegex(ValueError, re.escape(first_case.name)) as raised:
            ed25519.validate_verifier_backend(raising_backend)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)

    def test_all_production_consumers_use_the_strict_module_boundary(self):
        observed = {}
        forbidden = []
        production_roots = (
            _ROOT / "python" / "afp_session",
            _ROOT / "python" / "afp_mixnet",
            _ROOT / "python" / "afp_payment",
            _ROOT / "python" / "afp_ceremony",
        )
        for source_root in production_roots:
            for path in source_root.rglob("*.py"):
                relative = path.relative_to(_ROOT).as_posix()
                strict_calls, source_forbidden = _inspect_strict_boundary_calls(
                    path.read_text(encoding="utf-8"), relative
                )
                forbidden.extend(source_forbidden)
                if strict_calls:
                    observed[relative] = strict_calls

        self.assertEqual([], forbidden)
        self.assertEqual(_EXPECTED_STRICT_VERIFY_CALLS, observed)
        self.assertEqual(14, sum(observed.values()))

    def test_consumer_inventory_rejects_alias_and_dynamic_bypasses(self):
        valid_call = (
            "from afp_session import ed25519\n"
            "ed25519.verify_strict(message, signature, public_key)\n"
        )
        bypasses = {
            "direct-legacy": (
                "from afp_session import ed25519\n"
                "ed25519.verify(message, signature, public_key)\n"
            ),
            "from-alias": (
                "from afp_session import ed25519 as crypto\n"
                "crypto.verify(message, signature, public_key)\n"
            ),
            "module-alias": (
                "import afp_session.ed25519 as crypto\n"
                "crypto.verify(message, signature, public_key)\n"
            ),
            "assigned-module": (
                "from afp_session import ed25519\n"
                "crypto = ed25519\n"
                "crypto.verify(message, signature, public_key)\n"
            ),
            "getattr": (
                "from afp_session import ed25519\n"
                "getattr(ed25519, 'verify')(message, signature, public_key)\n"
            ),
            "callback": (
                "from afp_session import ed25519\n"
                "consume(ed25519.verify)\n"
            ),
        }

        strict_calls, forbidden = _inspect_strict_boundary_calls(
            valid_call, "valid.py"
        )
        self.assertEqual(1, strict_calls)
        self.assertEqual([], forbidden)

        strict_calls, forbidden = _inspect_strict_boundary_calls(
            valid_call, "python/afp_session/subsystem/consumer.py"
        )
        self.assertEqual(1, strict_calls)
        self.assertEqual([], forbidden)

        for name, bypass in bypasses.items():
            with self.subTest(name=name):
                strict_calls, forbidden = _inspect_strict_boundary_calls(
                    valid_call + bypass, f"{name}.py"
                )
                self.assertEqual(1, strict_calls)
                self.assertTrue(forbidden, name)

        source_substitutions = {
            "wrong-from-source": (
                "from weakcrypto import ed25519\n"
                "ed25519.verify_strict(message, signature, public_key)\n"
            ),
            "wrong-import-source": (
                "import weakcrypto.ed25519 as ed25519\n"
                "ed25519.verify_strict(message, signature, public_key)\n"
            ),
        }
        for name, substituted_source in source_substitutions.items():
            with self.subTest(name=name):
                strict_calls, forbidden = _inspect_strict_boundary_calls(
                    substituted_source, f"{name}.py"
                )
                self.assertEqual(1, strict_calls)
                self.assertTrue(forbidden, name)

        nested_relative_substitution = (
            "from . import ed25519\n"
            "ed25519.verify_strict(message, signature, public_key)\n"
        )
        strict_calls, forbidden = _inspect_strict_boundary_calls(
            nested_relative_substitution,
            "python/afp_session/subsystem/consumer.py",
        )
        self.assertEqual(1, strict_calls)
        self.assertTrue(forbidden)


if __name__ == "__main__":
    unittest.main()
