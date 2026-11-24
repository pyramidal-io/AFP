"""§12.7.1, §12.7.2 and §15.5 state outcomes; the guide holds reference internals."""

import _path  # noqa: F401

from pathlib import Path
import re
import unittest

from scripts.check_afp_interface_surface import specification_text

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs/afp_implementation_security_guide.md"


def section(text: str, heading: str, end: str) -> str:
    start = text.index(heading)
    return text[start:text.index(end, start)]


def normalized(text: str) -> str:
    return " ".join(text.split())


class ImplementationSecurityGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = specification_text()
        cls.coord = section(spec, "#### 12.7.1 ", "#### 12.7.2 ")
        cls.native = section(spec, "#### 12.7.2 ", "### 12.8 ")
        cls.pay = section(spec, "### 15.5 ", "### 15.6 ")
        cls.guide = GUIDE.read_text(encoding="utf-8")

    def test_sections_state_no_reference_internals(self):
        for name, text in (("12.7.1", self.coord), ("12.7.2", self.native), ("15.5", self.pay)):
            for internal in (
                "SQLite", "HMAC", "closure", "monkey-patch", "Python",
                "AcceptedPaymentQuote", "PaymentReceiptVerificationContext",
                "composition root", "constructor", "process-local", "interpreter",
            ):
                with self.subTest(section=name, internal=internal):
                    self.assertNotRegex(text, rf"\b{re.escape(internal)}\b")

    def test_protected_outcomes_stay_normative(self):
        for text, outcome in (
            (self.coord, "The durable record MUST survive a restart of the receiving instance"),
            (self.coord, "A workflow instance's completion is therefore applied at most once, including across a restart."),
            (self.native, "Any later use of an accepted credential MUST confirm that this receiver accepted that exact, unchanged record and that its session is still live"),
            (self.pay, "a stored or transferred token MUST NOT stand in for that state"),
            (self.pay, "it MUST NOT use a quote hash supplied by the caller or the counterparty"),
            (self.pay, "Request data and received records MUST NOT select, replace, or supply any of them"),
            (self.pay, "An accepted quote executes at most once, including across a restart."),
            (self.pay, "A restart MUST NOT clear the durable replay reservation or the route claim."),
            (self.pay, "A deployment MUST NOT run tenant code, plugins, or other untrusted extensions with that authority."),
        ):
            with self.subTest(outcome=outcome):
                self.assertIn(outcome, normalized(text))

    def test_specification_names_the_guide_as_non_normative(self):
        self.assertIn(
            "AFP implementation-security guide (`docs/afp_implementation_security_guide.md`, non-normative)",
            normalized(self.pay),
        )

    def test_guide_is_informative_and_adds_no_requirement(self):
        front = self.guide.split("## 1.", 1)[0]
        self.assertIn("**Status:** Informative. This guide is not part of the AFP specification.", front)
        self.assertRegex(front, r"\*\*Document revision:\*\* \d+ \(\d{4}-\d{2}-\d{2}\)")
        self.assertIn("It adds no requirement and creates no exception.", self.guide)
        self.assertIn("the specification controls (§11)", self.guide)
        self.assertIsNone(
            re.search(r"\b(MUST|SHALL|SHOULD|REQUIRED|RECOMMENDED|OPTIONAL|MAY)\b", self.guide)
        )

    def test_guide_describes_each_moved_mechanism_under_its_section(self):
        for heading, mechanisms in (
            ("## 2. Native credential receive (§12.7.2)", ("AcceptedCredentialEnvelope", "require_verified_native_credential")),
            ("## 3. Coord v2 completion store (§12.7.1)", ("SqliteCoordCompletionStore", "`:memory:`", "`file:` URI")),
            ("### 4.1 Live-session handle", ("VerifiedLiveSession", "rehydrates")),
            ("### 4.2 Accepted capability: `AcceptedPaymentQuote`", ("closure", "direct construction raises")),
            ("### 4.3 Process-local seal", ("HMAC-SHA-256", "hmac.compare_digest", "**not authorization**")),
            ("### 4.4 Composition root: `PaymentReceiptVerificationContext`", ("composition root", "verifier or a time parameter")),
            ("### 4.5 Store-issued limited authority and the issued-instance set", ("weak set of issued views", "SQLiteReplayStore")),
            ("## 5. In-process trust boundary", ("monkey-patch", "KMS or an HSM")),
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.guide)
                body = self.guide.split(heading, 1)[1].split("\n#", 1)[0]
                for mechanism in mechanisms:
                    self.assertIn(mechanism, body)


if __name__ == "__main__":
    unittest.main()
