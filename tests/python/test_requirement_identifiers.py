"""Requirement identifiers and the requirement index (ADR-0013 section 4)."""

import _path  # noqa: F401

import copy
import os
import subprocess
import hashlib
import json
import pathlib
import re
import shutil
import tempfile
import unittest
import unittest.mock

from scripts import afp_requirement_ids as ids

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADING_IDS_SHA256 = "b2a62808c0bd0ca17ee5632a68ed79e7063bcd81c33a5be8722ff857c127647d"
HEADING_IDS_COUNT = 128


def analyze(text, document="docs/afp_specification.md"):
    return ids.analyze(document, text)


class AnalyzerTests(unittest.TestCase):
    def test_sentences_list_items_and_rows_are_the_units(self):
        text = (
            "## 4.1 Example\n\n"
            "A first sentence. The tenant MUST sign. Another sentence MAY follow.\n"
            "- A list item that MUST hold;\n"
            "  and wraps to a second line.\n\n"
            "| a | b |\n|---|---|\n| row MUST hold. Second MAY hold. | x |\n"
        )
        got = [(s.section, s.keywords) for s in analyze(text).statements]
        self.assertEqual(
            got,
            [("4.1", ["MUST"]), ("4.1", ["MAY"]), ("4.1", ["MUST"]), ("4.1", ["MUST", "MAY"])],
        )

    def test_one_marker_for_a_sentence_with_several_keywords(self):
        statements = analyze("The tenant MUST sign and MUST NOT retry, and MAY stop.\n").statements
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0].keywords, ["MUST", "MUST NOT", "MAY"])

    def test_code_fences_comments_headings_and_code_spans_are_not_statements(self):
        text = (
            "## 1. MUST in a heading\n\n"
            "```text\nA fenced line MUST be ignored.\n```\n"
            "<!-- afp-set:include docs/x.md -->\n"
            "A code span `MUST` is not a keyword. An abbreviation e.g. MUST not split.\n"
        )
        got = analyze(text).statements
        self.assertEqual([s.keywords for s in got], [["MUST"]])

    def test_markers_are_transparent_and_must_sit_at_a_statement_start(self):
        text = "A sentence. [AFP-0001] The tenant MUST sign. The tenant MUST stop [AFP-0002] now.\n"
        analysis = analyze(text)
        self.assertEqual([s.marker_id for s in analysis.statements], ["AFP-0001", None])
        self.assertEqual([m for m, _ in analysis.stray], ["AFP-0002"])

    def test_list_and_quote_prefixes_precede_the_marker(self):
        text = "> - [AFP-0001] The tenant MUST sign.\n"
        statement = analyze(text).statements[0]
        self.assertEqual(statement.marker_id, "AFP-0001")


class AnalyzerRegressionTests(unittest.TestCase):
    def test_adjacent_markers_are_both_reported(self):
        statement = analyze("[AFP-9999] [AFP-0001] The tenant MUST sign.\n").statements[0]
        self.assertEqual(statement.marker_id, "AFP-9999")
        self.assertEqual(statement.extra_markers, ("AFP-0001",))

    def test_marker_shaped_text_in_code_is_not_a_marker(self):
        text = (
            "Use `[AFP-9999]` as an example. The tenant MUST sign.\n\n"
            "```text\n[AFP-9998] sample\n```\n\n"
            "Also ``[AFP-9997]`` here. A verifier MAY stop.\n"
        )
        analysis = analyze(text)
        self.assertEqual(analysis.stray, [])
        self.assertEqual([s.marker_id for s in analysis.statements], [None, None])

    def test_sentence_boundaries_after_initials_quotes_and_parentheses(self):
        text = (
            "The tenant MUST validate X. The tenant MUST sign. \"A verifier MUST check.\" "
            "(The relay MUST forward.) See Appendix A. The tenant MAY stop.\n"
        )
        self.assertEqual(len(analyze(text).statements), 5)

    def test_abbreviations_do_not_split(self):
        self.assertEqual(len(analyze("Use a key, e.g. A tenant key, which MUST rotate.\n").statements), 1)

    def test_tenant_subject_mapping(self):
        for text, expected in (
            ("A conforming tenant MUST sign.", "tenant"),
            ("Every tenant MUST emit cover traffic.", "tenant"),
            ("Tenants MUST reject expired directories.", "tenant"),
            ("The tenant's operator MUST NOT observe it.", "implementation"),
            ("A relay MUST forward.", "implementation"),
        ):
            with self.subTest(text):
                self.assertEqual(ids.applies_to(ids.ROUTING, "8.7", text), expected)
        self.assertEqual(ids.applies_to(ids.CORE, "15.2", "A tenant MUST sign."), "pay")
        self.assertEqual(ids.applies_to(ids.CORE, "1.5.1", "A relay MUST forward."), "tenant")


class BaseComparisonTests(unittest.TestCase):
    def entry(self, number, **over):
        base = {
            "id": f"AFP-{number:04d}", "document": ids.CORE, "section": "1", "keywords": ["MUST"],
            "applies_to": "implementation", "status": "active",
            "introduced_in": {"document": ids.CORE, "document_revision": 1}, "superseded_by": None,
        }
        base.update(over)
        return base

    def test_dropped_tail_entry_is_caught(self):
        base = {"entries": [self.entry(1), self.entry(2)]}
        self.assertTrue(ids.compare_to_base({"entries": [self.entry(1)]}, base))
        self.assertEqual(ids.compare_to_base(base, base), [])

    def test_resurrection_and_subject_change_are_caught(self):
        tomb = self.entry(2, status="withdrawn", withdrawn_in={"document": ids.CORE, "document_revision": 2})
        base = {"entries": [self.entry(1), tomb]}
        revived = {"entries": [self.entry(1, applies_to="tenant"), self.entry(2)]}
        problems = ids.compare_to_base(revived, base)
        self.assertTrue(any("applies_to" in p for p in problems) and any("active again" in p for p in problems))

    def test_reviewed_label_correction_is_allowed_and_accidental_change_is_not(self):
        base = {"entries": [self.entry(1)]}
        accidental = {"entries": [self.entry(1, applies_to="tenant")]}
        self.assertTrue(any("applies_to_correction" in p for p in ids.compare_to_base(accidental, base)))
        corrected = {"entries": [self.entry(
            1, applies_to="tenant",
            applies_to_correction={"from": "implementation", "reason": "A tenant is the subject of the obligation."},
        )]}
        self.assertEqual(ids.compare_to_base(corrected, base), [])
        wrong_origin = {"entries": [self.entry(
            1, applies_to="tenant",
            applies_to_correction={"from": "pay", "reason": "A tenant is the subject of the obligation."},
        )]}
        self.assertTrue(ids.compare_to_base(wrong_origin, base))

    def test_repository_index_matches_itself(self):
        index = json.loads(ids.INDEX_PATH.read_text())
        self.assertEqual(ids.compare_to_base(index, index), [])


class FenceTests(unittest.TestCase):
    CASES = {
        "indented fence": "  ```\n  [AFP-9999] sample\n  ```\n",
        "block-quote fence": "> ```\n> [AFP-9999] sample\n> ```\n",
        "long closing fence": "````text\n[AFP-9999] sample\n`````\n",
        "tilde fence": "~~~\n[AFP-9999] sample\n~~~\n",
        "indented code block": "Intro paragraph.\n\n    [AFP-9999] sample\n",
    }

    def test_analyzer_ignores_markers_in_every_code_form(self):
        for name, block in self.CASES.items():
            with self.subTest(name):
                analysis = analyze(block + "\nA relay MUST forward.\n")
                self.assertEqual(analysis.markers, [])
                self.assertEqual(analysis.stray, [])


class HistoryComparisonTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True)

    def repo(self, index=None):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        self.git(root, "init", "-q", "-b", "main")
        self.git(root, "config", "user.email", "t@example.invalid")
        self.git(root, "config", "user.name", "t")
        (root / "docs").mkdir()
        (root / "docs/other.md").write_text("x\n")
        if index is not None:
            (root / "docs/afp_requirement_index.json").write_text(json.dumps(index))
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", "base")
        self.git(root, "checkout", "-q", "-b", "feature")
        return root

    def test_first_introduction_is_explicit(self):
        root = self.repo()
        self.assertEqual(ids.base_index_from_history(root), ("first-introduction", None))

    def test_unavailable_base_is_reported(self):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        self.git(root, "init", "-q", "-b", "other")
        self.assertEqual(ids.base_index_from_history(root)[0], "unavailable")

    def commit_all(self, root, message, index=None):
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs/other.md").write_text(message + "\n")
        if index is not None:
            (root / "docs/afp_requirement_index.json").write_text(json.dumps(index))
        self.git(root, "add", "-A")
        self.git(
            root, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
            "-c", "commit.gpgsign=false", "commit", "-q", "-m", message,
        )

    def isolated_repo(self, branch):
        """An empty repository whose only branch is ``branch``, with no ``main``."""
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        self.git(root, "init", "-q", "-b", branch)
        return root

    def without_base_sha(self):
        patcher = unittest.mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AFP_BASE_SHA", None)

    def test_complete_root_commit_without_a_base_is_a_first_introduction(self):
        self.without_base_sha()
        root = self.isolated_repo("candidate")
        self.commit_all(root, "candidate")
        self.assertEqual(self.git(root, "rev-list", "--parents", "-n1", "HEAD").stdout.split(), [
            self.git(root, "rev-parse", "HEAD").stdout.strip()
        ])
        self.assertEqual(ids.base_index_from_history(root), ("first-introduction", None))

    def test_explicit_base_wins_over_the_root_commit_rule(self):
        root = self.isolated_repo("candidate")
        index = json.loads(ids.INDEX_PATH.read_text())
        self.commit_all(root, "candidate", index)
        head = self.git(root, "rev-parse", "HEAD").stdout.strip()
        with unittest.mock.patch.dict(os.environ, {"AFP_BASE_SHA": head}):
            status, base = ids.base_index_from_history(root)
        self.assertEqual((status, base), ("found", index))

    def test_commit_with_a_parent_and_no_base_is_unavailable(self):
        self.without_base_sha()
        root = self.isolated_repo("candidate")
        self.commit_all(root, "first")
        self.commit_all(root, "second")
        self.assertEqual(ids.base_index_from_history(root), ("unavailable", None))

    def test_shallow_checkout_that_looks_like_a_root_commit_is_unavailable(self):
        self.without_base_sha()
        source = self.isolated_repo("candidate")
        self.commit_all(source, "first")
        self.commit_all(source, "second")
        clone = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, clone)
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", f"file://{source}", str(clone / "work")],
            check=True, capture_output=True, text=True,
        )
        work = clone / "work"
        self.assertEqual(self.git(work, "rev-parse", "--is-shallow-repository").stdout.strip(), "true")
        self.assertEqual(len(self.git(work, "rev-list", "--parents", "-n1", "HEAD").stdout.split()), 1)
        self.assertEqual(ids.base_index_from_history(work), ("unavailable", None))

    def test_base_index_is_read_from_the_merge_base(self):
        index = json.loads(ids.INDEX_PATH.read_text())
        root = self.repo(index)
        status, base = ids.base_index_from_history(root)
        self.assertEqual(status, "found")
        self.assertEqual(ids.compare_to_base(index, base), [])
        shortened = {"format": index["format"], "entries": index["entries"][:-1]}
        self.assertTrue(ids.compare_to_base(shortened, base))

    def test_candidate_index_is_compared_with_the_target_branch_in_ci(self):
        status, base = ids.base_index_from_history()
        in_ci = any(os.environ.get(name) for name in ("CI", "GITHUB_ACTIONS", "FORGEJO_ACTIONS"))
        if status == "unavailable":
            if in_ci:
                self.fail("CI must provide a base commit for the identifier history comparison")
            self.skipTest("no base commit resolvable outside CI")
        if base is not None:
            self.assertEqual(ids.compare_to_base(json.loads(ids.INDEX_PATH.read_text()), base), [])


class AllocationFloorTests(unittest.TestCase):
    """The highest allocated serial per prefix. A PR that allocates raises it; no PR lowers it.

    A single tree cannot show that the tail identifier was deleted and then
    reissued (``check --base-index`` compares with main). This pin makes the
    same rule fail in CI without a base: deleting an entry above the floor, or
    lowering the floor, is a visible edit to this constant.
    """

    FLOOR = {"AFP": 520, "KDC": 22}

    def test_no_identifier_up_to_the_floor_is_missing_or_reused(self):
        index = json.loads(ids.INDEX_PATH.read_text())
        present = {e["id"] for e in index["entries"]}
        for prefix, floor in self.FLOOR.items():
            for number in range(1, floor + 1):
                self.assertIn(f"{prefix}-{number:04d}", present)
        for prefix, floor in self.FLOOR.items():
            top = max(ids.serial(i) for i in present if i.startswith(prefix))
            self.assertEqual(top, floor, "raise FLOOR in the PR that allocates")


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        for relative in ids.members():
            target = self.tmp / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, target)
        self.index_path = self.tmp / "index.json"
        shutil.copy(ids.INDEX_PATH, self.index_path)
        self.index = json.loads(self.index_path.read_text())

    def problems(self, index=None):
        if index is not None:
            self.index_path.write_text(json.dumps(index))
        return ids.check(self.index_path, self.tmp, ROOT / "protocol-family/afp-interface-surface-v1.json")

    def test_repository_index_and_markers_agree(self):
        self.assertEqual(ids.check(), [])
        self.assertEqual(self.index["format"], "afp:requirement-index:v1")

    def test_every_entry_has_the_required_fields_and_section(self):
        for entry in self.index["entries"]:
            self.assertTrue(entry["section"], entry["id"])
            self.assertTrue(entry["keywords"], entry["id"])
            self.assertIn(entry["status"], ("active", "withdrawn"), entry["id"])
            if entry["status"] == "withdrawn":
                self.assertEqual(
                    entry["withdrawn_in"]["document"], entry["document"], entry["id"]
                )
            self.assertEqual(
                entry["introduced_in"]["document"], entry["document"], entry["id"]
            )

    def test_validator_catches_each_rule_violation(self):
        first = self.index["entries"][0]["id"]
        kdc = (self.tmp / ids.KDC)
        original = kdc.read_text()
        cases = {}
        mutated = copy.deepcopy(self.index)
        mutated["entries"].append(dict(mutated["entries"][0]))
        cases["reused id"] = mutated
        mutated = copy.deepcopy(self.index)
        mutated["entries"] = [e for e in mutated["entries"] if e["id"] != first]
        cases["entry without marker"] = mutated
        mutated = copy.deepcopy(self.index)
        mutated["entries"][0]["status"] = "withdrawn"
        mutated["entries"][0]["withdrawn_in"] = {"document": ids.CORE, "document_revision": 1}
        cases["withdrawn entry with live marker"] = mutated
        mutated = copy.deepcopy(self.index)
        mutated["entries"][0]["keywords"] = ["SHOULD"]
        cases["keywords drift"] = mutated
        mutated = copy.deepcopy(self.index)
        mutated["entries"][0]["superseded_by"] = "AFP-9999"
        cases["unknown successor"] = mutated
        for name, bad in cases.items():
            with self.subTest(name):
                self.assertTrue(self.problems(bad), name)
        self.assertEqual(self.problems(self.index), [])

        marker = re.search(r"\[KDC-0001\] ", original)
        for name, text in {
            "missing marker": original.replace("[KDC-0001] ", "", 1),
            "duplicate marker": original.replace("[KDC-0002]", "[KDC-0001]", 1),
            "link definition": original + "\n[KDC-0001]: https://example.invalid\n",
            "stray marker": original.replace("MUST be generated", "MUST [KDC-0001] be generated", 1),
            "marker without keyword": original.replace("# AFP Key Derivation Core", "[KDC-0001] x\n\n# AFP Key Derivation Core", 1),
        }.items():
            with self.subTest(name):
                self.assertIsNotNone(marker)
                kdc.write_text(text)
                self.assertTrue(self.problems(self.index), name)
        kdc.write_text(original)
        self.assertEqual(self.problems(self.index), [])

    def test_correction_record_shape_is_validated(self):
        for bad in (
            {"from": "implementation", "reason": "short"},
            {"from": "implementation", "reason": "A reason that is long enough to count."},
            {"reason": "A reason that is long enough to count."},
        ):
            with self.subTest(bad):
                mutated = copy.deepcopy(self.index)
                mutated["entries"][0]["applies_to_correction"] = bad
                self.assertTrue(any("applies_to_correction" in p for p in self.problems(mutated)))

    def test_changed_statement_text_without_index_update_fails(self):
        kdc = self.tmp / ids.KDC
        original = kdc.read_text()
        kdc.write_text(original.replace("MUST be generated", "MUST be produced", 1))
        problems = self.problems(self.index)
        kdc.write_text(original)
        self.assertTrue(any("text_sha256" in p for p in problems), problems)
        self.assertEqual(self.problems(self.index), [])

    def test_text_digest_ignores_whitespace_layout_only(self):
        self.assertEqual(ids.text_digest("A tenant MUST sign.\n"), ids.text_digest("A  tenant\nMUST sign."))
        self.assertNotEqual(ids.text_digest("A tenant MUST sign."), ids.text_digest("A tenant MAY sign."))

    def test_serials_must_not_skip(self):
        mutated = copy.deepcopy(self.index)
        mutated["entries"] = [e for e in mutated["entries"] if e["id"] != "KDC-0003"]
        self.assertTrue(any("contiguous" in p for p in self.problems(mutated)))

    def test_kdc_statements_use_the_kdc_prefix(self):
        for entry in self.index["entries"]:
            if entry["document"] == ids.KDC:
                self.assertTrue(entry["id"].startswith("KDC-"))
                self.assertEqual(entry["applies_to"], "kdc")
            else:
                self.assertTrue(entry["id"].startswith("AFP-"))

    def test_index_is_outside_the_interface_surface(self):
        surface = (ROOT / "protocol-family/afp-interface-surface-v1.json").read_text()
        manifest = (ROOT / "protocol-family/interface-manifest-v1.json").read_text()
        self.assertNotIn("afp_requirement_index", surface)
        self.assertNotIn("afp_requirement_index", manifest)


class GuideCitationTests(unittest.TestCase):
    """ADR-0013 section 4: the guide carries no marker, and each guide section cites the identifiers it serves."""

    GUIDE = ROOT / "docs/afp_implementation_security_guide.md"

    def test_each_mechanism_section_cites_active_identifiers(self):
        guide = self.GUIDE.read_text()
        index = {e["id"]: e for e in json.loads(ids.INDEX_PATH.read_text())["entries"]}
        self.assertEqual(ids.MARKER_RE.findall(guide), [])
        sections = re.split(r"\n(?=#{2,3} (?:[2-5]\.|4\.\d))", guide)[1:]
        self.assertEqual(len(sections), 10)
        for section in sections:
            heading = section.splitlines()[0]
            if heading.startswith("## 4. "):
                continue
            with self.subTest(heading):
                served = re.search(r"^\*\*Serves:\*\* (.+)\.$", section, re.MULTILINE)
                self.assertIsNotNone(served)
                cited = re.findall(r"\b(?:AFP|KDC)-\d{4,}\b", served.group(1))
                self.assertTrue(cited)
                for identifier in cited:
                    self.assertEqual(index[identifier]["status"], "active", identifier)


class WebsiteAnchorTests(unittest.TestCase):
    def test_each_marker_has_one_anchor_and_headings_are_stable(self):
        page = (ROOT / "website/spec/index.html").read_text()
        index = json.loads(ids.INDEX_PATH.read_text())
        anchors = re.findall(r'<span id="((?:AFP|KDC)-\d{4,})">\[\1\]</span>', page)
        self.assertEqual(sorted(anchors), sorted(e["id"] for e in index["entries"] if e["status"] == "active"))
        all_ids = re.findall(r'\bid="([^"]+)"', page)
        self.assertEqual(len(all_ids), len(set(all_ids)))
        headings = re.findall(r'<h[1-6] id="([^"]+)"', page)
        self.assertEqual(len(headings), HEADING_IDS_COUNT)
        self.assertEqual(
            hashlib.sha256("\n".join(sorted(headings)).encode()).hexdigest(), HEADING_IDS_SHA256
        )


if __name__ == "__main__":
    unittest.main()
