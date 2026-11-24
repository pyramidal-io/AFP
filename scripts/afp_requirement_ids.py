#!/usr/bin/env python3
"""Requirement identifiers for the AFP specification set (ADR-0013 section 4).

``check`` validates ``docs/afp_requirement_index.json`` against the markers in
the normative members of ``authority.specification_set``. ``allocate`` adds a
marker and an index entry for every statement that has none, in document order.

Statements. A statement is a sentence, a list item or a table row that contains
an upper-case BCP 14 keyword (outside inline code) in a normative member.
Headings, fenced code blocks and HTML comments are never statements. Each
statement carries exactly one marker, the plain token ``[AFP-0123]`` (``KDC-``
in the KDC document), at its start:

* a paragraph or list item is split into sentences; each sentence with a
  keyword is a statement and its marker precedes the sentence text, after any
  list bullet or blockquote prefix;
* a table row is one statement; its marker follows the opening pipe.

The index is on the document axis. It is outside ``interface_set_id``. Each
entry records ``text_sha256``, the SHA-256 of the statement text with the
marker removed and whitespace runs collapsed, so CI fails when a statement and
its index entry differ. A reworded statement with the same obligation keeps
its identifier and updates the digest in the same change; the diff shows it.

Conformance subject. ``applies_to`` records who must satisfy a statement:
``implementation``, ``tenant``, a profile name, or ``kdc``. A statement whose
obligation moves to another subject is a changed obligation: withdraw the old
identifier and allocate a new one (ADR-0013 section 4). A label that was simply
recorded wrongly may be corrected in place with an ``applies_to_correction``
record, ``{"from": <earlier label>, "reason": <why the earlier label was
wrong>}``. The record makes the correction visible in review; it is not
semantic enforcement. The validator checks only its shape (a reason of at
least 20 characters and a ``from`` that differs from the current label), and
``compare_to_base`` accepts a changed label only when ``from`` equals the label
at the base. ``introduced_in`` never changes.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SURFACE = ROOT / "protocol-family" / "afp-interface-surface-v1.json"
INDEX_PATH = ROOT / "docs" / "afp_requirement_index.json"
INDEX_FORMAT = "afp:requirement-index:v1"
CORE = "docs/afp_specification.md"
KDC = "docs/kdc_specification.md"
INTRO = "docs/afp_introduction_profile.md"
ROUTING = "docs/afp_routing_specification.md"
# Members whose every keyword statement must carry a marker. Identifiers are
# introduced member by member; a member joins this tuple in the PR that marks it.
ENFORCED = (CORE, ROUTING, INTRO, KDC)

ID_RE = re.compile(r"^(AFP|KDC)-(\d{4,})$")
MARKER_RE = re.compile(r"\[((?:AFP|KDC)-\d{4,})\]")
LINK_DEFINITION_RE = re.compile(r"^\s{0,3}\[(?:AFP|KDC)-\d{4,}\]:", re.MULTILINE)
KEYWORD_RE = re.compile(
    r"\b(NOT RECOMMENDED|MUST NOT|MUST|REQUIRED|SHALL NOT|SHALL|SHOULD NOT|SHOULD|"
    r"RECOMMENDED|MAY|OPTIONAL)\b"
)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})([^`]*)$|^\s*(~{3,})(.*)$")
QUOTE_PREFIX_RE = re.compile(r"^(?:\s{0,3}>[ \t]?)*")
LIST_RE = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s+")
QUOTE_RE = re.compile(r"^(?:\s{0,3}>\s?)+")
ROW_RE = re.compile(r"^\s*\|")
RULE_RE = re.compile(r"^\s*(?:---+|\*\*\*+|___+)\s*$")
REVISION_RE = re.compile(r"^\*\*Document revision:\*\*\s*(\d+)\s*\(", re.MULTILINE)
SECTION_TOKEN_RE = re.compile(r"^(\d+(?:\.\d+)*|[A-Z](?:\.\d+)+)\.?$")
APPENDIX_RE = re.compile(r"^Appendix ([A-Z])\b")
ABBREVIATIONS = frozenset(
    {"e.g", "i.e", "vs", "etc", "cf", "resp", "approx", "no", "fig", "al"}
)
STATUSES = ("active", "withdrawn")
PROFILE_RE = re.compile(r"^[a-z][a-z0-9_.]*$")


class IdError(RuntimeError):
    """A requirement-identifier rule is violated."""


@dataclasses.dataclass
class Statement:
    document: str
    section: str
    keywords: list[str]
    start: int  # real offset of the statement text
    marker_id: str | None
    line: int
    text: str = ""
    extra_markers: tuple[str, ...] = ()


@dataclasses.dataclass
class Analysis:
    statements: list[Statement]
    stray: list[tuple[str, int]]  # (marker id, line) not at a statement start
    markers: list[str] = dataclasses.field(default_factory=list)  # every prose marker


def text_digest(text: str) -> str:
    """Digest of a statement's text: marker removed, whitespace runs collapsed."""
    normalized = " ".join(text.split())
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def prefix_for(document: str) -> str:
    return "KDC" if document == KDC else "AFP"


def mask_code(text: str) -> str:
    """Replace inline code spans with 'C' so they hide terminators and keywords."""
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "`":
            i += 1
            continue
        j = i
        while j < n and text[j] == "`":
            j += 1
        ticks = j - i
        close = text.find("`" * ticks, j)
        while close != -1 and close + ticks < n and text[close + ticks] == "`":
            close = text.find("`" * ticks, close + 1)
        if close == -1:
            i = j
            continue
        for k in range(i, close + ticks):
            out[k] = "C"
        i = close + ticks
    return "".join(out)


def section_of(title: str) -> str:
    appendix = APPENDIX_RE.match(title)
    if appendix:
        return appendix.group(1)
    token = title.split(None, 1)[0] if title else ""
    if SECTION_TOKEN_RE.match(token):
        return token.rstrip(".")
    return title


def sentence_starts(masked: str, original: str) -> list[int]:
    """Offsets of sentence starts in marker-free text.

    A boundary is a terminator (with closing quotes or brackets), whitespace, and
    then a capital letter, an inline-code or bold start, a section sign, or a
    version token such as ``v1``, optionally behind an opening quote or parenthesis. A terminator after ``e.g``, ``i.e``,
    ``vs``, ``etc``, ``cf``, ``resp``, ``approx``, ``no``, ``fig`` or ``al`` is not
    a boundary.
    """
    starts = [0]
    for match in re.finditer(r"[.!?][)\]\"'*_\u201d\u2019]*(\s+)", masked):
        end = match.end()
        if end >= len(masked):
            continue
        probe = end
        if original[probe] in "\"'\u201c\u2018(" and probe + 1 < len(original):
            probe += 1
        opens = original[probe].isupper() or original[probe] in "`*\u00a7"
        if not opens and re.match(r"v\d", original[probe : probe + 2]):
            opens = True
        if not opens:
            continue
        before = masked[: match.start()]
        word = re.search(r"([A-Za-z.]+)$", before)
        if word and word.group(1).lower().rstrip(".") in ABBREVIATIONS:
            continue
        starts.append(end)
    return sorted(set(starts))


def analyze(document: str, text: str) -> Analysis:
    statements: list[Statement] = []
    stray: list[tuple[str, int]] = []
    prose_markers: list[str] = []
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)

    state = {"section": "", "kind": "paragraph", "line": 0}
    block: list[tuple[int, int]] = []

    def handle(spans: list[tuple[int, int]], kind: str, first_line: int) -> None:
        # Mask code on the raw joined text first, so a marker-shaped token inside
        # a code span or example is text, not a marker.
        raw: list[str] = []
        raw_real: list[int] = []
        for index, (start, end) in enumerate(spans):
            if index:
                raw.append("\n")
                raw_real.append(start)
            for k in range(start, end):
                raw.append(text[k])
                raw_real.append(k)
        raw_text = "".join(raw)
        raw_masked = mask_code(raw_text)
        virtual: list[str] = []
        real: list[int] = []
        markers: dict[int, list[tuple[str, int]]] = {}
        cursor = 0
        for match in MARKER_RE.finditer(raw_masked):
            for k in range(cursor, match.start()):
                virtual.append(raw_text[k])
                real.append(raw_real[k])
            markers.setdefault(len(virtual), []).append((match.group(1), raw_real[match.start()]))
            cursor = match.end()
            if cursor < len(raw_text) and raw_text[cursor] == " ":
                cursor += 1
        for k in range(cursor, len(raw_text)):
            virtual.append(raw_text[k])
            real.append(raw_real[k])
        original = "".join(virtual)
        masked = mask_code(original)
        starts = [0] if kind == "row" else sentence_starts(masked, original)
        bounds = starts + [len(original)]
        used: set[int] = set()
        for number, begin in enumerate(starts):
            end = bounds[number + 1]
            keywords: list[str] = []
            for found in KEYWORD_RE.finditer(masked[begin:end]):
                if found.group(1) not in keywords:
                    keywords.append(found.group(1))
            found_markers = markers.get(begin, [])
            marker = found_markers[0] if found_markers else None
            if found_markers:
                used.add(begin)
            if (not keywords and marker is None) or begin >= len(real):
                continue
            statements.append(
                Statement(
                    document=document,
                    section=state["section"],
                    keywords=keywords,
                    start=real[begin],
                    marker_id=marker[0] if marker else None,
                    line=first_line,
                    text=original[begin:end],
                    extra_markers=tuple(m[0] for m in found_markers[1:]),
                )
            )
        for tokens in markers.values():
            prose_markers.extend(token for token, _offset in tokens)
        for vindex, tokens in markers.items():
            if vindex not in used:
                stray.extend((token, first_line) for token, _offset in tokens)

    def flush() -> None:
        nonlocal block
        if block:
            handle(block, state["kind"], state["line"])
        block = []
        state["kind"] = "paragraph"

    in_fence: str | None = None
    in_comment = False
    in_list = False
    in_indented_code = False
    previous_blank = True
    for number, line in enumerate(lines):
        stripped = line.rstrip("\n")
        start = offsets[number]
        was_blank = previous_blank
        previous_blank = not stripped.strip()
        if in_indented_code:
            if previous_blank or stripped.startswith("    ") or stripped.startswith("\t"):
                continue
            in_indented_code = False
        elif (
            was_blank and not in_list and not block
            and (stripped.startswith("    ") or stripped.startswith("\t"))
        ):
            in_indented_code = True
            continue
        unquoted = stripped[QUOTE_PREFIX_RE.match(stripped).end():]
        if in_fence is not None:
            candidate = unquoted.strip()
            if candidate and set(candidate) == {in_fence[0]} and len(candidate) >= len(in_fence):
                in_fence = None
            continue
        fence = FENCE_RE.match(unquoted)
        if fence:
            flush()
            in_fence = fence.group(1) or fence.group(3)
            continue
        if in_comment:
            if "-->" in stripped:
                in_comment = False
            continue
        if stripped.lstrip().startswith("<!--"):
            flush()
            if "-->" not in stripped:
                in_comment = True
            continue
        if not stripped.strip():
            flush()
            continue
        heading = HEADING_RE.match(stripped)
        if heading:
            flush()
            state["section"] = section_of(heading.group(2))
            continue
        if RULE_RE.match(stripped):
            flush()
            continue
        quote = QUOTE_RE.match(stripped)
        body_off = quote.end() if quote else 0
        body = stripped[body_off:]
        if ROW_RE.match(body):
            flush()
            pipe = body.index("|") + 1
            while pipe < len(body) and body[pipe] == " ":
                pipe += 1
            handle([(start + body_off + pipe, start + len(stripped))], "row", number + 1)
            continue
        item = LIST_RE.match(body)
        if not item and not stripped.startswith((" ", "\t")):
            in_list = False
        if item:
            in_list = True
            flush()
            block = [(start + body_off + item.end(), start + len(stripped))]
            state["line"] = number + 1
            continue
        if not block:
            state["line"] = number + 1
        indent = len(body) - len(body.lstrip())
        block.append((start + body_off + indent, start + len(stripped)))
    flush()
    return Analysis(statements, stray, prose_markers)


def read_text(relative: str, root: pathlib.Path = ROOT) -> str:
    return (root / relative).read_text(encoding="utf-8")


def members(surface: pathlib.Path = SURFACE) -> list[str]:
    declared = json.loads(surface.read_text(encoding="utf-8"))["authority"]["specification_set"]
    if not isinstance(declared, list) or declared[:1] != [CORE]:
        raise IdError("specification_set must list the core specification first")
    return list(declared)


def document_revision(text: str, relative: str) -> int:
    match = REVISION_RE.search(text)
    if match is None:
        raise IdError(f"{relative} has no **Document revision:** line")
    return int(match.group(1))


TENANT_SUBJECT_RE = re.compile(r"\btenants?\b(?![\u2019']s)", re.IGNORECASE)


def subject_is_tenant(text: str) -> bool:
    """True when a tenant is the grammatical subject of the first keyword.

    The subject is read from the last two words before the first keyword, so
    "A conforming tenant MUST", "Every tenant MUST" and "Tenants MUST" match,
    while "the tenant's operator MUST NOT" and "how a tenant behaves and MUST" do
    not. This is a drafting aid for allocation: the reviewed list in the pull
    request decides each label, and a reviewed correction uses
    ``applies_to_correction``.
    """
    found = KEYWORD_RE.search(mask_code(text))
    if found is None:
        return False
    words = re.findall(r"[A-Za-z\u2019']+", mask_code(text)[: found.start()])
    return bool(TENANT_SUBJECT_RE.search(" ".join(words[-2:])))


def applies_to(document: str, section: str, text: str = "") -> str:
    """The conformance subject: the document or profile, else tenant, else implementation."""
    if document == KDC:
        return "kdc"
    if document == INTRO:
        return "afp.introduction"
    if document == CORE:
        if section.startswith("15.9"):
            return "pay_venue"
        if section == "15" or section.startswith("15."):
            return "pay"
        if section.startswith("1.5.1"):
            return "tenant"
    return "tenant" if subject_is_tenant(text) else "implementation"


def load_index(path: pathlib.Path = INDEX_PATH) -> dict:
    if not path.exists():
        return {"format": INDEX_FORMAT, "entries": []}
    return json.loads(path.read_text(encoding="utf-8"))


def serial(identifier: str) -> int:
    return int(identifier.split("-", 1)[1])


def write_index(index: dict, path: pathlib.Path = INDEX_PATH) -> None:
    index["entries"] = sorted(
        index["entries"], key=lambda e: (e["id"][:3] != "AFP", serial(e["id"]))
    )
    path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def allocate(documents: list[str] | None = None) -> int:
    """Insert markers and index entries for unmarked statements, in set order."""
    index = load_index()
    entries = index["entries"]
    counters = {"AFP": 0, "KDC": 0}
    for entry in entries:
        key = entry["id"][:3]
        counters[key] = max(counters[key], serial(entry["id"]))
    added = 0
    for document in members():
        if documents is not None and document not in documents:
            continue
        text = read_text(document)
        revision = document_revision(text, document)
        analysis = analyze(document, text)
        if analysis.stray:
            raise IdError(f"{document}: stray markers {analysis.stray}")
        insertions: list[tuple[int, str]] = []
        for statement in analysis.statements:
            if statement.marker_id is not None or not statement.keywords:
                continue
            prefix = prefix_for(document)
            counters[prefix] += 1
            identifier = f"{prefix}-{counters[prefix]:04d}"
            insertions.append((statement.start, f"[{identifier}] "))
            entries.append(
                {
                    "id": identifier,
                    "document": document,
                    "section": statement.section,
                    "keywords": statement.keywords,
                    "applies_to": applies_to(document, statement.section, statement.text),
                    "status": "active",
                    "introduced_in": {"document": document, "document_revision": revision},
                    "superseded_by": None,
                    "text_sha256": text_digest(statement.text),
                }
            )
            added += 1
        for offset, token in sorted(insertions, reverse=True):
            text = text[:offset] + token + text[offset:]
        (ROOT / document).write_text(text, encoding="utf-8")
    write_index(index)
    return added


def check(
    index_path: pathlib.Path = INDEX_PATH,
    root: pathlib.Path = ROOT,
    surface: pathlib.Path = SURFACE,
) -> list[str]:
    problems: list[str] = []
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"{index_path.name}: unreadable index: {error}"]
    if not isinstance(index, dict) or index.get("format") != INDEX_FORMAT or set(index) != {"format", "entries"}:
        return [f"index must be exactly {{format: {INDEX_FORMAT!r}, entries}}"]
    entries = index["entries"]
    if not isinstance(entries, list):
        return ["index entries must be a list"]
    by_id: dict[str, dict] = {}
    for entry in entries:
        identifier = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(identifier, str) or ID_RE.match(identifier) is None:
            problems.append(f"entry has an invalid id: {identifier!r}")
        elif identifier in by_id:
            problems.append(f"{identifier}: identifier is reused")
        else:
            by_id[identifier] = entry
    fields = {
        "id", "document", "section", "keywords", "applies_to", "status",
        "introduced_in", "superseded_by", "text_sha256",
    }
    for identifier, entry in by_id.items():
        extra = set(entry) - fields - {"withdrawn_in", "applies_to_correction"}
        missing = fields - set(entry)
        if extra or missing:
            problems.append(f"{identifier}: fields extra={sorted(extra)} missing={sorted(missing)}")
            continue
        if entry["status"] not in STATUSES:
            problems.append(f"{identifier}: status must be active or withdrawn")
        applies = entry["applies_to"]
        if applies not in ("implementation", "tenant", "kdc") and not (
            isinstance(applies, str) and PROFILE_RE.match(applies)
        ):
            problems.append(f"{identifier}: invalid applies_to {applies!r}")
        if identifier.startswith("KDC-") != (applies == "kdc"):
            problems.append(f"{identifier}: the KDC prefix and applies_to kdc go together")
        for key in ("introduced_in", "withdrawn_in"):
            value = entry.get(key)
            if value is None and key == "withdrawn_in":
                continue
            if not (
                isinstance(value, dict)
                and set(value) == {"document", "document_revision"}
                and isinstance(value["document"], str)
                and isinstance(value["document_revision"], int)
                and value["document_revision"] >= 1
            ):
                problems.append(f"{identifier}: {key} must be a {{document, document_revision}} pair")
        correction = entry.get("applies_to_correction")
        if correction is not None and not (
            isinstance(correction, dict)
            and set(correction) == {"from", "reason"}
            and isinstance(correction["from"], str)
            and isinstance(correction["reason"], str)
            and len(correction["reason"].strip()) >= 20
            and correction["from"] != applies
        ):
            problems.append(
                f"{identifier}: applies_to_correction must be {{from, reason}} with a reason "
                "of at least 20 characters and a different earlier label"
            )
        if entry["status"] == "active" and entry.get("withdrawn_in") is not None:
            problems.append(f"{identifier}: an active entry has withdrawn_in")
        if entry["status"] == "withdrawn" and entry.get("withdrawn_in") is None:
            problems.append(f"{identifier}: a withdrawn entry needs withdrawn_in")
        successor = entry["superseded_by"]
        if successor is not None and successor not in by_id:
            problems.append(f"{identifier}: superseded_by names an unknown identifier")
        if entry["status"] == "active" and successor is not None:
            problems.append(f"{identifier}: an active entry has superseded_by")
    for prefix in ("AFP", "KDC"):
        serials = sorted(serial(i) for i in by_id if i.startswith(prefix))
        if serials != list(range(1, len(serials) + 1)):
            problems.append(f"{prefix}: serials must be contiguous from 0001 (never reused, never skipped)")

    found: dict[str, list[Statement]] = {}
    for document in members(surface):
        text = read_text(document, root)
        if LINK_DEFINITION_RE.search(text):
            problems.append(f"{document}: a link reference definition has an identifier label")
        analysis = analyze(document, text)
        for marker_id, line in analysis.stray:
            problems.append(f"{document}:{line}: marker {marker_id} is not at the start of a keyword statement")
        for statement in analysis.statements:
            where = f"{document}:{statement.line}"
            if statement.marker_id is None:
                if document in ENFORCED:
                    problems.append(f"{where}: statement with {statement.keywords} has no marker")
                continue
            if not statement.keywords:
                problems.append(f"{where}: marker {statement.marker_id} sits on a statement with no keyword")
            for extra in statement.extra_markers:
                problems.append(f"{where}: more than one marker at the start of a statement ({extra})")
            if not statement.marker_id.startswith(prefix_for(document)):
                problems.append(f"{where}: marker {statement.marker_id} has the wrong prefix for {document}")
            found.setdefault(statement.marker_id, []).append(statement)
    for identifier, hits in found.items():
        if len(hits) != 1:
            problems.append(f"{identifier}: {len(hits)} markers in the set, expected exactly one")
            continue
        entry = by_id.get(identifier)
        if entry is None:
            problems.append(f"{identifier}: marker has no index entry")
        elif entry.get("status") != "active":
            problems.append(f"{identifier}: marker for a withdrawn entry")
        else:
            statement = hits[0]
            for key, value in (
                ("document", statement.document),
                ("section", statement.section),
                ("keywords", statement.keywords),
                ("text_sha256", text_digest(statement.text)),
            ):
                if entry.get(key) != value:
                    problems.append(f"{identifier}: index {key} {entry.get(key)!r} != {value!r}")
    for identifier, entry in by_id.items():
        if entry.get("status") == "active" and identifier not in found:
            problems.append(f"{identifier}: active entry has no marker")
    return problems


def compare_to_base(index: dict, base: dict) -> list[str]:
    """History rules that a single tree cannot show: no id disappears or is reused.

    ``base`` is the index at the target branch. Every base entry must remain with
    the same ``introduced_in``. Its ``applies_to`` stays the same unless the entry
    carries an ``applies_to_correction`` whose ``from`` is the base label (a
    reviewed correction of a wrongly recorded label, not a change of obligation).
    A withdrawn entry stays withdrawn with its tombstone fields, and tail serials
    are never dropped, so allocation cannot reissue an identifier.
    """
    problems: list[str] = []
    current = {e["id"]: e for e in index["entries"] if isinstance(e, dict) and "id" in e}
    for entry in base["entries"]:
        identifier = entry["id"]
        now = current.get(identifier)
        if now is None:
            problems.append(f"{identifier}: entry was dropped (withdraw it; tombstones stay)")
            continue
        if now.get("introduced_in") != entry.get("introduced_in"):
            problems.append(
                f"{identifier}: introduced_in changed; a changed obligation withdraws the old id "
                "and allocates a new one"
            )
        if now.get("applies_to") != entry.get("applies_to"):
            # A wrong label is not a new obligation. A reviewed correction names the
            # label it replaces and the reason; an accidental change has no such record.
            correction = now.get("applies_to_correction")
            if not (isinstance(correction, dict) and correction.get("from") == entry.get("applies_to")):
                problems.append(
                    f"{identifier}: applies_to changed without an applies_to_correction naming the "
                    f"earlier label {entry.get('applies_to')!r} and the reason (a changed obligation "
                    "withdraws the old id and allocates a new one)"
                )
        if entry["status"] == "withdrawn" and now.get("status") != "withdrawn":
            problems.append(f"{identifier}: a withdrawn entry was made active again")
        if entry["status"] == "withdrawn":
            for key in ("withdrawn_in", "superseded_by"):
                if now.get(key) != entry.get(key):
                    problems.append(f"{identifier}: tombstone field {key} changed")
    return problems


def base_index_from_history(root: pathlib.Path = ROOT) -> tuple[str, dict | None]:
    """The index at the merge base with the target branch, from git history.

    Returns ``("found", index)``, ``("first-introduction", None)`` when the base
    commit has no index or when no base resolves and ``HEAD`` is a root commit of
    a complete (non-shallow) repository, or ``("unavailable", None)`` when no base
    commit can be resolved otherwise. The base is ``$AFP_BASE_SHA`` when set, else
    the merge base with ``origin/main``, ``main`` or ``refs/remotes/forgejo/main``.

    A complete root commit has no history to compare with, so every identifier
    in it is a first introduction; the zero-parent public snapshot candidate is
    such a checkout. A shallow checkout only appears to be a root commit, so it
    stays ``unavailable``, as does an unborn ``HEAD``.
    """
    import os
    import subprocess

    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)

    candidates = [os.environ.get("AFP_BASE_SHA", "")]
    for ref in ("origin/main", "main", "refs/remotes/forgejo/main"):
        merged = git("merge-base", "HEAD", ref)
        if merged.returncode == 0:
            candidates.append(merged.stdout.strip())
    for sha in filter(None, candidates):
        if git("cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
            continue
        shown = git("show", f"{sha}:docs/afp_requirement_index.json")
        if shown.returncode != 0:
            return "first-introduction", None
        return "found", json.loads(shown.stdout)
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "false":
        head = git("rev-list", "--parents", "-n", "1", "HEAD")
        if head.returncode == 0 and len(head.stdout.split()) == 1:
            return "first-introduction", None
    return "unavailable", None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("check", "allocate"))
    parser.add_argument("--document", action="append", help="limit allocate to this member")
    parser.add_argument(
        "--base-index",
        type=pathlib.Path,
        help="check: also compare with this copy of the index at the target branch",
    )
    parser.add_argument(
        "--base-history",
        action="store_true",
        help="check: compare with the index at the merge base with main (fails when no base is found)",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "allocate":
            print(f"allocated {allocate(args.document)} identifier(s)")
            return 0
        problems = check()
        if args.base_history:
            status, base = base_index_from_history()
            if status == "unavailable":
                problems.append("no base commit found for the historical comparison")
            elif base is not None:
                problems += compare_to_base(load_index(), base)
        if args.base_index is not None:
            problems += compare_to_base(
                load_index(), json.loads(args.base_index.read_text(encoding="utf-8"))
            )
    except IdError as error:
        print(f"requirement identifiers: {error}", file=sys.stderr)
        return 1
    if problems:
        for problem in problems[:50]:
            print(problem, file=sys.stderr)
        if len(problems) > 50:
            print(f"... and {len(problems) - 50} more", file=sys.stderr)
        return 1
    index = load_index()
    active = sum(1 for e in index["entries"] if e["status"] == "active")
    print(f"requirement identifiers OK ({active} active, {len(index['entries']) - active} withdrawn)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
