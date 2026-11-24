#!/usr/bin/env python3
"""Fail closed unless a release tag matches the public specification notes."""

from __future__ import annotations

import argparse
import datetime
import pathlib
import re
import sys
from collections.abc import Iterator


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERSION_PATTERN = re.compile(r"^\*\*Version:\*\*\s*([^\s]+)\s*$")
FENCE_PATTERN = re.compile(r"^[ ]{0,3}(?P<fence>`{3,}|~{3,})")
RAW_HTML_BLOCK_PATTERN = re.compile(
    r"^[ ]{0,3}<(?P<tag>script|pre|style|textarea)(?:\s|>|$)", re.IGNORECASE
)
HTML_BLOCK_START_PATTERN = re.compile(
    r"^[ ]{0,3}</?[A-Za-z][A-Za-z0-9-]*(?:\s|/?>)"
)
HTML_BLOCK_DELIMITERS = (
    ("<?", "?>"),
    ("<![CDATA[", "]]>"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag in v<spec-version> form")
    parser.add_argument(
        "--spec", type=pathlib.Path, default=ROOT / "docs" / "afp_specification.md"
    )
    parser.add_argument("--changelog", type=pathlib.Path, default=ROOT / "CHANGELOG.md")
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def markdown_content_lines(markdown: str) -> Iterator[str]:
    """Yield lines that Markdown renders as content rather than code or comments."""
    fence_character: str | None = None
    fence_length = 0
    in_html_comment = False
    html_block_closer: str | None = None
    html_block_until_blank = False

    for line in markdown.splitlines():
        fence_match = FENCE_PATTERN.match(line)
        if fence_character is not None:
            if fence_match is not None:
                fence = fence_match.group("fence")
                if (
                    fence[0] == fence_character
                    and len(fence) >= fence_length
                    and not line[fence_match.end() :].strip()
                ):
                    fence_character = None
                    fence_length = 0
            continue

        if in_html_comment:
            if "-->" in line:
                in_html_comment = False
            continue

        if html_block_closer is not None:
            if html_block_closer in line.lower():
                html_block_closer = None
            continue

        if html_block_until_blank:
            if not line.strip():
                html_block_until_blank = False
            continue

        if fence_match is not None:
            fence = fence_match.group("fence")
            fence_character = fence[0]
            fence_length = len(fence)
            continue

        if "<!--" in line:
            if "-->" not in line.split("<!--", maxsplit=1)[1]:
                in_html_comment = True
            continue

        raw_html_match = RAW_HTML_BLOCK_PATTERN.match(line)
        if raw_html_match is not None:
            closer = f"</{raw_html_match.group('tag').lower()}>"
            if closer not in line.lower()[raw_html_match.end() :]:
                html_block_closer = closer
            continue

        stripped_line = line.lstrip(" ")
        for opener, closer in HTML_BLOCK_DELIMITERS:
            if stripped_line.startswith(opener):
                if closer not in stripped_line[len(opener) :]:
                    html_block_closer = closer.lower()
                break
        else:
            if re.match(r"^<![A-Z]", stripped_line):
                if ">" not in stripped_line[2:]:
                    html_block_closer = ">"
                continue
            if HTML_BLOCK_START_PATTERN.match(line) is not None:
                html_block_until_blank = True
                continue
            yield line
            continue
        continue


def parse_specification_version(specification: str) -> str | None:
    """Return one unique visible version from the specification header."""
    versions: list[str] = []
    header_versions: list[str] = []
    in_header = True

    for line in markdown_content_lines(specification):
        if line.strip() == "---":
            in_header = False
            continue
        version_match = VERSION_PATTERN.fullmatch(line)
        if version_match is None:
            continue
        version = version_match.group(1)
        versions.append(version)
        if in_header:
            header_versions.append(version)

    if len(versions) != 1 or len(header_versions) != 1:
        return None
    return header_versions[0]


def main() -> int:
    args = parse_args()
    if not args.tag.startswith("v") or len(args.tag) == 1:
        return fail("release tag must use v<spec-version> form")

    try:
        specification = args.spec.read_text(encoding="utf-8")
        changelog = args.changelog.read_text(encoding="utf-8")
    except OSError as error:
        return fail(str(error))

    specification_version = parse_specification_version(specification)
    if specification_version is None:
        return fail("specification header must contain one unique, visible version")
    if args.tag[1:] != specification_version:
        return fail("release tag does not match specification version")

    heading = re.compile(
        rf"^## \[{re.escape(specification_version)}\] - "
        rf"(?P<date>\d{{4}}-\d{{2}}-\d{{2}})\s*$"
    )
    for line in markdown_content_lines(changelog):
        heading_match = heading.fullmatch(line)
        if heading_match is None:
            continue
        try:
            datetime.date.fromisoformat(heading_match.group("date"))
        except ValueError:
            continue
        return 0

    return fail("release tag has no matching public changelog entry with a valid date")


if __name__ == "__main__":
    raise SystemExit(main())
