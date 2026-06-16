"""Shared path canonicalization heuristics for file-access analyzers."""

from __future__ import annotations

import re

CANONICALIZATION_HINTS = re.compile(
    r"\b(resolve|realpath|abspath|canonicalize|normpath|is_relative_to|startswith)\b",
    re.I,
)

PATH_ACCESS_HINTS = re.compile(
    r"\b(open\s*\(|read_file|write_file|Path\s*\(|pathlib|os\.path|unlink|rmtree|read_text)\b",
    re.I,
)


def handler_has_path_canonicalization(
    snippet: str,
    source_files: dict[str, str],
    source_file: str | None,
) -> bool:
    """Return True when handler or its source module shows path canonicalization."""
    if snippet and CANONICALIZATION_HINTS.search(snippet):
        return True
    if source_file and source_file in source_files:
        return bool(CANONICALIZATION_HINTS.search(source_files[source_file]))
    return False
