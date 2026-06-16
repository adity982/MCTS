"""Filesystem tool depth patterns (FS-*)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_filesystem_abuse_finding

_READ_MULTIPLE = re.compile(r"read_multiple_files|readMultipleFiles", re.IGNORECASE)
_READ_MEDIA = re.compile(r"read_media_file|readMediaFile", re.IGNORECASE)
_SEARCH_FILES = re.compile(r"search_files|searchFiles", re.IGNORECASE)
_PATHS_ARRAY = re.compile(r'["\']paths["\']\s*:\s*\{\s*["\']type["\']\s*:\s*["\']array["\']', re.IGNORECASE)
_STRUCTURED_DUP = re.compile(r"structuredContent", re.MULTILINE)
_MAX_PATHS = re.compile(r"max_paths|maxPaths|le\s*=\s*\d+|maxLength\s*:\s*\d+", re.IGNORECASE)
_BYTE_CAP = re.compile(r"max_bytes|maxBytes|byte.?cap|MAX_.*BYTES", re.IGNORECASE)


class FilesystemAbuseAnalyzer(BaseAnalyzer):
    name = "filesystem_abuse"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            if "filesystem" not in path and "mcp_server_filesystem" not in path:
                continue
            findings.extend(self._check_patterns(path, content))
        return [tag_filesystem_abuse_finding(f) for f in findings]

    def _check_patterns(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        if _READ_MULTIPLE.search(content) and not _MAX_PATHS.search(content):
            findings.append(
                _fs_finding(
                    "FS-01",
                    "read_multiple_files without max paths bound",
                    "Batch read tool accepts unbounded paths array.",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _READ_MULTIPLE),
                )
            )
        if _READ_MEDIA.search(content) and not _BYTE_CAP.search(content):
            findings.append(
                _fs_finding(
                    "FS-02",
                    "read_media_file without output byte cap",
                    "Media read returns base64 without documented size limit.",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _READ_MEDIA),
                )
            )
        if _SEARCH_FILES.search(content) and "excludePatterns" not in content:
            findings.append(
                _fs_finding(
                    "FS-03",
                    "search_files broad glob without excludePatterns guard",
                    "Broad glob search may be vulnerable to ReDoS or over-read.",
                    Severity.LOW,
                    path,
                    _line_no(content, _SEARCH_FILES),
                )
            )
        if _PATHS_ARRAY.search(content) and not _MAX_PATHS.search(content):
            findings.append(
                _fs_finding(
                    "FS-04",
                    "Unbounded paths array in tool JSON schema",
                    "Tool schema allows arbitrary-length paths list.",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _PATHS_ARRAY),
                )
            )
        if _STRUCTURED_DUP.search(content) and ("content" in content or "text" in content):
            findings.append(
                _fs_finding(
                    "FS-07",
                    "structuredContent duplicates sensitive data in text channel",
                    "Dual-channel tool output may leak paths or file contents (parameter_exfil overlap).",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _STRUCTURED_DUP),
                )
            )
        return findings


def _fs_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str,
    line: int | None,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"fs-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="filesystem_abuse",
            title=title,
            description=f"{description} ({rule_id}).",
            severity=severity,
            recommendation="Cap batch sizes, media bytes, and avoid dual-channel sensitive output.",
        ),
        surface="tool",
        rule_id=rule_id,
        analysis_depth="L1",
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(0.65)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
