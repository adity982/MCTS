"""TOCTOU and symlink logic patterns (SYM-01–05)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_sym_toctou_finding

_RACE_TEST = re.compile(
    r"race condition[\s\S]{0,1200}SECRET CONTENT[\s\S]{0,800}readFile",
    re.IGNORECASE,
)
_VALIDATE_THEN_READ = re.compile(
    r"validatePath[\s\S]{0,300}readFile",
    re.MULTILINE,
)
_NO_NOFOLLOW = re.compile(r"O_NOFOLLOW|lstat\s*\(", re.MULTILINE)
_READDIR_STAT = re.compile(r"readdir[\s\S]{0,600}stat\s*\(", re.MULTILINE)
_EDIT_VALIDATE_READ = re.compile(r"validatePath[\s\S]{0,300}edit_file|readFile", re.MULTILINE)
_SYMLINK_ALLOWLIST = re.compile(r"symlink[\s\S]{0,200}realpath|realpath[\s\S]{0,200}allowlist", re.IGNORECASE)
_ATOMIC_RENAME = re.compile(r"flag\s*:\s*['\"]wx['\"]|atomic.*rename", re.IGNORECASE)


class SymToctouAnalyzer(BaseAnalyzer):
    name = "sym_toctou"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            is_test = any(p in path for p in ("test", "__tests__", ".test."))
            if is_test:
                match = _RACE_TEST.search(content)
                if match:
                    line = content[: match.start()].count("\n") + 1
                    findings.append(
                        _sym_finding(
                            "SYM-01",
                            "Test documents TOCTOU race between validatePath and readFile",
                            "Filesystem tests confirm symlink race allows reading outside allowlist.",
                            Severity.HIGH,
                            path,
                            line,
                            analysis_depth="L2",
                            confidence=0.85,
                        )
                    )
            if "filesystem" in path or "mcp_server_filesystem" in path or "lib.ts" in path:
                if _VALIDATE_THEN_READ.search(content) and not _NO_NOFOLLOW.search(content):
                    findings.append(
                        _sym_finding(
                            "SYM-01",
                            "validatePath followed by readFile without O_NOFOLLOW",
                            "TOCTOU window between path validation and read operation.",
                            Severity.HIGH,
                            path,
                            _line_no(content, _VALIDATE_THEN_READ),
                        )
                    )
                if _EDIT_VALIDATE_READ.search(content) and "edit_file" in content:
                    findings.append(
                        _sym_finding(
                            "SYM-03",
                            "validatePath then read on edit_file path",
                            "Same TOCTOU pattern on edit_file read path.",
                            Severity.HIGH,
                            path,
                            _line_no(content, _EDIT_VALIDATE_READ),
                        )
                    )
                if _READDIR_STAT.search(content) and not re.search(r"\blstat\b", content):
                    findings.append(
                        _sym_finding(
                            "SYM-02",
                            "readdir followed by stat without per-entry lstat",
                            "Symlink metadata may differ between directory listing and stat.",
                            Severity.MEDIUM,
                            path,
                            _line_no(content, _READDIR_STAT),
                        )
                    )
                if _SYMLINK_ALLOWLIST.search(content):
                    findings.append(
                        _sym_finding(
                            "SYM-04",
                            "Symlink path and realpath both pushed into allowlist",
                            "Operator may not be warned when symlink and canonical path are both allowed.",
                            Severity.MEDIUM,
                            path,
                            _line_no(content, _SYMLINK_ALLOWLIST),
                        )
                    )
                if _ATOMIC_RENAME.search(content):
                    findings.append(
                        _sym_finding(
                            "SYM-05",
                            "Reference pattern: wx flag and atomic rename (positive control)",
                            "Documented safe write pattern — use as hardened fixture baseline.",
                            Severity.LOW,
                            path,
                            _line_no(content, _ATOMIC_RENAME),
                            finding_class="informational",
                            confidence=0.9,
                        )
                    )
        return [tag_sym_toctou_finding(f) for f in findings]


def _sym_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str,
    line: int | None,
    *,
    analysis_depth: str = "L1",
    confidence: float = 0.7,
    finding_class: str = "security",
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"sym-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="sym_toctou",
            title=title,
            description=f"{description} ({rule_id}).",
            severity=severity,
            recommendation="Use O_NOFOLLOW, per-entry lstat, and atomic wx writes after validation.",
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class=finding_class,  # type: ignore[arg-type]
        analysis_depth=analysis_depth,  # type: ignore[arg-type]
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(confidence)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
