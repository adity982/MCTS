"""Optional Semgrep SAST adapter for MCP server source trees."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity

_DEFAULT_RULES = Path(__file__).resolve().parents[1] / "sast" / "semgrep" / "rules" / "mcts-mcp.yaml"

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepAdapterAnalyzer(BaseAnalyzer):
    """Run bundled Semgrep rules against the scan target (requires semgrep CLI)."""

    name = "semgrep_sast"

    def __init__(
        self,
        target: Path,
        rules_path: Path | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        self.target = target
        self.rules_path = rules_path or _DEFAULT_RULES
        self.timeout_seconds = timeout_seconds

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        targets = _semgrep_targets(self.target, server)
        if not targets:
            return []
        payload = run_semgrep_scan(targets, self.rules_path, timeout=self.timeout_seconds)
        return _findings_from_payload(payload, analyzer=self.name)


def run_semgrep_scan(targets: Path | list[Path], rules_path: Path, *, timeout: int = 120) -> dict:
    """Invoke semgrep CLI and return parsed JSON payload."""
    target_list = [targets] if isinstance(targets, Path) else [path for path in targets if path.exists()]
    if not target_list:
        return {"results": [], "errors": [{"message": "no semgrep targets"}]}
    if not shutil.which("semgrep"):
        return {"results": [], "errors": [{"message": "semgrep CLI not found on PATH"}]}
    if not rules_path.exists():
        return {"results": [], "errors": [{"message": f"rules not found: {rules_path}"}]}
    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--quiet",
        "--config",
        str(rules_path),
        *[str(path) for path in target_list],
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"results": [], "errors": [{"message": "semgrep scan timed out"}]}
    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "semgrep failed").strip()
        return {"results": [], "errors": [{"message": err}]}
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"results": [], "errors": [{"message": "invalid semgrep JSON output"}]}


def _findings_from_payload(payload: dict, *, analyzer: str) -> list[Finding]:
    findings: list[Finding] = []
    for row in payload.get("results") or []:
        if not isinstance(row, dict):
            continue
        check_id = str(row.get("check_id") or "semgrep-rule")
        path = str(row.get("path") or "")
        start = row.get("start") if isinstance(row.get("start"), dict) else {}
        extra = row.get("extra") if isinstance(row.get("extra"), dict) else {}
        message = str(extra.get("message") or check_id)
        raw_sev = str(extra.get("severity") or "ERROR").upper()
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        technique_id = str(metadata.get("technique_id") or "MCTS-T-1003")
        rule_id = str(metadata.get("rule_id") or check_id)
        line = int(start.get("line") or 0)
        col = int(start.get("col") or 0)
        slug = check_id.replace(".", "-").replace("/", "-")
        builder = (
            FindingBuilder(
                finding_id=f"semgrep-{slug}-{line}-{col}",
                analyzer=analyzer,
                title=f"Semgrep: {check_id}",
                description=message,
                severity=_SEVERITY_MAP.get(raw_sev, Severity.MEDIUM),
                recommendation="Review matched source for unsafe MCP tool handler behavior.",
            )
            .technique(technique_id)
            .confidence(0.85)
            .location(path, line if line else None)
            .fact(
                rule_id=rule_id,
                match=message,
                field="semgrep_match",
                file=path or None,
                line=line if line else None,
            )
            .evidence(
                check_id=check_id,
                rule_id=rule_id,
                path=path,
                semgrep_severity=raw_sev,
                category=metadata.get("category"),
                finding_class=metadata.get("finding_class"),
                analysis_depth=metadata.get("analysis_depth"),
            )
        )
        finding = builder.build()
        if metadata.get("category") == "network_egress" or str(rule_id).startswith("NET-"):
            from mcts.scoring.evidence_tags import tag_network_egress_finding

            finding = tag_network_egress_finding(finding)
        findings.append(finding)
    if not findings:
        for err in payload.get("errors") or []:
            if not isinstance(err, dict):
                continue
            message = str(err.get("message") or "").strip()
            if not message:
                continue
            findings.append(
                FindingBuilder(
                    finding_id="semgrep-skipped",
                    analyzer=analyzer,
                    title="Semgrep scan skipped",
                    description=message,
                    severity=Severity.LOW,
                    recommendation=(
                        "Install the semgrep CLI (`uv sync --extra semgrep`) or remove --semgrep "
                        "when SAST is not required."
                    ),
                    rule_stability="mature",
                )
                .confidence(1.0)
                .evidence(skipped=True, reason=message)
                .build(require_fact=False)
            )
            break
    return findings


def _semgrep_targets(scan_target: Path, server: MCPServerInfo) -> list[Path]:
    """Prefer full discovery surface union over single entrypoint (DISC-04)."""
    if server.source_files:
        paths = sorted(Path(path) for path in server.source_files if not path.endswith("#mcp-block"))
        existing = [path for path in paths if path.is_file()]
        if existing:
            return existing
    if scan_target.exists():
        return [scan_target]
    return []
