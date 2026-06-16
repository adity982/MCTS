"""GraphBuilder integration tests."""

from __future__ import annotations

from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Severity, SourceLocation
from mcts.scoring.attack_graph_builder import GraphBuilder


def _capability(**flags: bool):
    from mcts.mcp.models import CapabilityProfile

    return CapabilityProfile(**flags)


def test_builder_ssrf_exfil_template() -> None:
    server = MCPServerInfo(
        name="fetch",
        tools=[MCPTool(name="fetch", description="fetch url", capability=_capability(egresses_network=True))],
    )
    findings = [
        build_analyzer_finding(
            finding_id="net-01",
            analyzer="network_egress",
            title="NET-01",
            description="egress",
            severity=Severity.HIGH,
            recommendation="fix",
            rule_id="NET-01",
            match="httpx",
            field="handler",
            tool="fetch",
            location=SourceLocation(file="server.py", line=10),
            confidence=0.85,
        )
    ]
    graph = GraphBuilder(config=ScanConfig(target=".")).build(server, findings)
    report = graph.to_report_dict()
    assert report["version"] == 3
    assert report["edges"]
    chain_findings = graph.to_findings()
    assert chain_findings
    assert any((f.evidence or {}).get("template_id") == "SSRF_EXFIL" for f in chain_findings)


def test_builder_http_takeover_template() -> None:
    server = MCPServerInfo(
        name="everything",
        tools=[
            MCPTool(
                name="get-env",
                description="env dump",
                capability=_capability(accesses_sensitive_data=True),
            )
        ],
    )
    findings = [
        build_analyzer_finding(
            finding_id="cap-01",
            analyzer="transport_exposure",
            title="CAP-01",
            description="http exposed",
            severity=Severity.CRITICAL,
            recommendation="auth",
            rule_id="CAP-01",
            match="app.listen",
            field="transport",
            location=SourceLocation(file="transports/streamableHttp.ts", line=1),
            confidence=0.9,
        ),
        build_analyzer_finding(
            finding_id="cap-03",
            analyzer="data_leakage",
            title="CAP-03",
            description="env",
            severity=Severity.CRITICAL,
            recommendation="remove",
            rule_id="CAP-03",
            match="get-env",
            field="tool",
            tool="get-env",
            location=SourceLocation(file="tools/get-env.ts", line=1),
            confidence=0.9,
        ),
    ]
    graph = GraphBuilder(config=ScanConfig(target=".")).build(server, findings)
    report = graph.to_report_dict()
    assert report["edges"]
    assert any((f.evidence or {}).get("template_id") == "HTTP_TAKEOVER" for f in graph.to_findings())


def test_builder_read_exfil_template() -> None:
    from mcts.mcp.models import CapabilityProfile

    server = MCPServerInfo(
        tools=[
            MCPTool(
                name="read_and_send",
                description="read then egress",
                capability=CapabilityProfile(reads_untrusted_input=True, egresses_network=True),
            )
        ]
    )
    findings = [
        build_analyzer_finding(
            finding_id="fs-1",
            analyzer="filesystem_abuse",
            title="FS read",
            description="read paths",
            severity=Severity.HIGH,
            recommendation="fix",
            rule_id="FS-01",
            match="read",
            field="tool",
            tool="read_and_send",
            location=SourceLocation(file="f.ts", line=1),
        )
    ]
    graph = GraphBuilder(config=ScanConfig(target=".")).build(server, findings)
    matched = {c.template_id for c in graph.matched_chains}
    assert "READ_EXFIL" in matched


def test_builder_memory_poison_template() -> None:
    server = MCPServerInfo(
        name="memory",
        tools=[
            MCPTool(
                name="create_entities",
                description="write memory",
                capability=_capability(mutates_state=True),
            ),
            MCPTool(
                name="open_nodes",
                description="read memory",
                capability=_capability(reads_untrusted_input=True),
            ),
        ],
    )
    findings = [
        build_analyzer_finding(
            finding_id="mem-05",
            analyzer="shared_memory_poisoning",
            title="MEM-05",
            description="create_entities writes cross-session memory",
            severity=Severity.HIGH,
            recommendation="cap writes",
            rule_id="MEM-05",
            match="create_entities",
            field="tool",
            tool="create_entities",
            location=SourceLocation(file="index.ts", line=10),
            confidence=0.8,
        ),
    ]
    graph = GraphBuilder(config=ScanConfig(target=".")).build(server, findings)
    matched = {c.template_id for c in graph.matched_chains}
    assert "MEMORY_POISON" in matched
