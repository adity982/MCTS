"""Pydantic models and enums for attack graph v3 (Phase 3a MVP)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GraphLayer(StrEnum):
    MCP_SURFACE = "mcp_surface"
    DATAFLOW = "dataflow"
    TRANSPORT = "transport"
    TRUST_BOUNDARY = "trust_boundary"
    INVENTORY = "inventory"


class NodeKind(StrEnum):
    SOURCE = "source"
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    TRANSPORT = "transport"
    CAPABILITY = "capability"
    SINK = "sink"
    CONTROL = "control"


class EdgeKind(StrEnum):
    INVOKES = "INVOKES"
    READS = "READS"
    WRITES = "WRITES"
    EXPOSES = "EXPOSES"
    GUARDS = "GUARDS"
    DELIVERS_TO_CONTEXT = "DELIVERS_TO_CONTEXT"
    RESOURCE_READABLE_BY_CONTEXT = "RESOURCE_READABLE_BY_CONTEXT"
    DELIVERS_TO_CLIENT_LLM = "DELIVERS_TO_CLIENT_LLM"
    EGRESS = "EGRESS"
    PERSISTS = "PERSISTS"
    TRIGGERS = "TRIGGERS"


class TrustLevel(StrEnum):
    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi_trusted"
    TRUSTED = "trusted"
    EXTERNAL = "external"


class SensitivityLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceStrength(StrEnum):
    HEURISTIC = "heuristic"
    STATIC = "static"
    INTERPROCEDURAL = "interprocedural"
    RUNTIME = "runtime"


SINK_NAMES: tuple[str, ...] = (
    "model_context",
    "external_network",
    "client_llm",
    "env",
    "disk",
    "cross_session",
)

SOURCE_NAMES: tuple[str, ...] = (
    "user_input",
    "client_roots",
    "untrusted_memory",
    "session_state",
)


def canonical_node_id(kind: NodeKind | str, local_id: str) -> str:
    """Stable node key: ``{kind}:{id}``."""
    kind_value = kind.value if isinstance(kind, NodeKind) else str(kind)
    if local_id.startswith(f"{kind_value}:"):
        return local_id
    return f"{kind_value}:{local_id}"


def parse_node_id(node_id: str) -> tuple[str, str]:
    if ":" not in node_id:
        return "tool", node_id
    kind, local = node_id.split(":", 1)
    return kind, local


def is_sink_node(node_id: str) -> bool:
    kind, _ = parse_node_id(node_id)
    return kind == NodeKind.SINK.value


TERMINAL_SINKS = frozenset(
    {
        "sink:model_context",
        "sink:external_network",
        "sink:client_llm",
    }
)


def is_path_terminal(node_id: str) -> bool:
    return node_id in TERMINAL_SINKS


def _edge_id(kind: EdgeKind, from_node: str, to_node: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"{kind.value}:{from_node}:{to_node}".encode()).hexdigest()[:12]
    return f"edge-{digest}"


class GraphNode(BaseModel):
    id: str
    kind: NodeKind
    label: str
    layer: GraphLayer = GraphLayer.MCP_SURFACE
    trust: TrustLevel = TrustLevel.SEMI_TRUSTED
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    scope: str = "local_server"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def synthetic(
        cls,
        kind: NodeKind,
        local_id: str,
        *,
        label: str | None = None,
        layer: GraphLayer | None = None,
        trust: TrustLevel | None = None,
        sensitivity: SensitivityLevel | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GraphNode:
        node_id = canonical_node_id(kind, local_id)
        default_layer = (
            GraphLayer.TRUST_BOUNDARY if kind in {NodeKind.SOURCE, NodeKind.SINK} else GraphLayer.MCP_SURFACE
        )
        return cls(
            id=node_id,
            kind=kind,
            label=label or local_id,
            layer=layer or default_layer,
            trust=trust or TrustLevel.SEMI_TRUSTED,
            sensitivity=sensitivity or SensitivityLevel.MEDIUM,
            metadata=dict(metadata or {}),
        )


class EdgeEvidence(BaseModel):
    file: str | None = None
    line: int | None = None
    rule_id: str | None = None
    analyzer: str | None = None
    finding_id: str | None = None


class GraphEdge(BaseModel):
    id: str
    kind: EdgeKind
    layer: GraphLayer = GraphLayer.DATAFLOW
    from_node: str
    to_node: str
    label: str = ""
    confidence: float = 0.7
    reachability: float = 1.0
    access_probability: float | None = None
    evidence_strength: EvidenceStrength = EvidenceStrength.STATIC
    analysis_depth: str = "L1"
    policy: bool = False
    evidence: list[EdgeEvidence] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def merge_from(self, other: GraphEdge) -> None:
        """Merge provenance from *other*; confidence takes max."""
        self.confidence = max(self.confidence, other.confidence)
        self.reachability = max(self.reachability, other.reachability)
        if other.access_probability is not None:
            prob = other.access_probability
            self.access_probability = (
                max(self.access_probability, prob) if self.access_probability is not None else prob
            )
        if other.label and not self.label:
            self.label = other.label
        if other.layer == GraphLayer.TRUST_BOUNDARY and self.layer == GraphLayer.DATAFLOW:
            self.layer = GraphLayer.TRUST_BOUNDARY
        seen = {(e.rule_id, e.analyzer, e.finding_id) for e in self.evidence}
        for item in other.evidence:
            key = (item.rule_id, item.analyzer, item.finding_id)
            if key not in seen:
                self.evidence.append(item)
                seen.add(key)
        self.metadata.update(other.metadata)


class GraphPath(BaseModel):
    """Ordered edge path ending at a sink or terminal node."""

    nodes: list[str] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    end: str = ""

    @property
    def hop_count(self) -> int:
        return len(self.edges)

    def tool_names_on_path(self) -> list[str]:
        names: list[str] = []
        for node_id in self.nodes:
            kind, local = parse_node_id(node_id)
            if kind == NodeKind.TOOL.value and local not in names:
                names.append(local)
        return names


class ExplanationStep(BaseModel):
    message: str
    derived_from: list[str] = Field(default_factory=list)


class MatchedChain(BaseModel):
    template_id: str
    path: GraphPath
    path_confidence: float = 0.0
    path_reachability: float = 0.0
    chain_risk_score: float = 0.0
    trust_boundary_crossings: int = 0
    explanation: list[ExplanationStep] = Field(default_factory=list)
    legacy_finding_id: str | None = None
    counterfactual_remediation: dict[str, Any] | None = None
    recommended_fixes: list[dict[str, Any]] = Field(default_factory=list)
