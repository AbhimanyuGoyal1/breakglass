import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

def generate_evidence_id(kind: str, identity: Dict[str, Any]) -> str:
    """Generates a stable, collision-resistant evidence ID using SHA-256."""
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"EVID-{kind.upper().replace('_', '-')}-{digest[:16]}"


@dataclass(frozen=True)
class EvidenceNode:
    """Represents a validated, authenticated, and immutable evidence node in the graph."""
    kind: str
    path: str
    content: str
    source: str
    confidence: float
    line: Optional[int] = None
    column: Optional[int] = None
    provenance_metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(init=False)
    fingerprint: str = field(init=False)

    def __post_init__(self):
        if not self.kind or not isinstance(self.kind, str):
            raise ValueError("kind must be a non-empty string")
        if not self.path or not isinstance(self.path, str):
            raise ValueError("path must be a non-empty string")
        if self.content is None or not isinstance(self.content, str):
            raise ValueError("content must be a string")
        if not self.source or not isinstance(self.source, str):
            raise ValueError("source must be a non-empty string")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool) or not math.isfinite(self.confidence) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be a finite float between 0.0 and 1.0")
        if self.line is not None and (not isinstance(self.line, int) or isinstance(self.line, bool) or self.line <= 0):
            raise ValueError("line must be a positive integer or None")
        if self.column is not None and (not isinstance(self.column, int) or isinstance(self.column, bool) or self.column <= 0):
            raise ValueError("column must be a positive integer or None")
        if not isinstance(self.provenance_metadata, dict):
            raise ValueError("provenance_metadata must be a dictionary")

        # Normalize path separators to forward slashes
        norm_path = self.path.replace("\\", "/")
        object.__setattr__(self, "path", norm_path)

        # Compute SHA-256 fingerprint of content
        fp = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        object.__setattr__(self, "fingerprint", fp)

        # Reconstruct identity dictionary for stable hashing
        identity = {
            "kind": self.kind,
            "path": norm_path,
            "line": self.line,
            "column": self.column,
            "content": self.content
        }
        evid_id = generate_evidence_id(self.kind, identity)
        object.__setattr__(self, "id", evid_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "content": self.content,
            "source": self.source,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "provenance_metadata": self.provenance_metadata
        }


@dataclass(frozen=True)
class EvidenceEdge:
    """Represents a validated, immutable relationship between evidence and other entities."""
    source_id: str
    target_id: str
    type: str

    def __post_init__(self):
        if not self.source_id or not isinstance(self.source_id, str):
            raise ValueError("source_id must be a non-empty string")
        if not self.target_id or not isinstance(self.target_id, str):
            raise ValueError("target_id must be a non-empty string")
        
        allowed_types = {
            "finding_to_evidence",
            "evidence_to_hypothesis",
            "hypothesis_to_evidence",
            "evidence_to_related_evidence"
        }
        if self.type not in allowed_types:
            raise ValueError(f"Invalid relationship type: {self.type}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.type
        }


@dataclass
class EvidenceGraphConfig:
    """Strictly validated boundaries and limits configuration for the Evidence Graph."""
    max_nodes: int = 1000
    max_edges: int = 2000
    max_evidence_references_per_hypothesis: int = 10
    max_evidence_snippet_bytes: int = 4096
    max_total_evidence_bytes: int = 100 * 1024  # 100KB
    max_provenance_depth: int = 5
    max_serialized_graph_size: int = 200 * 1024  # 200KB

    def validate(self) -> None:
        """Validates all limits strictly, rejecting non-positives, NaNs, infinities, or booleans."""
        if not isinstance(self.max_nodes, int) or self.max_nodes <= 0 or isinstance(self.max_nodes, bool):
            raise ValueError("max_nodes must be a positive integer")
        if not isinstance(self.max_edges, int) or self.max_edges <= 0 or isinstance(self.max_edges, bool):
            raise ValueError("max_edges must be a positive integer")
        if not isinstance(self.max_evidence_references_per_hypothesis, int) or self.max_evidence_references_per_hypothesis <= 0 or isinstance(self.max_evidence_references_per_hypothesis, bool):
            raise ValueError("max_evidence_references_per_hypothesis must be a positive integer")
        if not isinstance(self.max_evidence_snippet_bytes, int) or self.max_evidence_snippet_bytes <= 0 or isinstance(self.max_evidence_snippet_bytes, bool):
            raise ValueError("max_evidence_snippet_bytes must be a positive integer")
        if not isinstance(self.max_total_evidence_bytes, int) or self.max_total_evidence_bytes <= 0 or isinstance(self.max_total_evidence_bytes, bool):
            raise ValueError("max_total_evidence_bytes must be a positive integer")
        if not isinstance(self.max_provenance_depth, int) or self.max_provenance_depth <= 0 or isinstance(self.max_provenance_depth, bool):
            raise ValueError("max_provenance_depth must be a positive integer")
        if not isinstance(self.max_serialized_graph_size, int) or self.max_serialized_graph_size <= 0 or isinstance(self.max_serialized_graph_size, bool):
            raise ValueError("max_serialized_graph_size must be a positive integer")


class EvidenceGraph:
    """Resource-bounded, stable, JSON-serializable graph for evidence provenance tracking."""
    def __init__(self, config: Optional[EvidenceGraphConfig] = None):
        self.config = config or EvidenceGraphConfig()
        self.config.validate()
        self.nodes: Dict[str, EvidenceNode] = {}
        self.edges: List[EvidenceEdge] = []
        self.metadata: Dict[str, Any] = {}
        self.total_evidence_bytes = 0

    def add_node(self, node: EvidenceNode) -> str:
        """Adds a node if it fits the configured resource budget, deduplicating on ID."""
        if len(self.nodes) >= self.config.max_nodes:
            raise ValueError(f"Max nodes limit of {self.config.max_nodes} exceeded")
        
        node_bytes = len(node.content.encode("utf-8"))
        if self.total_evidence_bytes + node_bytes > self.config.max_total_evidence_bytes:
            raise ValueError(f"Max total evidence bytes limit of {self.config.max_total_evidence_bytes} exceeded")

        if node.id in self.nodes:
            return node.id

        self.nodes[node.id] = node
        self.total_evidence_bytes += node_bytes
        return node.id

    def add_edge(self, edge: EvidenceEdge) -> None:
        """Adds a relationship edge, deduplicating on ID connections and edge type."""
        if len(self.edges) >= self.config.max_edges:
            raise ValueError(f"Max edges limit of {self.config.max_edges} exceeded")
        
        duplicate = any(e.source_id == edge.source_id and e.target_id == edge.target_id and e.type == edge.type for e in self.edges)
        if not duplicate:
            self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        """Provides sorted dictionary representation for deterministic ordering."""
        sorted_nodes = sorted([node.to_dict() for node in self.nodes.values()], key=lambda x: x["id"])
        sorted_edges = sorted([
            {
                "source_id": e.source_id,
                "target_id": e.target_id,
                "type": e.type
            }
            for e in self.edges
        ], key=lambda x: (x["source_id"], x["target_id"], x["type"]))
        
        return {
            "metadata": self.metadata,
            "nodes": sorted_nodes,
            "edges": sorted_edges
        }

    def to_json(self) -> str:
        """Renders the graph to a strictly validated JSON string with strict size checking."""
        serialized = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(serialized.encode("utf-8")) > self.config.max_serialized_graph_size:
            raise ValueError(f"Serialized graph size exceeds budget of {self.config.max_serialized_graph_size} bytes")
        return serialized
