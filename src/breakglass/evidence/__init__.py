"""Evidence Graph and Authentication Module."""

from breakglass.evidence.models import (
    EvidenceNode,
    EvidenceEdge,
    EvidenceGraphConfig,
    EvidenceGraph,
    generate_evidence_id
)
from breakglass.evidence.auth import authenticate_evidence_reference
from breakglass.evidence.creator import EvidenceGraphBuilder

__all__ = [
    "EvidenceNode",
    "EvidenceEdge",
    "EvidenceGraphConfig",
    "EvidenceGraph",
    "generate_evidence_id",
    "authenticate_evidence_reference",
    "EvidenceGraphBuilder"
]
