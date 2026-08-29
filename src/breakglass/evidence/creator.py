import os
import hashlib
from typing import List, Optional, Dict, Tuple
from pathlib import Path

from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.evidence.models import EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceGraphConfig
from breakglass.inspection.scanner import _is_contained_in
from breakglass.inspection.indicators import redact_secrets
from breakglass.evidence.auth import authenticate_evidence_reference

def generate_finding_id(kind: str, file: str, line: Optional[int], extra: str) -> str:
    """Generates a stable finding ID for provenance mapping in the graph."""
    norm_file = file.replace("\\", "/")
    canonical = f"{kind}:{norm_file}:{line}:{extra}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"FIND-{kind.upper().replace('_', '-')}-{digest[:16]}"


class EvidenceGraphBuilder:
    """Constructs a deterministic, resource-bounded EvidenceGraph from RepositoryReport and hypotheses."""
    def __init__(self, config: Optional[EvidenceGraphConfig] = None):
        self.config = config or EvidenceGraphConfig()
        self.config.validate()

    def build_graph(
        self,
        report: RepositoryReport,
        hypotheses: List[SecurityHypothesis],
        repo_root: str
    ) -> EvidenceGraph:
        """Builds and returns an EvidenceGraph."""
        graph = EvidenceGraph(self.config)
        graph.metadata["repository_root"] = repo_root.replace("\\", "/")

        # Map to find node ID from (type, file, line)
        finding_to_evid_id: Dict[Tuple[str, str, Optional[int]], str] = {}

        # 1. Process Security Indicators
        for ind in getattr(report, "security_indicators", []) or []:
            if ind is None:
                continue
            try:
                ind_file = getattr(ind, "file", None)
                if not ind_file or not isinstance(ind_file, str):
                    continue
                
                # Check path containment
                abs_path = Path(repo_root) / ind_file
                if not _is_contained_in(Path(repo_root), abs_path):
                    continue

                category = getattr(ind, "category", "")
                ind_type = getattr(ind, "indicator_type", "")
                raw_ev = getattr(ind, "evidence", "") or ""
                
                # Redact secrets and enforce limits
                snippet = redact_secrets(raw_ev)
                if len(snippet.encode("utf-8")) > self.config.max_evidence_snippet_bytes:
                    snippet = snippet[:self.config.max_evidence_snippet_bytes]

                confidence = getattr(ind, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)):
                    confidence = 0.8

                node = EvidenceNode(
                    kind="security_indicator",
                    path=ind_file,
                    content=snippet,
                    source="security_finding",
                    confidence=float(confidence),
                    line=getattr(ind, "line", None),
                    provenance_metadata={
                        "category": category,
                        "indicator_type": ind_type
                    }
                )
                evid_id = graph.add_node(node)
                finding_to_evid_id[("security_indicator", ind_file.replace("\\", "/"), node.line)] = evid_id

                # Create finding to evidence edge
                find_id = generate_finding_id("indicator", ind_file, node.line, category)
                graph.add_edge(EvidenceEdge(
                    source_id=find_id,
                    target_id=evid_id,
                    type="finding_to_evidence"
                ))

            except Exception:
                # Isolate malformed finding
                continue

        # 2. Process Routes
        for r in getattr(report, "routes", []) or []:
            if r is None:
                continue
            try:
                r_file = getattr(r, "file", None)
                if not r_file or not isinstance(r_file, str):
                    continue
                
                abs_path = Path(repo_root) / r_file
                if not _is_contained_in(Path(repo_root), abs_path):
                    continue

                method = getattr(r, "method", "")
                pattern = getattr(r, "pattern", "")
                raw_ev = getattr(r, "evidence", "") or ""

                snippet = redact_secrets(raw_ev)
                if len(snippet.encode("utf-8")) > self.config.max_evidence_snippet_bytes:
                    snippet = snippet[:self.config.max_evidence_snippet_bytes]

                confidence = getattr(r, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)):
                    confidence = 0.85

                node = EvidenceNode(
                    kind="route",
                    path=r_file,
                    content=snippet,
                    source="repository_inspection",
                    confidence=float(confidence),
                    line=getattr(r, "line", None),
                    provenance_metadata={
                        "method": method,
                        "pattern": pattern
                    }
                )
                evid_id = graph.add_node(node)
                finding_to_evid_id[("route", r_file.replace("\\", "/"), node.line)] = evid_id

                find_id = generate_finding_id("route", r_file, node.line, f"{method} {pattern}")
                graph.add_edge(EvidenceEdge(
                    source_id=find_id,
                    target_id=evid_id,
                    type="finding_to_evidence"
                ))

            except Exception:
                continue

        # 3. Process Entry Points
        for ep in getattr(report, "entry_points", []) or []:
            if ep is None:
                continue
            try:
                ep_file = getattr(ep, "file", None)
                if not ep_file or not isinstance(ep_file, str):
                    continue
                
                abs_path = Path(repo_root) / ep_file
                if not _is_contained_in(Path(repo_root), abs_path):
                    continue

                ep_type = getattr(ep, "type", "")
                desc = getattr(ep, "description", "") or ""

                snippet = redact_secrets(desc)
                if len(snippet.encode("utf-8")) > self.config.max_evidence_snippet_bytes:
                    snippet = snippet[:self.config.max_evidence_snippet_bytes]

                confidence = getattr(ep, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)):
                    confidence = 0.8

                node = EvidenceNode(
                    kind="entry_point",
                    path=ep_file,
                    content=snippet,
                    source="repository_inspection",
                    confidence=float(confidence),
                    line=getattr(ep, "line", None),
                    provenance_metadata={
                        "type": ep_type
                    }
                )
                evid_id = graph.add_node(node)
                finding_to_evid_id[("entry_point", ep_file.replace("\\", "/"), node.line)] = evid_id

                find_id = generate_finding_id("entry_point", ep_file, node.line, ep_type)
                graph.add_edge(EvidenceEdge(
                    source_id=find_id,
                    target_id=evid_id,
                    type="finding_to_evidence"
                ))

            except Exception:
                continue

        # 4. Connect Evidence to Hypotheses
        for hyp in hypotheses:
            if hyp is None:
                continue
            try:
                hyp_id = getattr(hyp, "id", None)
                if not hyp_id:
                    continue

                # Bounded evidence references count check
                refs = getattr(hyp, "evidence_references", []) or []
                bounded_refs = refs[:self.config.max_evidence_references_per_hypothesis]

                # Resolve and connect
                evid_nodes_for_hyp = []
                for ref in bounded_refs:
                    if ref is None:
                        continue
                    
                    ref_file = getattr(ref, "file", None)
                    ref_type = getattr(ref, "type", None)
                    ref_line = getattr(ref, "line", None)
                    if not ref_file or not ref_type:
                        continue

                    ref_file_norm = ref_file.replace("\\", "/")
                    node_id = finding_to_evid_id.get((ref_type, ref_file_norm, ref_line))

                    # If node does not exist (e.g., file reference or unmapped), create it dynamically
                    if not node_id:
                        # Validate path containment
                        abs_path = Path(repo_root) / ref_file
                        if not _is_contained_in(Path(repo_root), abs_path):
                            continue

                        if ref_type == "file" and ref_line is None:
                            node = EvidenceNode(
                                kind="file",
                                path=ref_file,
                                content="",
                                source="repository_inspection",
                                confidence=1.0,
                                provenance_metadata={}
                            )
                            node_id = graph.add_node(node)
                            finding_to_evid_id[("file", ref_file_norm, None)] = node_id
                        else:
                            # Skip untrusted or unauthenticated references
                            continue

                    evid_nodes_for_hyp.append(node_id)

                    # Create edge: evidence -> hypothesis
                    graph.add_edge(EvidenceEdge(
                        source_id=node_id,
                        target_id=hyp_id,
                        type="evidence_to_hypothesis"
                    ))

                    # Create edge: hypothesis -> evidence
                    graph.add_edge(EvidenceEdge(
                        source_id=hyp_id,
                        target_id=node_id,
                        type="hypothesis_to_evidence"
                    ))

                # Create evidence -> related evidence edge for correlation
                if len(evid_nodes_for_hyp) > 1:
                    for i in range(len(evid_nodes_for_hyp) - 1):
                        graph.add_edge(EvidenceEdge(
                            source_id=evid_nodes_for_hyp[i],
                            target_id=evid_nodes_for_hyp[i+1],
                            type="evidence_to_related_evidence"
                        ))

            except Exception:
                continue

        return graph
