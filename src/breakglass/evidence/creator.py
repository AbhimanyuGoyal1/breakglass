import os
import hashlib
from typing import List, Optional, Dict, Tuple
from pathlib import Path

from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.evidence.models import EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceGraphConfig
from breakglass.inspection.scanner import _is_contained_in
from breakglass.inspection.indicators import redact_secrets
from breakglass.evidence.auth import authenticate_evidence_reference, _match_indicator_detail

def generate_finding_id(kind: str, file: str, line: Optional[int], extra: str) -> str:
    """Generates a stable finding ID for provenance mapping in the graph."""
    norm_file = file.replace("\\", "/")
    canonical = f"{kind}:{norm_file}:{line}:{extra}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"FIND-{kind.upper().replace('_', '-')}-{digest[:16]}"

def _safe_utf8_truncate(s: str, max_bytes: int) -> str:
    """Genuinely byte-safe UTF-8 truncation discarding incomplete trailing code units."""
    encoded = s.encode("utf-8")
    if len(encoded) <= max_bytes:
        return s
    truncated_bytes = encoded[:max_bytes]
    return truncated_bytes.decode("utf-8", errors="ignore")


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

        # Map to find node ID from unique finding ID
        finding_to_evid_id: Dict[str, str] = {}

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
                
                # Redact secrets and enforce limits via byte-safe UTF-8 truncation
                snippet = redact_secrets(raw_ev)
                snippet = _safe_utf8_truncate(snippet, self.config.max_evidence_snippet_bytes)

                confidence = getattr(ind, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
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
                
                # Use unique finding ID (Finding 3)
                find_id = generate_finding_id("indicator", ind_file, node.line, snippet)
                finding_to_evid_id[find_id] = evid_id

                # Create finding to evidence edge
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
                snippet = _safe_utf8_truncate(snippet, self.config.max_evidence_snippet_bytes)

                confidence = getattr(r, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
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

                find_id = generate_finding_id("route", r_file, node.line, f"{method} {pattern}")
                finding_to_evid_id[find_id] = evid_id

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
                snippet = _safe_utf8_truncate(snippet, self.config.max_evidence_snippet_bytes)

                confidence = getattr(ep, "confidence", None)
                if confidence is None or not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
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

                find_id = generate_finding_id("entry_point", ep_file, node.line, ep_type)
                finding_to_evid_id[find_id] = evid_id

                graph.add_edge(EvidenceEdge(
                    source_id=find_id,
                    target_id=evid_id,
                    type="finding_to_evidence"
                ))

            except Exception:
                continue

        # 4. Connect Evidence to Hypotheses (enforcing strict authentication)
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
                    
                    # Finding 8: Validate the supplied reference through the canonical boundary first
                    valid, auth_detail = authenticate_evidence_reference(ref, report, repo_root, self.config)
                    if not valid:
                        continue
                    
                    ref_file = getattr(ref, "file", None)
                    ref_type = getattr(ref, "type", None)
                    ref_line = getattr(ref, "line", None)
                    if not ref_file or not ref_type:
                        continue

                    node_id = None
                    ref_file_norm = ref_file.replace("\\", "/")

                    # Map authenticated reference to its unique finding ID node
                    if ref_type == "security_indicator":
                        for ind in getattr(report, "security_indicators", []) or []:
                            if ind is None:
                                continue
                            ind_file = getattr(ind, "file", None)
                            ind_line = getattr(ind, "line", None)
                            if ind_file and ind_file.replace("\\", "/") == ref_file_norm:
                                if ind_line == ref_line or (ind_line is None and ref_line is None):
                                    if _match_indicator_detail(ind, auth_detail):
                                        snippet = redact_secrets(getattr(ind, "evidence", "") or "")
                                        snippet = _safe_utf8_truncate(snippet, self.config.max_evidence_snippet_bytes)
                                        find_id = generate_finding_id("indicator", ind_file, ind_line, snippet)
                                        node_id = finding_to_evid_id.get(find_id)
                                        break

                    elif ref_type == "route":
                        for r in getattr(report, "routes", []) or []:
                            if r is None:
                                continue
                            r_file = getattr(r, "file", None)
                            r_line = getattr(r, "line", None)
                            if r_file and r_file.replace("\\", "/") == ref_file_norm and r_line == ref_line:
                                method = getattr(r, "method", "")
                                pattern = getattr(r, "pattern", "")
                                if auth_detail == f"Route: {method} {pattern}":
                                    find_id = generate_finding_id("route", r_file, r_line, f"{method} {pattern}")
                                    node_id = finding_to_evid_id.get(find_id)
                                    break

                    elif ref_type == "entry_point":
                        for ep in getattr(report, "entry_points", []) or []:
                            if ep is None:
                                continue
                            ep_file = getattr(ep, "file", None)
                            ep_line = getattr(ep, "line", None)
                            if ep_file and ep_file.replace("\\", "/") == ref_file_norm and ep_line == ref_line:
                                ep_type = getattr(ep, "type", "")
                                desc = getattr(ep, "description", "")
                                if auth_detail == f"Entry point: {ep_type} ({desc})":
                                    find_id = generate_finding_id("entry_point", ep_file, ep_line, ep_type)
                                    node_id = finding_to_evid_id.get(find_id)
                                    break

                    elif ref_type == "file":
                        # Determine if we already created a node for this file
                        find_id = generate_finding_id("file", ref_file, None, "")
                        node_id = finding_to_evid_id.get(find_id)
                        if not node_id:
                            # Verify if it was authenticated as a valid file
                            if auth_detail == f"File: {ref_file_norm}":
                                node = EvidenceNode(
                                    kind="file",
                                    path=ref_file,
                                    content="",
                                    source="repository_inspection",
                                    confidence=1.0,
                                    provenance_metadata={}
                                )
                                node_id = graph.add_node(node)
                                finding_to_evid_id[find_id] = node_id

                    if not node_id:
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
