import unittest
import tempfile
import json
import math
from pathlib import Path
from typing import Dict, Any

from breakglass.inspection.models import RepositoryReport, RepositorySummary, SecurityIndicator, RouteCandidate, EntryPointCandidate
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.evidence.models import EvidenceNode, EvidenceEdge, EvidenceGraph, EvidenceGraphConfig, generate_evidence_id
from breakglass.evidence.auth import authenticate_evidence_reference
from breakglass.evidence.creator import EvidenceGraphBuilder
from breakglass.validation.engine import ValidationEngine
from breakglass.validation.validator import MockSandboxValidator
from breakglass.hypothesis import SecurityHypothesisGenerator

class TestEvidenceGraph(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_root = str(Path(self.temp_dir.name).resolve())
        
        # Write dummy files to prevent resolution errors
        Path(self.repo_root, "src").mkdir(exist_ok=True)
        self.dummy_file = "src/main.py"
        Path(self.repo_root, self.dummy_file).write_text("print('hello')\n")
        
        # Safe default config
        self.config = EvidenceGraphConfig()

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. Identity & Authentication Tests ---
    def test_deterministic_evidence_ids(self):
        """Verify identical evidence fields produce the same ID, and changes produce different IDs."""
        node1 = EvidenceNode(
            kind="security_indicator",
            path="src/main.py",
            content="print('indicator')",
            source="security_finding",
            confidence=0.9,
            line=10,
            provenance_metadata={}
        )
        node2 = EvidenceNode(
            kind="security_indicator",
            path="src/main.py",
            content="print('indicator')",
            source="security_finding",
            confidence=0.9,
            line=10,
            provenance_metadata={}
        )
        node_diff_content = EvidenceNode(
            kind="security_indicator",
            path="src/main.py",
            content="print('different')",
            source="security_finding",
            confidence=0.9,
            line=10,
            provenance_metadata={}
        )
        node_diff_path = EvidenceNode(
            kind="security_indicator",
            path="src/other.py",
            content="print('indicator')",
            source="security_finding",
            confidence=0.9,
            line=10,
            provenance_metadata={}
        )

        self.assertEqual(node1.id, node2.id)
        self.assertEqual(node1.fingerprint, node2.fingerprint)
        
        self.assertNotEqual(node1.id, node_diff_content.id)
        self.assertNotEqual(node1.id, node_diff_path.id)

    def test_authentication_tampered_elements(self):
        """Verify tampered path, line, or content fails authentication."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[SecurityIndicator(category="secret_config", indicator_type="api", file=self.dummy_file, line=10, evidence="API_KEY=[REDACTED]")],
            routes=[], entry_points=[], manifests=[], errors=[]
        )

        # Valid reference
        ref_valid = EvidenceReference(
            type="security_indicator",
            file=self.dummy_file,
            line=10,
            detail="Exposed secret config: API_KEY=[REDACTED]"
        )
        valid, canonical = authenticate_evidence_reference(ref_valid, report, self.repo_root)
        self.assertTrue(valid)

        # Tampered detail
        ref_bad_detail = EvidenceReference(
            type="security_indicator",
            file=self.dummy_file,
            line=10,
            detail="Exposed secret config: API_KEY=forged"
        )
        valid, _ = authenticate_evidence_reference(ref_bad_detail, report, self.repo_root)
        self.assertFalse(valid)

        # Tampered line
        ref_bad_line = EvidenceReference(
            type="security_indicator",
            file=self.dummy_file,
            line=20,
            detail="Exposed secret config: API_KEY=[REDACTED]"
        )
        valid, _ = authenticate_evidence_reference(ref_bad_line, report, self.repo_root)
        self.assertFalse(valid)

        # Tampered path
        ref_bad_path = EvidenceReference(
            type="security_indicator",
            file="src/missing.py",
            line=10,
            detail="Exposed secret config: API_KEY=[REDACTED]"
        )
        valid, _ = authenticate_evidence_reference(ref_bad_path, report, self.repo_root)
        self.assertFalse(valid)

    # --- 2. Path Security Tests ---
    def test_path_traversal_rejection(self):
        """Verify directory traversal path attacks are strictly rejected."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[], routes=[], entry_points=[], manifests=[], errors=[]
        )

        traversal_paths = [
            "../outside.py",
            "src/../../outside.py",
            "/etc/passwd",
            "C:/Windows/System32",
            "src/main.py/../../outside.py"
        ]

        for p in traversal_paths:
            ref = EvidenceReference(type="file", file=p, line=None, detail=f"File: {p}")
            valid, _ = authenticate_evidence_reference(ref, report, self.repo_root)
            self.assertFalse(valid, f"Traversal path '{p}' was incorrectly authenticated")

    def test_sibling_directory_prefix_collision(self):
        """Verify sibling directory attacks (e.g. repo_root_sibling) are rejected."""
        # Create a sibling directory
        sibling_dir = Path(self.repo_root).parent / (Path(self.repo_root).name + "_sibling")
        sibling_dir.mkdir(exist_ok=True)
        sibling_file = sibling_dir / "attack.py"
        sibling_file.write_text("print('hack')")

        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[]),
            security_indicators=[], routes=[], entry_points=[], manifests=[], errors=[]
        )

        rel_sibling = "../" + sibling_dir.name + "/attack.py"
        ref = EvidenceReference(type="file", file=rel_sibling, line=None, detail=f"File: {rel_sibling}")
        valid, _ = authenticate_evidence_reference(ref, report, self.repo_root)
        self.assertFalse(valid, "Sibling folder access escape should be rejected")

    # --- 3. Graph Integrity Tests ---
    def test_graph_deduplication(self):
        """Verify duplicate nodes and edges are cleanly deduplicated in construction."""
        graph = EvidenceGraph(self.config)
        node = EvidenceNode(
            kind="security_indicator", path=self.dummy_file, content="evidence",
            source="security_finding", confidence=0.8, line=10
        )
        
        # Add node twice
        id1 = graph.add_node(node)
        id2 = graph.add_node(node)
        self.assertEqual(id1, id2)
        self.assertEqual(len(graph.nodes), 1)

        # Add duplicate edges
        edge = EvidenceEdge(source_id="A", target_id="B", type="evidence_to_hypothesis")
        graph.add_edge(edge)
        graph.add_edge(edge)
        self.assertEqual(len(graph.edges), 1)

    def test_graph_malformed_finding_isolation(self):
        """Verify that a malformed finding (missing path/type) does not abort graph creation for valid findings."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=2, total_directories=1, config_files=[self.dummy_file]),
            security_indicators=[
                None, # Malformed element
                SecurityIndicator(category="secret_config", indicator_type=None, file=None, line=10, evidence=""), # Invalid attributes
                SecurityIndicator(category="secret_config", indicator_type="api", file=self.dummy_file, line=10, evidence="API_KEY=123") # Valid finding
            ],
            routes=[], entry_points=[], manifests=[], errors=[]
        )

        builder = EvidenceGraphBuilder(self.config)
        graph = builder.build_graph(report, [], self.repo_root)
        
        # Valid node should be built despite the earlier malformed entries
        self.assertEqual(len(graph.nodes), 1)
        node = list(graph.nodes.values())[0]
        self.assertEqual(node.path, self.dummy_file)

    # --- 4. Resource & Config Limits Tests ---
    def test_invalid_config_inputs_rejected(self):
        """Verify negative, NaN, infinity, and boolean values are strictly rejected in config."""
        invalid_values = [-10, 0, float('nan'), float('inf'), -float('inf'), True, False, "100"]
        
        for val in invalid_values:
            with self.assertRaises(ValueError):
                cfg = EvidenceGraphConfig(max_nodes=val)
                cfg.validate()

    def test_max_nodes_and_edges_limits(self):
        """Verify max nodes and edge budget constraints are strictly enforced."""
        cfg = EvidenceGraphConfig(max_nodes=3, max_edges=3, max_total_evidence_bytes=1000)
        graph = EvidenceGraph(cfg)

        for i in range(3):
            node = EvidenceNode(
                kind="security_indicator", path=self.dummy_file, content=f"ev_{i}",
                source="security_finding", confidence=0.8, line=i+1
            )
            graph.add_node(node)

        # 4th node must trigger budget limit error
        node_overflow = EvidenceNode(
            kind="security_indicator", path=self.dummy_file, content="overflow",
            source="security_finding", confidence=0.8, line=100
        )
        with self.assertRaises(ValueError):
            graph.add_node(node_overflow)

        # Edges overflow check
        for i in range(3):
            graph.add_edge(EvidenceEdge(source_id=f"A_{i}", target_id=f"B_{i}", type="evidence_to_hypothesis"))
        with self.assertRaises(ValueError):
            graph.add_edge(EvidenceEdge(source_id="X", target_id="Y", type="evidence_to_hypothesis"))

    def test_total_evidence_bytes_and_serialized_size_budget(self):
        """Verify snippet lengths and serialized json bounds constraints are enforced."""
        # 1. Total snippet bytes limit
        cfg = EvidenceGraphConfig(max_total_evidence_bytes=20)
        graph = EvidenceGraph(cfg)
        node1 = EvidenceNode(kind="file", path=self.dummy_file, content="1234567890", source="repository_inspection", confidence=1.0)
        graph.add_node(node1)
        node2 = EvidenceNode(kind="file", path=self.dummy_file, content="123456789012", source="repository_inspection", confidence=1.0, line=5)
        with self.assertRaises(ValueError):
            graph.add_node(node2)

        # 2. Max serialized size limit
        cfg_size = EvidenceGraphConfig(max_serialized_graph_size=100) # tiny limit
        graph_tiny = EvidenceGraph(cfg_size)
        node_tiny = EvidenceNode(kind="file", path=self.dummy_file, content="small", source="repository_inspection", confidence=1.0)
        graph_tiny.add_node(node_tiny)
        with self.assertRaises(ValueError):
            graph_tiny.to_json()

    # --- 5. Secret Security Tests ---
    def test_graph_evidence_secrets_redaction(self):
        """Verify that secrets are correctly redacted before being stored inside graph nodes."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[
                SecurityIndicator(category="secret_config", indicator_type="api", file=self.dummy_file, line=10, evidence="API_KEY=\"secret123\""),
                SecurityIndicator(category="secret_config", indicator_type="password", file=self.dummy_file, line=20, evidence="DB_PASSWORD: hunter2"),
                SecurityIndicator(category="secret_config", indicator_type="token", file=self.dummy_file, line=30, evidence="TOKEN=abc123")
            ],
            routes=[], entry_points=[], manifests=[], errors=[]
        )

        builder = EvidenceGraphBuilder(self.config)
        graph = builder.build_graph(report, [], self.repo_root)
        
        serialized = graph.to_json()
        self.assertNotIn("secret123", serialized)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("abc123", serialized)
        self.assertIn("[REDACTED]", serialized)

    # --- 6. Integration Tests ---
    def test_full_pipeline_evidence_graph_integration(self):
        """Verify repository report -> graph -> hypothesis -> validation pipeline flow."""
        # 1. Generate Report
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[SecurityIndicator(category="secret_config", indicator_type="api_key_indicator", file=self.dummy_file, line=5, evidence="API_KEY=[REDACTED]")],
            routes=[], entry_points=[], manifests=[], errors=[]
        )

        # 2. Generate Hypothesis
        generator = SecurityHypothesisGenerator()
        hyp_res = generator.generate_and_rank(report, self.repo_root)
        self.assertGreater(len(hyp_res.hypotheses), 0)
        hyp = hyp_res.hypotheses[0]

        # 3. Construct Graph
        builder = EvidenceGraphBuilder(self.config)
        graph = builder.build_graph(report, hyp_res.hypotheses, self.repo_root)
        self.assertGreater(len(graph.nodes), 0)
        self.assertGreater(len(graph.edges), 0)

        # 4. Validation Engine Shapes Authenticate
        engine = ValidationEngine(MockSandboxValidator())
        valid, canonical_hyp, err_msg = engine.validate_hypothesis_shape(hyp, report)
        self.assertTrue(valid, f"Validation failed: {err_msg}")
        self.assertEqual(canonical_hyp.id, hyp.id)
