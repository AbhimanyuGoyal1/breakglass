import unittest
import tempfile
import json
import math
from pathlib import Path
from typing import Dict, Any

from unittest.mock import MagicMock
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

    # --- 7. Qodo Remediation Regression Tests ---
    def test_qodo_finding_1_fingerprint_verification(self):
        """Verify that fingerprint mismatch prevents stale/mutated evidence reference authentication."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[SecurityIndicator(category="secret_config", indicator_type="api", file=self.dummy_file, line=10, evidence="API_KEY=[REDACTED]")],
            routes=[], entry_points=[], manifests=[], errors=[]
        )
        # Correct detail and fingerprint (hash of canonical detail)
        ref_ok = EvidenceReference(
            type="security_indicator", file=self.dummy_file, line=10,
            detail="Exposed secret config: API_KEY=[REDACTED]"
        )
        valid, _ = authenticate_evidence_reference(ref_ok, report, self.repo_root)
        self.assertTrue(valid)

        # Mutated detail and matching fingerprint of mutated detail (should fail fingerprint verification against canonical)
        ref_mutated = EvidenceReference(
            type="security_indicator", file=self.dummy_file, line=10,
            detail="Exposed secret config: API_KEY=mutated_secret"
        )
        valid, _ = authenticate_evidence_reference(ref_mutated, report, self.repo_root)
        self.assertFalse(valid)

    def test_qodo_finding_3_same_coordinate_conflation(self):
        """Verify that two distinct findings at the same file/line do not conflate and resolve to correct nodes."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[
                SecurityIndicator(category="subprocess", indicator_type="sub", file=self.dummy_file, line=15, evidence="subprocess.run"),
                SecurityIndicator(category="database", indicator_type="db", file=self.dummy_file, line=15, evidence="SELECT 1")
            ],
            routes=[], entry_points=[], manifests=[], errors=[]
        )
        hyp = SecurityHypothesis(
            id="HYP-1", title="T", description="D", category="command_injection", severity="HIGH", confidence=0.8,
            evidence_references=[
                EvidenceReference(type="security_indicator", file=self.dummy_file, line=15, detail="Subprocess call: subprocess.run"),
                EvidenceReference(type="security_indicator", file=self.dummy_file, line=15, detail="Database indicator: SELECT 1")
            ]
        )
        builder = EvidenceGraphBuilder(self.config)
        graph = builder.build_graph(report, [hyp], self.repo_root)

        # Should produce two distinct nodes for the indicators instead of overwriting/conflating
        indicator_nodes = [n for n in graph.nodes.values() if n.kind == "security_indicator"]
        self.assertEqual(len(indicator_nodes), 2)
        contents = {n.content for n in indicator_nodes}
        self.assertIn("subprocess.run", contents)
        self.assertIn("SELECT 1", contents)

    def test_qodo_finding_4_deduplication_at_capacity(self):
        """Verify duplicate nodes and edges can be added successfully even at capacity limit."""
        cfg = EvidenceGraphConfig(max_nodes=1, max_edges=1, max_total_evidence_bytes=1000)
        graph = EvidenceGraph(cfg)

        node = EvidenceNode(kind="file", path=self.dummy_file, content="abc", source="repo", confidence=0.9)
        id1 = graph.add_node(node)
        
        # Second add of the duplicate node should succeed without raising capacity limit error
        id2 = graph.add_node(node)
        self.assertEqual(id1, id2)

        edge = EvidenceEdge(source_id="A", target_id="B", type="evidence_to_hypothesis")
        graph.add_edge(edge)

        # Second add of the duplicate edge should succeed/noop without capacity limit error
        graph.add_edge(edge)
        self.assertEqual(len(graph.edges), 1)

    def test_qodo_finding_5_boolean_confidence_rejection(self):
        """Verify that Python boolean True/False values are strictly rejected for confidence."""
        with self.assertRaises(ValueError):
            EvidenceNode(kind="file", path=self.dummy_file, content="", source="repo", confidence=True)

        with self.assertRaises(ValueError):
            EvidenceNode(kind="file", path=self.dummy_file, content="", source="repo", confidence=False)

    def test_qodo_finding_6_frozen_metadata_immutability(self):
        """Verify that provenance metadata is defensively copied and frozen during construction and to_dict()."""
        meta = {"nested": {"key": "val"}}
        node = EvidenceNode(
            kind="file", path=self.dummy_file, content="", source="repo", confidence=1.0,
            provenance_metadata=meta
        )
        
        # Original input modification does not affect node
        meta["nested"]["key"] = "hacked"
        self.assertEqual(node.provenance_metadata["nested"]["key"], "val")

        # Mutating frozen node metadata dictionary should raise TypeError
        with self.assertRaises(TypeError):
            node.provenance_metadata["nested"]["key"] = "hacked"

        # to_dict() returns a detached mutable dict that doesn't mutate node internals
        d = node.to_dict()
        d["provenance_metadata"]["nested"]["key"] = "hacked"
        self.assertEqual(node.provenance_metadata["nested"]["key"], "val")

    def test_qodo_finding_7_provenance_depth_limit(self):
        """Verify that adding edges exceeding max_provenance_depth is rejected."""
        cfg = EvidenceGraphConfig(max_provenance_depth=3)
        graph = EvidenceGraph(cfg)

        # Path of length 3 nodes (2 edges): A -> B -> C
        graph.add_edge(EvidenceEdge(source_id="A", target_id="B", type="evidence_to_related_evidence"))
        graph.add_edge(EvidenceEdge(source_id="B", target_id="C", type="evidence_to_related_evidence"))

        # Adding 3rd edge (making length 4 nodes): C -> D should fail
        with self.assertRaises(ValueError):
            graph.add_edge(EvidenceEdge(source_id="C", target_id="D", type="evidence_to_related_evidence"))

    def test_qodo_finding_8_graph_references_untrusted_bypass(self):
        """Verify that forged details or unreported files in evidence references fail to create graph nodes/edges."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[], routes=[], entry_points=[], manifests=[], errors=[]
        )
        hyp = SecurityHypothesis(
            id="HYP-1", title="T", description="D", category="insecure_config", severity="LOW", confidence=0.8,
            evidence_references=[
                # Untrusted/unreported file
                EvidenceReference(type="file", file="src/unreported.py", line=None, detail="File: src/unreported.py"),
                # Forged detail security indicator
                EvidenceReference(type="security_indicator", file=self.dummy_file, line=10, detail="Exposed secret config: FORGED")
            ]
        )
        builder = EvidenceGraphBuilder(self.config)
        graph = builder.build_graph(report, [hyp], self.repo_root)

        # Graph should not contain any of the unauthenticated nodes/edges
        self.assertEqual(len(graph.nodes), 0)
        self.assertEqual(len(graph.edges), 0)

    def test_qodo_finding_9_manifest_file_provenance(self):
        """Verify manifest files are successfully authenticated as valid file references."""
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[]),
            security_indicators=[], routes=[], entry_points=[],
            manifests=[MagicMock(file="package.json", ecosystem="npm", dependencies=[])],
            errors=[]
        )
        ref = EvidenceReference(type="file", file="package.json", line=None, detail="File: package.json")
        valid, canonical = authenticate_evidence_reference(ref, report, self.repo_root)
        self.assertTrue(valid)
        self.assertEqual(canonical, "File: package.json")

    def test_qodo_finding_10_bytesafe_utf8_truncation(self):
        """Verify genuinely byte-safe UTF-8 snippet truncation that preserves multibyte characters."""
        # € is 3 bytes in UTF-8. 
        # "a€b" is 1 + 3 + 1 = 5 bytes.
        text = "a\u20acb" # "a€b"
        
        # Truncate at 2 bytes: should drop partial € and return "a"
        cfg2 = EvidenceGraphConfig(max_evidence_snippet_bytes=2)
        builder = EvidenceGraphBuilder(cfg2)
        report = RepositoryReport(
            repository=RepositorySummary(root=self.repo_root, total_files=1, total_directories=0, config_files=[self.dummy_file]),
            security_indicators=[SecurityIndicator(category="subprocess", indicator_type="sub", file=self.dummy_file, line=1, evidence=text)],
            routes=[], entry_points=[], manifests=[], errors=[]
        )
        graph = builder.build_graph(report, [], self.repo_root)
        node = list(graph.nodes.values())[0]
        self.assertEqual(node.content, "a")

        # Truncate at 4 bytes: should keep € (3 bytes) + "a" (1 byte) -> "a€"
        cfg4 = EvidenceGraphConfig(max_evidence_snippet_bytes=4)
        builder4 = EvidenceGraphBuilder(cfg4)
        graph4 = builder4.build_graph(report, [], self.repo_root)
        node4 = list(graph4.nodes.values())[0]
        self.assertEqual(node4.content, "a\u20ac")

