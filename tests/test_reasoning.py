"""Unit tests for BREAKGLASS agent reasoning/security hypothesis layer."""

import unittest
from unittest.mock import patch
from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate
)
from breakglass.reasoning.engine import DeterministicReasoningEngine
from breakglass.reasoning.models import EvidenceReference, SecurityHypothesis


class TestAgentReasoning(unittest.TestCase):
    """Test suite for deterministic agent reasoning layer."""

    def setUp(self):
        self.engine = DeterministicReasoningEngine()
        self.empty_summary = RepositorySummary(
            root="/repo",
            total_files=0,
            total_directories=0,
            languages={},
            frameworks=[],
            ecosystems=[],
            config_files=[],
            docker_configs=[],
            cicd_configs=[],
            infrastructure_configs=[],
            test_files=[]
        )

    def test_no_evidence_produces_no_hypotheses(self):
        """Test that an empty inspection report produces no hypotheses."""
        report = RepositoryReport(
            repository=self.empty_summary,
            entry_points=[],
            routes=[],
            security_indicators=[],
            manifests=[],
            errors=[]
        )
        res = self.engine.generate_hypotheses(report)
        self.assertEqual(len(res.hypotheses), 0)

    def test_single_indicator_no_correlation(self):
        """Test that single indicators with no correlating routes/frameworks yield no hypotheses."""
        # Only a subprocess indicator, no routes
        report = RepositoryReport(
            repository=self.empty_summary,
            entry_points=[],
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/exec.py",
                    line=10,
                    evidence="subprocess.run(...)"
                )
            ]
        )
        res = self.engine.generate_hypotheses(report)
        self.assertEqual(len(res.hypotheses), 0)

        # Only a database indicator, no routes
        report2 = RepositoryReport(
            repository=self.empty_summary,
            entry_points=[],
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="database",
                    indicator_type="raw_sql_construction_indicator",
                    file="src/db.py",
                    line=5,
                    evidence="query(f'SELECT ...')"
                )
            ]
        )
        res2 = self.engine.generate_hypotheses(report2)
        self.assertEqual(len(res2.hypotheses), 0)

    def test_subprocess_route_correlation_local(self):
        """Test local (same-file) correlation of subprocess indicator and route."""
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/server.py",
                    line=12,
                    method="POST",
                    pattern="/run-task",
                    evidence="@app.post('/run-task')"
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run(...)"
                )
            ]
        )
        res = self.engine.generate_hypotheses(report)
        self.assertEqual(len(res.hypotheses), 1)

        hyp = res.hypotheses[0]
        self.assertTrue(hyp.id.startswith("HYP-COMMAND-INJECTION-"))
        self.assertEqual(hyp.category, "command_injection")
        self.assertEqual(hyp.severity, "HIGH")
        self.assertEqual(hyp.confidence, 0.85)
        self.assertEqual(len(hyp.evidence_references), 2)
        # Ensure references are present
        types = {ref.type for ref in hyp.evidence_references}
        self.assertIn("security_indicator", types)
        self.assertIn("route", types)

    def test_subprocess_route_correlation_cross(self):
        """Test cross-file correlation is disabled and produces no hypotheses."""
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/api.py",
                    line=10,
                    method="GET",
                    pattern="/execute",
                    evidence="@app.get('/execute')"
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/exec.py",
                    line=5,
                    evidence="os.system(...)"
                )
            ]
        )
        res = self.engine.generate_hypotheses(report)
        self.assertEqual(len(res.hypotheses), 0)

    def test_database_route_correlation(self):
        """Test database/route local raw SQL correlation, cross-file exclusion, and generic ORM exclusion."""
        # 1. Local raw SQL construction + route in same file -> SQL injection hypothesis
        report_local = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/db.py",
                    line=8,
                    method="GET",
                    pattern="/users",
                    evidence="@app.get('/users')"
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="database",
                    indicator_type="raw_sql_construction_indicator",
                    file="src/db.py",
                    line=12,
                    evidence="query(f'SELECT ...')"
                )
            ]
        )
        res_local = self.engine.generate_hypotheses(report_local)
        self.assertEqual(len(res_local.hypotheses), 1)
        self.assertTrue(res_local.hypotheses[0].id.startswith("HYP-SQL-INJECTION-"))
        self.assertEqual(res_local.hypotheses[0].severity, "HIGH")
        self.assertEqual(res_local.hypotheses[0].confidence, 0.80)

        # 2. Local generic database query indicator + route -> NO hypothesis (Generic ORM exclusion)
        report_generic = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/db.py",
                    line=8,
                    method="GET",
                    pattern="/users",
                    evidence="@app.get('/users')"
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="database",
                    indicator_type="database_query_indicator",
                    file="src/db.py",
                    line=12,
                    evidence="SELECT id FROM users"
                )
            ]
        )
        res_generic = self.engine.generate_hypotheses(report_generic)
        self.assertEqual(len(res_generic.hypotheses), 0)

        # 3. Cross-file SQL correlation -> NO hypothesis (Same-file rule)
        report_cross = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/api.py",
                    line=20,
                    method="POST",
                    pattern="/save",
                    evidence="@app.post('/save')"
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="database",
                    indicator_type="raw_sql_construction_indicator",
                    file="src/db.py",
                    line=12,
                    evidence="query(f'INSERT INTO users')"
                )
            ]
        )
        res_cross = self.engine.generate_hypotheses(report_cross)
        self.assertEqual(len(res_cross.hypotheses), 0)

    def test_serialization_entry_point_correlation(self):
        """Test local RCE correlation and cross-file RCE exclusion."""
        # Local RCE correlation
        report_local = RepositoryReport(
            repository=self.empty_summary,
            entry_points=[
                EntryPointCandidate(
                    file="src/main.py",
                    type="cli/script",
                    description="Python __main__ execution block",
                    line=30
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="serialization",
                    indicator_type="unsafe_deserialization_indicator",
                    file="src/main.py",
                    line=15,
                    evidence="pickle.loads(...)"
                )
            ]
        )
        res_local = self.engine.generate_hypotheses(report_local)
        self.assertEqual(len(res_local.hypotheses), 1)
        self.assertTrue(res_local.hypotheses[0].id.startswith("HYP-REMOTE-CODE-EXECUTION-"))
        self.assertEqual(res_local.hypotheses[0].severity, "CRITICAL")
        self.assertEqual(res_local.hypotheses[0].confidence, 0.90)

        # Cross-file RCE correlation -> NO hypothesis
        report_cross = RepositoryReport(
            repository=self.empty_summary,
            entry_points=[
                EntryPointCandidate(
                    file="src/main.py",
                    type="main",
                    description="Java entry point",
                    line=10
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="serialization",
                    indicator_type="unsafe_deserialization_indicator",
                    file="src/utils.py",
                    line=25,
                    evidence="eval(payload)"
                )
            ]
        )
        res_cross = self.engine.generate_hypotheses(report_cross)
        self.assertEqual(len(res_cross.hypotheses), 0)

    def test_cloud_secrets_framework_correlation(self):
        """Test correlation of cloud credentials and secrets configuration with frameworks."""
        summary = RepositorySummary(
            root="/repo",
            total_files=5,
            total_directories=2,
            languages={"Python": 5},
            frameworks=["FastAPI", "FastAPI"],  # Framework duplicate
            ecosystems=["pip"],
            config_files=[],
            docker_configs=[],
            cicd_configs=[],
            infrastructure_configs=[],
            test_files=[]
        )
        report = RepositoryReport(
            repository=summary,
            security_indicators=[
                SecurityIndicator(
                    category="cloud_sdk",
                    indicator_type="cloud_sdk_indicator",
                    file="src/cloud.py",
                    line=8,
                    evidence="boto3.client('s3')"
                )
            ]
        )
        res = self.engine.generate_hypotheses(report)
        self.assertEqual(len(res.hypotheses), 1)

        hyp = res.hypotheses[0]
        self.assertTrue(hyp.id.startswith("HYP-CREDENTIAL-EXPOSURE-"))
        self.assertEqual(hyp.category, "credential_exposure")
        self.assertEqual(hyp.severity, "MEDIUM")
        self.assertEqual(hyp.confidence, 0.75)
        self.assertEqual(len(hyp.evidence_references), 1)
        self.assertEqual(hyp.evidence_references[0].type, "security_indicator")

    def test_id_collisions_with_similar_paths_and_indicators(self):
        """Verify that similar paths, distinct indicators, and routes produce unique IDs."""
        # 1. Path collision checks (a/b.py vs a.b.py)
        report_path_1 = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="a/b.py", line=1, method="GET", pattern="/", evidence="")],
            security_indicators=[SecurityIndicator(category="subprocess", indicator_type="", file="a/b.py", line=1, evidence="")]
        )
        report_path_2 = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="a.b.py", line=1, method="GET", pattern="/", evidence="")],
            security_indicators=[SecurityIndicator(category="subprocess", indicator_type="", file="a.b.py", line=1, evidence="")]
        )
        res1 = self.engine.generate_hypotheses(report_path_1)
        res2 = self.engine.generate_hypotheses(report_path_2)
        self.assertNotEqual(res1.hypotheses[0].id, res2.hypotheses[0].id)

        # 2. Distinct indicators at same file/line
        report_ind = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/api.py", line=5, method="GET", pattern="/", evidence="")],
            security_indicators=[
                SecurityIndicator(category="subprocess", indicator_type="ind_a", file="src/api.py", line=5, evidence="subprocess_a"),
                SecurityIndicator(category="subprocess", indicator_type="ind_b", file="src/api.py", line=5, evidence="subprocess_b")
            ]
        )
        res_ind = self.engine.generate_hypotheses(report_ind)
        self.assertEqual(len(res_ind.hypotheses), 2)
        self.assertNotEqual(res_ind.hypotheses[0].id, res_ind.hypotheses[1].id)

        # 3. Distinct routes at same location
        report_route = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/api.py", line=5, method="GET", pattern="/route_a", evidence=""),
                RouteCandidate(file="src/api.py", line=5, method="POST", pattern="/route_b", evidence="")
            ],
            security_indicators=[
                SecurityIndicator(category="subprocess", indicator_type="ind", file="src/api.py", line=5, evidence="subprocess")
            ]
        )
        res_route = self.engine.generate_hypotheses(report_route)
        self.assertEqual(len(res_route.hypotheses), 2)
        self.assertNotEqual(res_route.hypotheses[0].id, res_route.hypotheses[1].id)

    def test_deterministic_output_and_sorting(self):
        """Verify that hypotheses output order is strictly sorted and deterministic."""
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/server.py", line=1, method="GET", pattern="/z", evidence=""),
                RouteCandidate(file="src/server.py", line=2, method="POST", pattern="/a", evidence="")
            ],
            security_indicators=[
                SecurityIndicator(category="subprocess", indicator_type="", file="src/server.py", line=1, evidence=""),
                SecurityIndicator(category="database", indicator_type="raw_sql_construction_indicator", file="src/server.py", line=2, evidence="")
            ]
        )

        res1 = self.engine.generate_hypotheses(report)
        res2 = self.engine.generate_hypotheses(report)

        # Confirm equal reports
        self.assertEqual(res1.to_dict(), res2.to_dict())

        # Verify sorted by ID
        ids = [h.id for h in res1.hypotheses]
        self.assertEqual(ids, sorted(ids))

        # Verify evidence reference sorting within hypotheses
        for hyp in res1.hypotheses:
            ref_keys = [(ref.file, ref.line or 0, ref.type, ref.detail) for ref in hyp.evidence_references]
            self.assertEqual(ref_keys, sorted(ref_keys))

    def test_duplicate_prevention(self):
        """Test that duplicate hypotheses are prevented."""
        # Two identical pairs of route and indicator inputs (same files, lines, and content)
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/api.py", line=5, method="GET", pattern="/test", evidence=""),
                RouteCandidate(file="src/api.py", line=5, method="GET", pattern="/test", evidence="")
            ],
            security_indicators=[
                SecurityIndicator(category="subprocess", indicator_type="", file="src/api.py", line=5, evidence=""),
                SecurityIndicator(category="subprocess", indicator_type="", file="src/api.py", line=5, evidence="")
            ]
        )
        res = self.engine.generate_hypotheses(report)
        # Should generate exactly 1 unique hypothesis, not multiple duplicates
        self.assertEqual(len(res.hypotheses), 1)

    @patch("builtins.open")
    @patch("subprocess.run")
    def test_safety_boundary(self, mock_run, mock_open):
        """Test that the reasoning engine never opens files or executes subprocesses."""
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/api.py", line=5, method="GET", pattern="/", evidence="")],
            security_indicators=[SecurityIndicator(category="subprocess", indicator_type="", file="src/api.py", line=5, evidence="")]
        )
        self.engine.generate_hypotheses(report)

        # Confirm no IO or execution occurred
        mock_open.assert_not_called()
        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
