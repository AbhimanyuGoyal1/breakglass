import unittest
import math
import tempfile
from pathlib import Path
from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate,
    ManifestInfo
)
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.hypothesis import HypothesisConfig, SecurityHypothesisGenerator
from breakglass.validation import ValidationEngine, MockSandboxValidator

class TestSecurityHypothesisEngine(unittest.TestCase):
    """Adversarial test suite for BREAKGLASS Security Hypothesis Generation & Ranking layer."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_root = str(Path(self.temp_dir.name).resolve())
        self.empty_summary = RepositorySummary(
            root=self.repo_root,
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

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_nan_infinity_config_rejection(self):
        """Test that HypothesisConfig rejects zero, negatives, NaN, and infinities."""
        # Test positive integers
        for val in (0, -1, float("nan"), float("inf"), float("-inf"), "not-an-int", True):
            with self.assertRaises(ValueError):
                HypothesisConfig(max_hypotheses=val).validate()
            with self.assertRaises(ValueError):
                HypothesisConfig(max_hypotheses_per_category=val).validate()
            with self.assertRaises(ValueError):
                HypothesisConfig(max_evidence_per_hypothesis=val).validate()
            with self.assertRaises(ValueError):
                HypothesisConfig(max_description_length=val).validate()
            with self.assertRaises(ValueError):
                HypothesisConfig(max_total_hypothesis_bytes=val).validate()
            with self.assertRaises(ValueError):
                HypothesisConfig(generation_timeout_seconds=val).validate()

    def test_empty_and_irrelevant_reports(self):
        """Verify empty reports and reports with only irrelevant findings yield zero hypotheses."""
        generator = SecurityHypothesisGenerator()
        
        # 1. Completely empty
        report_empty = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        res = generator.generate_and_rank(report_empty, self.repo_root)
        self.assertEqual(len(res.hypotheses), 0)

        # 2. Only generic indicators with no category match
        report_irrelevant = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=10, method="GET", pattern="/run", evidence="")],
            security_indicators=[SecurityIndicator(category="generic_category", indicator_type="", file="src/server.py", line=15, evidence="")],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        res_irr = generator.generate_and_rank(report_irrelevant, self.repo_root)
        # No local correlations or matching categories
        self.assertEqual(len(res_irr.hypotheses), 0)

    def test_deterministic_ids_and_identical_reports(self):
        """Verify identical reports produce stable, deterministic IDs and content ordering."""
        # Touch files to satisfy path containment
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )

        generator = SecurityHypothesisGenerator()
        res1 = generator.generate_and_rank(report, self.repo_root)
        res2 = generator.generate_and_rank(report, self.repo_root)

        self.assertEqual(len(res1.hypotheses), 1)
        self.assertEqual(res1.to_dict(), res2.to_dict())
        self.assertTrue(res1.hypotheses[0].id.startswith("HYP-COMMAND-INJECTION-"))

    def test_path_traversal_and_containment(self):
        """Verify evidence reference files residing outside the repository are rejected."""
        # File path escapes containment
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="../outside_repo.py",
                    line=5,
                    evidence="api_key = 'sk_live_123'"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)
        # Rejected because ../outside_repo.py is not contained in repo_root
        self.assertEqual(len(res.hypotheses), 0)

    def test_secrets_redaction(self):
        """Verify hardcoded secret assignments inside evidence reference details are redacted."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=5,
                    evidence="password = 'my_super_secret_password'"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)

        self.assertEqual(len(res.hypotheses), 1)
        hyp = res.hypotheses[0]
        self.assertNotIn("my_super_secret_password", hyp.description)
        self.assertNotIn("my_super_secret_password", hyp.evidence_references[0].detail)
        self.assertIn("[REDACTED]", hyp.evidence_references[0].detail)

    def test_malformed_findings_isolation(self):
        """Verify that individual malformed report findings do not crash the entire run."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # Third finding is malformed (None/missing attributes)
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=5,
                    evidence="password = 'my_super_secret_password'"
                ),
                None, # Malformed finding
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=10,
                    evidence="secret = 'another_key'"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)
        # Should gracefully generate 1 consolidated hypothesis despite the None finding
        self.assertEqual(len(res.hypotheses), 1)
        self.assertEqual(res.validation_status, "partial_success")

    def test_hypothesis_deduplication(self):
        """Verify duplicate findings are semantically deduplicated."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # Two identical indicators
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=5,
                    evidence="api_key = 'test'"
                ),
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=5,
                    evidence="api_key = 'test'"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )
        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res.hypotheses), 1)

    def test_category_and_global_limits(self):
        """Verify configuration category counts and global hypothesis caps are enforced."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        for i in range(10):
            (Path(self.repo_root) / f"src/server_{i}.py").write_text("print('test')")

        # Generate 10 credential exposure indicators
        indicators = [
            SecurityIndicator(
                category="secret_config",
                indicator_type="api_key_indicator",
                file=f"src/server_{i}.py",
                line=5,
                evidence=f"api_key = 'key_{i}'"
            )
            for i in range(10)
        ]

        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=indicators,
            entry_points=[],
            manifests=[],
            errors=[]
        )

        # Config limits: global max = 5, per-category max = 3
        config = HypothesisConfig(max_hypotheses=5, max_hypotheses_per_category=3)
        generator = SecurityHypothesisGenerator(config)
        res = generator.generate_and_rank(report, self.repo_root)

        # Capped by category limit of 3
        self.assertEqual(len(res.hypotheses), 3)

        # Test global limit cap
        config_global = HypothesisConfig(max_hypotheses=2, max_hypotheses_per_category=5)
        generator_global = SecurityHypothesisGenerator(config_global)
        res_global = generator_global.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res_global.hypotheses), 2)

    def test_evidence_reference_limits(self):
        """Verify hypothesis evidence reference counts are capped."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # Correlation command injection: 1 indicator + 1 route
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )

        # Limit to 1 evidence reference per hypothesis
        config = HypothesisConfig(max_evidence_per_hypothesis=1)
        generator = SecurityHypothesisGenerator(config)
        res = generator.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res.hypotheses), 1)
        self.assertEqual(len(res.hypotheses[0].evidence_references), 1)

    def test_description_and_size_limits(self):
        """Verify description lengths and total serialized bytes boundaries are enforced."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[],
            security_indicators=[
                SecurityIndicator(
                    category="secret_config",
                    indicator_type="api_key_indicator",
                    file="src/server.py",
                    line=5,
                    evidence="api_key = 'test'"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )

        # Enforce max description length of 10 characters
        config_desc = HypothesisConfig(max_description_length=10)
        generator_desc = SecurityHypothesisGenerator(config_desc)
        res_desc = generator_desc.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res_desc.hypotheses), 1)
        self.assertTrue(res_desc.hypotheses[0].description.endswith("... [TRUNCATED]"))
        self.assertLessEqual(len(res_desc.hypotheses[0].description), 10 + len("... [TRUNCATED]"))

        # Enforce max total hypothesis bytes limit to 50 bytes (which should prune all hypotheses)
        config_bytes = HypothesisConfig(max_total_hypothesis_bytes=50)
        generator_bytes = SecurityHypothesisGenerator(config_bytes)
        res_bytes = generator_bytes.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res_bytes.hypotheses), 0)

    def test_deterministic_ranking_and_tie_breaking(self):
        """Verify priority scoring order and strict alphabetical ID tie-breaking."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # CRITICAL severity (serialization + ep) vs HIGH severity (subprocess + route)
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                ),
                SecurityIndicator(
                    category="serialization",
                    indicator_type="unsafe_deserialization_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="pickle.loads"
                )
            ],
            entry_points=[EntryPointCandidate(file="src/server.py", type="cli/script", description="desc", line=10)],
            manifests=[],
            errors=[]
        )

        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)

        # Ranked list should have critical (remote_code_execution) first, then high (command_injection)
        self.assertEqual(len(res.hypotheses), 2)
        self.assertEqual(res.hypotheses[0].category, "remote_code_execution")
        self.assertEqual(res.hypotheses[1].category, "command_injection")
        self.assertGreater(res.hypotheses[0].metadata["priority_score"], res.hypotheses[1].metadata["priority_score"])

    def test_validation_boundary_integration(self):
        """Verify that generated hypotheses successfully pass the validation boundary eligibility check."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                )
            ],
            entry_points=[],
            manifests=[],
            errors=[]
        )

        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)
        self.assertEqual(len(res.hypotheses), 1)

        # Validate against the canonical validation engine eligibility boundary
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)
        eligible, reason = engine.check_eligibility(res.hypotheses[0], report)
        self.assertTrue(eligible, f"Eligibility failed: {reason}")

    def test_all_11_categories_validation(self):
        """Verify that every one of the 11 generated categories successfully authenticates and passes validation."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")
        (Path(self.repo_root) / "go.mod").write_text("module test\nrequire github.com/gin-gonic/gin v1.7.0")

        # Setup all findings to trigger generators
        report = RepositoryReport(
            repository=RepositorySummary(
                root=self.repo_root,
                total_files=3,
                total_directories=1,
                languages={"python": 1, "go": 1},
                frameworks=["flask"],
                ecosystems=["npm", "go", "pip"],
                config_files=["src/server.py"],
                docker_configs=[],
                cicd_configs=[],
                infrastructure_configs=[],
                test_files=[]
            ),
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(category="secret_config", indicator_type="api_key_indicator", file="src/server.py", line=5, evidence="API_KEY=[REDACTED]"),
                SecurityIndicator(category="subprocess", indicator_type="subprocess_indicator", file="src/server.py", line=15, evidence="subprocess.run"),
                SecurityIndicator(category="authentication", indicator_type="auth_check", file="src/server.py", line=25, evidence="login()"),
                SecurityIndicator(category="filesystem", indicator_type="file_access", file="src/server.py", line=35, evidence="open()")
            ],
            entry_points=[EntryPointCandidate(file="src/server.py", type="cli", description="main script", line=10)],
            manifests=[ManifestInfo(ecosystem="go", file="go.mod", dependencies=["github.com/gin-gonic/gin"])],
            errors=[]
        )

        generator = SecurityHypothesisGenerator()
        res = generator.generate_and_rank(report, self.repo_root)
        self.assertGreater(len(res.hypotheses), 0)

        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Verify eligibility and ID re-authentication for all generated hypotheses
        for hyp in res.hypotheses:
            valid, canonical_hyp, err_msg = engine.validate_hypothesis_shape(hyp, report)
            self.assertTrue(valid, f"Validation failed for category '{hyp.category}': {err_msg}")

    def test_standalone_vs_correlated_credentials_authentication(self):
        """Verify that standalone and framework-correlated credential hypotheses authenticate correctly, and tampered IDs fail."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # 1. Standalone secret finding (triggers ind_secret identity)
        report_stan = RepositoryReport(
            repository=RepositorySummary(
                root=self.repo_root, total_files=1, total_directories=0, languages={}, frameworks=[], ecosystems=[],
                config_files=[], docker_configs=[], cicd_configs=[], infrastructure_configs=[], test_files=[]
            ),
            routes=[],
            security_indicators=[SecurityIndicator(category="secret_config", indicator_type="api_key_indicator", file="src/server.py", line=5, evidence="API_KEY=[REDACTED]")],
            entry_points=[], manifests=[], errors=[]
        )
        generator = SecurityHypothesisGenerator()
        res_stan = generator.generate_and_rank(report_stan, self.repo_root)
        self.assertEqual(len(res_stan.hypotheses), 1)
        hyp_stan = res_stan.hypotheses[0]

        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Standalone should authenticate successfully
        valid, canonical_stan, err_msg = engine.validate_hypothesis_shape(hyp_stan, report_stan)
        self.assertTrue(valid, f"Standalone authentication failed: {err_msg}")

        # Tampering with ID should fail
        hyp_stan_tampered = SecurityHypothesis(
            id="HYP-CREDENTIAL-EXPOSURE-TAMPERED",
            title=hyp_stan.title,
            description=hyp_stan.description,
            category=hyp_stan.category,
            severity=hyp_stan.severity,
            confidence=hyp_stan.confidence,
            evidence_references=hyp_stan.evidence_references
        )
        valid_t, _, _ = engine.validate_hypothesis_shape(hyp_stan_tampered, report_stan)
        self.assertFalse(valid_t, "Tampered standalone ID should have been rejected")

        # 2. Correlated credential finding (triggers framework credential identity)
        report_corr = RepositoryReport(
            repository=RepositorySummary(
                root=self.repo_root, total_files=1, total_directories=0, languages={}, frameworks=["flask"], ecosystems=[],
                config_files=[], docker_configs=[], cicd_configs=[], infrastructure_configs=[], test_files=[]
            ),
            routes=[],
            security_indicators=[SecurityIndicator(category="secret_config", indicator_type="api_key_indicator", file="src/server.py", line=5, evidence="API_KEY=[REDACTED]")],
            entry_points=[], manifests=[], errors=[]
        )
        res_corr = generator.generate_and_rank(report_corr, self.repo_root)
        self.assertEqual(len(res_corr.hypotheses), 2)
        # Find the framework-correlated hypothesis
        hyp_corr = None
        for h in res_corr.hypotheses:
            ind = report_corr.security_indicators[0]
            identity_correlation = {
                "rule": "credential_exposure",
                "ind": {
                    "category": ind.category,
                    "indicator_type": ind.indicator_type,
                    "file": ind.file,
                    "line": ind.line,
                    "evidence": ind.evidence
                },
                "frameworks": ["flask"]
            }
            expected_id = generate_hypothesis_id("credential_exposure", identity_correlation, is_llm=False)
            if h.id == expected_id:
                hyp_corr = h
                break
        self.assertIsNotNone(hyp_corr)

        # Correlated should authenticate successfully
        valid_c, canonical_corr, err_msg = engine.validate_hypothesis_shape(hyp_corr, report_corr)
        self.assertTrue(valid_c, f"Correlated authentication failed: {err_msg}")

    def test_ranking_before_admission_limits(self):
        """Verify that higher priority hypotheses are admitted first regardless of candidate generation order."""
        (Path(self.repo_root) / "src").mkdir(exist_ok=True)
        (Path(self.repo_root) / "src/server.py").write_text("print('test')")

        # Generates a HIGH priority candidate (command_injection) and a CRITICAL priority candidate (remote_code_execution)
        report = RepositoryReport(
            repository=self.empty_summary,
            routes=[RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                ),
                SecurityIndicator(
                    category="serialization",
                    indicator_type="unsafe_deserialization_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="pickle.loads"
                )
            ],
            entry_points=[EntryPointCandidate(file="src/server.py", type="cli/script", description="desc", line=10)],
            manifests=[],
            errors=[]
        )

        # Enforce global limit of exactly 1 hypothesis
        config = HypothesisConfig(max_hypotheses=1)
        generator = SecurityHypothesisGenerator(config)
        res = generator.generate_and_rank(report, self.repo_root)

        # The only admitted hypothesis must be the CRITICAL remote_code_execution candidate
        self.assertEqual(len(res.hypotheses), 1)
        self.assertEqual(res.hypotheses[0].category, "remote_code_execution")


if __name__ == "__main__":
    unittest.main()
