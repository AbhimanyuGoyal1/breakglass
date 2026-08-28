"""Unit tests for the BREAKGLASS sandbox validation engine."""

import unittest
from unittest.mock import patch, MagicMock
from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate
)
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import MockSandboxValidator, TrueForgeSandboxValidator
from breakglass.validation.engine import ValidationConfig, ValidationEngine


class TestSandboxValidation(unittest.TestCase):
    """Test suite for the sandbox validation engine, adapter, and config models."""

    def setUp(self):
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
        self.report = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(
                    file="src/server.py",
                    line=12,
                    method="POST",
                    pattern="/run",
                    evidence=""
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="",
                    file="src/server.py",
                    line=15,
                    evidence=""
                )
            ]
        )
        self.valid_hyp = SecurityHypothesis(
            id="HYP-001",
            title="Title",
            description="Desc",
            category="command_injection",
            severity="HIGH",
            confidence=0.85,
            evidence_references=[
                EvidenceReference(type="route", file="src/server.py", line=12, detail=""),
                EvidenceReference(type="security_indicator", file="src/server.py", line=15, detail="")
            ]
        )

    def test_validation_result_model(self):
        """Verify model dictionary serialization and status schema values."""
        res = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Confirmed vulnerability"
        )
        d = res.to_dict()
        self.assertEqual(d["hypothesis_id"], "HYP-001")
        self.assertEqual(d["status"], "VALIDATED")
        self.assertTrue(d["attempted"])
        self.assertTrue(d["confirmed"])
        self.assertEqual(d["evidence"], "Confirmed vulnerability")

    def test_config_parameter_validation(self):
        """Verify that invalid configuration limits are rejected strictly."""
        with self.assertRaises(ValueError):
            ValidationConfig(timeout_seconds=-5.0).validate()
        with self.assertRaises(ValueError):
            ValidationConfig(max_output_bytes=0).validate()
        with self.assertRaises(ValueError):
            ValidationConfig(max_hypotheses_per_run=0).validate()
        with self.assertRaises(ValueError):
            ValidationConfig(max_payload_bytes=-100).validate()

    def test_eligibility_validation(self):
        """Verify hypothesis eligibility boundary logic."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # 1. Valid hypothesis is eligible
        eligible, reason = engine.check_eligibility(self.valid_hyp, self.report)
        self.assertTrue(eligible, f"Expected eligible, got: {reason}")

        # 2. Invalid ID rejected
        bad_id_hyp = SecurityHypothesis(
            id="", title="T", description="D", category="command_injection",
            severity="HIGH", confidence=0.8, evidence_references=[EvidenceReference(type="route", file="src/server.py", line=12)]
        )
        eligible, reason = engine.check_eligibility(bad_id_hyp, self.report)
        self.assertFalse(eligible)

        # 3. Unsupported category rejected
        bad_cat_hyp = SecurityHypothesis(
            id="HYP-001", title="T", description="D", category="unsupported_vuln_category",
            severity="HIGH", confidence=0.8, evidence_references=[EvidenceReference(type="route", file="src/server.py", line=12)]
        )
        eligible, reason = engine.check_eligibility(bad_cat_hyp, self.report)
        self.assertFalse(eligible)

        # 4. Missing/empty evidence references rejected
        no_ref_hyp = SecurityHypothesis(
            id="HYP-001", title="T", description="D", category="command_injection",
            severity="HIGH", confidence=0.8, evidence_references=[]
        )
        eligible, reason = engine.check_eligibility(no_ref_hyp, self.report)
        self.assertFalse(eligible)

        # 5. Fabricated evidence reference rejected
        fake_ref_hyp = SecurityHypothesis(
            id="HYP-001", title="T", description="D", category="command_injection",
            severity="HIGH", confidence=0.8, evidence_references=[
                EvidenceReference(type="route", file="src/admin.py", line=999)  # Fabricated reference
            ]
        )
        eligible, reason = engine.check_eligibility(fake_ref_hyp, self.report)
        self.assertFalse(eligible)

    def test_sandbox_boundary_mock_execution(self):
        """Verify batch orchestrator logic, output truncation, and safety exception wrapping."""
        # Predefined mock results
        res_success = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            stdout="Orchestrator validation output",
            stderr=""
        )
        validator = MockSandboxValidator(predefined_results={"HYP-001": res_success})
        config = ValidationConfig(max_output_bytes=10)  # Restrict output size
        engine = ValidationEngine(validator, config)

        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.hypothesis_id, "HYP-001")
        self.assertEqual(r.status, ValidationStatus.VALIDATED)
        self.assertTrue(r.attempted)
        self.assertTrue(r.confirmed)
        # Verify output truncation
        self.assertTrue(r.stdout.endswith("[TRUNCATED]"))
        self.assertEqual(len(r.stdout), 10 + len("... [TRUNCATED]"))

    def test_sandbox_exception_safety(self):
        """Verify that single validator failures/exceptions fail closed and do not abort the run."""
        class CrashValidator(MockSandboxValidator):
            def validate(self, hypothesis, context):
                raise RuntimeError("Sandbox environment crashed")

        engine = ValidationEngine(CrashValidator())
        results = engine.validate_hypotheses([self.valid_hyp], self.report)

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, ValidationStatus.SANDBOX_ERROR)
        self.assertTrue(r.attempted)
        self.assertFalse(r.confirmed)
        self.assertIn("Validator raised exception: Sandbox environment crashed", r.error_message)

    def test_trueforge_adapter_configuration_failure(self):
        """Verify TrueForgeSandboxValidator configuration check fails safely."""
        # Fail closed on invalid API key configuration
        tf_validator = TrueForgeSandboxValidator(api_key="")
        res = tf_validator.validate(self.valid_hyp, self.report)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)
        self.assertFalse(res.attempted)
        self.assertIn("Missing TRUEFORGE_API_KEY", res.error_message)

    def test_deterministic_hypothesis_sorting(self):
        """Verify validation results are output in deterministic order sorted by ID."""
        hyp2 = SecurityHypothesis(
            id="HYP-002",
            title="T2",
            description="D2",
            category="command_injection",
            severity="HIGH",
            confidence=0.8,
            evidence_references=[EvidenceReference(type="route", file="src/server.py", line=12)]
        )
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Order input randomly
        results = engine.validate_hypotheses([hyp2, self.valid_hyp], self.report)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].hypothesis_id, "HYP-001")
        self.assertEqual(results[1].hypothesis_id, "HYP-002")

    @patch("builtins.open")
    @patch("subprocess.run")
    @patch("os.system")
    def test_safety_boundary(self, mock_system, mock_run, mock_open):
        """Verify host filesystem, shell, and subprocess commands are never executed."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)
        engine.validate_hypotheses([self.valid_hyp], self.report)

        mock_open.assert_not_called()
        mock_run.assert_not_called()
        mock_system.assert_not_called()


if __name__ == "__main__":
    unittest.main()
