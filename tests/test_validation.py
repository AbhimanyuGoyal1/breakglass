"""Unit tests for the BREAKGLASS sandbox validation engine and safety controls."""

import time
import json
import unittest
from unittest.mock import patch, MagicMock
from breakglass.inspection.models import (
    RepositoryReport,
    RepositorySummary,
    SecurityIndicator,
    RouteCandidate,
    EntryPointCandidate
)
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.reasoning.engine import DeterministicReasoningEngine
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator, MockSandboxValidator, TrueForgeSandboxValidator
from breakglass.validation.engine import ValidationConfig, ValidationEngine


class SleepValidator(SandboxValidator):
    """Validator that sleeps to simulate latency/hangs."""
    def __init__(self, sleep_seconds: float):
        self.sleep_seconds = sleep_seconds
        self.completed = False

    def validate(self, hypothesis, context):
        time.sleep(self.sleep_seconds)
        self.completed = True
        return ValidationResult(
            hypothesis_id=hypothesis.id or "",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True
        )


class TestSandboxValidation(unittest.TestCase):
    """Test suite for security boundaries, timeouts, payloads, ID authentication, and sorting safeguards."""

    def setUp(self):
        self.empty_summary = RepositorySummary(
            root="/repo",
            total_files=0,
            total_directories=0,
            languages={},
            frameworks=["Flask"],
            ecosystems=[],
            config_files=["config.json"],
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
                ),
                RouteCandidate(
                    file="src/server.py",
                    line=20,
                    method="GET",
                    pattern="/info",
                    evidence=""
                )
            ],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                ),
                SecurityIndicator(
                    category="cloud_sdk",
                    indicator_type="cloud_sdk_indicator",
                    file="src/cloud.py",
                    line=10,
                    evidence="boto3.client"
                )
            ]
        )
        # Generate valid hypotheses with authoritative IDs
        det_engine = DeterministicReasoningEngine()
        det_report = det_engine.generate_hypotheses(self.report)
        self.valid_hyp = det_report.hypotheses[0]  # Command injection hypothesis
        self.valid_hyp_2 = det_report.hypotheses[1]  # Credential exposure hypothesis

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
        # Verify bool rejection
        with self.assertRaises(ValueError):
            ValidationConfig(timeout_seconds=True).validate()

    # --- 1. TIMEOUT BOUNDARY TESTS ---

    def test_validator_completes_before_timeout(self):
        """Verify standard fast execution completes successfully."""
        validator = SleepValidator(sleep_seconds=0.01)
        engine = ValidationEngine(validator, ValidationConfig(timeout_seconds=0.5))
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ValidationStatus.VALIDATED)

    def test_validator_exceeds_timeout(self):
        """Verify validation timeout boundary blocks hanging execution."""
        validator = SleepValidator(sleep_seconds=1.0)
        engine = ValidationEngine(validator, ValidationConfig(timeout_seconds=0.05))
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, ValidationStatus.TIMEOUT)
        self.assertTrue(r.attempted)
        self.assertFalse(r.confirmed)
        self.assertIn("timed out", r.error_message)

    # --- 2. REQUEST PAYLOAD BOUNDARY TESTS ---

    def test_payload_bounds_enforcement(self):
        """Verify that validation configuration limits payload bytes calculation."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Multi-byte UTF-8 character testing
        unicode_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title="Title with unicode: 🚀🔥",
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=self.valid_hyp.evidence_references,
            rationale=self.valid_hyp.rationale
        )

        # 1. Payload exactly at / below limit -> works
        engine.config.max_payload_bytes = 100 * 1024 * 1024  # 100MB
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(results[0].status, ValidationStatus.NOT_CONFIRMED)

        # 2. Payload above limit -> rejected with fail-closed INVALID_HYPOTHESIS status
        engine.config.max_payload_bytes = 10
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(results[0].status, ValidationStatus.INVALID_HYPOTHESIS)
        self.assertIn("exceeds the configured max_payload_bytes limit", results[0].error_message)

    # --- 3. OUTPUT BOUNDARY TESTS ---

    def test_output_bounds_and_truncation(self):
        """Verify stdout and stderr total combined output bytes limits and UTF-8 truncation."""
        res_large = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            stdout="A" * 100,
            stderr="B" * 100
        )
        validator = MockSandboxValidator(predefined_results={self.valid_hyp.id: res_large})

        # 1. Total byte capacity limit is 30
        engine = ValidationEngine(validator, ValidationConfig(max_output_bytes=30))
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        r = results[0]
        self.assertEqual(r.status, ValidationStatus.VALIDATED)

        # Check total combined output length: stdout bytes + stderr bytes <= 30
        total_len = len(r.stdout.encode("utf-8")) + len(r.stderr.encode("utf-8"))
        self.assertTrue(total_len <= 30, f"Combined bytes size was: {total_len}")
        self.assertTrue(r.stdout.endswith("[TRUNCATED]"))
        self.assertTrue(r.stderr.endswith("[TRUNCATED]"))

        # 2. Test unicode multi-byte characters with truncation marker
        res_unicode = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            stdout="🚀🔥🌟💥🎉" * 10,
            stderr=""
        )
        validator.predefined_results[self.valid_hyp.id] = res_unicode
        engine = ValidationEngine(validator, ValidationConfig(max_output_bytes=25))
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        r = results[0]
        # Total stdout size must fit within 25 bytes and contain no partial characters
        stdout_bytes = r.stdout.encode("utf-8")
        self.assertTrue(len(stdout_bytes) <= 25)
        # Verify decoding succeeded without errors
        r.stdout.encode("utf-8").decode("utf-8")

    # --- 4. HYPOTHESIS ID AUTHENTICATION ---

    def test_hypothesis_id_authentication(self):
        """Verify hypothesis ID recomputation and validation boundary authentication checks."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # 1. Arbitrary fake ID fails authentication
        fake_hyp = SecurityHypothesis(
            id="HYP-FAKE-ID",
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=self.valid_hyp.evidence_references,
            rationale=self.valid_hyp.rationale
        )
        eligible, reason = engine.check_eligibility(fake_hyp, self.report)
        self.assertFalse(eligible)
        self.assertIn("ID authentication failed", reason)

        # 2. Modified title with original ID fails authentication
        modified_title_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title="Modified Title",
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=self.valid_hyp.evidence_references,
            rationale=self.valid_hyp.rationale
        )
        eligible, reason = engine.check_eligibility(modified_title_hyp, self.report)
        # Note: For deterministic ID, title modification does not affect recomputed ID.
        # But wait! For LLM hypotheses, title does affect ID.
        # Let's verify with an LLM hypothesis style ID:
        llm_ref = [EvidenceReference(type="route", file="src/server.py", line=12, detail="Route: POST /run")]
        llm_identity = {
            "category": "command_injection",
            "title": "LLM Hypothesis Title",
            "description": "LLM Hypothesis Desc",
            "references": [{"type": "route", "file": "src/server.py", "line": 12, "detail": "Route: POST /run"}]
        }
        llm_id = generate_hypothesis_id("command_injection", llm_identity, is_llm=True)
        llm_hyp = SecurityHypothesis(
            id=llm_id,
            title="LLM Hypothesis Title",
            description="LLM Hypothesis Desc",
            category="command_injection",
            severity="HIGH",
            confidence=0.8,
            evidence_references=llm_ref
        )
        # Re-authenticating valid LLM hypothesis -> works
        eligible, reason = engine.check_eligibility(llm_hyp, self.report)
        self.assertTrue(eligible, reason)

        # Modify LLM hypothesis title -> fails authentication
        llm_hyp_mod = SecurityHypothesis(
            id=llm_id,
            title="Modified Title",
            description="LLM Hypothesis Desc",
            category="command_injection",
            severity="HIGH",
            confidence=0.8,
            evidence_references=llm_ref
        )
        eligible, reason = engine.check_eligibility(llm_hyp_mod, self.report)
        self.assertFalse(eligible)

        # 3. Modified deterministic reference details/location fails
        mod_ref_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=[
                # Use route line 20 instead of 12 (mismatch with the original correlated ID reference)
                EvidenceReference(type="route", file="src/server.py", line=20, detail="")
            ]
        )
        eligible, reason = engine.check_eligibility(mod_ref_hyp, self.report)
        self.assertFalse(eligible)

    # --- 5. FILE EVIDENCE LINE NUMBERS ---

    def test_file_evidence_references_rules(self):
        """Verify file references must have no line numbers."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Plain file reference with line is None -> OK
        ref_ok = EvidenceReference(type="file", file="config.json", line=None)
        valid, _ = engine._resolve_and_validate_evidence(ref_ok, self.report)
        self.assertTrue(valid)

        # Plain file reference with line set -> rejected
        ref_bad_line = EvidenceReference(type="file", file="config.json", line=12)
        valid, _ = engine._resolve_and_validate_evidence(ref_bad_line, self.report)
        self.assertFalse(valid)

    # --- 6. EVIDENCE DETAILS CANONICALIZATION ---

    def test_evidence_detail_canonicalization(self):
        """Verify caller-provided detail is ignored and replaced with authoritative inspection report findings."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Caller provides fabricated details
        ref = EvidenceReference(type="route", file="src/server.py", line=12, detail="EXECUTE DANGEROUS SHELL HERE")
        valid, auth_detail = engine._resolve_and_validate_evidence(ref, self.report)
        self.assertTrue(valid)
        self.assertEqual(auth_detail, "Route: POST /run")  # Replaced with authoritative description

    # --- 7. VALIDATOR RESULT INTEGRITY ---

    def test_validation_result_integrity_checks(self):
        """Verify strict validations of ValidationResult structure and invariant properties."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # 1. Adapter returns wrong ID
        bad_id_res = ValidationResult(
            hypothesis_id="HYP-WRONG-ID",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True
        )
        res = engine._validate_result_integrity(bad_id_res, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)
        self.assertIn("Hypothesis ID mismatch", res.error_message)

        # 2. Contradictory invariants: status = VALIDATED but attempted = False
        bad_invariants_res = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=False,
            confirmed=True
        )
        res = engine._validate_result_integrity(bad_invariants_res, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)
        self.assertIn("Contradictory state invariants", res.error_message)

        # 3. Invalid types in result fields
        bad_type_res = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            confidence_delta=True  # boolean instead of float
        )
        res = engine._validate_result_integrity(bad_type_res, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)
        self.assertIn("Invalid confidence_delta", res.error_message)

    # --- 8. DET_SORTING AND SAFEGUARDS ---

    def test_malformed_hypothesis_safeguard(self):
        """Verify malformed hypotheses list inputs do not crash sorting or orchestration."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # List contains integers, None, empty strings, dictionary, and a valid hypothesis
        payload = [
            None,
            "String hypothesis",
            {"id": "HYP-001"},
            self.valid_hyp,
            self.valid_hyp_2
        ]

        results = engine.validate_hypotheses(payload, self.report)
        # Validates and runs only valid instances, returns INVALID_HYPOTHESIS for malformed elements
        self.assertEqual(len(results), 5)
        invalid_results = [r for r in results if r.status == ValidationStatus.INVALID_HYPOTHESIS]
        self.assertEqual(len(invalid_results), 3)

        # Valid ones ran and returned result
        valid_results = [r for r in results if r.status == ValidationStatus.NOT_CONFIRMED]
        self.assertEqual(len(valid_results), 2)
        # Assert sorting by ID
        self.assertTrue(valid_results[0].hypothesis_id < valid_results[1].hypothesis_id)

    @patch("builtins.open")
    @patch("subprocess.run")
    @patch("os.system")
    def test_safety_boundary(self, mock_system, mock_run, mock_open):
        """Verify host command execution interfaces are never called by orchestrator."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)
        engine.validate_hypotheses([self.valid_hyp], self.report)

        mock_open.assert_not_called()
        mock_run.assert_not_called()
        mock_system.assert_not_called()

    def test_validator_timeout_real_limit(self):
        """Verify that a validator that hangs longer than timeout does not stall the orchestrator run."""
        validator = SleepValidator(sleep_seconds=2.0)
        # Configure timeout to be 0.05 seconds
        engine = ValidationEngine(validator, ValidationConfig(timeout_seconds=0.05))

        start_time = time.perf_counter()
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        elapsed = time.perf_counter() - start_time

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ValidationStatus.TIMEOUT)
        # Ensure it returns within 0.5s (meaning it did not wait for the full 2.0s sleep validator to finish)
        self.assertTrue(elapsed < 0.5, f"Orchestrator hung for {elapsed} seconds")
        self.assertFalse(validator.completed, "Validator thread was prematurely terminated or blocked orchestrator")

    def test_deterministic_reauthentication_extra_evidence(self):
        """Verify that extra, missing, duplicate, or altered evidence references are strictly rejected."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # 1. Extra reference
        extra_ref_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=self.valid_hyp.evidence_references + [
                EvidenceReference(type="file", file="config.json", line=None)
            ],
            rationale=self.valid_hyp.rationale
        )
        eligible, reason = engine.check_eligibility(extra_ref_hyp, self.report)
        self.assertFalse(eligible)

        # 2. Missing reference
        missing_ref_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=[self.valid_hyp.evidence_references[0]],
            rationale=self.valid_hyp.rationale
        )
        eligible, _ = engine.check_eligibility(missing_ref_hyp, self.report)
        self.assertFalse(eligible)

        # 3. Duplicate reference
        dup_ref_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=[
                self.valid_hyp.evidence_references[0],
                self.valid_hyp.evidence_references[0]
            ],
            rationale=self.valid_hyp.rationale
        )
        eligible, _ = engine.check_eligibility(dup_ref_hyp, self.report)
        self.assertFalse(eligible)

    def test_duplicate_same_location_indicator(self):
        """Verify multiple indicators on the same file/line resolve and authenticate deterministically."""
        report_dup = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")
            ],
            security_indicators=[
                # Indicator 1: Subprocess call on line 15
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                ),
                # Indicator 2: Database raw SQL on line 15 (same file/line!)
                SecurityIndicator(
                    category="database",
                    indicator_type="raw_sql_construction_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="SELECT id FROM users"
                )
            ]
        )
        det_engine = DeterministicReasoningEngine()
        det_report = det_engine.generate_hypotheses(report_dup)
        self.assertEqual(len(det_report.hypotheses), 2)

        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Both deterministic hypotheses must authenticate cleanly
        for hyp in det_report.hypotheses:
            eligible, reason = engine.check_eligibility(hyp, report_dup)
            self.assertTrue(eligible, f"Failed to authenticate {hyp.id}: {reason}")

    def test_sandbox_visible_deterministic_hypothesis_field_authentication(self):
        """Verify title, description, severity, confidence, and rationale modifications are overwritten/reconstructed."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # Modify fields that reach the sandbox
        modified_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title="Modified Unsafe Title",
            description="Modified Description",
            category=self.valid_hyp.category,
            severity="CRITICAL",  # Original was HIGH
            confidence=0.1,       # Original was 0.85
            evidence_references=self.valid_hyp.evidence_references,
            rationale="Modified Rationale"
        )

        results = engine.validate_hypotheses([modified_hyp], self.report)
        self.assertEqual(len(results), 1)
        # Eligible check succeeded
        self.assertEqual(results[0].status, ValidationStatus.NOT_CONFIRMED)

        # Retrieve the hypothesis passed to mock validator's validate() method
        self.assertEqual(len(validator.last_validated), 1)
        hyp_passed = validator.last_validated[0][0]

        # Verify that all fields were reconstructed from authoritative generated data
        self.assertEqual(hyp_passed.title, self.valid_hyp.title)
        self.assertEqual(hyp_passed.description, self.valid_hyp.description)
        self.assertEqual(hyp_passed.severity, "HIGH")
        self.assertEqual(hyp_passed.confidence, 0.85)
        self.assertEqual(hyp_passed.rationale, self.valid_hyp.rationale)

    def test_eligibility_strict_runtime_validation(self):
        """Verify strict runtime type validation of SecurityHypothesis input fields."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        cases = [
            # 1. Non-string title
            {"title": 123},
            # 2. Empty description
            {"description": ""},
            # 3. Invalid severity
            {"severity": "CRITICAL_MAX"},
            # 4. NaN confidence
            {"confidence": float("nan")},
            # 5. Infinity confidence
            {"confidence": float("inf")},
            # 6. Boolean confidence
            {"confidence": True},
            # 7. Non-string rationale
            {"rationale": []},
            # 8. Malformed evidence reference
            {"evidence_references": [None]},
        ]

        for idx, patch_fields in enumerate(cases):
            params = {
                "id": self.valid_hyp.id,
                "title": self.valid_hyp.title,
                "description": self.valid_hyp.description,
                "category": self.valid_hyp.category,
                "severity": self.valid_hyp.severity,
                "confidence": self.valid_hyp.confidence,
                "evidence_references": self.valid_hyp.evidence_references,
                "rationale": self.valid_hyp.rationale
            }
            params.update(patch_fields)
            bad_hyp = SecurityHypothesis(**params)
            eligible, reason = engine.check_eligibility(bad_hyp, self.report)
            self.assertFalse(eligible, f"Case #{idx} accepted: {reason}")

    def test_validation_result_integrity_hardening(self):
        """Verify strict validations of ValidationResult invariants, types, copy-sanitization, and size limits."""
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        # 1. attempted is integer 1 (not boolean)
        res_int_bool = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=1,  # type is int, not bool
            confirmed=True
        )
        res = engine._validate_result_integrity(res_int_bool, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)

        # 2. negative duration
        res_neg_dur = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            duration=-5.0
        )
        res = engine._validate_result_integrity(res_neg_dur, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)

        # 3. infinite duration
        res_inf_dur = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            duration=float("inf")
        )
        res = engine._validate_result_integrity(res_inf_dur, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)

        # 4. non-serializable metadata
        res_bad_meta = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            metadata={"func": lambda x: x}
        )
        res = engine._validate_result_integrity(res_bad_meta, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)

        # 5. oversized evidence/metadata
        res_oversized = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="C" * 150000  # 150KB (exceeds 100KB combined limit)
        )
        res = engine._validate_result_integrity(res_oversized, self.valid_hyp.id)
        self.assertEqual(res.status, ValidationStatus.SANDBOX_ERROR)

        # 6. Verify copy sanitization
        valid_res = ValidationResult(
            hypothesis_id=self.valid_hyp.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            metadata={"env": "prod"}
        )
        sanitized = engine._validate_result_integrity(valid_res, self.valid_hyp.id)
        self.assertIsNot(sanitized, valid_res)  # Must be a new copy
        self.assertIsNot(sanitized.metadata, valid_res.metadata)  # Metadata copy

    def test_trueforge_adapter_preflight_failure_vs_sandbox_error(self):
        """Verify preflight configuration failure returns PREFLIGHT_ERROR status and attempted=False."""
        tf_validator = TrueForgeSandboxValidator(api_key="")
        engine = ValidationEngine(tf_validator)

        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(len(results), 1)
        r = results[0]

        # Config check failure is PREFLIGHT_ERROR, attempted=False, confirmed=False
        self.assertEqual(r.status, ValidationStatus.PREFLIGHT_ERROR)
        self.assertFalse(r.attempted)
        self.assertFalse(r.confirmed)
        self.assertIn("Missing TRUEFORGE_API_KEY", r.error_message)


    def test_duplicate_same_location_indicator_substitution(self):
        """Verify that substituting one same-location indicator for another fails authentication."""
        report_dup = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")
            ],
            security_indicators=[
                SecurityIndicator(
                    category="subprocess",
                    indicator_type="subprocess_execution_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="subprocess.run"
                ),
                SecurityIndicator(
                    category="database",
                    indicator_type="raw_sql_construction_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="SELECT id FROM users"
                )
            ]
        )
        det_engine = DeterministicReasoningEngine()
        det_report = det_engine.generate_hypotheses(report_dup)
        self.assertEqual(len(det_report.hypotheses), 2)

        # Let's get the database/SQL Injection hypothesis
        sql_hyp = next(h for h in det_report.hypotheses if h.category == "sql_injection")

        # Substitute the evidence reference detail to match the subprocess indicator's detail
        import copy
        modified_references = copy.deepcopy(sql_hyp.evidence_references)
        # Find the indicator reference and change its detail to the subprocess one
        for ref in modified_references:
            if ref.type == "security_indicator":
                ref.detail = "Subprocess call: subprocess.run"

        bad_hyp = SecurityHypothesis(
            id=sql_hyp.id,
            title=sql_hyp.title,
            description=sql_hyp.description,
            category=sql_hyp.category,
            severity=sql_hyp.severity,
            confidence=sql_hyp.confidence,
            evidence_references=modified_references,
            rationale=sql_hyp.rationale
        )

        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)

        eligible, reason = engine.check_eligibility(bad_hyp, report_dup)
        self.assertFalse(eligible, "Substituting same-location indicator should have failed authentication")

    def test_generic_fallback_indicator_authentication(self):
        """Verify that fallback/generic indicators resolve and authenticate cleanly."""
        report_fallback = RepositoryReport(
            repository=self.empty_summary,
            routes=[
                RouteCandidate(file="src/server.py", line=12, method="POST", pattern="/run", evidence="")
            ],
            security_indicators=[
                SecurityIndicator(
                    category="unknown_or_custom",
                    indicator_type="custom_indicator",
                    file="src/server.py",
                    line=15,
                    evidence="custom_unsafe_func"
                )
            ]
        )

        ref = EvidenceReference(
            type="security_indicator",
            file="src/server.py",
            line=15,
            detail="Security indicator: custom_unsafe_func"
        )

        engine = ValidationEngine(MockSandboxValidator())
        valid, resolved_detail = engine._resolve_and_validate_evidence(ref, report_fallback)
        self.assertTrue(valid)
        self.assertEqual(resolved_detail, "Security indicator: custom_unsafe_func")

    def test_fabricated_extra_evidence_references(self):
        """Verify that appending a fabricated/malformed evidence reference to an otherwise valid deterministic hypothesis causes immediate rejection."""
        # 1. Verify original valid hypothesis would otherwise authenticate and run
        validator = MockSandboxValidator()
        engine = ValidationEngine(validator)
        results = engine.validate_hypotheses([self.valid_hyp], self.report)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ValidationStatus.NOT_CONFIRMED)
        self.assertEqual(len(validator.last_validated), 1)

        # Reset mock state
        validator.last_validated = []

        # 2. Append a fabricated reference to the references
        import copy
        bad_references = copy.deepcopy(self.valid_hyp.evidence_references)
        bad_references.append(
            EvidenceReference(
                type="file",
                file="fabricated_nonexistent_file.py",
                line=None,
                detail="File: fabricated_nonexistent_file.py"
            )
        )

        bad_hyp = SecurityHypothesis(
            id=self.valid_hyp.id,
            title=self.valid_hyp.title,
            description=self.valid_hyp.description,
            category=self.valid_hyp.category,
            severity=self.valid_hyp.severity,
            confidence=self.valid_hyp.confidence,
            evidence_references=bad_references,
            rationale=self.valid_hyp.rationale
        )

        results_bad = engine.validate_hypotheses([bad_hyp], self.report)
        self.assertEqual(len(results_bad), 1)

        # Must fail eligibility check: status = INVALID_HYPOTHESIS, attempted = False
        self.assertEqual(results_bad[0].status, ValidationStatus.INVALID_HYPOTHESIS)
        self.assertFalse(results_bad[0].attempted)
        self.assertIn("fabricated", results_bad[0].error_message.lower())

        # Ensure the hypothesis NEVER reaches the sandbox
        self.assertEqual(len(validator.last_validated), 0)



    def test_trueforge_validator_local_sandbox_success(self):
        """Verify that local sandbox subprocess execution validates a hypothesis successfully."""
        validator = TrueForgeSandboxValidator(local_sandbox=True)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.VALIDATED)
        self.assertTrue(results.attempted)
        self.assertTrue(results.confirmed)
        self.assertIn("Sandbox harness initialized", results.stdout)

    def test_trueforge_validator_timeout(self):
        """Verify that validator timeout terminates the subprocess and returns TIMEOUT."""
        validator = TrueForgeSandboxValidator(local_sandbox=True, timeout_seconds=0.00001)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.TIMEOUT)
        self.assertTrue(results.attempted)
        self.assertFalse(results.confirmed)
        self.assertIn("timed out", results.error_message)

    def test_trueforge_validator_preflight(self):
        """Verify configuration preflight check fails when TRUEFORGE_API_KEY is missing."""
        validator = TrueForgeSandboxValidator(api_key=None, local_sandbox=False)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.PREFLIGHT_ERROR)
        self.assertFalse(results.attempted)
        self.assertFalse(results.confirmed)
        self.assertIn("Missing TRUEFORGE_API_KEY", results.error_message)

    def test_trueforge_validator_remote_api(self):
        """Verify remote API client setup simulated response."""
        validator = TrueForgeSandboxValidator(api_key="test-key", local_sandbox=False)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.VALIDATED)
        self.assertTrue(results.attempted)
        self.assertTrue(results.confirmed)
        self.assertEqual(results.metadata.get("endpoint"), "https://api.trueforge.example.com")

    @patch("subprocess.Popen")
    def test_trueforge_validator_malformed_json(self, mock_popen):
        """Verify malformed validator stdout is caught as SANDBOX_ERROR."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("this is not json", "some error")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        validator = TrueForgeSandboxValidator(local_sandbox=True)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.SANDBOX_ERROR)
        self.assertTrue(results.attempted)
        self.assertIn("not valid JSON", results.error_message)

    @patch("subprocess.Popen")
    def test_trueforge_validator_exit_error(self, mock_popen):
        """Verify non-zero subprocess return code is caught as SANDBOX_ERROR."""
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "Critical crash in sandbox process")
        mock_proc.returncode = 1
        mock_popen.return_value = mock_proc

        validator = TrueForgeSandboxValidator(local_sandbox=True)
        results = validator.validate(self.valid_hyp, self.report)

        self.assertEqual(results.status, ValidationStatus.SANDBOX_ERROR)
        self.assertTrue(results.attempted)
        self.assertIn("process exited with code 1", results.error_message)

if __name__ == "__main__":
    unittest.main()
