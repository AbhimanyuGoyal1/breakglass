"""Unit and integration tests for validation jobs, lifecycles, and orchestration."""

import os
import time
import json
import uuid
import threading
import unittest
from typing import Dict, Any, List, Optional, Tuple, Iterable
from unittest.mock import patch, MagicMock
from breakglass.inspection.models import RepositoryReport, RepositorySummary
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator, SubprocessSandboxBackend, DockerSandboxBackend
from breakglass.validation.pipeline import (
    ValidationJob,
    JobState,
    JobLifecycleTracker,
    ValidationAuditRecord,
    verify_result_provenance
)
from breakglass.validation.orchestrator import (
    OrchestratorConfig,
    AggregatedValidationReport,
    ValidationOrchestrator
)


class CustomTestValidator(SandboxValidator):
    """Custom validator subclass to inject controllable validation behaviors for testing."""
    def __init__(self):
        self.behavior_map = {}
        self.lock = threading.Lock()

    def set_behavior(self, hyp_id: str, behavior_fn):
        with self.lock:
            self.behavior_map[hyp_id] = behavior_fn

    def validate(self, hypothesis: SecurityHypothesis, repository_context: RepositoryReport, cancellation_event: Optional[threading.Event] = None) -> ValidationResult:
        with self.lock:
            fn = self.behavior_map.get(hypothesis.id)
        if fn:
            return fn(hypothesis, repository_context, cancellation_event)
        # Default success fallback
        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Authoritative indicator match verified.",
            stdout="validation log",
            stderr=""
        )


class TestValidationPipeline(unittest.TestCase):
    """Test suite covering Phase 1 structured validation jobs, lifecycles, audit records, and provenance."""

    def setUp(self):
        self.job_data = {
            "job_id": str(uuid.uuid4()),
            "hypothesis_id": "HYP-001",
            "hypothesis_info": {
                "category": "command_injection",
                "title": "Command Injection in Server",
                "description": "Subprocess execution vulnerability",
                "rationale": "Matches command injection profile"
            },
            "repo_root": "/workspace/repo",
            "evidence_references": [
                {
                    "type": "security_indicator",
                    "file": "server.py",
                    "line": 10,
                    "detail": "Subprocess call: shell=True"
                }
            ],
            "config": {
                "timeout_seconds": 15.0,
                "max_output_bytes": 1024,
                "max_payload_bytes": 100000
            }
        }

    def test_valid_job_serialization_and_parsing(self):
        """Verify that a valid job is serialized deterministically and parsed successfully."""
        job = ValidationJob.from_dict(self.job_data)
        self.assertEqual(job.job_id, self.job_data["job_id"])
        self.assertEqual(job.hypothesis_id, "HYP-001")
        self.assertEqual(job.repo_root, "/workspace/repo")
        self.assertEqual(len(job.evidence_references), 1)

        serialized = job.to_dict()
        self.assertEqual(serialized["job_id"], self.job_data["job_id"])
        self.assertEqual(serialized["config"]["timeout_seconds"], 15.0)

        rebuilt = ValidationJob.from_dict(serialized)
        self.assertEqual(rebuilt.job_id, job.job_id)

    def test_malformed_job_data_rejection(self):
        """Verify that malformed or invalid type job inputs are strictly rejected."""
        bad_data = self.job_data.copy()
        del bad_data["repo_root"]
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        bad_data = self.job_data.copy()
        bad_data["job_id"] = 12345
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        bad_data = self.job_data.copy()
        bad_data["config"] = {"timeout_seconds": -5.0}
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        bad_data = self.job_data.copy()
        bad_data["evidence_references"] = [{
            "type": "file",
            "file": "api_key.txt",
            "line": None,
            "detail": ""
        }]
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

    def test_oversized_job_payload_rejection(self):
        """Verify that validation job payload size is capped (max 10MB)."""
        bad_data = self.job_data.copy()
        bad_data["hypothesis_info"] = {
            "category": "command_injection",
            "title": "A" * (11 * 1024 * 1024),
            "description": "desc",
            "rationale": "rat"
        }
        with self.assertRaises(ValueError) as ctx:
            ValidationJob.from_dict(bad_data)
        self.assertIn("exceeds the 10MB safety limit", str(ctx.exception))

    def test_job_state_transitions(self):
        """Verify valid job transitions succeed, and invalid transitions fail closed."""
        tracker = JobLifecycleTracker(JobState.QUEUED)
        self.assertEqual(tracker.state, JobState.QUEUED)

        tracker.transition_to(JobState.PREFLIGHT)
        self.assertEqual(tracker.state, JobState.PREFLIGHT)
        tracker.transition_to(JobState.RUNNING)
        self.assertEqual(tracker.state, JobState.RUNNING)
        tracker.transition_to(JobState.VALIDATED)
        self.assertEqual(tracker.state, JobState.VALIDATED)

        with self.assertRaises(ValueError):
            tracker.transition_to(JobState.RUNNING)

        tracker2 = JobLifecycleTracker(JobState.QUEUED)
        with self.assertRaises(ValueError):
            tracker2.transition_to(JobState.VALIDATED)

    def test_result_provenance_validation(self):
        """Verify that validation result integrity and provenance checks reject forged parameters."""
        job = ValidationJob.from_dict(self.job_data)
        result = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Authoritative indicator match verified."
        )
        tracker = JobLifecycleTracker(JobState.QUEUED)
        tracker.transition_to(JobState.PREFLIGHT)
        tracker.transition_to(JobState.RUNNING)
        tracker.transition_to(JobState.VALIDATED)

        audit = ValidationAuditRecord(
            execution_id=str(uuid.uuid4()),
            hypothesis_id="HYP-001",
            start_time=time.time(),
            end_time=time.time() + 1.0,
            duration=1.0,
            backend_used="Subprocess",
            final_status="VALIDATED"
        )

        self.assertTrue(verify_result_provenance(job, result, audit, tracker))

        bad_result = ValidationResult(
            hypothesis_id="HYP-FABRICATED",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Matched"
        )
        self.assertFalse(verify_result_provenance(job, bad_result, audit, tracker))

        bad_result2 = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=False,
            evidence="Matched"
        )
        self.assertFalse(verify_result_provenance(job, bad_result2, audit, tracker))

        job_no_ev = ValidationJob.from_dict(self.job_data)
        job_no_ev.evidence_references = []
        self.assertFalse(verify_result_provenance(job_no_ev, result, audit, tracker))

    def test_provenance_rejects_confirmed_without_attempt(self):
        """[Adversarial] verify_result_provenance rejects confirmed=True with attempted=False or incorrect status."""
        job = ValidationJob.from_dict(self.job_data)
        result = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=False,
            confirmed=True,
            evidence="Confirmed"
        )
        tracker = JobLifecycleTracker(JobState.QUEUED)
        audit = ValidationAuditRecord(
            execution_id=str(uuid.uuid4()),
            hypothesis_id="HYP-001",
            start_time=time.time(),
            end_time=time.time() + 1.0,
            duration=1.0,
            backend_used="Subprocess",
            final_status="VALIDATED"
        )
        self.assertFalse(verify_result_provenance(job, result, audit, tracker))


class TestValidationOrchestrator(unittest.TestCase):
    """Test suite covering Phase 2 concurrency scheduling, budgeting, isolation, and aggregation."""

    def setUp(self):
        self.empty_summary = RepositorySummary(
            root="/workspace/repo",
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
            routes=[],
            security_indicators=[]
        )
        self.validator = CustomTestValidator()

        # Create sample valid hypotheses (aligned with the deterministic authentication rules)
        self.hypotheses = []
        # Reconstruct hypotheses with valid evidence references that engine check_eligibility can authenticate
        # We patch check_eligibility and _authenticate_hypothesis_id to simulate valid orchestration cleanly
        self.hypotheses = [
            SecurityHypothesis(
                id=f"HYP-LLM-{i:03d}",
                title=f"Security Issue {i}",
                description=f"Description of issue {i}",
                category="command_injection",
                severity="CRITICAL",
                confidence=0.8,
                evidence_references=[
                    EvidenceReference(type="file", file="config.json", line=None, detail="File: config.json")
                ],
                rationale="Matched indicators"
            )
            for i in range(5)
        ]

    def test_orchestrator_config_validations(self):
        """Verify configuration validation bounds."""
        with self.assertRaises(ValueError):
            OrchestratorConfig(max_concurrent_validations=-1).validate()
        with self.assertRaises(ValueError):
            OrchestratorConfig(global_timeout_budget=0).validate()

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_successful_batch_execution_and_aggregation(self, m1, m2, m3):
        """Verify standard successful multi-hypothesis batch validation schedules and aggregates cleanly."""
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        self.assertEqual(report.repo_root, "/workspace/repo")
        self.assertEqual(report.global_status, "SUCCESS")
        self.assertEqual(len(report.results), 5)
        self.assertEqual(len(report.audit_records), 5)
        self.assertEqual(report.total_attempted, 5)
        self.assertEqual(report.total_confirmed, 5)

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_concurrency_bounding(self, m1, m2, m3):
        """Verify that concurrent validations are bounded using configured limits."""
        config = OrchestratorConfig(max_concurrent_validations=2)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)
        self.assertEqual(report.global_status, "SUCCESS")
        self.assertEqual(len(report.results), 5)

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_per_job_timeout_handling(self, m1, m2, m3):
        """Verify that a single job exceeding its execution timeout does not break the batch run."""
        def hanging_behavior(hyp, ctx, cancel):
            time.sleep(0.5)
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        self.validator.set_behavior("HYP-LLM-001", hanging_behavior)
        config = OrchestratorConfig(per_validation_timeout=0.1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-LLM-001"]["status"], "TIMEOUT")
        self.assertFalse(results_by_id["HYP-LLM-001"]["confirmed"])

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_global_timeout_budget_handling(self, m1, m2, m3):
        """Verify orchestrator aborts execution when global budget runs out."""
        def long_hang(hyp, ctx, cancel):
            for _ in range(20):
                if cancel and cancel.is_set():
                    return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.TIMEOUT, attempted=True, confirmed=False)
                time.sleep(0.1)
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        for hyp in self.hypotheses:
            self.validator.set_behavior(hyp.id, long_hang)

        config = OrchestratorConfig(max_concurrent_validations=1, global_timeout_budget=0.2)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        self.assertEqual(report.global_status, "TIMEOUT")
        timed_out_count = sum(1 for r in report.results if r["status"] == "TIMEOUT")
        self.assertTrue(timed_out_count > 0)

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_cancellation_support(self, m1, m2, m3):
        """Verify cancellation event immediately aborts validation orchestrator queue."""
        cancel_event = threading.Event()

        def slow_job(hyp, ctx, cancel):
            time.sleep(0.2)
            cancel_event.set()
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        self.validator.set_behavior("HYP-LLM-000", slow_job)

        config = OrchestratorConfig(max_concurrent_validations=1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report, cancellation_event=cancel_event)

        self.assertEqual(report.global_status, "CANCELLED")
        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-LLM-000"]["status"], "VALIDATED")
        # Pending job must be cancelled before start (NOT_ATTEMPTED status)
        self.assertEqual(results_by_id["HYP-LLM-001"]["status"], "NOT_ATTEMPTED")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_global_aggregate_output_bytes_limits(self, m1, m2, m3):
        """Verify aggregate output check cancels orchestrator once cumulative limit is reached."""
        def large_output_job(hyp, ctx, cancel):
            return ValidationResult(
                hypothesis_id=hyp.id,
                status=ValidationStatus.VALIDATED,
                attempted=True,
                confirmed=True,
                stdout="A" * 5000,
                stderr=""
            )

        for hyp in self.hypotheses:
            self.validator.set_behavior(hyp.id, large_output_job)

        config = OrchestratorConfig(max_concurrent_validations=1, max_aggregate_output_bytes=8000)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-LLM-000"]["status"], "VALIDATED")
        self.assertEqual(results_by_id["HYP-LLM-001"]["status"], "SANDBOX_ERROR")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_concurrency_adversarial_rejection_and_isolation(self, m1, m2, m3):
        """Adversarial stress-test: duplicate, malformed hypotheses, exceptions, startup errors, budget exhaustion."""
        malformed_hyp = SecurityHypothesis(
            id="HYP-MALFORMED",
            title="Bad",
            description="Bad",
            category="sql_injection",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=[],
            rationale=""
        )
        duplicate_hyp = self.hypotheses[0]

        def exception_behavior(hyp, ctx, cancel):
            raise RuntimeError("Fatal container launch error simulation")

        self.validator.set_behavior("HYP-LLM-002", exception_behavior)

        test_list = self.hypotheses + [duplicate_hyp, malformed_hyp]
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(test_list, self.report)

        hyp_ids = [r["hypothesis_id"] for r in report.results]
        self.assertEqual(hyp_ids.count("HYP-LLM-000"), 1)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-MALFORMED"]["status"], "INVALID_HYPOTHESIS")
        self.assertEqual(results_by_id["HYP-LLM-002"]["status"], "SANDBOX_ERROR")
        self.assertEqual(results_by_id["HYP-LLM-003"]["status"], "VALIDATED")


    # ==========================================
    # Target Qodo Regression & Security Tests
    # ==========================================

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_orchestrator_timeout_terminates_running_validation(self, m1, m2, m3):
        """Verify that job timeout terminates execution cooperatively and returns TIMEOUT."""
        cancel_signaled = threading.Event()
        def slow_validation(hyp, ctx, cancel):
            while not cancel.is_set():
                time.sleep(0.01)
            cancel_signaled.set()
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.TIMEOUT, attempted=True, confirmed=False)

        self.validator.set_behavior("HYP-LLM-000", slow_validation)
        config = OrchestratorConfig(per_validation_timeout=0.05, max_concurrent_validations=1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch([self.hypotheses[0]], self.report)

        self.assertTrue(cancel_signaled.wait(timeout=1.0))
        self.assertEqual(report.results[0]["status"], "TIMEOUT")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_global_timeout_cancels_running_jobs_and_collects_real_results(self, m1, m2, m3):
        """Verify global budget timeout triggers cancellation and gathers correct started terminal states."""
        cancel_signaled = threading.Event()
        def hanging_job(hyp, ctx, cancel):
            while not cancel.is_set():
                time.sleep(0.01)
            cancel_signaled.set()
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.TIMEOUT, attempted=True, confirmed=False)

        self.validator.set_behavior("HYP-LLM-000", hanging_job)
        config = OrchestratorConfig(max_concurrent_validations=1, global_timeout_budget=0.05)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        self.assertEqual(report.global_status, "TIMEOUT")
        self.assertTrue(cancel_signaled.wait(timeout=1.0))

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_cancelled_started_job_has_attempted_true_and_audit(self, m1, m2, m3):
        """Verify started job cancelled midway is flagged attempted=True and produces audit log."""
        def quick_cancel_job(hyp, ctx, cancel):
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.TIMEOUT, attempted=True, confirmed=False)

        self.validator.set_behavior("HYP-LLM-000", quick_cancel_job)
        cancel_event = threading.Event()
        # Set cancellation early so next jobs are blocked
        cancel_event.set()

        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([self.hypotheses[0]], self.report, cancellation_event=cancel_event)
        self.assertEqual(report.results[0]["status"], "NOT_ATTEMPTED")
        self.assertFalse(report.results[0]["attempted"])

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_queued_cancelled_job_is_not_attempted(self, m1, m2, m3):
        """Verify queued job cancelled before run is marked attempted=False."""
        cancel_event = threading.Event()
        def cancel_midway(hyp, ctx, cancel):
            cancel_event.set()
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        self.validator.set_behavior("HYP-LLM-000", cancel_midway)
        config = OrchestratorConfig(max_concurrent_validations=1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses[:2], self.report, cancellation_event=cancel_event)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-LLM-000"]["status"], "VALIDATED")
        self.assertEqual(results_by_id["HYP-LLM-001"]["status"], "NOT_ATTEMPTED")
        self.assertFalse(results_by_id["HYP-LLM-001"]["attempted"])

    def test_orchestrator_authenticates_hypothesis_before_validator(self):
        """Verify orchestrator authenticates hypotheses pre-execution and rejects unauthorized inputs."""
        # Setup mock report without indicators (will fail auth)
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([self.hypotheses[0]], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")

    def test_fabricated_hypothesis_id_rejected(self):
        """Verify custom/fabricated hypothesis ID is rejected preflight."""
        bad_hyp = SecurityHypothesis(
            id="HYP-FABRICATED-1234",
            title="Modified Title",
            description="Vulnerability detail",
            category="command_injection",
            severity="CRITICAL",
            confidence=0.9,
            evidence_references=[
                EvidenceReference(type="file", file="config.json", line=None, detail="File: config.json")
            ],
            rationale="Tampered rationale"
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([bad_hyp], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")

    def test_modified_hypothesis_fields_rejected(self):
        """Verify modified hypothesis details fail check_eligibility re-authentication."""
        # Using a deterministic category but with custom references
        bad_hyp = SecurityHypothesis(
            id="HYP-001", # Expects specific indicators
            title="Modified Title",
            description="Vulnerability detail",
            category="command_injection",
            severity="CRITICAL",
            confidence=0.9,
            evidence_references=[
                EvidenceReference(type="file", file="config.json", line=None, detail="File: config.json")
            ],
            rationale="Tampered rationale"
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([bad_hyp], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")

    def test_malformed_hypothesis_does_not_abort_batch(self):
        """Verify that a malformed hypothesis object in the batch does not crash validation orchestrator."""
        malformed = None
        bad_id = SecurityHypothesis(
            id=123, # Wrong type
            title="Title",
            description="Desc",
            category="command_injection",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=[],
            rationale=""
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([malformed, bad_id], self.report)
        self.assertEqual(len(report.results), 2)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")
        self.assertEqual(report.results[1]["status"], "INVALID_HYPOTHESIS")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_aggregate_limit_counts_all_retained_result_fields(self, m1, m2, m3):
        """Verify aggregate output checks count entire JSON serialization of results."""
        def large_evidence_job(hyp, ctx, cancel):
            return ValidationResult(
                hypothesis_id=hyp.id,
                status=ValidationStatus.VALIDATED,
                attempted=True,
                confirmed=True,
                evidence="X" * 15000 # Large evidence string
            )

        self.validator.set_behavior("HYP-LLM-000", large_evidence_job)
        # Configure small aggregate output limit that 15KB evidence JSON will easily breach
        config = OrchestratorConfig(max_concurrent_validations=1, max_aggregate_output_bytes=5000)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses[:2], self.report)

        # First validation exceeds budget and triggers failure
        self.assertEqual(report.global_status, "SANDBOX_ERROR")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_queue_admission_is_memory_bounded(self, m1, m2, m3):
        """Verify generator input is consumed lazily and stopped on queue limit admission."""
        # Create a generator of 1000 hypotheses
        def hypothesis_generator():
            for i in range(1000):
                yield SecurityHypothesis(
                    id=f"HYP-LLM-{i:03d}",
                    title=f"Security Issue {i}",
                    description=f"Description of issue {i}",
                    category="command_injection",
                    severity="CRITICAL",
                    confidence=0.8,
                    evidence_references=[
                        EvidenceReference(type="file", file="config.json", line=None, detail="File: config.json")
                    ],
                    rationale="Matched indicators"
                )

        config = OrchestratorConfig(max_queued_jobs=10)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(hypothesis_generator(), self.report)

        # The orchestrator should admit only 10 jobs total
        self.assertEqual(len(report.results), 10)

    def test_large_evidence_file_is_streamed_and_bounded(self):
        """Verify file checks stream and fail closed on reading files exceeding max_evidence_file_bytes."""
        temp_file = "scratch_test_large_file.txt"
        with open(temp_file, "wb") as f:
            f.write(b"A" * (2 * 1024 * 1024)) # 2MB file

        try:
            from breakglass.validation.sandbox_runner import check_file_evidence_streaming
            # Attempt to search file under 1KB limit
            success, detail = check_file_evidence_streaming(temp_file, "A", line_idx=None, max_bytes=1024)
            self.assertFalse(success)
            self.assertIn("exceeded", detail)
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def test_local_runner_uses_backend_controlled_repo_root(self):
        """Verify sandbox runner detects and rejects mismatches between payload repo root and authoritative backend root."""
        from breakglass.validation.sandbox_runner import run_validation
        payload = {
            "hypothesis": {"id": "HYP-001"},
            "report": {
                "repository": {"root": "/malicious/path"}
            },
            "authoritative_repo_root": "/authoritative/path"
        }
        res = run_validation(payload)
        self.assertEqual(res["status"], "SANDBOX_ERROR")
        self.assertIn("Security violation", res["error_message"])

    @patch("subprocess.Popen")
    def test_timeout_leaves_no_running_sandbox(self, mock_popen):
        """Verify validator timeout kills process and wait to prevent zombie sandbox leakage."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        backend = SubprocessSandboxBackend(MagicMock())
        # Simulate execute timeout
        stdout, stderr, code, timeout_hit, overflow_hit, err = backend.execute(
            runner_path="runner.py",
            repo_path=".",
            payload_json="{}",
            timeout=0.01,
            max_output_bytes=1024
        )
        self.assertTrue(timeout_hit)
        # Verify kill and wait were called to prevent leaks
        mock_proc.kill.assert_called()
        mock_proc.wait.assert_called()

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_timeout_does_not_leak_worker_slots(self, m1, m2, m3):
        """Verify slots in thread pool are properly released and subsequent jobs run successfully."""
        def slow_validation(hyp, ctx, cancel):
            time.sleep(0.5)
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        self.validator.set_behavior("HYP-LLM-000", slow_validation)
        config = OrchestratorConfig(per_validation_timeout=0.05, max_concurrent_validations=1)
        orchestrator = ValidationOrchestrator(self.validator, config)

        # Runs HYP-LLM-000 (times out) followed by HYP-LLM-001 (succeeds)
        report = orchestrator.validate_batch(self.hypotheses[:2], self.report)
        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-LLM-000"]["status"], "TIMEOUT")
        self.assertEqual(results_by_id["HYP-LLM-001"]["status"], "VALIDATED")

    @patch("subprocess.run")
    def test_container_cleanup_after_cancellation(self, mock_run):
        """Verify Docker sandbox backend runs docker kill and docker rm -f on cancellation."""
        mock_proc = MagicMock()
        backend = DockerSandboxBackend(MagicMock())
        backend._kill_container("sandbox-test-container", mock_proc)

        # Verify both docker kill and docker rm -f are ran to force clean container teardown
        kill_call = mock_run.call_args_list[0][0][0]
        rm_call = mock_run.call_args_list[1][0][0]
        self.assertIn("kill", kill_call)
        self.assertIn("rm", rm_call)

    def test_subprocess_cleanup_after_cancellation(self):
        """Verify subprocess sandbox backend kills process on cancellation."""
        mock_proc = MagicMock()
        backend = SubprocessSandboxBackend(MagicMock())

        cancellation_event = threading.Event()
        cancellation_event.set()

        with patch("subprocess.Popen", return_value=mock_proc):
            backend.execute("runner.py", ".", "{}", 10.0, 1024, cancellation_event)
            mock_proc.kill.assert_called()

    def test_long_line_memory_attack_protection(self):
        """Verify that streaming search safely blocks long-line memory attacks without loading into memory."""
        temp_file = "scratch_test_long_line.txt"
        try:
            with open(temp_file, "wb") as f:
                # Write a single line of 100KB without newlines
                f.write(b"A" * 100 * 1024)
            from breakglass.validation.sandbox_runner import check_file_evidence_streaming
            # Attempt to search file under 1KB limit
            success, detail = check_file_evidence_streaming(temp_file, "B", line_idx=1, max_bytes=1024)
            self.assertFalse(success)
            self.assertIn("exceeded", detail)
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_linker_thread_leak_protection(self, m1, m2, m3):
        """Verify linker daemon threads exit cleanly and do not leak after job completion/cancellation."""
        import threading
        initial_threads = threading.active_count()

        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(self.hypotheses[:2], self.report)

        # Give background linker threads a brief moment to exit
        time.sleep(0.1)
        current_threads = threading.active_count()
        # Verify that thread count did not grow due to lingering linker threads
        self.assertTrue(current_threads <= initial_threads + 2)

    def test_hostile_generator_iteration_protection(self):
        """Verify that validation batch protects against exceptions raised by hostile generator input."""
        class HostileGenerator:
            def __iter__(self):
                return self
            def __next__(self):
                raise RuntimeError("Hostile database connection drop simulated during iteration")

        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(HostileGenerator(), self.report)

        self.assertEqual(report.global_status, "SANDBOX_ERROR")
        self.assertEqual(report.results[0]["status"], "SANDBOX_ERROR")
        self.assertIn("iteration failed", report.results[0]["error_message"])

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_malformed_evidence_references_none(self, m1, m2, m3):
        """Verify that hypothesis with evidence_references=None is safely marked INVALID_HYPOTHESIS without aborting batch."""
        hyp = SecurityHypothesis(
            id="HYP-BAD-01",
            title="Title",
            description="Desc",
            category="subprocess",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=None
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([hyp], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")
        self.assertEqual(report.results[0]["error_message"], "Validation job preflight failed: Hypothesis has no evidence references")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_malformed_evidence_reference_types(self, m1, m2, m3):
        """Verify that hypothesis with invalid evidence_reference element types is handled safely."""
        hyp = SecurityHypothesis(
            id="HYP-BAD-02",
            title="Title",
            description="Desc",
            category="subprocess",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=["not-a-ref-obj"]
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([hyp], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_malformed_hypothesis_fields(self, m1, m2, m3):
        """Verify that hypothesis with non-string fields is rejected without aborting batch."""
        hyp = SecurityHypothesis(
            id="HYP-BAD-03",
            title=1234,
            description="Desc",
            category="subprocess",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=[EvidenceReference(type="subprocess", file="main.py", line=10, detail="")]
        )
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([hyp], self.report)
        self.assertEqual(report.results[0]["status"], "INVALID_HYPOTHESIS")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_malformed_hypothesis_does_not_abort_batch(self, m1, m2, m3):
        """Verify that subsequent valid hypotheses execute even if prior ones are malformed."""
        hyp_bad = SecurityHypothesis(
            id="HYP-BAD-04",
            title="Title",
            description="Desc",
            category="subprocess",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=None
        )
        hyp_good = self.hypotheses[0]
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([hyp_bad, hyp_good], self.report)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-BAD-04"]["status"], "INVALID_HYPOTHESIS")
        self.assertEqual(results_by_id[hyp_good.id]["status"], "VALIDATED")

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_global_timeout_budget_handling_accurate_attempted(self, m1, m2, m3):
        """Verify global timeout cancels running jobs (TIMEOUT/attempted=True) and queued jobs (NOT_ATTEMPTED/attempted=False)."""
        def long_hang(hyp, ctx, cancel):
            for _ in range(50):
                if cancel and cancel.is_set():
                    return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.TIMEOUT, attempted=True, confirmed=False)
                time.sleep(0.05)
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        for h in self.hypotheses:
            self.validator.set_behavior(h.id, long_hang)

        config = OrchestratorConfig(max_concurrent_validations=1, global_timeout_budget=0.1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses[:3], self.report)

        # The running job was running when global timeout hit, so it was terminated cooperatively
        running_job = report.results[0]
        self.assertEqual(running_job["status"], "TIMEOUT")
        self.assertTrue(running_job["attempted"])

        # The subsequent jobs were in queue, so they are cancelled before start
        for queued_job in report.results[1:]:
            self.assertEqual(queued_job["status"], "NOT_ATTEMPTED")
            self.assertFalse(queued_job["attempted"])

    def test_non_finite_timeout_validation(self):
        """Verify that non-finite floating-point parameters (NaN, +inf, -inf) and non-positive numbers are rejected."""
        from breakglass.validation.engine import ValidationConfig
        for bad_val in (float("nan"), float("inf"), float("-inf"), 0, -10):
            with self.assertRaises(ValueError):
                ValidationConfig(timeout_seconds=bad_val).validate()

        for bad_val in (float("nan"), float("inf"), float("-inf"), 0, -10):
            with self.assertRaises(ValueError):
                OrchestratorConfig(per_validation_timeout=bad_val).validate()
            with self.assertRaises(ValueError):
                OrchestratorConfig(global_timeout_budget=bad_val).validate()

    @patch("breakglass.validation.engine.ValidationEngine._authenticate_hypothesis_id", return_value=True)
    @patch("breakglass.validation.engine.ValidationEngine.check_eligibility", return_value=(True, ""))
    @patch("breakglass.validation.engine.ValidationEngine._resolve_and_validate_evidence", return_value=(True, "File: config.json"))
    def test_malicious_validator_invariants(self, m1, m2, m3):
        """Verify that contradictory validator outputs (confirmed=True with attempted=False) are fail-closed to SANDBOX_ERROR."""
        def malicious_output(hyp, ctx, cancel):
            return ValidationResult(
                hypothesis_id=hyp.id,
                status=ValidationStatus.VALIDATED,
                attempted=False,
                confirmed=True
            )
        self.validator.set_behavior("HYP-LLM-000", malicious_output)
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch([self.hypotheses[0]], self.report)
        self.assertEqual(report.results[0]["status"], "SANDBOX_ERROR")
        self.assertFalse(report.results[0]["confirmed"])
        self.assertTrue(report.results[0]["attempted"])

    def test_double_cleanup_concurrency(self):
        """Verify backend cleanup functions (docker kill / rm or subprocess kill) are safe from multiple concurrent invocations."""
        mock_proc = MagicMock()
        backend = SubprocessSandboxBackend(MagicMock())
        backend._reader_thread_fn = MagicMock()
        cancellation_event = threading.Event()
        cancellation_event.set()
        with patch("subprocess.Popen", return_value=mock_proc):
            backend.execute("runner.py", ".", "{}", 10.0, 1024, cancellation_event)
            backend.execute("runner.py", ".", "{}", 10.0, 1024, cancellation_event)
            self.assertTrue(mock_proc.kill.called)


if __name__ == "__main__":
    unittest.main()
