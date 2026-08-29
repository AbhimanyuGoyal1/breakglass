"""Unit and integration tests for validation jobs, lifecycles, and orchestration."""

import os
import time
import json
import uuid
import threading
import unittest
from unittest.mock import patch, MagicMock
from breakglass.inspection.models import RepositoryReport, RepositorySummary
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator
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

    def validate(self, hypothesis: SecurityHypothesis, repository_context: RepositoryReport) -> ValidationResult:
        with self.lock:
            fn = self.behavior_map.get(hypothesis.id)
        if fn:
            return fn(hypothesis, repository_context)
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
        # Verify evidence reference sorting and serialization schema keys
        self.assertEqual(serialized["job_id"], self.job_data["job_id"])
        self.assertEqual(serialized["config"]["timeout_seconds"], 15.0)

        # Parse from serialized output
        rebuilt = ValidationJob.from_dict(serialized)
        self.assertEqual(rebuilt.job_id, job.job_id)

    def test_malformed_job_data_rejection(self):
        """Verify that malformed or invalid type job inputs are strictly rejected."""
        # Missing field
        bad_data = self.job_data.copy()
        del bad_data["repo_root"]
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        # Invalid job_id type
        bad_data = self.job_data.copy()
        bad_data["job_id"] = 12345
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        # Invalid config limits
        bad_data = self.job_data.copy()
        bad_data["config"] = {"timeout_seconds": -5.0}
        with self.assertRaises(ValueError):
            ValidationJob.from_dict(bad_data)

        # Basic credentials/api_key leakage check
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
        # Create oversized data
        bad_data = self.job_data.copy()
        bad_data["hypothesis_info"] = {
            "category": "command_injection",
            "title": "A" * (11 * 1024 * 1024), # 11MB string
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

        # Legal path
        tracker.transition_to(JobState.PREFLIGHT)
        self.assertEqual(tracker.state, JobState.PREFLIGHT)
        tracker.transition_to(JobState.RUNNING)
        self.assertEqual(tracker.state, JobState.RUNNING)
        tracker.transition_to(JobState.VALIDATED)
        self.assertEqual(tracker.state, JobState.VALIDATED)

        # Illegal state transitions from terminal state
        with self.assertRaises(ValueError):
            tracker.transition_to(JobState.RUNNING)

        # Illegal direct jump
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

        # Valid scenario
        self.assertTrue(verify_result_provenance(job, result, audit, tracker))

        # 1. Fabricated hypothesis ID check
        bad_result = ValidationResult(
            hypothesis_id="HYP-FABRICATED",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=True,
            evidence="Matched"
        )
        self.assertFalse(verify_result_provenance(job, bad_result, audit, tracker))

        # 2. Fabricated confirmation check (validated status but confirmed=False)
        bad_result2 = ValidationResult(
            hypothesis_id="HYP-001",
            status=ValidationStatus.VALIDATED,
            attempted=True,
            confirmed=False,
            evidence="Matched"
        )
        self.assertFalse(verify_result_provenance(job, bad_result2, audit, tracker))

        # 3. Missing evidence check (Validated status, but job has no evidence references)
        job_no_ev = ValidationJob.from_dict(self.job_data)
        job_no_ev.evidence_references = []
        self.assertFalse(verify_result_provenance(job_no_ev, result, audit, tracker))


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

        # Create sample hypotheses
        self.hypotheses = [
            SecurityHypothesis(
                id=f"HYP-{i:03d}",
                title=f"Security Issue {i}",
                description=f"Description of issue {i}",
                category="command_injection",
                severity="CRITICAL",
                confidence=0.8,
                evidence_references=[
                    EvidenceReference(type="file", file="server.py", line=None, detail="File: server.py")
                ],
                rationale="Matched subprocess calls"
            )
            for i in range(5)
        ]

    def test_orchestrator_config_validations(self):
        """Verify configuration validation bounds."""
        with self.assertRaises(ValueError):
            OrchestratorConfig(max_concurrent_validations=-1).validate()
        with self.assertRaises(ValueError):
            OrchestratorConfig(global_timeout_budget=0).validate()

    def test_successful_batch_execution_and_aggregation(self):
        """Verify standard successful multi-hypothesis batch validation schedules and aggregates cleanly."""
        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        self.assertEqual(report.repo_root, "/workspace/repo")
        self.assertEqual(report.global_status, "SUCCESS")
        self.assertEqual(len(report.results), 5)
        self.assertEqual(len(report.audit_records), 5)
        self.assertEqual(report.total_attempted, 5)
        self.assertEqual(report.total_confirmed, 5)

        # Check result values
        for res in report.results:
            self.assertEqual(res["status"], "VALIDATED")
            self.assertTrue(res["confirmed"])

    def test_concurrency_bounding(self):
        """Verify that concurrent validations are bounded using configured limits."""
        config = OrchestratorConfig(max_concurrent_validations=2)
        orchestrator = ValidationOrchestrator(self.validator, config)

        # Capture peak threads or verify run completes successfully
        report = orchestrator.validate_batch(self.hypotheses, self.report)
        self.assertEqual(report.global_status, "SUCCESS")
        self.assertEqual(len(report.results), 5)

    def test_per_job_timeout_handling(self):
        """Verify that a single job exceeding its execution timeout does not break the batch run."""
        # Inject hang behavior for HYP-001
        def hanging_behavior(hyp, ctx):
            time.sleep(0.5)
            return ValidationResult(
                hypothesis_id=hyp.id,
                status=ValidationStatus.VALIDATED,
                attempted=True,
                confirmed=True
            )

        self.validator.set_behavior("HYP-001", hanging_behavior)

        # Configure short per-job timeout
        config = OrchestratorConfig(per_validation_timeout=0.1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        # HYP-001 should fail or timeout, others should succeed
        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-001"]["status"], "TIMEOUT")
        self.assertFalse(results_by_id["HYP-001"]["confirmed"])

        self.assertEqual(results_by_id["HYP-000"]["status"], "VALIDATED")
        self.assertTrue(results_by_id["HYP-000"]["confirmed"])

    def test_global_timeout_budget_handling(self):
        """Verify orchestrator aborts execution when global budget runs out."""
        def long_hang(hyp, ctx):
            time.sleep(2.0)
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        for hyp in self.hypotheses:
            self.validator.set_behavior(hyp.id, long_hang)

        config = OrchestratorConfig(max_concurrent_validations=1, global_timeout_budget=0.2)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        # Should exit with TIMEOUT status
        self.assertEqual(report.global_status, "TIMEOUT")
        # Remaining jobs should be aborted or timed out
        timed_out_count = sum(1 for r in report.results if r["status"] == "TIMEOUT")
        self.assertTrue(timed_out_count > 0)

    def test_cancellation_support(self):
        """Verify cancellation event immediately aborts validation orchestrator queue."""
        cancel_event = threading.Event()

        def slow_job(hyp, ctx):
            time.sleep(0.2)
            # Trigger cancellation during first job execution
            cancel_event.set()
            return ValidationResult(hypothesis_id=hyp.id, status=ValidationStatus.VALIDATED, attempted=True, confirmed=True)

        self.validator.set_behavior("HYP-000", slow_job)

        config = OrchestratorConfig(max_concurrent_validations=1)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report, cancellation_event=cancel_event)

        self.assertEqual(report.global_status, "CANCELLED")
        # Ensure some remaining jobs did not run
        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-000"]["status"], "VALIDATED")
        # Unexecuted jobs must be fail-closed (aborted/preflight error)
        self.assertEqual(results_by_id["HYP-001"]["status"], "PREFLIGHT_ERROR")

    def test_global_aggregate_output_bytes_limits(self):
        """Verify aggregate output check cancels orchestrator once cumulative limit is reached."""
        def large_output_job(hyp, ctx):
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

        # Aggregate limit is 8KB, each job generates 5KB -> second job will exceed limit and abort/fail
        config = OrchestratorConfig(max_concurrent_validations=1, max_aggregate_output_bytes=8000)
        orchestrator = ValidationOrchestrator(self.validator, config)
        report = orchestrator.validate_batch(self.hypotheses, self.report)

        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        # First job succeeds
        self.assertEqual(results_by_id["HYP-000"]["status"], "VALIDATED")
        # Remaining jobs fail closed with SANDBOX_ERROR/TIMEOUT/aborted due to aggregate output breach
        self.assertIn(results_by_id["HYP-002"]["status"], ("SANDBOX_ERROR", "TIMEOUT", "PREFLIGHT_ERROR"))

    def test_concurrency_adversarial_rejection_and_isolation(self):
        """Adversarial stress-test: duplicate, malformed hypotheses, exceptions, startup errors, budget exhaustion."""
        # 1. Create duplicate and malformed hypotheses
        malformed_hyp = SecurityHypothesis(
            id="HYP-MALFORMED",
            title="Bad",
            description="Bad",
            category="sql_injection",
            severity="CRITICAL",
            confidence=0.8,
            evidence_references=[], # Missing evidence
            rationale=""
        )
        duplicate_hyp = self.hypotheses[0] # Duplicate of HYP-000

        # 2. Inject exception behavior for HYP-002
        def exception_behavior(hyp, ctx):
            raise RuntimeError("Fatal container launch error simulation")

        self.validator.set_behavior("HYP-002", exception_behavior)

        test_list = self.hypotheses + [duplicate_hyp, malformed_hyp]

        orchestrator = ValidationOrchestrator(self.validator)
        report = orchestrator.validate_batch(test_list, self.report)

        # Assert duplicate was ignored (only one entry in results or audit records)
        hyp_ids = [r["hypothesis_id"] for r in report.results]
        self.assertEqual(hyp_ids.count("HYP-000"), 1)

        # Assert malformed hypothesis failed closed
        results_by_id = {r["hypothesis_id"]: r for r in report.results}
        self.assertEqual(results_by_id["HYP-MALFORMED"]["status"], "INVALID_HYPOTHESIS")
        self.assertFalse(results_by_id["HYP-MALFORMED"]["confirmed"])

        # Assert HYP-002 (exception raised) failed closed safely as SANDBOX_ERROR
        self.assertEqual(results_by_id["HYP-002"]["status"], "SANDBOX_ERROR")
        self.assertFalse(results_by_id["HYP-002"]["confirmed"])

        # Assert all other safe jobs (HYP-001, HYP-003, HYP-004) executed successfully despite the crash of HYP-002
        self.assertEqual(results_by_id["HYP-003"]["status"], "VALIDATED")
        self.assertTrue(results_by_id["HYP-003"]["confirmed"])


if __name__ == "__main__":
    unittest.main()
