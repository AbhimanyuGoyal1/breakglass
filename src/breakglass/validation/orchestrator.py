"""Multi-hypothesis validation scheduler and aggregator."""

import time
import uuid
import threading
import concurrent.futures
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator
from breakglass.validation.pipeline import (
    ValidationJob,
    JobState,
    JobLifecycleTracker,
    ValidationAuditRecord,
    verify_result_provenance
)

@dataclass
class OrchestratorConfig:
    max_concurrent_validations: int = 4
    max_total_validations: int = 20
    per_validation_timeout: float = 30.0
    global_timeout_budget: float = 300.0
    max_aggregate_output_bytes: int = 10 * 1024 * 1024  # 10MB
    max_queued_jobs: int = 100

    def validate(self) -> None:
        if not isinstance(self.max_concurrent_validations, int) or self.max_concurrent_validations <= 0 or isinstance(self.max_concurrent_validations, bool):
            raise ValueError("max_concurrent_validations must be a positive integer")
        if not isinstance(self.max_total_validations, int) or self.max_total_validations <= 0 or isinstance(self.max_total_validations, bool):
            raise ValueError("max_total_validations must be a positive integer")
        if not isinstance(self.per_validation_timeout, (int, float)) or self.per_validation_timeout <= 0 or isinstance(self.per_validation_timeout, bool):
            raise ValueError("per_validation_timeout must be a positive number")
        if not isinstance(self.global_timeout_budget, (int, float)) or self.global_timeout_budget <= 0 or isinstance(self.global_timeout_budget, bool):
            raise ValueError("global_timeout_budget must be a positive number")
        if not isinstance(self.max_aggregate_output_bytes, int) or self.max_aggregate_output_bytes <= 0 or isinstance(self.max_aggregate_output_bytes, bool):
            raise ValueError("max_aggregate_output_bytes must be a positive integer")
        if not isinstance(self.max_queued_jobs, int) or self.max_queued_jobs <= 0 or isinstance(self.max_queued_jobs, bool):
            raise ValueError("max_queued_jobs must be a positive integer")


@dataclass
class AggregatedValidationReport:
    repo_root: str
    total_attempted: int
    total_confirmed: int
    total_failed: int
    duration: float
    results: List[Dict[str, Any]]
    audit_records: List[Dict[str, Any]]
    global_status: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "total_attempted": self.total_attempted,
            "total_confirmed": self.total_confirmed,
            "total_failed": self.total_failed,
            "duration": self.duration,
            "results": self.results,
            "audit_records": self.audit_records,
            "global_status": self.global_status
        }


class ValidationOrchestrator:
    """Manages concurrent, isolated, resource-governed multi-hypothesis validations."""

    def __init__(self, validator: SandboxValidator, config: Optional[OrchestratorConfig] = None):
        if validator is None:
            raise ValueError("Validator cannot be None")
        self.validator = validator
        self.config = config or OrchestratorConfig()
        self.config.validate()

    def _execute_single_job(
        self,
        job: ValidationJob,
        report: RepositoryReport,
        aggregate_counter: Dict[str, int],
        counter_lock: threading.Lock,
        cancellation_event: Optional[threading.Event]
    ) -> Tuple[ValidationResult, ValidationAuditRecord]:
        """Runs a single job through the lifecycle and returns result + audit record."""
        tracker = JobLifecycleTracker(JobState.QUEUED)
        execution_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Check early cancellation
        if cancellation_event and cancellation_event.is_set():
            tracker.transition_to(JobState.FAILED)
            end_time = time.perf_counter()
            audit = ValidationAuditRecord(
                execution_id=execution_id,
                hypothesis_id=job.hypothesis_id,
                start_time=start_time,
                end_time=end_time,
                duration=end_time - start_time,
                backend_used="None",
                final_status="FAILED",
                termination_reason="Execution cancelled before start"
            )
            result = ValidationResult(
                hypothesis_id=job.hypothesis_id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message="Validation cancelled"
            )
            return result, audit

        # PREFLIGHT phase
        tracker.transition_to(JobState.PREFLIGHT)

        try:
            from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
            hyp = SecurityHypothesis(
                id=job.hypothesis_id,
                title=job.hypothesis_info.get("title", ""),
                description=job.hypothesis_info.get("description", ""),
                category=job.hypothesis_info.get("category", ""),
                severity="CRITICAL",
                confidence=0.8,
                evidence_references=[
                    EvidenceReference(
                        type=ref.get("type", ""),
                        file=ref.get("file", ""),
                        line=ref.get("line"),
                        detail=ref.get("detail", "")
                    )
                    for ref in job.evidence_references
                ],
                rationale=job.hypothesis_info.get("rationale", "")
            )
        except Exception as e:
            tracker.transition_to(JobState.FAILED)
            end_time = time.perf_counter()
            audit = ValidationAuditRecord(
                execution_id=execution_id,
                hypothesis_id=job.hypothesis_id,
                start_time=start_time,
                end_time=end_time,
                duration=end_time - start_time,
                backend_used="None",
                final_status="FAILED",
                termination_reason=f"Preflight reconstruction failed: {str(e)}"
            )
            result = ValidationResult(
                hypothesis_id=job.hypothesis_id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message=f"Preflight error: {str(e)}"
            )
            return result, audit

        # RUNNING phase
        tracker.transition_to(JobState.RUNNING)
        backend_name = "Docker" if getattr(self.validator, "container_sandbox", False) else "Subprocess"

        try:
            # Enforce per-job timeout by executing validator call inside a helper thread pool
            job_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = job_executor.submit(self.validator.validate, hyp, report)
            try:
                res = future.result(timeout=job.config["timeout_seconds"])
            except concurrent.futures.TimeoutError:
                res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=ValidationStatus.TIMEOUT,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Validation timed out after {job.config['timeout_seconds']} seconds"
                )
            except Exception as e:
                res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Execution failed: {str(e)}"
                )
            finally:
                job_executor.shutdown(wait=False)

            stdout_len = len(res.stdout.encode("utf-8")) if res.stdout else 0
            stderr_len = len(res.stderr.encode("utf-8")) if res.stderr else 0
            total_job_output = stdout_len + stderr_len

            with counter_lock:
                aggregate_counter["bytes"] += total_job_output
                if aggregate_counter["bytes"] > self.config.max_aggregate_output_bytes:
                    raise ValueError("Aggregate output bytes limit exceeded across all validations")

            if res.status == ValidationStatus.VALIDATED:
                tracker.transition_to(JobState.VALIDATED)
            elif res.status == ValidationStatus.NOT_CONFIRMED:
                tracker.transition_to(JobState.NOT_CONFIRMED)
            elif res.status == ValidationStatus.TIMEOUT:
                tracker.transition_to(JobState.TIMEOUT)
            elif res.status == ValidationStatus.SANDBOX_ERROR:
                tracker.transition_to(JobState.SANDBOX_ERROR)
            else:
                tracker.transition_to(JobState.FAILED)

        except Exception as e:
            tracker.transition_to(JobState.FAILED)
            res = ValidationResult(
                hypothesis_id=job.hypothesis_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Execution failed: {str(e)}"
            )

        end_time = time.perf_counter()
        duration = end_time - start_time

        audit = ValidationAuditRecord(
            execution_id=execution_id,
            hypothesis_id=job.hypothesis_id,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            backend_used=backend_name,
            final_status=tracker.state.value,
            termination_reason=res.error_message
        )

        if not verify_result_provenance(job, res, audit, tracker):
            res.status = ValidationStatus.SANDBOX_ERROR
            res.confirmed = False
            res.attempted = True
            res.error_message = "Integrity check failed: Result provenance could not be authenticated."
            audit.final_status = JobState.SANDBOX_ERROR.value
            audit.termination_reason = res.error_message

        return res, audit

    def validate_batch(
        self,
        hypotheses: List[SecurityHypothesis],
        report: RepositoryReport,
        cancellation_event: Optional[threading.Event] = None
    ) -> AggregatedValidationReport:
        """Schedules and executes multiple hypotheses in a controlled concurrency pool."""
        start_time = time.perf_counter()
        results_list = []
        audit_list = []
        global_status = "SUCCESS"

        seen_hypotheses = set()
        deduped_hypotheses = []
        for hyp in hypotheses:
            if not isinstance(hyp, SecurityHypothesis) or not hyp.id:
                continue
            if hyp.id in seen_hypotheses:
                continue
            seen_hypotheses.add(hyp.id)
            deduped_hypotheses.append(hyp)

        queued_hypotheses = deduped_hypotheses[:self.config.max_queued_jobs]
        target_hypotheses = queued_hypotheses[:self.config.max_total_validations]

        jobs = []
        for hyp in target_hypotheses:
            # Preflight validation: Reject hypotheses with no evidence references
            if not hyp.evidence_references:
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Validation job preflight failed: Hypothesis has no evidence references"
                )
                results_list.append(err_res.to_dict())
                continue

            job_id = str(uuid.uuid4())
            evidence_refs = [
                {
                    "type": ref.type,
                    "file": ref.file,
                    "line": ref.line,
                    "detail": ref.detail
                }
                for ref in hyp.evidence_references
            ]
            job = ValidationJob(
                job_id=job_id,
                hypothesis_id=hyp.id,
                hypothesis_info={
                    "category": hyp.category,
                    "title": hyp.title,
                    "description": hyp.description,
                    "rationale": hyp.rationale
                },
                repo_root=report.repository.root,
                evidence_references=evidence_refs,
                config={
                    "timeout_seconds": self.config.per_validation_timeout,
                    "max_output_bytes": getattr(self.validator, "max_output_bytes", 1024 * 1024),
                    "max_payload_bytes": getattr(self.validator, "max_payload_bytes", 100 * 1024 * 1024)
                }
            )
            try:
                validated_job = ValidationJob.from_dict(job.to_dict())
                jobs.append(validated_job)
            except Exception as e:
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Validation job preflight failed: {str(e)}"
                )
                results_list.append(err_res.to_dict())

        aggregate_counter = {"bytes": 0}
        counter_lock = threading.Lock()

        max_workers = min(self.config.max_concurrent_validations, len(jobs)) if jobs else 1
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        future_to_job = {}

        for job in jobs:
            future = executor.submit(
                self._execute_single_job,
                job,
                report,
                aggregate_counter,
                counter_lock,
                cancellation_event
            )
            future_to_job[future] = job

        pending = list(future_to_job.keys())
        budget_remaining = self.config.global_timeout_budget

        while pending and budget_remaining > 0:
            if cancellation_event and cancellation_event.is_set():
                global_status = "CANCELLED"
                break

            loop_start = time.perf_counter()
            done, not_done = concurrent.futures.wait(
                pending,
                timeout=min(0.1, budget_remaining),
                return_when=concurrent.futures.FIRST_COMPLETED
            )
            loop_duration = time.perf_counter() - loop_start
            budget_remaining -= loop_duration

            for fut in done:
                job = future_to_job[fut]
                try:
                    res, audit = fut.result()
                    results_list.append(res.to_dict())
                    audit_list.append(audit.to_dict())
                except Exception as e:
                    err_res = ValidationResult(
                        hypothesis_id=job.hypothesis_id,
                        status=ValidationStatus.SANDBOX_ERROR,
                        attempted=True,
                        confirmed=False,
                        error_message=f"Job thread raised exception: {str(e)}"
                    )
                    results_list.append(err_res.to_dict())
                    audit_list.append(
                        ValidationAuditRecord(
                            execution_id=str(uuid.uuid4()),
                            hypothesis_id=job.hypothesis_id,
                            start_time=loop_start,
                            end_time=time.perf_counter(),
                            duration=time.perf_counter() - loop_start,
                            backend_used="None",
                            final_status="FAILED",
                            termination_reason=str(e)
                        ).to_dict()
                    )
                pending.remove(fut)

        if pending:
            if global_status != "CANCELLED":
                global_status = "TIMEOUT"

            executor.shutdown(wait=False, cancel_futures=True)

            for fut in pending:
                job = future_to_job[fut]
                err_res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=ValidationStatus.TIMEOUT if global_status == "TIMEOUT" else ValidationStatus.PREFLIGHT_ERROR,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Validation batch aborted: {global_status}"
                )
                results_list.append(err_res.to_dict())
        else:
            executor.shutdown(wait=False)

        # Final check if cancellation occurred at any point during run
        if cancellation_event and cancellation_event.is_set():
            global_status = "CANCELLED"

        duration = time.perf_counter() - start_time

        total_attempted = 0
        total_confirmed = 0
        total_failed = 0
        for r in results_list:
            if r.get("attempted"):
                total_attempted += 1
            if r.get("confirmed"):
                total_confirmed += 1
            if r.get("status") in (ValidationStatus.SANDBOX_ERROR.value, ValidationStatus.TIMEOUT.value, ValidationStatus.PREFLIGHT_ERROR.value):
                total_failed += 1

        return AggregatedValidationReport(
            repo_root=report.repository.root,
            total_attempted=total_attempted,
            total_confirmed=total_confirmed,
            total_failed=total_failed,
            duration=duration,
            results=results_list,
            audit_records=audit_list,
            global_status=global_status
        )
