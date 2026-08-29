"""Multi-hypothesis validation scheduler and aggregator."""

import time
import uuid
import json
import threading
import concurrent.futures
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple, Iterable
from breakglass.inspection.models import RepositoryReport
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
                status=ValidationStatus.NOT_ATTEMPTED,
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

        # Create job-specific cancellation event linked with the global batch cancellation
        job_cancel = threading.Event()
        def link_cancellation():
            if cancellation_event:
                while not job_cancel.is_set():
                    if cancellation_event.is_set():
                        job_cancel.set()
                        break
                    time.sleep(0.01)
        linker = threading.Thread(target=link_cancellation, daemon=True)
        linker.start()

        try:
            # Enforce per-job timeout by executing validator call inside a helper thread pool
            import inspect
            job_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

            sig = inspect.signature(self.validator.validate)
            params = list(sig.parameters.values())
            has_cancellation = len(params) >= 3 or any(
                p.kind == inspect.Parameter.VAR_KEYWORD or p.kind == inspect.Parameter.VAR_POSITIONAL
                for p in params
            )

            if has_cancellation:
                future = job_executor.submit(self.validator.validate, hyp, report, job_cancel)
            else:
                future = job_executor.submit(self.validator.validate, hyp, report)

            try:
                res = future.result(timeout=job.config["timeout_seconds"])
            except concurrent.futures.TimeoutError:
                job_cancel.set()
                job_executor.shutdown(wait=False)
                res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=ValidationStatus.TIMEOUT,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Validation timed out after {job.config['timeout_seconds']} seconds"
                )
            except Exception as e:
                job_cancel.set()
                job_executor.shutdown(wait=False)
                res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Execution failed: {str(e)}"
                )
            finally:
                job_executor.shutdown(wait=False)

            # Run validator output through canonical ValidationEngine result integrity checks
            from breakglass.validation.engine import ValidationEngine
            engine = ValidationEngine(self.validator)
            res = engine._validate_result_integrity(res, job.hypothesis_id)

            # Enforce strict field size truncation limits on the host side
            if len((res.stdout or "").encode("utf-8")) > 100 * 1024:
                res.stdout = res.stdout[:100 * 1024] + "... [TRUNCATED]"
            if len((res.stderr or "").encode("utf-8")) > 100 * 1024:
                res.stderr = res.stderr[:100 * 1024] + "... [TRUNCATED]"
            if len((res.evidence or "").encode("utf-8")) > 50 * 1024:
                res.evidence = res.evidence[:50 * 1024] + "... [TRUNCATED]"
            if len((res.error_message or "").encode("utf-8")) > 10 * 1024:
                res.error_message = res.error_message[:10 * 1024] + "... [TRUNCATED]"

            # Atomic aggregate output bytes safety calculation over the entire result payload
            res_dict = res.to_dict()
            res_bytes_len = len(json.dumps(res_dict).encode("utf-8"))

            with counter_lock:
                aggregate_counter["bytes"] += res_bytes_len
                if aggregate_counter["bytes"] > self.config.max_aggregate_output_bytes:
                    raise ValueError(f"Aggregate batch output size of {aggregate_counter['bytes']} bytes exceeded limit of {self.config.max_aggregate_output_bytes} bytes")

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

        try:
            return res, audit
        finally:
            job_cancel.set()

    def validate_batch(
        self,
        hypotheses: Iterable[SecurityHypothesis],
        report: RepositoryReport,
        cancellation_event: Optional[threading.Event] = None
    ) -> AggregatedValidationReport:
        """Schedules and executes multiple hypotheses in a controlled concurrency pool."""
        start_time = time.perf_counter()
        results_list = []
        audit_list = []
        global_status = "SUCCESS"

        # Create/use batch cancellation event
        batch_cancel = cancellation_event or threading.Event()

        # Bounded deduplication/admission state to protect against memory exhaustion
        seen_hypotheses = set()
        jobs = []

        from breakglass.validation.engine import ValidationEngine
        engine = ValidationEngine(self.validator)

        # 1. Bounded admission loop iterating over generator/iterable on-demand
        iterator = iter(hypotheses)
        while True:
            try:
                hyp = next(iterator)
            except StopIteration:
                break
            except Exception as e:
                global_status = "SANDBOX_ERROR"
                batch_cancel.set()
                err_res = ValidationResult(
                    hypothesis_id="",
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Hypothesis iteration failed: {str(e)}"
                )
                results_list.append(err_res.to_dict())
                break

            # Stop once the total jobs + preflight failures satisfy max_queued_jobs limit
            if len(jobs) + len(results_list) >= self.config.max_queued_jobs:
                break

            # Complete shape & type checks on untrusted input object to prevent crash
            if not isinstance(hyp, SecurityHypothesis):
                err_res = ValidationResult(
                    hypothesis_id="",
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Invalid hypothesis shape: Not a SecurityHypothesis instance"
                )
                results_list.append(err_res.to_dict())
                continue

            if not isinstance(hyp.id, str) or not hyp.id.strip():
                err_res = ValidationResult(
                    hypothesis_id="",
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Invalid hypothesis shape: Empty or non-string ID"
                )
                results_list.append(err_res.to_dict())
                continue

            if hyp.id in seen_hypotheses:
                continue
            seen_hypotheses.add(hyp.id)

            if len(jobs) >= self.config.max_total_validations:
                # We have reached the maximum total validations target, ignore further jobs
                break

            if not isinstance(hyp.evidence_references, list) or not hyp.evidence_references:
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Validation job preflight failed: Hypothesis has no evidence references"
                )
                results_list.append(err_res.to_dict())
                continue

            # Strict field shape checking
            if not isinstance(hyp.title, str) or not isinstance(hyp.description, str) or not isinstance(hyp.category, str):
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Invalid hypothesis shape: title, description, and category must be strings"
                )
                results_list.append(err_res.to_dict())
                continue

            # 2. Strict ID/Fields/Evidence Authentication (Engine Alignment)
            # Reconstruct evidence references dynamically to check for fabricated entries
            canonical_references = []
            has_invalid_ref = False
            for ref in hyp.evidence_references:
                if not isinstance(ref, EvidenceReference):
                    has_invalid_ref = True
                    break
                valid, auth_detail = engine._resolve_and_validate_evidence(ref, report)
                if not valid:
                    has_invalid_ref = True
                    break
                canonical_references.append(
                    EvidenceReference(
                        type=ref.type,
                        file=ref.file,
                        line=ref.line,
                        detail=auth_detail
                    )
                )

            if has_invalid_ref:
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Eligibility check failed: Evidence reference failed to resolve or is fabricated"
                )
                results_list.append(err_res.to_dict())
                continue

            canonical_references.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

            canonical_hyp = SecurityHypothesis(
                id=hyp.id,
                title=hyp.title,
                description=hyp.description,
                category=hyp.category,
                severity=hyp.severity,
                confidence=hyp.confidence,
                evidence_references=canonical_references,
                rationale=hyp.rationale
            )

            # Authenticate ID
            if not engine._authenticate_hypothesis_id(canonical_hyp, report):
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message="Hypothesis authentication failed: ID does not match identity"
                )
                results_list.append(err_res.to_dict())
                continue

            # Check eligibility
            eligible, reason = engine.check_eligibility(canonical_hyp, report)
            if not eligible:
                err_res = ValidationResult(
                    hypothesis_id=hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Eligibility check failed: {reason}"
                )
                results_list.append(err_res.to_dict())
                continue

            job_id = str(uuid.uuid4())
            evidence_refs = [
                {
                    "type": r.type,
                    "file": r.file,
                    "line": r.line,
                    "detail": r.detail
                }
                for r in canonical_hyp.evidence_references
            ]
            job = ValidationJob(
                job_id=job_id,
                hypothesis_id=canonical_hyp.id,
                hypothesis_info={
                    "category": canonical_hyp.category,
                    "title": canonical_hyp.title,
                    "description": canonical_hyp.description,
                    "rationale": canonical_hyp.rationale
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
                    hypothesis_id=canonical_hyp.id,
                    status=ValidationStatus.INVALID_HYPOTHESIS,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Validation job preflight failed: {str(e)}"
                )
                results_list.append(err_res.to_dict())

        # Thread safety counter for cumulative output
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
                batch_cancel
            )
            future_to_job[future] = job

        pending = list(future_to_job.keys())
        budget_remaining = self.config.global_timeout_budget

        while pending and budget_remaining > 0:
            if batch_cancel.is_set():
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

            # Cooperative check for aggregate output budget breach
            with counter_lock:
                budget_breached = aggregate_counter["bytes"] > self.config.max_aggregate_output_bytes

            if budget_breached:
                global_status = "SANDBOX_ERROR"
                batch_cancel.set()
                break

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

        # 3. Clean global cancellation / timeout cleanup (no leaks left behind)
        if pending:
            if global_status != "CANCELLED" and global_status != "SANDBOX_ERROR":
                global_status = "TIMEOUT"

            # Set cancellation event to kill all active runner processes
            batch_cancel.set()

            # Non-blocking shutdown to allow immediate return
            executor.shutdown(wait=False)

            for fut in pending:
                job = future_to_job[fut]
                status_val = ValidationStatus.NOT_ATTEMPTED
                if global_status == "TIMEOUT":
                    status_val = ValidationStatus.TIMEOUT
                elif global_status == "SANDBOX_ERROR":
                    status_val = ValidationStatus.SANDBOX_ERROR

                err_res = ValidationResult(
                    hypothesis_id=job.hypothesis_id,
                    status=status_val,
                    attempted=False,
                    confirmed=False,
                    error_message=f"Validation batch aborted: {global_status}"
                )
                results_list.append(err_res.to_dict())
        else:
            executor.shutdown(wait=False)

        if batch_cancel.is_set() and global_status == "SUCCESS":
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
