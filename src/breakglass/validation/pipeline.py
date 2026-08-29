"""Structured validation pipeline, job schemas, state lifecycles, and provenance checks."""

import os
import time
import json
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from breakglass.validation.models import ValidationStatus, ValidationResult

class JobState(str, Enum):
    QUEUED = "QUEUED"
    PREFLIGHT = "PREFLIGHT"
    RUNNING = "RUNNING"
    VALIDATED = "VALIDATED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SANDBOX_ERROR = "SANDBOX_ERROR"


VALID_TRANSITIONS: Dict[JobState, Set[JobState]] = {
    JobState.QUEUED: {JobState.PREFLIGHT, JobState.FAILED},
    JobState.PREFLIGHT: {JobState.RUNNING, JobState.FAILED},
    JobState.RUNNING: {
        JobState.VALIDATED,
        JobState.NOT_CONFIRMED,
        JobState.TIMEOUT,
        JobState.SANDBOX_ERROR,
        JobState.FAILED
    },
    JobState.VALIDATED: set(),
    JobState.NOT_CONFIRMED: set(),
    JobState.FAILED: set(),
    JobState.TIMEOUT: set(),
    JobState.SANDBOX_ERROR: set(),
}


@dataclass
class ValidationJob:
    job_id: str
    hypothesis_id: str
    hypothesis_info: Dict[str, str]
    repo_root: str
    evidence_references: List[Dict[str, Any]]
    config: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Returns a deterministic dictionary serialization of the job."""
        return {
            "job_id": self.job_id,
            "hypothesis_id": self.hypothesis_id,
            "hypothesis_info": {
                "category": self.hypothesis_info.get("category", ""),
                "title": self.hypothesis_info.get("title", ""),
                "description": self.hypothesis_info.get("description", ""),
                "rationale": self.hypothesis_info.get("rationale", "")
            },
            "repo_root": self.repo_root,
            "evidence_references": sorted(
                [
                    {
                        "type": ref.get("type", ""),
                        "file": ref.get("file", ""),
                        "line": ref.get("line"),
                        "detail": ref.get("detail", "")
                    }
                    for ref in self.evidence_references
                ],
                key=lambda x: (x["file"], x["line"] or 0, x["type"], x["detail"])
            ),
            "config": {
                "timeout_seconds": float(self.config.get("timeout_seconds", 30.0)),
                "max_output_bytes": int(self.config.get("max_output_bytes", 1024 * 1024)),
                "max_payload_bytes": int(self.config.get("max_payload_bytes", 100 * 1024 * 1024))
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationJob":
        """Performs strict type validation and constructs a ValidationJob."""
        if not isinstance(data, dict):
            raise ValueError("Job data must be a dictionary")

        # Required fields check
        required_keys = {"job_id", "hypothesis_id", "hypothesis_info", "repo_root", "evidence_references", "config"}
        missing = required_keys - data.keys()
        if missing:
            raise ValueError(f"Missing required job fields: {missing}")

        job_id = data["job_id"]
        hypothesis_id = data["hypothesis_id"]
        hypothesis_info = data["hypothesis_info"]
        repo_root = data["repo_root"]
        evidence_references = data["evidence_references"]
        config = data["config"]

        # Validate types strictly
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("job_id must be a non-empty string")
        if not isinstance(hypothesis_id, str) or not hypothesis_id:
            raise ValueError("hypothesis_id must be a non-empty string")
        if not isinstance(repo_root, str) or not repo_root:
            raise ValueError("repo_root must be a non-empty string")
        if not isinstance(hypothesis_info, dict):
            raise ValueError("hypothesis_info must be a dictionary")
        if not isinstance(evidence_references, list):
            raise ValueError("evidence_references must be a list")
        if not isinstance(config, dict):
            raise ValueError("config must be a dictionary")

        # Check hypothesis_info contents
        info_keys = {"category", "title", "description", "rationale"}
        for k in info_keys:
            val = hypothesis_info.get(k)
            if not isinstance(val, str):
                raise ValueError(f"hypothesis_info field '{k}' must be a string")

        # Check config limits
        timeout_seconds = config.get("timeout_seconds", 30.0)
        max_output_bytes = config.get("max_output_bytes", 1024 * 1024)
        max_payload_bytes = config.get("max_payload_bytes", 100 * 1024 * 1024)

        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0 or isinstance(timeout_seconds, bool):
            raise ValueError("config.timeout_seconds must be a positive number")
        if not isinstance(max_output_bytes, int) or max_output_bytes <= 0 or isinstance(max_output_bytes, bool):
            raise ValueError("config.max_output_bytes must be a positive integer")
        if not isinstance(max_payload_bytes, int) or max_payload_bytes <= 0 or isinstance(max_payload_bytes, bool):
            raise ValueError("config.max_payload_bytes must be a positive integer")

        # Bounded payload check to prevent memory exhaustion (maximum 10MB limit)
        serialized_size = len(json.dumps(data).encode("utf-8"))
        if serialized_size > 10 * 1024 * 1024:
            raise ValueError(f"Job payload size {serialized_size} bytes exceeds the 10MB safety limit")

        # Evidence references validation
        validated_refs = []
        for ref in evidence_references:
            if not isinstance(ref, dict):
                raise ValueError("Each evidence reference must be a dictionary")
            ref_type = ref.get("type")
            ref_file = ref.get("file")
            ref_line = ref.get("line")
            ref_detail = ref.get("detail")

            if not isinstance(ref_type, str) or not ref_type:
                raise ValueError("Evidence reference type must be a non-empty string")
            if not isinstance(ref_file, str) or not ref_file:
                raise ValueError("Evidence reference file must be a non-empty string")
            if ref_line is not None and (not isinstance(ref_line, int) or isinstance(ref_line, bool) or ref_line <= 0):
                raise ValueError("Evidence reference line must be a positive integer or None")
            if not isinstance(ref_detail, str):
                raise ValueError("Evidence reference detail must be a string")

            # Basic anti-leak check
            if "api_key" in ref_file.lower() or "secret" in ref_file.lower():
                raise ValueError("Evidence reference paths cannot contain sensitive credential names")

            validated_refs.append({
                "type": ref_type,
                "file": ref_file,
                "line": ref_line,
                "detail": ref_detail
            })

        return cls(
            job_id=job_id,
            hypothesis_id=hypothesis_id,
            hypothesis_info={k: hypothesis_info[k] for k in info_keys},
            repo_root=repo_root,
            evidence_references=validated_refs,
            config={
                "timeout_seconds": float(timeout_seconds),
                "max_output_bytes": int(max_output_bytes),
                "max_payload_bytes": int(max_payload_bytes)
            }
        )


class JobLifecycleTracker:
    """Enforces valid pipeline job state transitions."""
    def __init__(self, initial_state: JobState = JobState.QUEUED):
        self._state = initial_state

    @property
    def state(self) -> JobState:
        return self._state

    def transition_to(self, new_state: JobState) -> None:
        """Transitions state or raises ValueError if invalid."""
        valid_targets = VALID_TRANSITIONS.get(self._state, set())
        if new_state not in valid_targets:
            raise ValueError(f"Illegal state transition from {self._state.value} to {new_state.value}")
        self._state = new_state


@dataclass
class ValidationAuditRecord:
    execution_id: str
    hypothesis_id: str
    start_time: float
    end_time: float
    duration: float
    backend_used: str
    final_status: str
    termination_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "hypothesis_id": self.hypothesis_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "backend_used": self.backend_used,
            "final_status": self.final_status,
            "termination_reason": self.termination_reason
        }


def verify_result_provenance(
    job: ValidationJob,
    result: ValidationResult,
    audit: ValidationAuditRecord,
    tracker: JobLifecycleTracker
) -> bool:
    """Rigorous check verifying validation result correlation and integrity."""
    # 1. Basic type checks
    if not isinstance(result, ValidationResult) or not isinstance(audit, ValidationAuditRecord) or not isinstance(tracker, JobLifecycleTracker):
        return False

    # 2. Hypothesis ID correlation
    if result.hypothesis_id != job.hypothesis_id or audit.hypothesis_id != job.hypothesis_id:
        return False

    # 3. Validation result logic consistency
    if result.confirmed:
        if not result.attempted:
            return False
        if result.status != ValidationStatus.VALIDATED:
            return False

    if not result.attempted:
        if result.confirmed:
            return False
        if result.status == ValidationStatus.VALIDATED:
            return False

    # 4. Status consistency between result, lifecycle tracker and audit record
    if result.status == ValidationStatus.VALIDATED:
        if tracker.state != JobState.VALIDATED or audit.final_status != "VALIDATED":
            return False
        if not job.evidence_references:
            return False
        if not result.confirmed or not result.attempted:
            return False

    elif result.status == ValidationStatus.NOT_CONFIRMED:
        if tracker.state != JobState.NOT_CONFIRMED or audit.final_status != "NOT_CONFIRMED":
            return False
        if result.confirmed or not result.attempted:
            return False

    elif result.status == ValidationStatus.TIMEOUT:
        if tracker.state != JobState.TIMEOUT or audit.final_status != "TIMEOUT":
            return False
        if result.confirmed:
            return False

    elif result.status == ValidationStatus.SANDBOX_ERROR:
        if tracker.state != JobState.SANDBOX_ERROR or audit.final_status != "SANDBOX_ERROR":
            return False
        if result.confirmed:
            return False

    elif result.status == ValidationStatus.PREFLIGHT_ERROR:
        if tracker.state != JobState.FAILED or audit.final_status not in ("FAILED", "PREFLIGHT_ERROR"):
            return False
        if result.confirmed or result.attempted:
            return False

    elif result.status == ValidationStatus.NOT_ATTEMPTED:
        if tracker.state != JobState.FAILED and tracker.state != JobState.QUEUED:
            return False
        if result.confirmed or result.attempted:
            return False

    else:
        return False

    # 5. Time execution consistency
    if audit.duration < 0 or (result.duration is not None and result.duration < 0):
        return False

    return True
