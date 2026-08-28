"""Validation Engine and eligibility boundary orchestrator."""

from dataclasses import dataclass, field
import time
from typing import List, Tuple, Optional
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator


@dataclass
class ValidationConfig:
    """Resource limits and configurations for sandbox validation runs."""
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1024 * 1024  # 1MB
    max_hypotheses_per_run: int = 20
    max_payload_bytes: int = 100 * 1024 * 1024  # 100MB

    def validate(self) -> None:
        """Validates configuration parameters strictly."""
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive number")
        if not isinstance(self.max_output_bytes, int) or self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be a positive integer")
        if not isinstance(self.max_hypotheses_per_run, int) or self.max_hypotheses_per_run <= 0:
            raise ValueError("max_hypotheses_per_run must be a positive integer")
        if not isinstance(self.max_payload_bytes, int) or self.max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be a positive integer")


class ValidationEngine:
    """Orchestrates security hypothesis validation against a SandboxValidator."""

    def __init__(self, validator: SandboxValidator, config: Optional[ValidationConfig] = None):
        if validator is None:
            raise ValueError("Validator cannot be None")
        self.validator = validator
        self.config = config or ValidationConfig()
        self.config.validate()

    def _validate_evidence_reference(self, ref: EvidenceReference, report: RepositoryReport) -> bool:
        """Verifies that an evidence reference matches actual inspection findings."""
        if ref.type == "security_indicator":
            for ind in report.security_indicators:
                if ind.file == ref.file and (ind.line == ref.line or (ind.line is None and ref.line is None)):
                    return True
            return False
        elif ref.type == "route":
            for r in report.routes:
                if r.file == ref.file and r.line == ref.line:
                    return True
            return False
        elif ref.type == "entry_point":
            for ep in report.entry_points:
                if ep.file == ref.file and ep.line == ref.line:
                    return True
            return False
        elif ref.type == "file":
            repo = report.repository
            valid_files = set()
            for list_attr in (repo.config_files, repo.docker_configs, repo.cicd_configs,
                              repo.infrastructure_configs, repo.test_files):
                valid_files.update(list_attr)
            for r in report.routes:
                valid_files.add(r.file)
            for ep in report.entry_points:
                valid_files.add(ep.file)
            for ind in report.security_indicators:
                valid_files.add(ind.file)
            return ref.file in valid_files
        return False

    def check_eligibility(self, hypothesis: SecurityHypothesis, report: RepositoryReport) -> Tuple[bool, str]:
        """Checks if a hypothesis is eligible for sandbox execution."""
        if not hypothesis.id or not isinstance(hypothesis.id, str):
            return False, "Invalid or missing hypothesis ID"

        supported_categories = {
            "command_injection",
            "sql_injection",
            "remote_code_execution",
            "credential_exposure",
            "untrusted_input_execution",
            "insecure_deserialization",
            "path_traversal",
            "broken_access_control",
            "insecure_authentication",
        }
        if hypothesis.category not in supported_categories:
            return False, f"Unsupported category: {hypothesis.category}"

        if not isinstance(hypothesis.evidence_references, list) or not hypothesis.evidence_references:
            return False, "Missing or invalid evidence references"

        for idx, ref in enumerate(hypothesis.evidence_references):
            if not isinstance(ref, EvidenceReference):
                return False, f"Evidence reference at index {idx} is not of type EvidenceReference"
            if not self._validate_evidence_reference(ref, report):
                return False, (
                    f"Evidence reference at index {idx} ({ref.type} at {ref.file}:{ref.line}) "
                    f"does not resolve to the inspection report"
                )

        return True, "Eligible"

    def validate_hypotheses(
        self,
        hypotheses: List[SecurityHypothesis],
        report: RepositoryReport
    ) -> List[ValidationResult]:
        """Orchestrates sandbox validation for a collection of hypotheses."""
        results = []
        # Sort deterministically by hypothesis ID
        sorted_hypotheses = sorted(hypotheses, key=lambda x: x.id or "")

        # Bind validation batch size
        limited_hypotheses = sorted_hypotheses[:self.config.max_hypotheses_per_run]

        for hyp in limited_hypotheses:
            eligible, reason = self.check_eligibility(hyp, report)
            if not eligible:
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id or "",
                        status=ValidationStatus.INVALID_HYPOTHESIS,
                        attempted=False,
                        confirmed=False,
                        error_message=f"Eligibility check failed: {reason}"
                    )
                )
                continue

            try:
                start_time = time.perf_counter()
                result = self.validator.validate(hyp, report)
                duration = time.perf_counter() - start_time

                # Enforce resource bounding limits on generated sandbox outputs
                if len(result.stdout) > self.config.max_output_bytes:
                    result.stdout = result.stdout[:self.config.max_output_bytes] + "... [TRUNCATED]"
                if len(result.stderr) > self.config.max_output_bytes:
                    result.stderr = result.stderr[:self.config.max_output_bytes] + "... [TRUNCATED]"

                if result.duration is None:
                    result.duration = duration

                results.append(result)
            except Exception as e:
                # Exceptions in sandbox are caught and wrapped safely (fails closed)
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id or "",
                        status=ValidationStatus.SANDBOX_ERROR,
                        attempted=True,
                        confirmed=False,
                        error_message=f"Validator raised exception: {str(e)}"
                    )
                )

        return results
