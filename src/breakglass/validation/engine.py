"""Validation Engine and eligibility boundary orchestrator."""

import concurrent.futures
from dataclasses import dataclass, field
import hashlib
import json
import time
from typing import List, Tuple, Optional, Any, Dict
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
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
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0 or isinstance(self.timeout_seconds, bool):
            raise ValueError("timeout_seconds must be a positive number")
        if not isinstance(self.max_output_bytes, int) or self.max_output_bytes <= 0 or isinstance(self.max_output_bytes, bool):
            raise ValueError("max_output_bytes must be a positive integer")
        if not isinstance(self.max_hypotheses_per_run, int) or self.max_hypotheses_per_run <= 0 or isinstance(self.max_hypotheses_per_run, bool):
            raise ValueError("max_hypotheses_per_run must be a positive integer")
        if not isinstance(self.max_payload_bytes, int) or self.max_payload_bytes <= 0 or isinstance(self.max_payload_bytes, bool):
            raise ValueError("max_payload_bytes must be a positive integer")


class ValidationEngine:
    """Orchestrates security hypothesis validation against a SandboxValidator."""

    def __init__(self, validator: SandboxValidator, config: Optional[ValidationConfig] = None):
        if validator is None:
            raise ValueError("Validator cannot be None")
        self.validator = validator
        self.config = config or ValidationConfig()
        self.config.validate()

    def _truncate_utf8(self, text: str, max_bytes: int) -> str:
        """Truncates a string to ensure its UTF-8 encoding is strictly within max_bytes."""
        if not isinstance(text, str):
            return ""
        marker = "... [TRUNCATED]"
        marker_bytes = marker.encode("utf-8")
        if max_bytes <= len(marker_bytes):
            return marker[:max_bytes]

        encoded = text.encode("utf-8")
        if len(encoded) <= max_bytes:
            return text

        allowed_bytes = max_bytes - len(marker_bytes)
        truncated_bytes = encoded[:allowed_bytes]
        # Decode ignoring any incomplete UTF-8 sequence at the end
        truncated_text = truncated_bytes.decode("utf-8", errors="ignore")
        return truncated_text + marker

    def _to_canonical_dict(self, obj: Any) -> Any:
        """Helper to recursively convert objects to standard dict representation for serialization."""
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        elif hasattr(obj, "__dict__"):
            return {k: self._to_canonical_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
        elif isinstance(obj, list):
            return [self._to_canonical_dict(x) for x in obj]
        elif isinstance(obj, dict):
            return {k: self._to_canonical_dict(v) for k, v in obj.items()}
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        else:
            return str(obj)

    def _calculate_payload_bytes(self, hyp: SecurityHypothesis, report: RepositoryReport) -> int:
        """Calculates canonical request size in bytes."""
        request_data = {
            "hypothesis": self._to_canonical_dict(hyp),
            "report": {
                "entry_points": self._to_canonical_dict(report.entry_points),
                "routes": self._to_canonical_dict(report.routes),
                "security_indicators": self._to_canonical_dict(report.security_indicators),
                "repository": self._to_canonical_dict(report.repository)
            }
        }
        canonical_str = json.dumps(request_data, sort_keys=True, separators=(",", ":"))
        return len(canonical_str.encode("utf-8"))

    def _resolve_and_validate_evidence(self, ref: EvidenceReference, report: RepositoryReport) -> Tuple[bool, str]:
        """Resolves untrusted evidence reference against authoritative report findings."""
        if not isinstance(ref, EvidenceReference):
            return False, ""
        if not isinstance(ref.type, str) or not isinstance(ref.file, str) or not isinstance(ref.detail, str):
            return False, ""
        if ref.line is not None and (not isinstance(ref.line, int) or isinstance(ref.line, bool)):
            return False, ""

        repo = report.repository
        valid_files = set()
        for list_attr in (repo.config_files, repo.docker_configs, repo.cicd_configs,
                          repo.infrastructure_configs, repo.test_files):
            valid_files.update(list_attr)

        if ref.type == "security_indicator":
            for ind in report.security_indicators:
                if ind.file == ref.file and (ind.line == ref.line or (ind.line is None and ref.line is None)):
                    return True, f"Security indicator: {ind.evidence}"
            return False, ""
        elif ref.type == "route":
            for r in report.routes:
                if r.file == ref.file and r.line == ref.line:
                    return True, f"Route: {r.method} {r.pattern}"
            return False, ""
        elif ref.type == "entry_point":
            for ep in report.entry_points:
                if ep.file == ref.file and ep.line == ref.line:
                    return True, f"Entry point: {ep.type} ({ep.description})"
            return False, ""
        elif ref.type == "file":
            # Plain file reference must have no line numbers
            if ref.line is not None:
                return False, ""
            # Gather files from any discovered indicators/routes/entry points to be comprehensive
            for r in report.routes:
                valid_files.add(r.file)
            for ep in report.entry_points:
                valid_files.add(ep.file)
            for ind in report.security_indicators:
                valid_files.add(ind.file)

            if ref.file in valid_files:
                return True, f"File: {ref.file}"
            return False, ""

        return False, ""

    def _authenticate_hypothesis_id(self, hypothesis: SecurityHypothesis, report: RepositoryReport) -> bool:
        """Recomputes expected hypothesis ID from canonical data and compares it to the supplied ID."""
        if not hypothesis.id or not isinstance(hypothesis.id, str):
            return False

        # Gather authoritative details for evidence references
        canonical_references = []
        for ref in hypothesis.evidence_references:
            valid, auth_detail = self._resolve_and_validate_evidence(ref, report)
            if not valid:
                return False
            canonical_references.append(
                EvidenceReference(
                    type=ref.type,
                    file=ref.file,
                    line=ref.line,
                    detail=auth_detail
                )
            )
        # Sort references deterministically
        canonical_references.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

        # Check if ID prefix suggests LLM reasoning vs deterministic reasoning
        is_llm = hypothesis.id.startswith("HYP-LLM-")

        if is_llm:
            ref_list = []
            for r in canonical_references:
                ref_list.append({
                    "type": r.type,
                    "file": r.file,
                    "line": r.line,
                    "detail": r.detail
                })
            identity = {
                "category": hypothesis.category,
                "title": hypothesis.title,
                "description": hypothesis.description,
                "references": ref_list
            }
            expected_id = generate_hypothesis_id(hypothesis.category, identity, is_llm=True)
        else:
            # Reconstruct deterministic reasoning identity mapping based on category and references
            # We match the indicator reference and correlating route/entry_point
            ind_ref = next((r for r in canonical_references if r.type == "security_indicator"), None)
            ind = None
            if ind_ref:
                ind = next((i for i in report.security_indicators if i.file == ind_ref.file and (i.line == ind_ref.line or (i.line is None and ind_ref.line is None))), None)

            if hypothesis.category == "command_injection":
                route_ref = next((r for r in canonical_references if r.type == "route"), None)
                route = None
                if route_ref:
                    route = next((r for r in report.routes if r.file == route_ref.file and r.line == route_ref.line), None)
                if not ind or not route:
                    return False
                identity = {
                    "rule": "command_injection",
                    "ind": {
                        "category": ind.category,
                        "indicator_type": ind.indicator_type,
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": ind.evidence
                    },
                    "route": {
                        "file": route.file,
                        "line": route.line,
                        "method": route.method,
                        "pattern": route.pattern,
                        "evidence": route.evidence
                    }
                }
            elif hypothesis.category == "sql_injection":
                route_ref = next((r for r in canonical_references if r.type == "route"), None)
                route = None
                if route_ref:
                    route = next((r for r in report.routes if r.file == route_ref.file and r.line == route_ref.line), None)
                if not ind or not route:
                    return False
                identity = {
                    "rule": "sql_injection",
                    "ind": {
                        "category": ind.category,
                        "indicator_type": ind.indicator_type,
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": ind.evidence
                    },
                    "route": {
                        "file": route.file,
                        "line": route.line,
                        "method": route.method,
                        "pattern": route.pattern,
                        "evidence": route.evidence
                    }
                }
            elif hypothesis.category == "remote_code_execution":
                ep_ref = next((r for r in canonical_references if r.type == "entry_point"), None)
                ep = None
                if ep_ref:
                    ep = next((e for e in report.entry_points if e.file == ep_ref.file and e.line == ep_ref.line), None)
                if not ind or not ep:
                    return False
                identity = {
                    "rule": "remote_code_execution",
                    "ind": {
                        "category": ind.category,
                        "indicator_type": ind.indicator_type,
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": ind.evidence
                    },
                    "entry_point": {
                        "file": ep.file,
                        "type": ep.type,
                        "description": ep.description,
                        "line": ep.line
                    }
                }
            elif hypothesis.category == "credential_exposure":
                if not ind:
                    return False
                sorted_frameworks = sorted(list(set(report.repository.frameworks)))
                identity = {
                    "rule": "credential_exposure",
                    "ind": {
                        "category": ind.category,
                        "indicator_type": ind.indicator_type,
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": ind.evidence
                    },
                    "frameworks": sorted_frameworks
                }
            else:
                return False

            expected_id = generate_hypothesis_id(hypothesis.category, identity, is_llm=False)

        return expected_id == hypothesis.id

    def check_eligibility(self, hypothesis: SecurityHypothesis, report: RepositoryReport) -> Tuple[bool, str]:
        """Checks if a hypothesis is eligible for sandbox execution."""
        if not hypothesis or not isinstance(hypothesis, SecurityHypothesis):
            return False, "Invalid hypothesis object type"
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

        # Authenticate ID and verify all references resolve to authoritative details
        if not self._authenticate_hypothesis_id(hypothesis, report):
            return False, "Hypothesis ID authentication failed: ID mismatch or fabricated references"

        return True, "Eligible"

    def _validate_result_integrity(self, result: Any, expected_id: str) -> ValidationResult:
        """Validates SandboxResult types, enum values, and state invariants strictly."""
        if not isinstance(result, ValidationResult):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Sandbox adapter returned invalid object type (not ValidationResult)"
            )

        # Enforce attribution matching
        if result.hypothesis_id != expected_id:
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Hypothesis ID mismatch in result: expected {expected_id}, got {result.hypothesis_id}"
            )

        # Validate status enum strictly
        if not isinstance(result.status, ValidationStatus):
            try:
                result.status = ValidationStatus(result.status)
            except ValueError:
                return ValidationResult(
                    hypothesis_id=expected_id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Sandbox adapter returned invalid status value: {result.status}"
                )

        # Validate state invariants
        invariants = {
            ValidationStatus.NOT_ATTEMPTED: (False, False),
            ValidationStatus.VALIDATED: (True, True),
            ValidationStatus.NOT_CONFIRMED: (True, False),
            ValidationStatus.SANDBOX_ERROR: (True, False),
            ValidationStatus.TIMEOUT: (True, False),
            ValidationStatus.INVALID_HYPOTHESIS: (False, False),
        }
        expected_attempted, expected_confirmed = invariants[result.status]
        if result.attempted != expected_attempted or result.confirmed != expected_confirmed:
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=(
                    f"Contradictory state invariants for status '{result.status.value}': "
                    f"attempted={result.attempted} (expected {expected_attempted}), "
                    f"confirmed={result.confirmed} (expected {expected_confirmed})"
                )
            )

        # Validate parameter types
        if result.duration is not None and (not isinstance(result.duration, (int, float)) or isinstance(result.duration, bool)):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Invalid duration type: {type(result.duration).__name__}"
            )
        if not isinstance(result.confidence_delta, (int, float)) or isinstance(result.confidence_delta, bool) or not (-1.0 <= result.confidence_delta <= 1.0):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Invalid confidence_delta range or type: {result.confidence_delta}"
            )
        if not isinstance(result.stdout, str) or not isinstance(result.stderr, str):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="stdout and stderr must be strings"
            )
        if result.error_message is not None and not isinstance(result.error_message, str):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="error_message must be a string or None"
            )

        return result

    def _run_with_timeout(self, hyp: SecurityHypothesis, report: RepositoryReport) -> ValidationResult:
        """Invokes SandboxValidator inside a thread pool with a timeout boundary."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.validator.validate, hyp, report)
            try:
                return future.result(timeout=self.config.timeout_seconds)
            except concurrent.futures.TimeoutError:
                return ValidationResult(
                    hypothesis_id=hyp.id or "",
                    status=ValidationStatus.TIMEOUT,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Validation timed out after {self.config.timeout_seconds} seconds"
                )

    def validate_hypotheses(
        self,
        hypotheses: List[SecurityHypothesis],
        report: RepositoryReport
    ) -> List[ValidationResult]:
        """Orchestrates sandbox validation for a collection of hypotheses."""
        results = []
        valid_hypotheses = []

        # 1. Filter out malformed/invalid hypotheses shape before sorting
        for hyp in hypotheses:
            if not isinstance(hyp, SecurityHypothesis) or not hyp.id or not isinstance(hyp.id, str):
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id if (hasattr(hyp, "id") and isinstance(hyp.id, str)) else "",
                        status=ValidationStatus.INVALID_HYPOTHESIS,
                        attempted=False,
                        confirmed=False,
                        error_message="Invalid hypothesis shape: Not a valid SecurityHypothesis instance, or ID is empty/not a string"
                    )
                )
            else:
                valid_hypotheses.append(hyp)

        # 2. Sort deterministically by hypothesis ID
        sorted_hypotheses = sorted(valid_hypotheses, key=lambda x: x.id)

        # Bind validation batch size
        limited_hypotheses = sorted_hypotheses[:self.config.max_hypotheses_per_run]

        for hyp in limited_hypotheses:
            # Reconstruct evidence with authoritative details before validation
            canonical_references = []
            for ref in hyp.evidence_references:
                valid, auth_detail = self._resolve_and_validate_evidence(ref, report)
                if valid:
                    canonical_references.append(
                        EvidenceReference(
                            type=ref.type,
                            file=ref.file,
                            line=ref.line,
                            detail=auth_detail
                        )
                    )
            canonical_references.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

            # Hypotheses passed to sandbox contains strictly canonicalized authoritative evidence
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

            # 3. Eligibility Check
            eligible, reason = self.check_eligibility(canonical_hyp, report)
            if not eligible:
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id,
                        status=ValidationStatus.INVALID_HYPOTHESIS,
                        attempted=False,
                        confirmed=False,
                        error_message=f"Eligibility check failed: {reason}"
                    )
                )
                continue

            # 4. Request Payload Size Bounding
            payload_bytes = self._calculate_payload_bytes(canonical_hyp, report)
            if payload_bytes > self.config.max_payload_bytes:
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id,
                        status=ValidationStatus.INVALID_HYPOTHESIS,
                        attempted=False,
                        confirmed=False,
                        error_message=(
                            f"Validation rejected: request payload size of {payload_bytes} bytes "
                            f"exceeds the configured max_payload_bytes limit of {self.config.max_payload_bytes} bytes"
                        )
                    )
                )
                continue

            # 5. Invoke Sandbox Validator safely under timeout boundary
            try:
                start_time = time.perf_counter()
                raw_result = self._run_with_timeout(canonical_hyp, report)
                duration = time.perf_counter() - start_time

                # Validate result integrity strictly
                result = self._validate_result_integrity(raw_result, hyp.id)

                # Enforce total combined output limits (len(stdout) + len(stderr) <= max_output_bytes)
                stdout_bytes = result.stdout.encode("utf-8")
                stderr_bytes = result.stderr.encode("utf-8")
                if len(stdout_bytes) + len(stderr_bytes) > self.config.max_output_bytes:
                    half_limit = self.config.max_output_bytes // 2
                    result.stdout = self._truncate_utf8(result.stdout, half_limit)
                    remaining_limit = self.config.max_output_bytes - len(result.stdout.encode("utf-8"))
                    result.stderr = self._truncate_utf8(result.stderr, remaining_limit)

                if result.duration is None:
                    result.duration = duration

                results.append(result)
            except Exception as e:
                # Exceptions in sandbox are caught and wrapped safely (fails closed)
                results.append(
                    ValidationResult(
                        hypothesis_id=hyp.id,
                        status=ValidationStatus.SANDBOX_ERROR,
                        attempted=True,
                        confirmed=False,
                        error_message=f"Validator raised exception: {str(e)}"
                    )
                )

        return results
