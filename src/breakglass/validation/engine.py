"""Validation Engine and eligibility boundary orchestrator (Milestone 4A)."""

import concurrent.futures
from dataclasses import dataclass, field
import hashlib
import json
import math
import time
from typing import List, Tuple, Optional, Any, Dict
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.validation.models import ValidationResult, ValidationStatus
from breakglass.validation.validator import SandboxValidator
from breakglass.inspection.indicators import redact_secrets


@dataclass
class ValidationConfig:
    """Resource limits and configurations for sandbox validation runs."""
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1024 * 1024  # 1MB
    max_hypotheses_per_run: int = 20
    max_payload_bytes: int = 100 * 1024 * 1024  # 100MB

    def validate(self) -> None:
        """Validates configuration parameters strictly."""
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a finite positive number")
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
        if hasattr(self.validator, "timeout_seconds"):
            self.validator.timeout_seconds = self.config.timeout_seconds

    def validate_hypothesis_shape(self, hyp: Any, report: RepositoryReport) -> Tuple[bool, Optional[SecurityHypothesis], str]:
        """Validates structural shape, types, authentication, and eligibility of a hypothesis.

        Returns:
            Tuple of (is_valid, canonical_hypothesis, error_message)
        """
        try:
            # 1. Base class type checks
            if not isinstance(hyp, SecurityHypothesis):
                return False, None, "Invalid hypothesis shape: Not a SecurityHypothesis instance"

            # 2. Hypothesis ID checks
            if not hasattr(hyp, "id") or not isinstance(hyp.id, str) or not hyp.id.strip():
                return False, None, "Invalid hypothesis shape: Empty or non-string ID"

            # 3. Core field checks
            if not hasattr(hyp, "title") or not isinstance(hyp.title, str):
                return False, None, "Invalid hypothesis shape: title must be a string"
            if not hasattr(hyp, "description") or not isinstance(hyp.description, str):
                return False, None, "Invalid hypothesis shape: description must be a string"
            if not hasattr(hyp, "category") or not isinstance(hyp.category, str):
                return False, None, "Invalid hypothesis shape: category must be a string"

            # 4. Evidence references collection checks
            if not hasattr(hyp, "evidence_references") or not isinstance(hyp.evidence_references, list) or not hyp.evidence_references:
                return False, None, "Validation job preflight failed: Hypothesis has no evidence references"

            # 5. Individual evidence reference type/value checks
            canonical_references = []
            for ref in hyp.evidence_references:
                if not isinstance(ref, EvidenceReference):
                    return False, None, "Invalid hypothesis shape: evidence reference is not an EvidenceReference instance"

                # Resolve and validate on the host
                valid, auth_detail = self._resolve_and_validate_evidence(ref, report)
                if not valid:
                    return False, None, "Eligibility check failed: Evidence reference failed to resolve or is fabricated"

                canonical_references.append(
                    EvidenceReference(
                        type=ref.type,
                        file=ref.file,
                        line=ref.line,
                        detail=auth_detail
                    )
                )

            # Sort deterministically
            canonical_references.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

            canonical_hyp = SecurityHypothesis(
                id=hyp.id,
                title=hyp.title,
                description=hyp.description,
                category=hyp.category,
                severity=getattr(hyp, "severity", "CRITICAL") or "CRITICAL",
                confidence=float(getattr(hyp, "confidence", 0.8) or 0.8),
                evidence_references=canonical_references,
                rationale=getattr(hyp, "rationale", "") or ""
            )

            # 6. Re-authenticate ID
            if not self._authenticate_hypothesis_id(canonical_hyp, report):
                return False, None, "Hypothesis authentication failed: ID does not match identity"

            # 7. Eligibility check
            eligible, reason = self.check_eligibility(canonical_hyp, report)
            if not eligible:
                return False, None, f"Eligibility check failed: {reason}"

            # 8. Request Payload Size Bounding
            payload_bytes = self._calculate_payload_bytes(canonical_hyp, report)
            if payload_bytes > self.config.max_payload_bytes:
                return False, None, (
                    f"Validation rejected: request payload size of {payload_bytes} bytes "
                    f"exceeds the configured max_payload_bytes limit of {self.config.max_payload_bytes} bytes"
                )

            return True, canonical_hyp, ""
        except Exception as e:
            return False, None, f"Validation preflight encountered unexpected error: {str(e)}"

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
        from breakglass.evidence.auth import authenticate_evidence_reference
        repo_root = getattr(getattr(report, "repository", None), "root", "") or ""
        return authenticate_evidence_reference(ref, report, repo_root)

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
                    detail=auth_detail,
                    fingerprint=hashlib.sha256(auth_detail.encode("utf-8")).hexdigest()
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
            return expected_id == hypothesis.id
        else:
            # Reconstruct deterministic identity from the correlated indicators and routes
            # Verify complete evidence set matches canonical references exactly.
            ind_ref = next((r for r in canonical_references if r.type == "security_indicator"), None)
            ind = None
            if ind_ref:
                # Find all indicators matching file, line, and the detail pattern using canonical detail matcher (Finding 2)
                matching_inds = []
                for i in getattr(report, "security_indicators", []) or []:
                    if i is None:
                        continue
                    i_file = getattr(i, "file", None)
                    i_line = getattr(i, "line", None)
                    if i_file and i_file.replace("\\", "/") == ind_ref.file.replace("\\", "/"):
                        if i_line == ind_ref.line or (i_line is None and ind_ref.line is None):
                            from breakglass.evidence.auth import _match_indicator_detail
                            if _match_indicator_detail(i, ind_ref.detail):
                                matching_inds.append(i)

                if len(matching_inds) == 1:
                    ind = matching_inds[0]
                elif len(matching_inds) > 1:
                    # Ambiguous match -> fail closed
                    return False

            if hypothesis.category == "command_injection":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                has_auth = any("access control" in getattr(r, "detail", "").lower() or "session" in getattr(r, "detail", "").lower() or "authentication" in getattr(r, "detail", "").lower() for r in canonical_references)
                
                identity_chain = {
                    "rule": "attack_chain",
                    "file": file_val,
                    "category": hypothesis.category,
                    "lines": lines,
                    "has_auth": has_auth
                }
                id_chain = generate_hypothesis_id(hypothesis.category, identity_chain, is_llm=False)
                
                route_ref = next((r for r in canonical_references if r.type == "route"), None)
                route = None
                if route_ref:
                    route = next((r for r in report.routes if r.file == route_ref.file and r.line == route_ref.line), None)
                    
                if ind and route:
                    identity_std = {
                        "rule": "command_injection",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": redact_secrets(ind.evidence)
                        },
                        "route": {
                            "file": route.file,
                            "line": route.line,
                            "method": route.method,
                            "pattern": route.pattern,
                            "evidence": route.evidence
                        }
                    }
                    id_std = generate_hypothesis_id(hypothesis.category, identity_std, is_llm=False)
                    if hypothesis.id == id_std:
                        identity = identity_std
                    elif hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
                else:
                    if hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
            elif hypothesis.category == "sql_injection":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                has_auth = any("access control" in getattr(r, "detail", "").lower() or "session" in getattr(r, "detail", "").lower() or "authentication" in getattr(r, "detail", "").lower() for r in canonical_references)
                
                identity_chain = {
                    "rule": "attack_chain",
                    "file": file_val,
                    "category": hypothesis.category,
                    "lines": lines,
                    "has_auth": has_auth
                }
                id_chain = generate_hypothesis_id(hypothesis.category, identity_chain, is_llm=False)
                
                route_ref = next((r for r in canonical_references if r.type == "route"), None)
                route = None
                if route_ref:
                    route = next((r for r in report.routes if r.file == route_ref.file and r.line == route_ref.line), None)
                    
                if ind and route:
                    identity_std = {
                        "rule": "sql_injection",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": redact_secrets(ind.evidence)
                        },
                        "route": {
                            "file": route.file,
                            "line": route.line,
                            "method": route.method,
                            "pattern": route.pattern,
                            "evidence": route.evidence
                        }
                    }
                    id_std = generate_hypothesis_id(hypothesis.category, identity_std, is_llm=False)
                    if hypothesis.id == id_std:
                        identity = identity_std
                    elif hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
                else:
                    if hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
            elif hypothesis.category == "remote_code_execution":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                has_auth = any("access control" in getattr(r, "detail", "").lower() or "session" in getattr(r, "detail", "").lower() or "authentication" in getattr(r, "detail", "").lower() for r in canonical_references)
                
                identity_chain = {
                    "rule": "attack_chain",
                    "file": file_val,
                    "category": hypothesis.category,
                    "lines": lines,
                    "has_auth": has_auth
                }
                id_chain = generate_hypothesis_id(hypothesis.category, identity_chain, is_llm=False)
                
                ep_ref = next((r for r in canonical_references if r.type == "entry_point"), None)
                ep = None
                if ep_ref:
                    ep = next((e for e in report.entry_points if e.file == ep_ref.file and e.line == ep_ref.line), None)
                    
                if ind and ep:
                    identity_std = {
                        "rule": "remote_code_execution",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": redact_secrets(ind.evidence)
                        },
                        "entry_point": {
                            "file": ep.file,
                            "type": ep.type,
                            "description": ep.description,
                            "line": ep.line
                        }
                    }
                    id_std = generate_hypothesis_id(hypothesis.category, identity_std, is_llm=False)
                    if hypothesis.id == id_std:
                        identity = identity_std
                    elif hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
                else:
                    if hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
            elif hypothesis.category == "credential_exposure":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                
                identity_consolidated = {
                    "rule": "consolidated_secret",
                    "file": file_val,
                    "lines": lines
                }
                id_cons = generate_hypothesis_id(hypothesis.category, identity_consolidated, is_llm=False)
                
                if ind:
                    sorted_frameworks = sorted(list(set(report.repository.frameworks)))
                    identity_correlation = {
                        "rule": "credential_exposure",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": redact_secrets(ind.evidence)
                        },
                        "frameworks": sorted_frameworks
                    }
                    identity_standalone = {
                        "rule": "ind_secret",
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": redact_secrets(ind.evidence)
                    }
                    id_corr = generate_hypothesis_id(hypothesis.category, identity_correlation, is_llm=False)
                    id_stan = generate_hypothesis_id(hypothesis.category, identity_standalone, is_llm=False)
                    if hypothesis.id == id_corr:
                        identity = identity_correlation
                    elif hypothesis.id == id_stan:
                        identity = identity_standalone
                    elif hypothesis.id == id_cons:
                        identity = identity_consolidated
                    else:
                        return False
                else:
                    if hypothesis.id == id_cons:
                        identity = identity_consolidated
                    else:
                        return False
            elif hypothesis.category == "insecure_auth":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                
                identity_consolidated = {
                    "rule": "consolidated_auth",
                    "file": file_val,
                    "lines": lines
                }
                id_cons = generate_hypothesis_id(hypothesis.category, identity_consolidated, is_llm=False)
                
                if ind:
                    identity_standalone = {
                        "rule": "ind_auth",
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": redact_secrets(ind.evidence)
                    }
                    id_stan = generate_hypothesis_id(hypothesis.category, identity_standalone, is_llm=False)
                    if hypothesis.id == id_stan:
                        identity = identity_standalone
                    elif hypothesis.id == id_cons:
                        identity = identity_consolidated
                    else:
                        return False
                else:
                    if hypothesis.id == id_cons:
                        identity = identity_consolidated
                    else:
                        return False
            elif hypothesis.category == "path_traversal":
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                has_auth = any("access control" in getattr(r, "detail", "").lower() or "session" in getattr(r, "detail", "").lower() or "authentication" in getattr(r, "detail", "").lower() for r in canonical_references)
                
                identity_chain = {
                    "rule": "attack_chain",
                    "file": file_val,
                    "category": hypothesis.category,
                    "lines": lines,
                    "has_auth": has_auth
                }
                id_chain = generate_hypothesis_id(hypothesis.category, identity_chain, is_llm=False)
                
                identity_consolidated = {
                    "rule": "consolidated_file",
                    "file": file_val,
                    "lines": lines
                }
                id_cons = generate_hypothesis_id(hypothesis.category, identity_consolidated, is_llm=False)
                
                if ind:
                    identity_standalone = {
                        "rule": "ind_file",
                        "file": ind.file,
                        "line": ind.line,
                        "evidence": redact_secrets(ind.evidence)
                    }
                    id_stan = generate_hypothesis_id(hypothesis.category, identity_standalone, is_llm=False)
                    if hypothesis.id == id_stan:
                        identity = identity_standalone
                    elif hypothesis.id == id_cons:
                        identity = identity_consolidated
                    elif hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
                else:
                    if hypothesis.id == id_cons:
                        identity = identity_consolidated
                    elif hypothesis.id == id_chain:
                        identity = identity_chain
                    else:
                        return False
            elif hypothesis.category in ("xss", "ssti", "ssrf", "xxe", "deserialization", "open_redirect", "idor", "mass_assignment", "broken_auth", "nosql_injection"):
                lines = sorted(list({r.line for r in canonical_references if r.line is not None}))
                file_val = canonical_references[0].file if canonical_references else ""
                has_auth = any("access control" in getattr(r, "detail", "").lower() or "session" in getattr(r, "detail", "").lower() or "authentication" in getattr(r, "detail", "").lower() for r in canonical_references)
                
                identity = {
                    "rule": "attack_chain",
                    "file": file_val,
                    "category": hypothesis.category,
                    "lines": lines,
                    "has_auth": has_auth
                }
            elif hypothesis.category == "insecure_dependency":
                file_ref = next((r for r in canonical_references if r.type == "file"), None)
                if not file_ref:
                    return False
                m = next((x for x in report.manifests if x.file == file_ref.file), None)
                if not m:
                    return False
                target_deps = [d for d in m.dependencies if d.lower() in ("express", "fastapi", "flask", "django", "requests", "boto3", "actix-web")]
                identity = {
                    "rule": "manifest_deps",
                    "file": m.file,
                    "deps": sorted(target_deps)
                }
            elif hypothesis.category == "exposed_debug":
                route_ref = next((r for r in canonical_references if r.type == "route"), None)
                route = None
                if route_ref:
                    route = next((r for r in report.routes if r.file == route_ref.file and r.line == route_ref.line), None)
                if not route:
                    return False
                identity = {
                    "rule": "route_debug",
                    "file": route.file,
                    "line": route.line,
                    "pattern": route.pattern
                }
            elif hypothesis.category == "insecure_config":
                file_ref = next((r for r in canonical_references if r.type == "file"), None)
                if not file_ref:
                    return False
                identity = {
                    "rule": "summary_config",
                    "file": file_ref.file
                }
            elif hypothesis.category == "dangerous_cicd":
                file_ref = next((r for r in canonical_references if r.type == "file"), None)
                if not file_ref:
                    return False
                identity = {
                    "rule": "summary_cicd",
                    "file": file_ref.file
                }
            elif hypothesis.category == "infrastructure_misconfig":
                file_ref = next((r for r in canonical_references if r.type == "file"), None)
                if not file_ref:
                    return False
                identity = {
                    "rule": "summary_docker",
                    "file": file_ref.file
                }
            elif hypothesis.category == "network_exposure":
                ep_ref = next((r for r in canonical_references if r.type == "entry_point"), None)
                ep = None
                if ep_ref:
                    ep = next((e for e in report.entry_points if e.file == ep_ref.file and e.line == ep_ref.line), None)
                if not ep:
                    return False
                identity = {
                    "rule": "summary_ep",
                    "file": ep.file,
                    "type": ep.type,
                    "line": ep.line
                }
            else:
                return False

            expected_id = generate_hypothesis_id(hypothesis.category, identity, is_llm=False)
            if expected_id != hypothesis.id:
                return False

            # Strict Re-Authentication of full deterministic fields to prevent parameters tampering
            from breakglass.reasoning.engine import DeterministicReasoningEngine
            det_report = DeterministicReasoningEngine().generate_hypotheses(report)
            auth_hyp = next((h for h in det_report.hypotheses if h.id == hypothesis.id), None)
            if not auth_hyp:
                return False

            # Enforce exact match on supplied references against authoritative list
            supplied_refs_canonical = []
            for ref in hypothesis.evidence_references:
                if not isinstance(ref, EvidenceReference):
                    return False
                valid, auth_detail = self._resolve_and_validate_evidence(ref, report)
                if not valid:
                    return False
                supplied_refs_canonical.append({
                    "type": ref.type,
                    "file": ref.file,
                    "line": ref.line,
                    "detail": auth_detail
                })

            expected_refs_canonical = [
                {
                    "type": r.type,
                    "file": r.file,
                    "line": r.line,
                    "detail": r.detail
                }
                for r in auth_hyp.evidence_references
            ]

            supplied_refs_canonical.sort(key=lambda x: (x["file"], x["line"] or 0, x["type"], x["detail"]))
            expected_refs_canonical.sort(key=lambda x: (x["file"], x["line"] or 0, x["type"], x["detail"]))

            if supplied_refs_canonical != expected_refs_canonical:
                return False

            # Overwrite all fields with authoritative ones
            hypothesis.title = auth_hyp.title
            hypothesis.description = auth_hyp.description
            hypothesis.category = auth_hyp.category
            hypothesis.severity = auth_hyp.severity
            hypothesis.confidence = auth_hyp.confidence
            hypothesis.evidence_references = auth_hyp.evidence_references
            hypothesis.rationale = auth_hyp.rationale
            return True

    def check_eligibility(self, hypothesis: SecurityHypothesis, report: RepositoryReport) -> Tuple[bool, str]:
        """Checks if a hypothesis is eligible for sandbox execution."""
        # 1. Strict Type Validation of SecurityHypothesis input shape
        if not hypothesis or not isinstance(hypothesis, SecurityHypothesis):
            return False, "Invalid hypothesis object type"
        if not isinstance(hypothesis.id, str) or not hypothesis.id.strip():
            return False, "Invalid or missing hypothesis ID"
        if not isinstance(hypothesis.title, str) or not hypothesis.title.strip():
            return False, "Invalid or missing title"
        if not isinstance(hypothesis.description, str) or not hypothesis.description.strip():
            return False, "Invalid or missing description"

        supported_categories = {
            "command_injection",
            "sql_injection",
            "nosql_injection",
            "remote_code_execution",
            "credential_exposure",
            "untrusted_input_execution",
            "insecure_deserialization",
            "path_traversal",
            "broken_access_control",
            "insecure_authentication",
            "insecure_auth",
            "insecure_dependency",
            "exposed_debug",
            "insecure_config",
            "dangerous_cicd",
            "infrastructure_misconfig",
            "network_exposure",
            "xss",
            "ssti",
            "ssrf",
            "xxe",
            "deserialization",
            "open_redirect",
            "idor",
            "mass_assignment",
            "broken_auth"
        }
        if not isinstance(hypothesis.category, str) or hypothesis.category not in supported_categories:
            return False, f"Unsupported or invalid category: {hypothesis.category}"
        if not isinstance(hypothesis.severity, str) or hypothesis.severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return False, f"Invalid severity: {hypothesis.severity}"

        if not isinstance(hypothesis.confidence, (int, float)) or isinstance(hypothesis.confidence, bool):
            return False, f"Invalid confidence type: {type(hypothesis.confidence).__name__}"
        if not math.isfinite(hypothesis.confidence) or not (0.0 <= hypothesis.confidence <= 1.0):
            return False, f"Confidence value out of bounds: {hypothesis.confidence}"

        if not isinstance(hypothesis.rationale, str):
            return False, "Invalid rationale type"

        if not isinstance(hypothesis.evidence_references, list) or not hypothesis.evidence_references:
            return False, "Missing or invalid evidence references list"

        for idx, ref in enumerate(hypothesis.evidence_references):
            if not isinstance(ref, EvidenceReference):
                return False, f"Evidence reference at index {idx} is not of type EvidenceReference"
            if not isinstance(ref.type, str) or ref.type not in {"security_indicator", "route", "entry_point", "file"}:
                return False, f"Invalid reference type at index {idx}"
            if not isinstance(ref.file, str) or not ref.file.strip():
                return False, f"Invalid reference file at index {idx}"
            if ref.line is not None:
                if not isinstance(ref.line, int) or isinstance(ref.line, bool):
                    return False, f"Invalid reference line at index {idx}"
            if not isinstance(ref.detail, str):
                return False, f"Invalid reference detail at index {idx}"

        # 2. Authenticate ID and verify all references resolve to authoritative details
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
            ValidationStatus.PREFLIGHT_ERROR: (False, False),
        }

        expected_attempted, expected_confirmed = invariants[result.status]
        # Check strict bool types (reject integers 0/1)
        if type(result.attempted) is not bool or type(result.confirmed) is not bool:
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="attempted and confirmed fields must be exactly booleans"
            )

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

        # Validate parameter types strictly
        if result.duration is not None:
            if not isinstance(result.duration, (int, float)) or isinstance(result.duration, bool):
                return ValidationResult(
                    hypothesis_id=expected_id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Invalid duration type: {type(result.duration).__name__}"
                )
            if not math.isfinite(result.duration) or result.duration < 0:
                return ValidationResult(
                    hypothesis_id=expected_id,
                    status=ValidationStatus.SANDBOX_ERROR,
                    attempted=True,
                    confirmed=False,
                    error_message=f"Invalid duration value: {result.duration}"
                )

        if not isinstance(result.confidence_delta, (int, float)) or isinstance(result.confidence_delta, bool):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="Invalid confidence_delta type: must be a float or int (and not bool)"
            )
        if not math.isfinite(result.confidence_delta) or not (-1.0 <= result.confidence_delta <= 1.0):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message=f"Invalid confidence_delta range: {result.confidence_delta}"
            )

        if not isinstance(result.stdout, str) or not isinstance(result.stderr, str) or not isinstance(result.evidence, str):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="stdout, stderr, and evidence must be strings"
            )

        if result.error_message is not None and not isinstance(result.error_message, str):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="error_message must be a string or None"
            )

        # Validate metadata serialization and format
        if not isinstance(result.metadata, dict):
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="metadata must be a dictionary"
            )
        try:
            json.dumps(result.metadata)
        except Exception:
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="metadata is not JSON-serializable"
            )

        # Enforce metadata/evidence size limits
        # Combined evidence + metadata serialized size <= 100KB
        meta_size = len(json.dumps(result.metadata).encode("utf-8"))
        ev_size = len(result.evidence.encode("utf-8"))
        if meta_size + ev_size > 100 * 1024:
            return ValidationResult(
                hypothesis_id=expected_id,
                status=ValidationStatus.SANDBOX_ERROR,
                attempted=True,
                confirmed=False,
                error_message="evidence + metadata size exceeds 100KB limit"
            )

        # Return a sanitized copy of ValidationResult
        return ValidationResult(
            hypothesis_id=expected_id,
            status=result.status,
            attempted=result.attempted,
            confirmed=result.confirmed,
            confidence_delta=float(result.confidence_delta),
            evidence=result.evidence,
            stdout=result.stdout,
            stderr=result.stderr,
            duration=result.duration,
            error_message=result.error_message,
            metadata=dict(result.metadata)
        )

    def _run_with_timeout(self, hyp: SecurityHypothesis, report: RepositoryReport) -> ValidationResult:
        """Invokes SandboxValidator inside a thread pool with a timeout boundary, shutting down non-blockingly."""
        import threading
        import inspect
        cancellation_event = threading.Event()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

        # Check if the validator's validate method accepts at least 3 parameters or var-positional
        sig = inspect.signature(self.validator.validate)
        params = list(sig.parameters.values())
        has_cancellation = len(params) >= 3 or any(
            p.kind == inspect.Parameter.VAR_KEYWORD or p.kind == inspect.Parameter.VAR_POSITIONAL
            for p in params
        )

        if has_cancellation:
            future = executor.submit(self.validator.validate, hyp, report, cancellation_event)
        else:
            future = executor.submit(self.validator.validate, hyp, report)

        try:
            result = future.result(timeout=self.config.timeout_seconds)
            executor.shutdown(wait=True)
            return result
        except concurrent.futures.TimeoutError:
            cancellation_event.set()
            executor.shutdown(wait=False)
            return ValidationResult(
                hypothesis_id=hyp.id or "",
                status=ValidationStatus.TIMEOUT,
                attempted=True,
                confirmed=False,
                error_message=f"Validation timed out after {self.config.timeout_seconds} seconds"
            )
        except Exception as e:
            cancellation_event.set()
            executor.shutdown(wait=False)
            raise e

    def validate_hypotheses(
        self,
        hypotheses: List[SecurityHypothesis],
        report: RepositoryReport
    ) -> List[ValidationResult]:
        """Orchestrates sandbox validation for a collection of hypotheses."""
        if hasattr(self.validator, "timeout_seconds"):
            self.validator.timeout_seconds = self.config.timeout_seconds
        results = []
        valid_hypotheses = []

        # 1. Filter out malformed/invalid hypotheses shape before sorting
        for hyp in hypotheses:
            is_valid, canonical_hyp, err_msg = self.validate_hypothesis_shape(hyp, report)
            if not is_valid:
                results.append(
                    ValidationResult(
                        hypothesis_id=getattr(hyp, "id", "") if (hasattr(hyp, "id") and isinstance(hyp.id, str)) else "",
                        status=ValidationStatus.INVALID_HYPOTHESIS,
                        attempted=False,
                        confirmed=False,
                        error_message=err_msg
                    )
                )
            else:
                valid_hypotheses.append(canonical_hyp)

        # 2. Sort deterministically by hypothesis ID
        sorted_hypotheses = sorted(valid_hypotheses, key=lambda x: x.id)

        # Bind validation batch size
        limited_hypotheses = sorted_hypotheses[:self.config.max_hypotheses_per_run]

        for hyp in limited_hypotheses:
            # 5. Invoke Sandbox Validator safely under timeout boundary
            try:
                start_time = time.perf_counter()
                raw_result = self._run_with_timeout(hyp, report)
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
