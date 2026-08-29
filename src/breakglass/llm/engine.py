"""LLM reasoning engine implementation with structured validation and integrity checks."""

import json
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import ReasoningReport, SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.llm.client import LLMClient
from breakglass.llm.prompts import build_system_prompt, build_user_prompt


class LLMReasoningEngine:
    """Consumes reports, generates queries for the LLM client, and validates raw outputs."""

    def __init__(self, client: LLMClient):
        self.client = client

    def _clean_json_text(self, text: str) -> str:
        """Strips markdown block wrappers and extracts raw JSON content."""
        if not isinstance(text, str):
            return ""
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return text

    def _collect_all_valid_files(self, report: RepositoryReport) -> set:
        """Gathers all actual repository file paths from the inspection report."""
        valid_files = set()
        repo = report.repository
        for list_attr in (repo.config_files, repo.docker_configs, repo.cicd_configs,
                          repo.infrastructure_configs, repo.test_files):
            valid_files.update(list_attr)
        for r in report.routes:
            valid_files.add(r.file)
        for ep in report.entry_points:
            valid_files.add(ep.file)
        for ind in report.security_indicators:
            valid_files.add(ind.file)
        return valid_files

    def _resolve_and_validate_evidence(
        self,
        ref_type: str,
        ref_file: str,
        ref_line: Optional[int],
        report: RepositoryReport,
        valid_files: set
    ) -> Tuple[bool, str]:
        """Resolves evidence references against the authoritative inspection report."""
        if ref_type == "security_indicator":
            for ind in report.security_indicators:
                if ind.file == ref_file and (ind.line == ref_line or (ind.line is None and ref_line is None)):
                    return True, f"Security indicator: {ind.evidence}"
            return False, ""
        elif ref_type == "route":
            for r in report.routes:
                if r.file == ref_file and r.line == ref_line:
                    return True, f"Route: {r.method} {r.pattern}"
            return False, ""
        elif ref_type == "entry_point":
            for ep in report.entry_points:
                if ep.file == ref_file and ep.line == ref_line:
                    return True, f"Entry point: {ep.type} ({ep.description})"
            return False, ""
        elif ref_type == "file":
            # Plain file evidence must not contain line numbers
            if ref_line is not None:
                return False, ""
            if ref_file in valid_files:
                return True, f"File: {ref_file}"
            return False, ""
        return False, ""

    def _generate_stable_id(self, category: str, title: str, description: str, references: List[EvidenceReference]) -> str:
        """Generates a stable, collision-resistant hypothesis ID using SHA-256."""
        ref_list = []
        for r in references:
            ref_list.append({
                "type": r.type,
                "file": r.file,
                "line": r.line,
                "detail": r.detail
            })
        identity = {
            "category": category,
            "title": title,
            "description": description,
            "references": ref_list
        }
        return generate_hypothesis_id(category, identity, is_llm=True)

    def analyze(
        self,
        inspection_report: RepositoryReport,
        deterministic_report: ReasoningReport
    ) -> ReasoningReport:
        """Executes LLM security analysis, validates schemas/evidence, and returns verified hypotheses."""
        system_prompt = build_system_prompt()
        user_prompt = build_user_prompt(inspection_report, deterministic_report)

        try:
            raw_response = self.client.generate(system_prompt, user_prompt)
        except Exception as e:
            return ReasoningReport(
                hypotheses=deterministic_report.hypotheses,
                validation_status="failed",
                errors=[f"LLM Client generation failed: {str(e)}"]
            )

        if not isinstance(raw_response, str):
            return ReasoningReport(
                hypotheses=deterministic_report.hypotheses,
                validation_status="failed",
                errors=[f"LLM Client returned invalid response type: {type(raw_response).__name__}"]
            )

        cleaned_text = self._clean_json_text(raw_response)

        try:
            data = json.loads(cleaned_text)
        except Exception as e:
            return ReasoningReport(
                hypotheses=deterministic_report.hypotheses,
                validation_status="failed",
                errors=[f"Failed to parse LLM response as JSON: {str(e)}"]
            )

        if not isinstance(data, dict) or "hypotheses" not in data:
            return ReasoningReport(
                hypotheses=deterministic_report.hypotheses,
                validation_status="failed",
                errors=["JSON root must contain a 'hypotheses' key"]
            )

        raw_hypotheses = data["hypotheses"]
        if not isinstance(raw_hypotheses, list):
            return ReasoningReport(
                hypotheses=deterministic_report.hypotheses,
                validation_status="failed",
                errors=["The 'hypotheses' key must point to a JSON list"]
            )

        valid_files = self._collect_all_valid_files(inspection_report)
        # Prepopulate with deterministic hypotheses to preserve them as baseline and avoid duplicates
        validated_hypotheses_dict = {h.id: h for h in deterministic_report.hypotheses}
        errors = []

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

        for idx, item in enumerate(raw_hypotheses, start=1):
            # Ensure hypothesis element is a dictionary/mapping
            if not isinstance(item, dict):
                errors.append(f"Hypothesis #{idx} is not a valid JSON object/dictionary")
                continue

            # 1. Schema check
            required_fields = ["id", "title", "description", "category", "severity", "confidence", "evidence_references", "rationale"]
            missing_fields = [f for f in required_fields if f not in item]
            if missing_fields:
                errors.append(f"Hypothesis #{idx} is missing required fields: {', '.join(missing_fields)}")
                continue

            # Validate field types strictly
            field_types = {
                "id": str,
                "title": str,
                "description": str,
                "category": str,
                "severity": str,
                "rationale": str,
            }
            type_errors = []
            for field_name, expected_type in field_types.items():
                val = item[field_name]
                if not isinstance(val, expected_type):
                    type_errors.append(f"'{field_name}' must be of type {expected_type.__name__} (got {type(val).__name__})")

            # Check confidence type explicitly (float or int, excluding bool)
            conf_val = item["confidence"]
            if not isinstance(conf_val, (int, float)) or isinstance(conf_val, bool):
                type_errors.append(f"'confidence' must be an integer or float (got {type(conf_val).__name__})")

            # Check evidence_references type
            refs_val = item["evidence_references"]
            if not isinstance(refs_val, list):
                type_errors.append(f"'evidence_references' must be a list (got {type(refs_val).__name__})")

            if type_errors:
                errors.append(f"Hypothesis #{idx} has invalid field types: {', '.join(type_errors)}")
                continue

            # 2. Field validation
            severity = item["severity"]
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                errors.append(f"Hypothesis #{idx} has invalid severity value: {severity}")
                continue

            confidence = float(item["confidence"])
            if not (0.0 <= confidence <= 1.0):
                errors.append(f"Hypothesis #{idx} confidence value is out of bounds: {confidence}")
                continue

            category = item["category"]
            if category not in supported_categories:
                errors.append(f"Hypothesis #{idx} has unsupported category: {category}")
                continue

            # 3. Evidence validation
            ref_errors = []
            parsed_references = []
            for r_idx, ref_item in enumerate(refs_val, start=1):
                # Ensure each reference is a dictionary
                if not isinstance(ref_item, dict):
                    ref_errors.append(f"Reference #{r_idx} in Hypothesis #{idx} is not a valid JSON object/dictionary")
                    continue

                ref_fields = ["type", "file", "detail"]
                missing_ref_fields = [f for f in ref_fields if f not in ref_item]
                if missing_ref_fields:
                    ref_errors.append(f"Reference #{r_idx} in Hypothesis #{idx} is missing fields: {', '.join(missing_ref_fields)}")
                    continue

                # Enforce strict field types on references
                ref_type = ref_item["type"]
                ref_file = ref_item["file"]
                ref_detail = ref_item["detail"]

                ref_type_errors = []
                if not isinstance(ref_type, str):
                    ref_type_errors.append(f"'type' must be str (got {type(ref_type).__name__})")
                if not isinstance(ref_file, str):
                    ref_type_errors.append(f"'file' must be str (got {type(ref_file).__name__})")
                if not isinstance(ref_detail, str):
                    ref_type_errors.append(f"'detail' must be str (got {type(ref_detail).__name__})")

                if ref_type_errors:
                    ref_errors.append(f"Reference #{r_idx} in Hypothesis #{idx} has invalid types: {', '.join(ref_type_errors)}")
                    continue

                if ref_type not in ("security_indicator", "route", "entry_point", "file"):
                    ref_errors.append(f"Reference #{r_idx} has invalid type: {ref_type}")
                    continue

                ref_line = ref_item.get("line")
                if ref_line is not None:
                    # Enforce strict schema-level integer check for line numbers (exclude floats and booleans)
                    if not isinstance(ref_line, int) or isinstance(ref_line, bool):
                        ref_errors.append(f"Reference #{r_idx} line number must be an integer or null (got {type(ref_line).__name__})")
                        continue

                # Resolve reference against authoritative inspection report
                is_valid, auth_detail = self._resolve_and_validate_evidence(
                    ref_type, ref_file, ref_line, inspection_report, valid_files
                )

                if not is_valid:
                    ref_errors.append(f"Reference #{r_idx} contains fabricated evidence: {ref_type} at {ref_file}:{ref_line}")
                    continue

                ev_ref = EvidenceReference(
                    type=ref_type,
                    file=ref_file,
                    line=ref_line,
                    detail=auth_detail  # Authoritative report detail overrides LLM
                )
                parsed_references.append(ev_ref)

            if ref_errors:
                errors.extend(ref_errors)
                continue

            # Sort references within hypothesis
            parsed_references.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

            # Generate stable collision-resistant hypothesis ID
            stable_id = self._generate_stable_id(
                category, str(item["title"]), str(item["description"]), parsed_references
            )

            # De-duplicate by ID (preserves deterministic if LLM generated it)
            stable_id_det = stable_id.replace("HYP-LLM-", "HYP-", 1)
            if stable_id in validated_hypotheses_dict or stable_id_det in validated_hypotheses_dict:
                continue

            validated_hypotheses_dict[stable_id] = SecurityHypothesis(
                id=stable_id,
                title=str(item["title"]),
                description=str(item["description"]),
                category=category,
                severity=severity,
                confidence=confidence,
                evidence_references=parsed_references,
                rationale=str(item["rationale"])
            )

        sorted_hypotheses = [validated_hypotheses_dict[k] for k in sorted(validated_hypotheses_dict.keys())]

        status = "success"
        if errors:
            status = "partial_success" if sorted_hypotheses else "failed"

        return ReasoningReport(
            hypotheses=sorted_hypotheses,
            validation_status=status,
            errors=errors
        )
