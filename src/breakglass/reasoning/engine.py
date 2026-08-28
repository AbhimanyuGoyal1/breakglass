"""Agent reasoning engines and security hypothesis generation logic."""

from abc import ABC, abstractmethod
import hashlib
from typing import Optional
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import ReasoningReport, SecurityHypothesis, EvidenceReference


class ReasoningEngine(ABC):
    """Abstract base class representing the agent reasoning layer."""

    @abstractmethod
    def generate_hypotheses(self, report: RepositoryReport) -> ReasoningReport:
        """Analyzes a RepositoryReport and generates security hypotheses.

        Args:
            report: The structured RepositoryReport from the inspection layer.

        Returns:
            A ReasoningReport containing a collection of security hypotheses.
        """
        pass


class DeterministicReasoningEngine(ReasoningEngine):
    """Deterministic security hypothesis engine correlating inspection evidence."""

    def _generate_stable_id(self, category: str, primary_file: str, primary_line: Optional[int], unique_salt: str) -> str:
        """Generates a stable, collision-resistant hypothesis ID using SHA-256."""
        identity = f"cat={category};file={primary_file};line={primary_line};salt={unique_salt}"
        hash_hex = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        prefix = f"HYP-{category.upper().replace('_', '-')}"
        return f"{prefix}-{hash_hex[:16]}"

    def generate_hypotheses(self, report: RepositoryReport) -> ReasoningReport:
        """Correlates static indicators, routes, and frameworks to generate hypotheses."""
        hypotheses_dict = {}

        # 1. Rule 1: Subprocess execution + Reachable route (SAME FILE ONLY)
        subprocess_indicators = [
            ind for ind in report.security_indicators if ind.category == "subprocess"
        ]
        if subprocess_indicators and report.routes:
            for ind in subprocess_indicators:
                for route in report.routes:
                    if ind.file == route.file:
                        salt = f"route_file={route.file};route_line={route.line};route_method={route.method};route_pattern={route.pattern};evidence={ind.evidence}"
                        hyp_id = self._generate_stable_id("command_injection", ind.file, ind.line, salt)
                        title = "Potential Local Command Injection via Endpoint"
                        severity = "HIGH"
                        confidence = 0.85
                        desc = (
                            f"A subprocess execution indicator in '{ind.file}' on line {ind.line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in the same file."
                        )
                        rationale = (
                            f"The HTTP route '{route.method} {route.pattern}' resides in the same file as a subprocess execution "
                            f"call. If request parameters are passed directly to the command execution without strict "
                            f"validation, it could lead to command injection."
                        )

                        ev_ref1 = EvidenceReference(
                            type="security_indicator",
                            file=ind.file,
                            line=ind.line,
                            detail=f"Subprocess call: {ind.evidence}"
                        )
                        ev_ref2 = EvidenceReference(
                            type="route",
                            file=route.file,
                            line=route.line,
                            detail=f"Route: {route.method} {route.pattern}"
                        )
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        hypotheses_dict[hyp_id] = SecurityHypothesis(
                            id=hyp_id,
                            title=title,
                            description=desc,
                            category="command_injection",
                            severity=severity,
                            confidence=confidence,
                            evidence_references=refs,
                            rationale=rationale
                        )

        # 2. Rule 2: SQL construction + Reachable route (SAME FILE ONLY, RAW SQL CONSTRUCTION ONLY)
        db_indicators = [
            ind for ind in report.security_indicators
            if ind.category == "database" and ind.indicator_type == "raw_sql_construction_indicator"
        ]
        if db_indicators and report.routes:
            for ind in db_indicators:
                for route in report.routes:
                    if ind.file == route.file:
                        salt = f"route_file={route.file};route_line={route.line};route_method={route.method};route_pattern={route.pattern};evidence={ind.evidence}"
                        hyp_id = self._generate_stable_id("sql_injection", ind.file, ind.line, salt)
                        title = "Potential Local SQL Injection"
                        severity = "HIGH"
                        confidence = 0.80
                        desc = (
                            f"A raw SQL construction indicator in '{ind.file}' on line {ind.line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in the same file."
                        )
                        rationale = (
                            f"The endpoint '{route.method} {route.pattern}' is defined in '{ind.file}', which also contains "
                            f"raw SQL query structures or query builders. Unsanitized route parameters could lead directly to "
                            f"SQL injection."
                        )

                        ev_ref1 = EvidenceReference(
                            type="security_indicator",
                            file=ind.file,
                            line=ind.line,
                            detail=f"Database indicator: {ind.evidence}"
                        )
                        ev_ref2 = EvidenceReference(
                            type="route",
                            file=route.file,
                            line=route.line,
                            detail=f"Route: {route.method} {route.pattern}"
                        )
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        hypotheses_dict[hyp_id] = SecurityHypothesis(
                            id=hyp_id,
                            title=title,
                            description=desc,
                            category="sql_injection",
                            severity=severity,
                            confidence=confidence,
                            evidence_references=refs,
                            rationale=rationale
                        )

        # 3. Rule 3: Deserialization / Unsafe Eval + Entry Point (SAME FILE ONLY)
        serialization_indicators = [
            ind for ind in report.security_indicators if ind.category == "serialization"
        ]
        if serialization_indicators and report.entry_points:
            for ind in serialization_indicators:
                for ep in report.entry_points:
                    if ind.file == ep.file:
                        salt = f"ep_file={ep.file};ep_line={ep.line};ep_type={ep.type};ep_desc={ep.description};evidence={ind.evidence}"
                        hyp_id = self._generate_stable_id("remote_code_execution", ind.file, ind.line, salt)
                        title = "Potential Local Code Execution via Entry Point"
                        severity = "CRITICAL"
                        confidence = 0.90
                        desc = (
                            f"An unsafe serialization/eval indicator in '{ind.file}' on line {ind.line} "
                            f"correlates with application entry point '{ep.type}' in the same file."
                        )
                        rationale = (
                            f"An application entry point is located in the same file as unsafe serialization or evaluation "
                            f"constructs (like eval/exec). Startup options or payloads routed through this entry point could "
                            f"trigger Remote Code Execution."
                        )

                        ev_ref1 = EvidenceReference(
                            type="security_indicator",
                            file=ind.file,
                            line=ind.line,
                            detail=f"Serialization call: {ind.evidence}"
                        )
                        ev_ref2 = EvidenceReference(
                            type="entry_point",
                            file=ep.file,
                            line=ep.line,
                            detail=f"Entry point: {ep.type} ({ep.description})"
                        )
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        hypotheses_dict[hyp_id] = SecurityHypothesis(
                            id=hyp_id,
                            title=title,
                            description=desc,
                            category="remote_code_execution",
                            severity=severity,
                            confidence=confidence,
                            evidence_references=refs,
                            rationale=rationale
                        )

        # 4. Rule 4: Cloud Secrets / Cloud SDK + Web Framework (BOUNDED project correlation)
        cloud_indicators = [
            ind for ind in report.security_indicators if ind.category in ("cloud_sdk", "secret_config")
        ]
        if cloud_indicators and report.repository.frameworks:
            sorted_frameworks = sorted(report.repository.frameworks)
            framework_list_str = ", ".join(sorted_frameworks)
            for ind in cloud_indicators:
                salt = f"frameworks={','.join(sorted_frameworks)};evidence={ind.evidence}"
                hyp_id = self._generate_stable_id("credential_exposure", ind.file, ind.line, salt)
                title = "Potential Cloud Credential / Config Exposure"
                desc = (
                    f"A cloud SDK or secret configuration reference in '{ind.file}' on line {ind.line} "
                    f"was found in a project using framework(s): {framework_list_str}."
                )
                rationale = (
                    f"The application utilizes the web framework(s) {framework_list_str} and references cloud SDKs or secret "
                    f"configurations in '{ind.file}'. If secrets/credentials are hardcoded, they are vulnerable to exposure."
                )

                ev_ref = EvidenceReference(
                    type="security_indicator",
                    file=ind.file,
                    line=ind.line,
                    detail=f"Cloud/Secrets indicator: {ind.evidence}"
                )
                refs = [ev_ref]

                hypotheses_dict[hyp_id] = SecurityHypothesis(
                    id=hyp_id,
                    title=title,
                    description=desc,
                    category="credential_exposure",
                    severity="MEDIUM",
                    confidence=0.75,
                    evidence_references=refs,
                    rationale=rationale
                )

        # Deterministic sorting of security hypotheses
        sorted_hypotheses = [hypotheses_dict[k] for k in sorted(hypotheses_dict.keys())]

        return ReasoningReport(hypotheses=sorted_hypotheses)
