"""Agent reasoning engines and security hypothesis generation logic."""

from abc import ABC, abstractmethod
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

    def _get_file_slug(self, filepath: str) -> str:
        """Generates a clean, normalized string identifier from a file path."""
        return filepath.replace("/", "_").replace("\\", "_").replace(".", "_")

    def generate_hypotheses(self, report: RepositoryReport) -> ReasoningReport:
        """Correlates static indicators, routes, and frameworks to generate hypotheses."""
        hypotheses_dict = {}

        # 1. Rule 1: Subprocess execution + Reachable route
        subprocess_indicators = [
            ind for ind in report.security_indicators if ind.category == "subprocess"
        ]
        if subprocess_indicators and report.routes:
            for ind in subprocess_indicators:
                ind_slug = self._get_file_slug(ind.file)
                ind_line = ind.line or 0
                for route in report.routes:
                    route_slug = self._get_file_slug(route.file)
                    route_line = route.line

                    if ind.file == route.file:
                        hyp_id = f"HYP-SUBPROCESS-LOCAL-{ind_slug}-{ind_line}-{route_line}"
                        title = "Potential Local Command Injection via Endpoint"
                        severity = "HIGH"
                        confidence = 0.85
                        desc = (
                            f"A subprocess execution indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in the same file."
                        )
                        rationale = (
                            f"The HTTP route '{route.method} {route.pattern}' resides in the same file as a subprocess execution "
                            f"call. If request parameters are passed directly to the command execution without strict "
                            f"validation, it could lead to command injection."
                        )
                    else:
                        hyp_id = f"HYP-SUBPROCESS-CROSS-{ind_slug}-{ind_line}-{route_slug}-{route_line}"
                        title = "Potential Cross-File Command Injection"
                        severity = "MEDIUM"
                        confidence = 0.60
                        desc = (
                            f"A subprocess execution indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in '{route.file}'."
                        )
                        rationale = (
                            f"The application exposes a route '{route.method} {route.pattern}' while executing subprocess "
                            f"commands in another file ('{ind.file}'). Depending on how parameters flow across layers, "
                            f"this correlation poses a potential command injection risk if inputs are unchecked."
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

        # 2. Rule 2: SQL construction + Reachable route
        db_indicators = [
            ind for ind in report.security_indicators if ind.category == "database"
        ]
        if db_indicators and report.routes:
            for ind in db_indicators:
                ind_slug = self._get_file_slug(ind.file)
                ind_line = ind.line or 0
                for route in report.routes:
                    route_slug = self._get_file_slug(route.file)
                    route_line = route.line

                    if ind.file == route.file:
                        hyp_id = f"HYP-SQL-LOCAL-{ind_slug}-{ind_line}-{route_line}"
                        title = "Potential Local SQL Injection"
                        severity = "HIGH"
                        confidence = 0.80
                        desc = (
                            f"A database query/SQL indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in the same file."
                        )
                        rationale = (
                            f"The endpoint '{route.method} {route.pattern}' is defined in '{ind.file}', which also contains "
                            f"raw SQL query structures or query builders. Unsanitized route parameters could lead directly to "
                            f"SQL injection."
                        )
                    else:
                        hyp_id = f"HYP-SQL-CROSS-{ind_slug}-{ind_line}-{route_slug}-{route_line}"
                        title = "Potential Cross-File SQL Injection"
                        severity = "MEDIUM"
                        confidence = 0.50
                        desc = (
                            f"A database query/SQL indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in '{route.file}'."
                        )
                        rationale = (
                            f"The repository defines a route '{route.method} {route.pattern}' in one file and database logic "
                            f"in another file ('{ind.file}'). If parameters travel between these files, it may introduce "
                            f"an injection risk if not parameterized correctly."
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

        # 3. Rule 3: Deserialization / Unsafe Eval + Entry Point
        serialization_indicators = [
            ind for ind in report.security_indicators if ind.category == "serialization"
        ]
        if serialization_indicators and report.entry_points:
            for ind in serialization_indicators:
                ind_slug = self._get_file_slug(ind.file)
                ind_line = ind.line or 0
                for ep in report.entry_points:
                    ep_slug = self._get_file_slug(ep.file)
                    ep_line = ep.line or 0

                    if ind.file == ep.file:
                        hyp_id = f"HYP-RCE-LOCAL-{ind_slug}-{ind_line}-{ep_line}"
                        title = "Potential Local Code Execution via Entry Point"
                        severity = "CRITICAL"
                        confidence = 0.90
                        desc = (
                            f"An unsafe serialization/eval indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with application entry point '{ep.type}' in the same file."
                        )
                        rationale = (
                            f"An application entry point is located in the same file as unsafe serialization or evaluation "
                            f"constructs (like eval/exec). Startup options or payloads routed through this entry point could "
                            f"trigger Remote Code Execution."
                        )
                    else:
                        hyp_id = f"HYP-RCE-CROSS-{ind_slug}-{ind_line}-{ep_slug}-{ep_line}"
                        title = "Potential Cross-File Code Execution via Entry Point"
                        severity = "HIGH"
                        confidence = 0.70
                        desc = (
                            f"An unsafe serialization/eval indicator in '{ind.file}' on line {ind_line} "
                            f"correlates with application entry point '{ep.type}' defined in '{ep.file}'."
                        )
                        rationale = (
                            f"The entry point '{ep.type}' in '{ep.file}' routes application execution which may flow "
                            f"to the unsafe deserialization/eval structures located in '{ind.file}'."
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

        # 4. Rule 4: Cloud Secrets / Cloud SDK + Web Framework
        cloud_indicators = [
            ind for ind in report.security_indicators if ind.category in ("cloud_sdk", "secret_config")
        ]
        if cloud_indicators and report.repository.frameworks:
            for ind in cloud_indicators:
                ind_slug = self._get_file_slug(ind.file)
                ind_line = ind.line or 0
                for framework in report.repository.frameworks:
                    fw_slug = self._get_file_slug(framework)

                    hyp_id = f"HYP-CLOUD-CONFIG-{ind_slug}-{ind_line}-{fw_slug}"
                    title = "Potential Cloud Credential / Config Exposure"
                    desc = (
                        f"A cloud SDK or secret configuration reference in '{ind.file}' on line {ind_line} "
                        f"was found in a project using the '{framework}' framework."
                    )
                    rationale = (
                        f"The application utilizes the web framework '{framework}' and references cloud SDKs or secret "
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
