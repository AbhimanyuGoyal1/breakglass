"""Agent reasoning engines and security hypothesis generation logic."""

from abc import ABC, abstractmethod
import hashlib
import json
from typing import Optional, Dict, Any, List
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

    MAX_LINE_DISTANCE = 50
    MAX_CORRELATIONS_PER_FILE = 50

    def _generate_stable_id(self, category: str, identity: Dict[str, Any]) -> str:
        """Generates a stable, collision-resistant hypothesis ID using SHA-256."""
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        prefix = f"HYP-{category.upper().replace('_', '-')}"
        return f"{prefix}-{digest[:16]}"

    def _check_proximity(self, line1: Optional[int], line2: Optional[int]) -> bool:
        """Verifies if two line numbers are within the allowed MAX_LINE_DISTANCE."""
        if line1 is None or line2 is None:
            return True
        return abs(line1 - line2) <= self.MAX_LINE_DISTANCE

    def generate_hypotheses(self, report: RepositoryReport) -> ReasoningReport:
        """Correlates static indicators, routes, and frameworks to generate hypotheses."""
        hypotheses_dict = {}

        # 1. Deduplicate input candidates deterministically
        unique_inds = []
        ind_seen = set()
        sorted_indicators = sorted(
            report.security_indicators,
            key=lambda x: (x.file, x.line or 0, x.category, x.indicator_type, x.evidence)
        )
        for ind in sorted_indicators:
            key = (ind.file, ind.line, ind.category, ind.indicator_type, ind.evidence)
            if key not in ind_seen:
                ind_seen.add(key)
                unique_inds.append(ind)

        unique_routes = []
        route_seen = set()
        sorted_routes = sorted(
            report.routes,
            key=lambda x: (x.file, x.line or 0, x.method, x.pattern, x.evidence)
        )
        for r in sorted_routes:
            key = (r.file, r.line, r.method, r.pattern, r.evidence)
            if key not in route_seen:
                route_seen.add(key)
                unique_routes.append(r)

        unique_eps = []
        ep_seen = set()
        sorted_eps = sorted(
            report.entry_points,
            key=lambda x: (x.file, x.line or 0, x.type, x.description)
        )
        for ep in sorted_eps:
            key = (ep.file, ep.line, ep.type, ep.description)
            if key not in ep_seen:
                ep_seen.add(key)
                unique_eps.append(ep)

        # 2. Group candidates by file
        inds_by_file = {}
        for ind in unique_inds:
            inds_by_file.setdefault(ind.file, []).append(ind)

        routes_by_file = {}
        for r in unique_routes:
            routes_by_file.setdefault(r.file, []).append(r)

        eps_by_file = {}
        for ep in unique_eps:
            eps_by_file.setdefault(ep.file, []).append(ep)

        # 3. Rule 1: Subprocess execution + Reachable route (SAME FILE + PROXIMITY BOUNDED)
        for filepath, file_inds in inds_by_file.items():
            subprocess_file_inds = [ind for ind in file_inds if ind.category == "subprocess"]
            file_routes = routes_by_file.get(filepath, [])
            if subprocess_file_inds and file_routes:
                correlations = 0
                for ind in subprocess_file_inds:
                    for route in file_routes:
                        if correlations >= self.MAX_CORRELATIONS_PER_FILE:
                            break
                        if not self._check_proximity(ind.line, route.line):
                            continue

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
                        hyp_id = self._generate_stable_id("command_injection", identity)
                        title = "Potential Local Command Injection via Endpoint"
                        severity = "HIGH"
                        confidence = 0.85
                        desc = (
                            f"A subprocess execution indicator in '{ind.file}' on line {ind.line} "
                            f"correlates with an HTTP route '{route.method} {route.pattern}' defined in the same file."
                        )
                        rationale = (
                            f"The HTTP route '{route.method} {route.pattern}' resides in the same file as a subprocess execution "
                            f"call within proximity. If request parameters are passed directly to the command execution without "
                            f"strict validation, it could lead to command injection."
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
                        correlations += 1

        # 4. Rule 2: SQL construction + Reachable route (SAME FILE + PROXIMITY BOUNDED, RAW SQL ONLY)
        for filepath, file_inds in inds_by_file.items():
            db_file_inds = [
                ind for ind in file_inds
                if ind.category == "database" and ind.indicator_type == "raw_sql_construction_indicator"
            ]
            file_routes = routes_by_file.get(filepath, [])
            if db_file_inds and file_routes:
                correlations = 0
                for ind in db_file_inds:
                    for route in file_routes:
                        if correlations >= self.MAX_CORRELATIONS_PER_FILE:
                            break
                        if not self._check_proximity(ind.line, route.line):
                            continue

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
                        hyp_id = self._generate_stable_id("sql_injection", identity)
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
                        correlations += 1

        # 5. Rule 3: Deserialization / Unsafe Eval + Entry Point (SAME FILE + PROXIMITY BOUNDED)
        for filepath, file_inds in inds_by_file.items():
            serialization_file_inds = [ind for ind in file_inds if ind.category == "serialization"]
            file_eps = eps_by_file.get(filepath, [])
            if serialization_file_inds and file_eps:
                correlations = 0
                for ind in serialization_file_inds:
                    for ep in file_eps:
                        if correlations >= self.MAX_CORRELATIONS_PER_FILE:
                            break
                        if not self._check_proximity(ind.line, ep.line):
                            continue

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
                        hyp_id = self._generate_stable_id("remote_code_execution", identity)
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
                        correlations += 1

        # 6. Rule 4: Cloud Secrets / Cloud SDK + Web Framework (BOUNDED project correlation)
        cloud_indicators = [
            ind for ind in unique_inds if ind.category in ("cloud_sdk", "secret_config")
        ]
        if cloud_indicators and report.repository.frameworks:
            sorted_frameworks = sorted(list(set(report.repository.frameworks)))
            framework_list_str = ", ".join(sorted_frameworks)
            for ind in cloud_indicators:
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
                hyp_id = self._generate_stable_id("credential_exposure", identity)
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
