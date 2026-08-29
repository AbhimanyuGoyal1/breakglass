"""Agent reasoning engines and security hypothesis generation logic."""

from abc import ABC, abstractmethod
import hashlib
import json
from typing import Optional, Dict, Any, List
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import ReasoningReport, SecurityHypothesis, EvidenceReference, generate_hypothesis_id
import json


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
        return generate_hypothesis_id(category, identity, is_llm=False)

    def _check_proximity(self, line1: Optional[int], line2: Optional[int]) -> bool:
        """Verifies if two line numbers are within the allowed MAX_LINE_DISTANCE."""
        if line1 is None or line2 is None:
            return True
        return abs(line1 - line2) <= self.MAX_LINE_DISTANCE

    def generate_hypotheses(self, report: RepositoryReport) -> ReasoningReport:
        """Correlates static indicators, routes, and frameworks to generate hypotheses."""
        repo_root = getattr(report.repository, "root", "") if (report.repository and hasattr(report.repository, "root")) else ""
        if not repo_root:
            import os
            repo_root = os.getcwd()

        from breakglass.hypothesis.engine import SecurityHypothesisGenerator
        generator = SecurityHypothesisGenerator()
        return generator.generate_and_rank(report, repo_root)
