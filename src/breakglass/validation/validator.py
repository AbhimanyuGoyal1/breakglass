"""Sandbox validator abstraction interface and sandbox implementations."""

from abc import ABC, abstractmethod
import os
from typing import Dict, Any, Optional
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis
from breakglass.validation.models import ValidationResult, ValidationStatus


class SandboxValidator(ABC):
    """Abstract interface representing a sandbox validation environment."""

    @abstractmethod
    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Validates a SecurityHypothesis inside a sandboxed environment.

        Args:
            hypothesis: The hypothesis to validate.
            repository_context: The authoritative codebase report.

        Returns:
            A ValidationResult representing the outcome.
        """
        pass


class MockSandboxValidator(SandboxValidator):
    """Mock validator returning predefined validation results for testing."""

    def __init__(self, predefined_results: Optional[Dict[str, ValidationResult]] = None):
        self.predefined_results = predefined_results or {}
        self.last_validated = []

    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Saves calls and returns configured or fallback validation results."""
        self.last_validated.append((hypothesis, repository_context))
        if hypothesis.id in self.predefined_results:
            return self.predefined_results[hypothesis.id]
        # Default fallback
        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=ValidationStatus.NOT_CONFIRMED,
            attempted=True,
            confirmed=False,
            evidence="Mock validation fallback: not confirmed"
        )


class TrueForgeSandboxValidator(SandboxValidator):
    """Adapter boundary for the TrueForge execution sandbox."""

    def __init__(self, api_key: Optional[str] = None, endpoint: Optional[str] = None):
        # Read from environment variables if not provided
        self.api_key = api_key or os.environ.get("TRUEFORGE_API_KEY")
        self.endpoint = endpoint or os.environ.get("TRUEFORGE_ENDPOINT", "https://api.trueforge.example.com")

    def validate(
        self,
        hypothesis: SecurityHypothesis,
        repository_context: RepositoryReport
    ) -> ValidationResult:
        """Executes verification inside the TrueForge container workspace."""
        # Safety check: Fail closed if invalid sandbox configuration
        if not self.api_key:
            return ValidationResult(
                hypothesis_id=hypothesis.id,
                status=ValidationStatus.PREFLIGHT_ERROR,
                attempted=False,
                confirmed=False,
                error_message="Sandbox configuration error: Missing TRUEFORGE_API_KEY"
            )

        # Container execution structures are configured here.
        # Direct network socket operations are mocked/stubbed for this milestone
        # to ensure offline testing suites run cleanly.
        return ValidationResult(
            hypothesis_id=hypothesis.id,
            status=ValidationStatus.NOT_ATTEMPTED,
            attempted=False,
            confirmed=False,
            evidence="TrueForge client configured. Actual container orchestration deferred.",
            metadata={"endpoint": self.endpoint}
        )
