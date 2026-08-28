"""Data models for sandbox validation of security hypotheses."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional


class ValidationStatus(str, Enum):
    """Execution outcome status of sandbox validation."""
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    VALIDATED = "VALIDATED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    SANDBOX_ERROR = "SANDBOX_ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_HYPOTHESIS = "INVALID_HYPOTHESIS"


@dataclass
class ValidationResult:
    """Contains results and execution evidence for a single hypothesis validation run."""
    hypothesis_id: str
    status: ValidationStatus
    attempted: bool
    confirmed: bool
    confidence_delta: float = 0.0
    evidence: str = ""
    stdout: str = ""
    stderr: str = ""
    duration: Optional[float] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the validation result into a dictionary."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "status": self.status.value,
            "attempted": self.attempted,
            "confirmed": self.confirmed,
            "confidence_delta": self.confidence_delta,
            "evidence": self.evidence,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": self.duration,
            "error_message": self.error_message,
            "metadata": self.metadata
        }
