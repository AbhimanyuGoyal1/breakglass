"""BREAKGLASS: Autonomous security assessment agent."""

from breakglass.inspection import inspect_repository, RepositoryReport, inspect, RepositoryInspectionEngine
from breakglass.reasoning import (
    EvidenceReference,
    SecurityHypothesis,
    ReasoningReport,
    ReasoningEngine,
    DeterministicReasoningEngine
)
from breakglass.llm import (
    LLMRequest,
    LLMResponse,
    LLMClient,
    MockLLMClient,
    LLMReasoningEngine
)
from breakglass.validation import (
    ValidationStatus,
    ValidationResult,
    SandboxValidator,
    MockSandboxValidator,
    TrueForgeSandboxValidator,
    ValidationConfig,
    ValidationEngine
)
from breakglass.hypothesis import SecurityHypothesisGenerator, HypothesisConfig

__all__ = [
    "inspect_repository",
    "inspect",
    "RepositoryInspectionEngine",
    "RepositoryReport",
    "EvidenceReference",
    "SecurityHypothesis",
    "ReasoningReport",
    "ReasoningEngine",
    "DeterministicReasoningEngine",
    "LLMRequest",
    "LLMResponse",
    "LLMClient",
    "MockLLMClient",
    "LLMReasoningEngine",
    "ValidationStatus",
    "ValidationResult",
    "SandboxValidator",
    "MockSandboxValidator",
    "TrueForgeSandboxValidator",
    "ValidationConfig",
    "ValidationEngine",
    "SecurityHypothesisGenerator",
    "HypothesisConfig"
]
__version__ = "0.1.0"

