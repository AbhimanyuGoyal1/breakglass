"""BREAKGLASS: Autonomous security assessment agent."""

from breakglass.inspection import inspect_repository, RepositoryReport
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

__all__ = [
    "inspect_repository",
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
    "LLMReasoningEngine"
]
__version__ = "0.1.0"

