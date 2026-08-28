"""Data models for the LLM reasoning agent layer."""

from dataclasses import dataclass, field
from typing import List, Optional
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis


@dataclass
class LLMRequest:
    """Contains context prompts and evidence payloads for the LLM request."""
    system_prompt: str
    user_prompt: str
    inspection_report: RepositoryReport
    deterministic_hypotheses: List[SecurityHypothesis]


@dataclass
class LLMResponse:
    """Contains raw outputs and validation status of the LLM execution."""
    raw_response: str
    hypotheses: List[SecurityHypothesis] = field(default_factory=list)
    model_identifier: Optional[str] = None
    validation_status: str = "success"  # success, partial_success, failed
    errors: List[str] = field(default_factory=list)
