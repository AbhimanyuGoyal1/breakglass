from dataclasses import dataclass
import math

@dataclass
class HypothesisConfig:
    """Resource bounds and limits for the hypothesis generation layer."""
    max_hypotheses: int = 100
    max_hypotheses_per_category: int = 50
    max_evidence_per_hypothesis: int = 5
    max_description_length: int = 1000
    max_total_hypothesis_bytes: int = 10 * 1024 * 1024  # 10MB
    generation_timeout_seconds: float = 15.0

    def validate(self) -> None:
        """Validates all limits, strictly rejecting non-positive values, NaN, or infinities."""
        if not isinstance(self.max_hypotheses, int) or self.max_hypotheses <= 0 or isinstance(self.max_hypotheses, bool):
            raise ValueError("max_hypotheses must be a positive integer")
        if not isinstance(self.max_hypotheses_per_category, int) or self.max_hypotheses_per_category <= 0 or isinstance(self.max_hypotheses_per_category, bool):
            raise ValueError("max_hypotheses_per_category must be a positive integer")
        if not isinstance(self.max_evidence_per_hypothesis, int) or self.max_evidence_per_hypothesis <= 0 or isinstance(self.max_evidence_per_hypothesis, bool):
            raise ValueError("max_evidence_per_hypothesis must be a positive integer")
        if not isinstance(self.max_description_length, int) or self.max_description_length <= 0 or isinstance(self.max_description_length, bool):
            raise ValueError("max_description_length must be a positive integer")
        if not isinstance(self.max_total_hypothesis_bytes, int) or self.max_total_hypothesis_bytes <= 0 or isinstance(self.max_total_hypothesis_bytes, bool):
            raise ValueError("max_total_hypothesis_bytes must be a positive integer")
        if not isinstance(self.generation_timeout_seconds, (int, float)) or isinstance(self.generation_timeout_seconds, bool) or not math.isfinite(self.generation_timeout_seconds) or self.generation_timeout_seconds <= 0:
            raise ValueError("generation_timeout_seconds must be a finite positive number")
