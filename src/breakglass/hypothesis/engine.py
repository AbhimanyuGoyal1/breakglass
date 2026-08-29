import time
import json
from typing import List, Optional, Dict
from breakglass.inspection.models import RepositoryReport
from breakglass.reasoning.models import SecurityHypothesis, ReasoningReport
from breakglass.hypothesis.models import HypothesisConfig
from breakglass.hypothesis.generators import generate_hypotheses_from_report
from breakglass.hypothesis.ranker import rank_hypotheses_deterministically

class SecurityHypothesisGenerator:
    """Coordinates deterministic security hypothesis generation, deduplication, ranking, and resource bounding."""

    def __init__(self, config: Optional[HypothesisConfig] = None):
        self.config = config or HypothesisConfig()
        self.config.validate()

    def generate_and_rank(self, report: RepositoryReport, repo_root: str) -> ReasoningReport:
        """Analyzes a RepositoryReport and returns ranked and resource-bounded SecurityHypotheses."""
        start_time = time.perf_counter()
        
        errors: List[str] = []
        timeout_reached = False

        # 1. Generate candidate hypotheses from report findings with exception isolation
        candidates: List[SecurityHypothesis] = []
        try:
            candidates = generate_hypotheses_from_report(report, repo_root, errors)
        except Exception as e:
            errors.append(f"Hypothesis generation encountered unexpected exception: {str(e)}")

        # 2. Deduplicate hypotheses using a semantic fingerprint
        deduplicated: List[SecurityHypothesis] = []
        seen_fingerprints = set()

        for hyp in candidates:
            # Check timeout budget
            if time.perf_counter() - start_time > self.config.generation_timeout_seconds:
                timeout_reached = True
                break

            try:
                # Build a semantic fingerprint based on category, title, and sorted evidence reference targets
                sorted_refs = sorted(
                    [(ref.file, ref.line, ref.type, ref.detail) for ref in hyp.evidence_references],
                    key=lambda x: (x[0], x[1] or 0, x[2], x[3])
                )
                fingerprint = (hyp.category, hyp.title, tuple(sorted_refs))

                if fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(fingerprint)
                    deduplicated.append(hyp)
            except Exception as e:
                # Catch malformed candidates safely
                errors.append(f"Failed to process candidate hypothesis: {str(e)}")

        # 3. Limit-bound individual hypothesis attributes
        bounded_candidates: List[SecurityHypothesis] = []
        category_counts: Dict[str, int] = {}

        for hyp in deduplicated:
            if time.perf_counter() - start_time > self.config.generation_timeout_seconds:
                timeout_reached = True
                break

            try:
                # Enforce max hypotheses per category
                cat = hyp.category
                cat_count = category_counts.get(cat, 0)
                if cat_count >= self.config.max_hypotheses_per_category:
                    continue
                
                # Enforce max evidence references per hypothesis
                if len(hyp.evidence_references) > self.config.max_evidence_per_hypothesis:
                    hyp.evidence_references = hyp.evidence_references[:self.config.max_evidence_per_hypothesis]

                # Enforce max description length
                if len(hyp.description) > self.config.max_description_length:
                    hyp.description = hyp.description[:self.config.max_description_length] + "... [TRUNCATED]"

                bounded_candidates.append(hyp)
                category_counts[cat] = cat_count + 1

                # Enforce max total hypotheses limit
                if len(bounded_candidates) >= self.config.max_hypotheses:
                    break
            except Exception as e:
                errors.append(f"Failed to bound hypothesis: {str(e)}")

        # 4. Rank candidates deterministically
        ranked_candidates: List[SecurityHypothesis] = []
        try:
            ranked_candidates = rank_hypotheses_deterministically(bounded_candidates)
        except Exception as e:
            errors.append(f"Hypothesis ranking failed: {str(e)}")
            ranked_candidates = bounded_candidates

        # 5. Enforce max total generated hypothesis bytes
        final_list: List[SecurityHypothesis] = []
        total_bytes = 0
        
        for hyp in ranked_candidates:
            if time.perf_counter() - start_time > self.config.generation_timeout_seconds:
                timeout_reached = True
                break

            try:
                hyp_dict = hyp.to_dict()
                hyp_bytes = len(json.dumps(hyp_dict).encode("utf-8"))
                
                if total_bytes + hyp_bytes <= self.config.max_total_hypothesis_bytes:
                    final_list.append(hyp)
                    total_bytes += hyp_bytes
                else:
                    # Exceeded max total hypothesis bytes, stop admission
                    break
            except Exception as e:
                errors.append(f"Failed to check size bound for hypothesis: {str(e)}")

        if timeout_reached:
            errors.append(f"Hypothesis generation reached timeout budget of {self.config.generation_timeout_seconds}s")

        status = "success"
        if errors:
            status = "partial_success" if final_list else "failed"

        return ReasoningReport(
            hypotheses=final_list,
            validation_status=status,
            errors=errors
        )
