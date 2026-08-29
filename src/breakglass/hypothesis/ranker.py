from typing import List
from breakglass.reasoning.models import SecurityHypothesis

SEVERITY_SCORES = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2
}

def rank_hypotheses_deterministically(hypotheses: List[SecurityHypothesis]) -> List[SecurityHypothesis]:
    """Scores, annotates, and sorts a collection of security hypotheses deterministically.

    Ranking algorithm computes:
      priority_score = Base(severity) + Confidence(0.5 max) + EvidenceCount(0.3 max) + Proximity factors

    Alphabetical sorting by hypothesis ID is used as the strict deterministic tie-breaker.
    """
    ranked_list = []
    
    for hyp in hypotheses:
        # 1. Base score from severity
        base_score = SEVERITY_SCORES.get(hyp.severity.upper(), 0.1)
        
        # 2. Confidence scaling (0.5 max)
        confidence_factor = hyp.confidence * 0.5
        
        # 3. Evidence count scaling (0.3 max)
        evidence_factor = min(0.3, len(hyp.evidence_references) * 0.1)
        
        # 4. Exploitability and proximity factors
        has_route = any(ref.type == "route" for ref in hyp.evidence_references)
        has_entry = any(ref.type == "entry_point" for ref in hyp.evidence_references)
        
        exploit_factor = 0.15 if has_route else 0.0
        entry_factor = 0.10 if has_entry else 0.0
        
        # Combined score calculation
        total_score = round(base_score + confidence_factor + evidence_factor + exploit_factor + entry_factor, 3)
        
        # Explainable metadata breakdown
        metadata = getattr(hyp, "metadata", {}) or {}
        metadata["priority_score"] = total_score
        metadata["ranking_breakdown"] = {
            "base_severity_score": base_score,
            "confidence_factor": confidence_factor,
            "evidence_count_factor": evidence_factor,
            "route_exploit_factor": exploit_factor,
            "entry_point_factor": entry_factor
        }
        hyp.metadata = metadata
        
        # Append explanation to the rationale
        explanation = (
            f" [Priority Rank Score: {total_score} computed from: "
            f"Severity={hyp.severity}, Confidence={hyp.confidence}, "
            f"EvidenceCount={len(hyp.evidence_references)}, "
            f"HasRoute={has_route}, HasEntryPoint={has_entry}]."
        )
        if explanation not in hyp.rationale:
            hyp.rationale = hyp.rationale + explanation
            
        ranked_list.append(hyp)

    # 5. Deterministic sorting: Descending by score, alphabetically by ID as a tie-breaker
    ranked_list.sort(key=lambda x: (-x.metadata["priority_score"], x.id))
    return ranked_list
