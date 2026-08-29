import os
import math
from pathlib import Path
from typing import Tuple, Optional, Any
from breakglass.reasoning.models import EvidenceReference
from breakglass.inspection.models import RepositoryReport
from breakglass.inspection.scanner import _is_contained_in
from breakglass.evidence.models import EvidenceGraphConfig

def _match_indicator_detail(ind: Any, detail: str) -> bool:
    """Checks if a SecurityIndicator matches the specified detail string pattern, redacting report side for safety."""
    category = getattr(ind, "category", None)
    evidence = getattr(ind, "evidence", None)
    if not category or evidence is None:
        return False

    from breakglass.inspection.indicators import redact_secrets
    redacted_evidence = redact_secrets(evidence)

    if category == "subprocess":
        return detail in (f"Subprocess call: {redacted_evidence}", f"Security indicator: {redacted_evidence}")
    elif category == "database":
        return detail in (f"Database indicator: {redacted_evidence}", f"Security indicator: {redacted_evidence}")
    elif category == "serialization":
        return detail in (f"Serialization call: {redacted_evidence}", f"Security indicator: {redacted_evidence}")
    elif category in ("cloud_sdk", "secret_config"):
        return detail in (
            f"Cloud/Secrets indicator: {redacted_evidence}",
            f"Exposed secret configuration reference: {redacted_evidence}",
            f"Exposed secret config: {redacted_evidence}",
            f"Security indicator: {redacted_evidence}"
        )
    elif category in ("authentication", "authorization"):
        return detail in (
            f"Access control: {redacted_evidence}",
            f"Security indicator: {redacted_evidence}"
        )
    elif category == "filesystem":
        return detail in (
            f"Filesystem access: {redacted_evidence}",
            f"Security indicator: {redacted_evidence}"
        )
    else:
        return detail == f"Security indicator: {redacted_evidence}"


def authenticate_evidence_reference(
    ref: EvidenceReference,
    report: RepositoryReport,
    repo_root: str,
    config: Optional[EvidenceGraphConfig] = None
) -> Tuple[bool, str]:
    """Canonical authentication boundary to validate an EvidenceReference.

    Verifies:
    1. Structure and types.
    2. Path normalization and component-aware containment.
    3. Authenticity against RepositoryReport findings.
    4. Bounded detail length limits.
    """
    cfg = config or EvidenceGraphConfig()
    
    # 1. Structural Validation
    if not isinstance(ref, EvidenceReference):
        return False, ""
    if not isinstance(ref.type, str) or not ref.type:
        return False, ""
    if not isinstance(ref.file, str) or not ref.file:
        return False, ""
    if not isinstance(ref.detail, str):
        return False, ""
    if ref.line is not None and (not isinstance(ref.line, int) or isinstance(ref.line, bool) or ref.line <= 0):
        return False, ""

    # 2. Path normalization & containment check
    try:
        file_norm = ref.file.replace("\\", "/")
        abs_path = Path(repo_root) / file_norm
        if not _is_contained_in(Path(repo_root), abs_path):
            return False, ""
    except Exception:
        return False, ""

    # 3. Bounded detail length validation
    if len(ref.detail.encode("utf-8")) > cfg.max_evidence_snippet_bytes:
        return False, ""

    # 4. Provenance and Authenticity matching against report findings
    if ref.type == "security_indicator":
        for ind in getattr(report, "security_indicators", []) or []:
            if ind is None:
                continue
            ind_file = getattr(ind, "file", None)
            ind_line = getattr(ind, "line", None)
            
            if ind_file and ind_file.replace("\\", "/") == file_norm:
                if ind_line == ref.line or (ind_line is None and ref.line is None):
                    if _match_indicator_detail(ind, ref.detail):
                        return True, ref.detail
        return False, ""

    elif ref.type == "route":
        # 1st Pass: attempt precise match on method/pattern if detail matches
        for r in getattr(report, "routes", []) or []:
            if r is None:
                continue
            r_file = getattr(r, "file", None)
            r_line = getattr(r, "line", None)
            
            if r_file and r_file.replace("\\", "/") == file_norm and r_line == ref.line:
                method = getattr(r, "method", "")
                pattern = getattr(r, "pattern", "")
                expected_detail = f"Route: {method} {pattern}"
                if ref.detail == expected_detail:
                    return True, expected_detail
        
        # 2nd Pass: Fallback for coordinate matching
        for r in getattr(report, "routes", []) or []:
            if r is None:
                continue
            r_file = getattr(r, "file", None)
            r_line = getattr(r, "line", None)
            
            if r_file and r_file.replace("\\", "/") == file_norm and r_line == ref.line:
                method = getattr(r, "method", "")
                pattern = getattr(r, "pattern", "")
                return True, f"Route: {method} {pattern}"
        return False, ""

    elif ref.type == "entry_point":
        # 1st Pass: precise match
        for ep in getattr(report, "entry_points", []) or []:
            if ep is None:
                continue
            ep_file = getattr(ep, "file", None)
            ep_line = getattr(ep, "line", None)
            
            if ep_file and ep_file.replace("\\", "/") == file_norm and ep_line == ref.line:
                ep_type = getattr(ep, "type", "")
                desc = getattr(ep, "description", "")
                expected_detail = f"Entry point: {ep_type} ({desc})"
                if ref.detail == expected_detail:
                    return True, expected_detail

        # 2nd Pass: coordinate fallback
        for ep in getattr(report, "entry_points", []) or []:
            if ep is None:
                continue
            ep_file = getattr(ep, "file", None)
            ep_line = getattr(ep, "line", None)
            
            if ep_file and ep_file.replace("\\", "/") == file_norm and ep_line == ref.line:
                ep_type = getattr(ep, "type", "")
                desc = getattr(ep, "description", "")
                return True, f"Entry point: {ep_type} ({desc})"
        return False, ""

    elif ref.type == "file":
        if ref.line is not None:
            return False, ""
        
        valid_files = set()
        repo = getattr(report, "repository", None)
        if repo:
            for attr in ("config_files", "docker_configs", "cicd_configs", "infrastructure_configs", "test_files"):
                val_list = getattr(repo, attr, []) or []
                for f in val_list:
                    if f:
                        valid_files.add(f.replace("\\", "/"))

        for r in getattr(report, "routes", []) or []:
            if r and getattr(r, "file", None):
                valid_files.add(r.file.replace("\\", "/"))
        for ep in getattr(report, "entry_points", []) or []:
            if ep and getattr(ep, "file", None):
                valid_files.add(ep.file.replace("\\", "/"))
        for ind in getattr(report, "security_indicators", []) or []:
            if ind and getattr(ind, "file", None):
                valid_files.add(ind.file.replace("\\", "/"))

        if file_norm in valid_files:
            return True, f"File: {file_norm}"
        return False, ""

    return False, ""
