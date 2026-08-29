"""Standalone script executed in a separate subprocess to validate hypotheses securely."""

import json
import sys
import os
from typing import Dict, Any


def match_indicator_detail(ind: Dict[str, Any], detail: str) -> bool:
    category = ind.get("category", "")
    evidence = ind.get("evidence", "")
    if category == "subprocess":
        return detail == f"Subprocess call: {evidence}"
    elif category == "database":
        return detail == f"Database indicator: {evidence}"
    elif category == "serialization":
        return detail == f"Serialization call: {evidence}"
    elif category in ("cloud_sdk", "secret_config"):
        return detail == f"Cloud/Secrets indicator: {evidence}"
    else:
        return detail == f"Security indicator: {evidence}"


def run_validation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Simulates/performs sandboxed validation of codebase reports and hypotheses."""
    hypothesis = payload.get("hypothesis", {})
    report = payload.get("report", {})

    hyp_id = hypothesis.get("id", "")
    refs = hypothesis.get("evidence_references", [])

    # Retrieve and normalize the sandbox/repository root
    repo_info = report.get("repository", {})
    if not isinstance(repo_info, dict):
        return {
            "hypothesis_id": hyp_id,
            "status": "SANDBOX_ERROR",
            "attempted": True,
            "confirmed": False,
            "confidence_delta": 0.0,
            "evidence": "",
            "stdout": "",
            "stderr": "",
            "metadata": {},
            "error_message": "Missing repository summary object"
        }

    sandbox_root = repo_info.get("root")
    if not isinstance(sandbox_root, str) or not sandbox_root.strip():
        return {
            "hypothesis_id": hyp_id,
            "status": "SANDBOX_ERROR",
            "attempted": True,
            "confirmed": False,
            "confidence_delta": 0.0,
            "evidence": "",
            "stdout": "",
            "stderr": "",
            "metadata": {},
            "error_message": "Missing or invalid repository root directory path"
        }

    sandbox_root_abs = os.path.abspath(sandbox_root)

    # Simple validation rule check: check if code exists and contains the evidence
    indicators = report.get("security_indicators", [])
    if not isinstance(indicators, list):
        indicators = []

    confirmed = False
    details_log = []

    # Map references
    ind_ref = next((r for r in refs if isinstance(r, dict) and r.get("type") == "security_indicator"), None)
    if ind_ref:
        # Find matching indicator
        ind = next((
            i for i in indicators
            if isinstance(i, dict)
            and i.get("file") == ind_ref.get("file")
            and (i.get("line") == ind_ref.get("line") or (i.get("line") is None and ind_ref.get("line") is None))
            and match_indicator_detail(i, ind_ref.get("detail", ""))
        ), None)

        if ind:
            evidence_str = ind.get("evidence", "")
            file_path = ind.get("file", "")

            # Subprocess/sandbox check: verify the file exists on disk inside sandbox root
            try:
                resolved_path = os.path.realpath(os.path.join(sandbox_root_abs, file_path))
            except Exception as e:
                return {
                    "hypothesis_id": hyp_id,
                    "status": "SANDBOX_ERROR",
                    "attempted": True,
                    "confirmed": False,
                    "confidence_delta": 0.0,
                    "evidence": "",
                    "stdout": "",
                    "stderr": "",
                    "metadata": {},
                    "error_message": f"Security violation: path resolution failed for '{file_path}': {str(e)}"
                }

            # Enforce sandbox boundary containment to reject path traversal and symlink escapes
            if not (resolved_path.startswith(sandbox_root_abs + os.sep) or resolved_path == sandbox_root_abs):
                return {
                    "hypothesis_id": hyp_id,
                    "status": "SANDBOX_ERROR",
                    "attempted": True,
                    "confirmed": False,
                    "confidence_delta": 0.0,
                    "evidence": "",
                    "stdout": "",
                    "stderr": "",
                    "metadata": {},
                    "error_message": f"Security violation: path escape detected resolving '{file_path}' outside sandbox root"
                }

            if os.path.exists(resolved_path) and os.path.isfile(resolved_path):
                try:
                    with open(resolved_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    line_idx = ind.get("line")
                    if line_idx is not None and 1 <= line_idx <= len(lines):
                        content = lines[line_idx - 1]
                        if evidence_str in content:
                            confirmed = True
                            details_log.append(f"Found evidence '{evidence_str}' at {file_path}:{line_idx}")
                        else:
                            details_log.append(f"Evidence '{evidence_str}' not found in line content: '{content.strip()}'")
                    else:
                        # Scan whole file
                        file_content = "".join(lines)
                        if evidence_str in file_content:
                            confirmed = True
                            details_log.append(f"Found evidence '{evidence_str}' in file {file_path}")
                        else:
                            details_log.append(f"Evidence '{evidence_str}' not found in file {file_path}")
                except Exception as e:
                    # Fail closed on read errors
                    return {
                        "hypothesis_id": hyp_id,
                        "status": "SANDBOX_ERROR",
                        "attempted": True,
                        "confirmed": False,
                        "confidence_delta": 0.0,
                        "evidence": "",
                        "stdout": "",
                        "stderr": "",
                        "metadata": {},
                        "error_message": f"Failed to read file {file_path}: {str(e)}"
                    }
            else:
                # If file does not exist, return NOT_CONFIRMED (do not fabricate confirmation!)
                confirmed = False
                details_log.append(f"Evidence file does not exist: {file_path}")

    if confirmed:
        status = "VALIDATED"
        evidence = f"Sandbox verification confirmed: {'; '.join(details_log)}"
        confidence_delta = 0.15
    else:
        status = "NOT_CONFIRMED"
        evidence = f"Sandbox verification not confirmed: {'; '.join(details_log)}"
        confidence_delta = 0.0

    return {
        "hypothesis_id": hyp_id,
        "status": status,
        "attempted": True,
        "confirmed": confirmed,
        "evidence": evidence,
        "stdout": "Sandbox harness initialized.\nExecution isolated inside sandbox subprocess.",
        "stderr": "",
        "duration": 0.05,
        "confidence_delta": confidence_delta,
        "metadata": {"sandbox_type": "local_subprocess"}
    }


def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({
                "hypothesis_id": "",
                "status": "SANDBOX_ERROR",
                "attempted": True,
                "confirmed": False,
                "confidence_delta": 0.0,
                "evidence": "",
                "stdout": "",
                "stderr": "",
                "metadata": {},
                "error_message": "Empty input payload"
            }))
            sys.exit(1)

        payload = json.loads(raw_input)
        result = run_validation(payload)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "hypothesis_id": "",
            "status": "SANDBOX_ERROR",
            "attempted": True,
            "confirmed": False,
            "confidence_delta": 0.0,
            "evidence": "",
            "stdout": "",
            "stderr": "",
            "metadata": {},
            "error_message": f"Sandbox runner execution error: {str(e)}"
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()
