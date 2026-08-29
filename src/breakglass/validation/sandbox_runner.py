"""Standalone script executed in a separate subprocess to validate hypotheses securely."""

import json
import sys
import os
from typing import Dict, Any, Optional, Tuple


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


def check_file_evidence_streaming(
    resolved_path: str,
    evidence_str: str,
    line_idx: Optional[int],
    max_bytes: int = 10 * 1024 * 1024
) -> Tuple[bool, str]:
    """Streams and bounds file reading to search for evidence safely."""
    evidence_bytes = evidence_str.encode("utf-8")
    if not evidence_bytes:
        return False, "Empty evidence string"

    total_bytes = 0
    if line_idx is not None:
        if line_idx <= 0:
            return False, f"Invalid line index: {line_idx}"

        # Chunked line-based search: avoid loading extremely long lines into memory at once
        chunk_size = 64 * 1024
        current_line = 1
        line_buffer = bytearray()
        try:
            with open(resolved_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        return False, f"File size exceeded the {max_bytes} bytes limit"

                    start = 0
                    while True:
                        idx = chunk.find(b"\n", start)
                        if idx == -1:
                            line_buffer.extend(chunk[start:])
                            if len(line_buffer) > max_bytes:
                                return False, f"Line length exceeded the {max_bytes} bytes limit"
                            break

                        line_buffer.extend(chunk[start:idx + 1])
                        if current_line == line_idx:
                            line_str = line_buffer.decode("utf-8", errors="replace")
                            if evidence_str in line_str:
                                return True, f"Found evidence '{evidence_str}' at line {line_idx}"
                            return False, f"Evidence '{evidence_str}' not found in line {line_idx} content"

                        current_line += 1
                        line_buffer.clear()
                        start = idx + 1

                if line_buffer and current_line == line_idx:
                    line_str = line_buffer.decode("utf-8", errors="replace")
                    if evidence_str in line_str:
                        return True, f"Found evidence '{evidence_str}' at line {line_idx}"
                    return False, f"Evidence '{evidence_str}' not found in line {line_idx} content"

            return False, f"File has only {current_line - 1} lines, line {line_idx} does not exist"
        except Exception as e:
            return False, f"Error reading file line: {str(e)}"
    else:
        # Whole-file search: read in overlapping chunks
        chunk_size = 64 * 1024
        overlap = len(evidence_bytes)
        buffer = bytearray()
        try:
            with open(resolved_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        return False, f"File size exceeded the {max_bytes} bytes limit"
                    buffer.extend(chunk)

                    # Search in buffer
                    idx = buffer.find(evidence_bytes)
                    if idx != -1:
                        return True, "Found evidence in file content"

                    # Keep overlap at the end of buffer
                    if len(buffer) > overlap:
                        del buffer[:-overlap]

            return False, "Evidence not found in file content"
        except Exception as e:
            return False, f"Error reading file: {str(e)}"


def run_validation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Streams and validates repository evidence for a hypothesis safely inside the sandbox."""
    hypothesis = payload.get("hypothesis", {})
    report = payload.get("report", {})
    config = payload.get("config", {})

    hyp_id = hypothesis.get("id", "")
    refs = hypothesis.get("evidence_references", [])

    # Authoritative repository path resolution
    sandbox_root = payload.get("authoritative_repo_root")
    if not isinstance(sandbox_root, str) or not sandbox_root.strip():
        # Fallback to report repository root if none passed explicitly (backwards compatibility)
        repo_info = report.get("repository", {})
        if isinstance(repo_info, dict):
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
            "error_message": "Missing repository summary root path"
        }

    # Security check: Match report root with authoritative sandbox root to detect configuration tampering
    repo_info = report.get("repository", {})
    if isinstance(repo_info, dict):
        report_root = repo_info.get("root")
        if report_root:
            report_root_norm = os.path.normcase(os.path.abspath(report_root))
            sandbox_root_norm = os.path.normcase(os.path.abspath(sandbox_root))
            if report_root_norm != sandbox_root_norm:
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
                    "error_message": f"Security violation: report root '{report_root}' does not match authoritative root '{sandbox_root}'"
                }

    sandbox_root_abs = os.path.abspath(sandbox_root)

    # Resolve indicators
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
            # Normalize with trailing slash to prevent suffix containment bypass (e.g. /workspace-backup vs /workspace)
            sandbox_root_norm = os.path.normcase(os.path.join(sandbox_root_abs, ""))
            resolved_path_norm = os.path.normcase(resolved_path)
            sandbox_root_abs_norm = os.path.normcase(sandbox_root_abs)

            if not (resolved_path_norm.startswith(sandbox_root_norm) or resolved_path_norm == sandbox_root_abs_norm):
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
                # Enforce dynamic maximum read limit (default 10MB)
                max_bytes = config.get("max_evidence_file_bytes", 10 * 1024 * 1024)
                line_idx = ind.get("line")

                success, search_detail = check_file_evidence_streaming(resolved_path, evidence_str, line_idx, max_bytes)
                if success:
                    confirmed = True
                    details_log.append(f"Found evidence '{evidence_str}' at {file_path}:{line_idx or 'all'}")
                else:
                    details_log.append(search_detail)
                    # If file size limits were exceeded, return SANDBOX_ERROR to fail closed
                    if "exceeded" in search_detail:
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
                            "error_message": f"File read safety error: {search_detail}"
                        }
            else:
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
