from __future__ import annotations
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.inspection.scanner import _is_contained_in
from breakglass.inspection.models import RepositoryReport

def validate_and_create_evidence_ref(
    ref_type: str,
    file_rel_path: str,
    line: Optional[int],
    detail: str,
    repo_root: str
) -> Optional[EvidenceReference]:
    """Validates that the file lies inside the repository root, redacts secrets, and returns an EvidenceReference."""
    try:
        if not file_rel_path or not isinstance(file_rel_path, str):
            return None
        
        abs_path = Path(repo_root) / file_rel_path
        if not _is_contained_in(Path(repo_root), abs_path):
            return None
        
        from breakglass.inspection.indicators import redact_secrets
        clean_detail = redact_secrets(detail)
        
        return EvidenceReference(
            type=ref_type,
            file=file_rel_path.replace("\\", "/"),
            line=line,
            detail=clean_detail
        )
    except Exception:
        return None

def generate_hypotheses_from_report(report: RepositoryReport, repo_root: str, errors: Optional[List[str]] = None) -> List[SecurityHypothesis]:
    """Generates candidate security hypotheses from authoritative inspection details in the report."""
    candidates: List[SecurityHypothesis] = []
    
    # 1. Deduplicate input candidates deterministically
    unique_inds = []
    ind_seen = set()
    try:
        raw_inds = []
        for x in (getattr(report, "security_indicators", []) or []):
            if x is None:
                if errors is not None:
                    errors.append("Malformed indicator: None found")
                continue
            raw_inds.append(x)

        sorted_indicators = sorted(
            raw_inds,
            key=lambda x: (
                getattr(x, "file", None) or "",
                getattr(x, "line", None) or 0,
                getattr(x, "category", None) or "",
                getattr(x, "indicator_type", None) or "",
                getattr(x, "evidence", None) or ""
            )
        )
        for ind in sorted_indicators:
            try:
                file_val = getattr(ind, "file", None)
                if not file_val or not isinstance(file_val, str):
                    if errors is not None:
                        errors.append(f"Malformed indicator: invalid file attribute: {file_val}")
                    continue
                key = (
                    file_val,
                    getattr(ind, "line", None),
                    getattr(ind, "category", None),
                    getattr(ind, "indicator_type", None),
                    getattr(ind, "evidence", None)
                )
                if key not in ind_seen:
                    ind_seen.add(key)
                    unique_inds.append(ind)
            except Exception as e:
                if errors is not None:
                    errors.append(f"Malformed indicator error: {str(e)}")
    except Exception as e:
        if errors is not None:
            errors.append(f"Failed parsing security indicators: {str(e)}")

    unique_routes = []
    route_seen = set()
    try:
        raw_routes = []
        for x in (getattr(report, "routes", []) or []):
            if x is None:
                if errors is not None:
                    errors.append("Malformed route: None found")
                continue
            raw_routes.append(x)

        sorted_routes = sorted(
            raw_routes,
            key=lambda x: (
                getattr(x, "file", None) or "",
                getattr(x, "line", None) or 0,
                getattr(x, "method", None) or "",
                getattr(x, "pattern", None) or "",
                getattr(x, "evidence", None) or ""
            )
        )
        for r in sorted_routes:
            try:
                file_val = getattr(r, "file", None)
                if not file_val or not isinstance(file_val, str):
                    if errors is not None:
                        errors.append(f"Malformed route: invalid file attribute: {file_val}")
                    continue
                key = (
                    file_val,
                    getattr(r, "line", None),
                    getattr(r, "method", None),
                    getattr(r, "pattern", None),
                    getattr(r, "evidence", None)
                )
                if key not in route_seen:
                    route_seen.add(key)
                    unique_routes.append(r)
            except Exception as e:
                if errors is not None:
                    errors.append(f"Malformed route error: {str(e)}")
    except Exception as e:
        if errors is not None:
            errors.append(f"Failed parsing routes: {str(e)}")

    unique_eps = []
    ep_seen = set()
    try:
        raw_eps = []
        for x in (getattr(report, "entry_points", []) or []):
            if x is None:
                if errors is not None:
                    errors.append("Malformed entry point: None found")
                continue
            raw_eps.append(x)

        sorted_eps = sorted(
            raw_eps,
            key=lambda x: (
                getattr(x, "file", None) or "",
                getattr(x, "line", None) or 0,
                getattr(x, "type", None) or "",
                getattr(x, "description", None) or ""
            )
        )
        for ep in sorted_eps:
            try:
                file_val = getattr(ep, "file", None)
                if not file_val or not isinstance(file_val, str):
                    if errors is not None:
                        errors.append(f"Malformed entry point: invalid file attribute: {file_val}")
                    continue
                key = (
                    file_val,
                    getattr(ep, "line", None),
                    getattr(ep, "type", None),
                    getattr(ep, "description", None)
                )
                if key not in ep_seen:
                    ep_seen.add(key)
                    unique_eps.append(ep)
            except Exception as e:
                if errors is not None:
                    errors.append(f"Malformed entry point error: {str(e)}")
    except Exception as e:
        if errors is not None:
            errors.append(f"Failed parsing entry points: {str(e)}")

    unique_manifests = []
    manifest_seen = set()
    try:
        raw_manifests = []
        for x in (getattr(report, "manifests", []) or []):
            if x is None:
                if errors is not None:
                    errors.append("Malformed manifest: None found")
                continue
            raw_manifests.append(x)

        sorted_manifests = sorted(
            raw_manifests,
            key=lambda x: (
                getattr(x, "file", None) or "",
                getattr(x, "ecosystem", None) or ""
            )
        )
        for m in sorted_manifests:
            try:
                file_val = getattr(m, "file", None)
                if not file_val or not isinstance(file_val, str):
                    if errors is not None:
                        errors.append(f"Malformed manifest: invalid file attribute: {file_val}")
                    continue
                key = (file_val, getattr(m, "ecosystem", None))
                if key not in manifest_seen:
                    manifest_seen.add(key)
                    unique_manifests.append(m)
            except Exception as e:
                if errors is not None:
                    errors.append(f"Malformed manifest error: {str(e)}")
    except Exception as e:
        if errors is not None:
            errors.append(f"Failed parsing manifests: {str(e)}")

    # Group candidates by file
    inds_by_file = {}
    for ind in unique_inds:
        inds_by_file.setdefault(ind.file, []).append(ind)

    routes_by_file = {}
    for r in unique_routes:
        routes_by_file.setdefault(r.file, []).append(r)

    eps_by_file = {}
    for ep in unique_eps:
        eps_by_file.setdefault(ep.file, []).append(ep)

    # Proximity helper
    def check_proximity(line1: Optional[int], line2: Optional[int]) -> bool:
        if line1 is None or line2 is None:
            return True
        return abs(line1 - line2) <= 50

    # Rule 1: Subprocess execution + Reachable route (command_injection)
    for filepath, file_inds in inds_by_file.items():
        subprocess_file_inds = [ind for ind in file_inds if ind.category == "subprocess"]
        file_routes = routes_by_file.get(filepath, [])
        if subprocess_file_inds and file_routes:
            correlations = 0
            for ind in subprocess_file_inds:
                for route in file_routes:
                    if correlations >= 50:
                        break
                    if not check_proximity(ind.line, route.line):
                        continue

                    identity = {
                        "rule": "command_injection",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": ind.evidence
                        },
                        "route": {
                            "file": route.file,
                            "line": route.line,
                            "method": route.method,
                            "pattern": route.pattern,
                            "evidence": route.evidence
                        }
                    }
                    hyp_id = generate_hypothesis_id("command_injection", identity, is_llm=False)
                    
                    ev_ref1 = validate_and_create_evidence_ref(
                        "security_indicator", ind.file, ind.line, f"Subprocess call: {ind.evidence}", repo_root
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "route", route.file, route.line, f"Route: {route.method} {route.pattern}", repo_root
                    )
                    if ev_ref1 and ev_ref2:
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential Local Command Injection via Endpoint",
                            description=f"A subprocess execution indicator in '{ind.file}' correlates with route '{route.method} {route.pattern}'.",
                            category="command_injection",
                            severity="HIGH",
                            confidence=0.85,
                            evidence_references=refs,
                            rationale=f"The HTTP route '{route.method} {route.pattern}' resides in the same file as a subprocess execution call.",
                            affected_paths=[ind.file]
                        ))
                        correlations += 1

    # Rule 2: SQL construction + Reachable route (sql_injection)
    for filepath, file_inds in inds_by_file.items():
        db_file_inds = [
            ind for ind in file_inds
            if ind.category == "database" and ind.indicator_type == "raw_sql_construction_indicator"
        ]
        file_routes = routes_by_file.get(filepath, [])
        if db_file_inds and file_routes:
            correlations = 0
            for ind in db_file_inds:
                for route in file_routes:
                    if correlations >= 50:
                        break
                    if not check_proximity(ind.line, route.line):
                        continue

                    identity = {
                        "rule": "sql_injection",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": ind.evidence
                        },
                        "route": {
                            "file": route.file,
                            "line": route.line,
                            "method": route.method,
                            "pattern": route.pattern,
                            "evidence": route.evidence
                        }
                    }
                    hyp_id = generate_hypothesis_id("sql_injection", identity, is_llm=False)
                    
                    ev_ref1 = validate_and_create_evidence_ref(
                        "security_indicator", ind.file, ind.line, f"Database indicator: {ind.evidence}", repo_root
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "route", route.file, route.line, f"Route: {route.method} {route.pattern}", repo_root
                    )
                    if ev_ref1 and ev_ref2:
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential Local SQL Injection",
                            description=f"A raw SQL construction indicator in '{ind.file}' correlates with route '{route.method} {route.pattern}'.",
                            category="sql_injection",
                            severity="HIGH",
                            confidence=0.80,
                            evidence_references=refs,
                            rationale=f"The endpoint '{route.method} {route.pattern}' is defined in a file containing raw SQL query builders.",
                            affected_paths=[ind.file]
                        ))
                        correlations += 1

    # Rule 3: Deserialization / Unsafe Eval + Entry Point (remote_code_execution)
    for filepath, file_inds in inds_by_file.items():
        serialization_file_inds = [ind for ind in file_inds if ind.category == "serialization"]
        file_eps = eps_by_file.get(filepath, [])
        if serialization_file_inds and file_eps:
            correlations = 0
            for ind in serialization_file_inds:
                for ep in file_eps:
                    if correlations >= 50:
                        break
                    if not check_proximity(ind.line, ep.line):
                        continue

                    identity = {
                        "rule": "remote_code_execution",
                        "ind": {
                            "category": ind.category,
                            "indicator_type": ind.indicator_type,
                            "file": ind.file,
                            "line": ind.line,
                            "evidence": ind.evidence
                        },
                        "entry_point": {
                            "file": ep.file,
                            "type": ep.type,
                            "description": ep.description,
                            "line": ep.line
                        }
                    }
                    hyp_id = generate_hypothesis_id("remote_code_execution", identity, is_llm=False)
                    
                    ev_ref1 = validate_and_create_evidence_ref(
                        "security_indicator", ind.file, ind.line, f"Serialization call: {ind.evidence}", repo_root
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "entry_point", ep.file, ep.line, f"Entry point: {ep.type} ({ep.description})", repo_root
                    )
                    if ev_ref1 and ev_ref2:
                        refs = [ev_ref1, ev_ref2]
                        refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential Local Code Execution via Entry Point",
                            description=f"An unsafe serialization/eval indicator in '{ind.file}' correlates with entry point '{ep.type}'.",
                            category="remote_code_execution",
                            severity="CRITICAL",
                            confidence=0.90,
                            evidence_references=refs,
                            rationale="An application entry point is located in the same file as unsafe serialization.",
                            affected_paths=[ind.file]
                        ))
                        correlations += 1

    # Rule 4: Cloud Secrets / Cloud SDK + Web Framework (credential_exposure)
    cloud_indicators = [
        ind for ind in unique_inds if ind.category in ("cloud_sdk", "secret_config")
    ]
    frameworks = getattr(report.repository, "frameworks", []) if (report and hasattr(report, "repository")) else []
    if cloud_indicators and frameworks:
        sorted_frameworks = sorted(list(set(frameworks)))
        framework_list_str = ", ".join(sorted_frameworks)
        for ind in cloud_indicators:
            identity = {
                "rule": "credential_exposure",
                "ind": {
                    "category": ind.category,
                    "indicator_type": ind.indicator_type,
                    "file": ind.file,
                    "line": ind.line,
                    "evidence": ind.evidence
                },
                "frameworks": sorted_frameworks
            }
            hyp_id = generate_hypothesis_id("credential_exposure", identity, is_llm=False)
            
            ev_ref = validate_and_create_evidence_ref(
                "security_indicator", ind.file, ind.line, f"Cloud/Secrets indicator: {ind.evidence}", repo_root
            )
            if ev_ref:
                refs = [ev_ref]
                candidates.append(SecurityHypothesis(
                    id=hyp_id,
                    title="Potential Cloud Credential / Config Exposure",
                    description=f"A cloud SDK or secret configuration reference in '{ind.file}' on line {ind.line} was found in a project using framework(s): {framework_list_str}.",
                    category="credential_exposure",
                    severity="MEDIUM",
                    confidence=0.75,
                    evidence_references=refs,
                    rationale=f"The application utilizes the web framework(s) {framework_list_str} and references secrets.",
                    affected_paths=[ind.file]
                ))

    # Single-Indicator and config rules for comprehensive category coverage
    # Exposed Secrets (independent)
    for ind in unique_inds:
        try:
            if ind.category == "secret_config":
                ref = validate_and_create_evidence_ref(
                    "security_indicator", ind.file, ind.line, f"Exposed secret config: {ind.evidence}", repo_root
                )
                if ref:
                    identity = {"rule": "ind_secret", "file": ind.file, "line": ind.line, "evidence": ind.evidence}
                    hyp_id = generate_hypothesis_id("credential_exposure", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Potential Exposed Config Secrets",
                        description=f"Config secret key detected in {ind.file} at line {ind.line}.",
                        category="credential_exposure",
                        severity="HIGH",
                        confidence=0.90,
                        evidence_references=[ref],
                        rationale="A plain text config secret/variable assignment was observed.",
                        affected_paths=[ind.file]
                    ))
        except Exception:
            pass

    # Insecure Auth/Authz
    for ind in unique_inds:
        try:
            if ind.category in ("authentication", "authorization"):
                ref = validate_and_create_evidence_ref(
                    "security_indicator", ind.file, ind.line, f"Access control: {ind.evidence}", repo_root
                )
                if ref:
                    identity = {"rule": "ind_auth", "file": ind.file, "line": ind.line, "evidence": ind.evidence}
                    hyp_id = generate_hypothesis_id("insecure_auth", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Potential Weak Access Control Checks",
                        description=f"Access control or auth pattern found in {ind.file} at line {ind.line}.",
                        category="insecure_auth",
                        severity="MEDIUM",
                        confidence=0.75,
                        evidence_references=[ref],
                        rationale="Sensitive role checks or auth variables are referenced in code.",
                        affected_paths=[ind.file]
                    ))
        except Exception:
            pass

    # Path Traversal
    for ind in unique_inds:
        try:
            if ind.category == "filesystem":
                ref = validate_and_create_evidence_ref(
                    "security_indicator", ind.file, ind.line, f"Filesystem access: {ind.evidence}", repo_root
                )
                if ref:
                    identity = {"rule": "ind_file", "file": ind.file, "line": ind.line, "evidence": ind.evidence}
                    hyp_id = generate_hypothesis_id("path_traversal", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Potential Path Traversal / Arbitrary File Manipulation",
                        description=f"Filesystem read/write operations detected in {ind.file} at line {ind.line}.",
                        category="path_traversal",
                        severity="HIGH",
                        confidence=0.80,
                        evidence_references=[ref],
                        rationale="An open or write operation occurs in code; lack of verification can cause path traversal.",
                        affected_paths=[ind.file]
                    ))
        except Exception:
            pass

    # Insecure dependencies
    for m in unique_manifests:
        try:
            target_deps = [d for d in m.dependencies if d.lower() in ("express", "fastapi", "flask", "django", "requests", "boto3", "actix-web")]
            if target_deps:
                ref = validate_and_create_evidence_ref(
                    "file", m.file, None, f"Dependency manifest containing framework usage: {m.ecosystem}", repo_root
                )
                if ref:
                    identity = {"rule": "manifest_deps", "file": m.file, "deps": sorted(target_deps)}
                    hyp_id = generate_hypothesis_id("insecure_dependency", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Potential Vulnerable Manifest Dependency",
                        description=f"Dependencies {', '.join(target_deps)} detected in {m.file}.",
                        category="insecure_dependency",
                        severity="MEDIUM",
                        confidence=0.75,
                        evidence_references=[ref],
                        rationale="The project imports third party library dependencies.",
                        affected_paths=[m.file]
                    ))
        except Exception:
            pass

    # Exposed debug
    for r in unique_routes:
        try:
            r_lower = r.pattern.lower()
            if any(x in r_lower for x in ("debug", "dev", "status", "health", "admin", "metrics")):
                ref = validate_and_create_evidence_ref(
                    "route", r.file, r.line, f"Route: {r.method} {r.pattern}", repo_root
                )
                if ref:
                    identity = {"rule": "route_debug", "file": r.file, "line": r.line, "pattern": r.pattern}
                    hyp_id = generate_hypothesis_id("exposed_debug", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Potential Exposed Debug / Status Endpoint",
                        description=f"Status or debug route '{r.method} {r.pattern}' found in {r.file}.",
                        category="exposed_debug",
                        severity="MEDIUM",
                        confidence=0.80,
                        evidence_references=[ref],
                        rationale="Development or status helper endpoints can leak internals.",
                        affected_paths=[r.file]
                    ))
        except Exception:
            pass

    # Insecure configurations (only generate if file name is explicitly suspicious)
    summary = getattr(report, "repository", None)
    if summary:
        try:
            for conf_f in getattr(summary, "config_files", []):
                f_name = os.path.basename(conf_f).lower()
                if any(x in f_name for x in ("secret", "private", "key", "cred", "auth", "token", ".env", "passwd", "shadow")):
                    ref = validate_and_create_evidence_ref("file", conf_f, None, "Suspicious configuration file", repo_root)
                    if ref:
                        identity = {"rule": "summary_config", "file": conf_f}
                        hyp_id = generate_hypothesis_id("insecure_config", identity, is_llm=False)
                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential Configuration File Vulnerability",
                            description=f"Static config file {conf_f} found.",
                            category="insecure_config",
                            severity="LOW",
                            confidence=0.70,
                            evidence_references=[ref],
                            rationale="Exposed configuration files can leak system setup metadata.",
                            affected_paths=[conf_f]
                        ))
        except Exception:
            pass

    # Dangerous CI/CD (only generate if file name is explicitly suspicious or contains warning keywords)
    if summary:
        try:
            for cicd_f in getattr(summary, "cicd_configs", []):
                f_name = os.path.basename(cicd_f).lower()
                if any(x in f_name for x in ("deploy", "publish", "release", "admin", "secret")):
                    ref = validate_and_create_evidence_ref("file", cicd_f, None, "CI/CD Pipeline file", repo_root)
                    if ref:
                        identity = {"rule": "summary_cicd", "file": cicd_f}
                        hyp_id = generate_hypothesis_id("dangerous_cicd", identity, is_llm=False)
                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential CI/CD Execution Misconfiguration",
                            description=f"CI/CD workflow configuration found in {cicd_f}.",
                            category="dangerous_cicd",
                            severity="MEDIUM",
                            confidence=0.80,
                            evidence_references=[ref],
                            rationale="CI/CD workflows running on pull request events are susceptible to code injection.",
                            affected_paths=[cicd_f]
                        ))
        except Exception:
            pass

    # Infrastructure/Container (only generate if file name contains deploy/production/privileged indicators)
    if summary:
        try:
            for dock_f in getattr(summary, "docker_configs", []):
                f_name = os.path.basename(dock_f).lower()
                if any(x in f_name for x in ("deploy", "prod", "priv", "root", "docker-compose")):
                    ref = validate_and_create_evidence_ref("file", dock_f, None, "Container deployment file", repo_root)
                    if ref:
                        identity = {"rule": "summary_docker", "file": dock_f}
                        hyp_id = generate_hypothesis_id("infrastructure_misconfig", identity, is_llm=False)
                        candidates.append(SecurityHypothesis(
                            id=hyp_id,
                            title="Potential Container Security Misconfiguration",
                            description=f"Docker or container runtime config found in {dock_f}.",
                            category="infrastructure_misconfig",
                            severity="MEDIUM",
                            confidence=0.75,
                            evidence_references=[ref],
                            rationale="Container execution as privileged root exposes host endpoints.",
                            affected_paths=[dock_f]
                        ))
        except Exception:
            pass

    # Network entry point (only generate for actual network-facing interfaces, excluding cli/main)
    for ep in unique_eps:
        try:
            if ep.type.lower() not in ("cli/script", "main", "cli", "script"):
                ref = validate_and_create_evidence_ref("entry_point", ep.file, ep.line, f"Entry point: {ep.type}", repo_root)
                if ref:
                    identity = {"rule": "summary_ep", "file": ep.file, "type": ep.type, "line": ep.line}
                    hyp_id = generate_hypothesis_id("network_exposure", identity, is_llm=False)
                    candidates.append(SecurityHypothesis(
                        id=hyp_id,
                        title="Suspicious Network-Facing Entry Point",
                        description=f"Application execution entry point '{ep.type}' found in {ep.file}.",
                        category="network_exposure",
                        severity="MEDIUM",
                        confidence=0.75,
                        evidence_references=[ref],
                        rationale="Execution entry points expose execution interfaces to inputs.",
                        affected_paths=[ep.file]
                    ))
        except Exception:
            pass

    return candidates
