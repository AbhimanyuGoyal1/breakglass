from __future__ import annotations
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from breakglass.reasoning.models import SecurityHypothesis, EvidenceReference, generate_hypothesis_id
from breakglass.inspection.scanner import _is_contained_in
from breakglass.inspection.models import RepositoryReport
from breakglass.inspection.indicators import redact_secrets

def validate_and_create_evidence_ref(
    ref_type: str,
    file_rel_path: str,
    line: Optional[int],
    detail: str,
    repo_root: str,
    report: Optional[RepositoryReport] = None
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
        
        ref = EvidenceReference(
            type=ref_type,
            file=file_rel_path.replace("\\", "/"),
            line=line,
            detail=clean_detail
        )

        if report is not None:
            from breakglass.evidence.auth import authenticate_evidence_reference
            valid, auth_detail = authenticate_evidence_reference(ref, report, repo_root)
            if not valid:
                return None
            ref.detail = auth_detail

        return ref
    except Exception:
        return None

def create_authenticated_evidence_ref(
    file_rel_path: str,
    line: int,
    repo_root: str,
    report: RepositoryReport
) -> Optional[EvidenceReference]:
    for ind in getattr(report, "security_indicators", []) or []:
        if ind and getattr(ind, "file", None) == file_rel_path and getattr(ind, "line", None) == line:
            category = ind.category
            evidence = ind.evidence
            from breakglass.inspection.indicators import redact_secrets
            redacted_evidence = redact_secrets(evidence)
            if category == "subprocess":
                detail = f"Subprocess call: {redacted_evidence}"
            elif category == "database":
                detail = f"Database indicator: {redacted_evidence}"
            elif category == "serialization":
                detail = f"Serialization call: {redacted_evidence}"
            elif category in ("cloud_sdk", "secret_config"):
                detail = f"Cloud/Secrets indicator: {redacted_evidence}"
            elif category in ("authentication", "authorization"):
                detail = f"Access control: {redacted_evidence}"
            elif category == "filesystem":
                detail = f"Filesystem access: {redacted_evidence}"
            else:
                detail = f"Security indicator: {redacted_evidence}"
            return validate_and_create_evidence_ref("security_indicator", file_rel_path, line, detail, repo_root, report)
            
    for r in getattr(report, "routes", []) or []:
        if r and getattr(r, "file", None) == file_rel_path and getattr(r, "line", None) == line:
            detail = f"Route: {r.method} {r.pattern}"
            return validate_and_create_evidence_ref("route", file_rel_path, line, detail, repo_root, report)
            
    for ep in getattr(report, "entry_points", []) or []:
        if ep and getattr(ep, "file", None) == file_rel_path and getattr(ep, "line", None) == line:
            detail = f"Entry point: {ep.type} ({ep.description})"
            return validate_and_create_evidence_ref("entry_point", file_rel_path, line, detail, repo_root, report)
            
    return None

import ast

def analyze_file_for_attack_chains(
    file_rel_path: str,
    repo_root: str,
    report: RepositoryReport
) -> List[SecurityHypothesis]:
    abs_path = os.path.join(repo_root, file_rel_path)
    if not os.path.exists(abs_path):
        return []

    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    ext = os.path.splitext(file_rel_path)[1].lower()

    sources = []       # list of {"line": int, "var": str, "detail": str}
    taints = []        # list of {"line": int, "var": str, "detail": str}
    sinks = []         # list of {"line": int, "var": str, "detail": str, "category": str, "method": str}
    auth_calls = []    # list of {"line": int, "detail": str}

    SINKS_BY_CATEGORY = {
        "sql_injection": {"execute", "query", "raw", "execute_sql"},
        "command_injection": {"Popen", "run", "call", "check_output", "check_call", "system", "popen", "execCommand", "spawn"},
        "path_traversal": {"open", "readFile", "writeFile", "createReadStream", "createWriteStream", "read", "write", "unlink"},
        "untrusted_input_execution": {"render_template", "render_template_string", "render", "compile", "eval", "exec"},
        "network_exposure": {"get", "post", "put", "delete", "patch", "request", "fetch", "Get", "Post"}
    }

    if ext == ".py":
        try:
            tree = ast.parse(content)

            class ASTFlowVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.sources = {}
                    self.taints = {}
                    self.sinks = []
                    self.auths = []

                def _is_source_expr(self, node):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Attribute):
                            if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                                return True
                            if isinstance(sub.value, ast.Attribute) and isinstance(sub.value.value, ast.Name) and sub.value.value.id == "request":
                                return True
                        elif isinstance(sub, ast.Subscript):
                            if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                                return True
                            if isinstance(sub.value, ast.Attribute) and isinstance(sub.value.value, ast.Name) and sub.value.value.id == "request":
                                return True
                    return False

                def visit_Assign(self, node):
                    targets = []
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            targets.append(t.id)
                        elif isinstance(t, ast.Subscript):
                            if isinstance(t.value, ast.Name) and t.value.id == "session":
                                self.auths.append((node.lineno, "session state modification"))

                    if not targets:
                        self.generic_visit(node)
                        return

                    is_src = self._is_source_expr(node.value)
                    if is_src:
                        for t in targets:
                            self.sources[t] = node.lineno
                    else:
                        depends_on_taint = False
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Name) and (sub.id in self.sources or sub.id in self.taints):
                                depends_on_taint = True
                                break
                            if isinstance(sub, ast.JoinedStr):
                                for val in sub.values:
                                    if isinstance(val, ast.FormattedValue):
                                        for s in ast.walk(val.value):
                                            if isinstance(s, ast.Name) and (s.id in self.sources or s.id in self.taints):
                                                depends_on_taint = True
                                                break
                        if depends_on_taint:
                            for t in targets:
                                self.taints[t] = node.lineno

                    self.generic_visit(node)

                def visit_Call(self, node):
                    method_name = None
                    if isinstance(node.func, ast.Attribute):
                        method_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        method_name = node.func.id

                    if method_name:
                        for cat, methods in SINKS_BY_CATEGORY.items():
                            if method_name in methods:
                                is_tainted = False
                                tainted_var = None
                                for arg in node.args:
                                    if isinstance(arg, ast.Name):
                                        if arg.id in self.sources or arg.id in self.taints:
                                            is_tainted = True
                                            tainted_var = arg.id
                                    elif isinstance(arg, ast.JoinedStr):
                                        for val in arg.values:
                                            if isinstance(val, ast.FormattedValue):
                                                for s in ast.walk(val.value):
                                                    if isinstance(s, ast.Name) and (s.id in self.sources or s.id in self.taints):
                                                        is_tainted = True
                                                        tainted_var = s.id
                                                        break
                                if is_tainted:
                                    self.sinks.append((node.lineno, tainted_var, cat, method_name))
                                    break

                        if method_name in ("redirect", "login_user", "authenticate", "login"):
                            self.auths.append((node.lineno, f"call to {method_name}"))

                    self.generic_visit(node)

            visitor = ASTFlowVisitor()
            visitor.visit(tree)

            for var, line in visitor.sources.items():
                sources.append({"line": line, "var": var, "detail": f"user-controlled variable '{var}' initialized"})
            for var, line in visitor.taints.items():
                taints.append({"line": line, "var": var, "detail": f"tainted variable '{var}' propagated"})
            for line, var, cat, method in visitor.sinks:
                sinks.append({"line": line, "var": var, "category": cat, "method": method, "detail": f"tainted input passed to database/system execution: {method}({var or ''})"})
            for line, detail in visitor.auths:
                auth_calls.append({"line": line, "detail": f"authentication context action: {detail}"})

        except Exception:
            pass

    if not sources and not sinks:
        lines = content.splitlines()
        src_pattern = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*.*?\b(request|req|params|input)\b", re.IGNORECASE)
        sink_pattern = re.compile(r"\b(execute|query|raw|execute_sql|system|popen|run|open|readFile|writeFile|render_template|fetch)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)?\b", re.IGNORECASE)
        auth_pattern = re.compile(r"\b(session\b.*?=|\bredirect\s*\(|\blogin_user\s*\(|\blogin\s*\()", re.IGNORECASE)

        tainted_vars = set()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue

            m_src = src_pattern.search(line)
            if m_src:
                var = m_src.group(1)
                tainted_vars.add(var)
                sources.append({"line": idx, "var": var, "detail": f"user-controlled variable '{var}' initialized"})
                continue

            if tainted_vars:
                assign_match = re.match(r"\s*\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
                if assign_match:
                    target_var = assign_match.group(1)
                    rhs = line[assign_match.end():]
                    if any(re.search(rf"\b{re.escape(v)}\b", rhs) for v in tainted_vars):
                        tainted_vars.add(target_var)
                        taints.append({"line": idx, "var": target_var, "detail": f"tainted variable '{target_var}' propagated"})
                        continue

            m_sink = sink_pattern.search(line)
            if m_sink:
                func_name = m_sink.group(1)
                arg_var = m_sink.group(2)
                is_sink_tainted = False
                if arg_var and arg_var in tainted_vars:
                    is_sink_tainted = True
                elif any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted_vars):
                    is_sink_tainted = True

                if is_sink_tainted:
                    cat = "sql_injection"
                    for c, methods in SINKS_BY_CATEGORY.items():
                        if func_name in methods:
                            cat = c
                            break
                    sinks.append({"line": idx, "var": arg_var, "category": cat, "method": func_name, "detail": f"untrusted input passed to security-sensitive API: {func_name}"})

            m_auth = auth_pattern.search(line)
            if m_auth:
                auth_calls.append({"line": idx, "detail": f"authentication context action: {m_auth.group(1)}"})

    hypotheses = []

    for sink in sinks:
        cat = sink["category"]
        sink_line = sink["line"]

        refs = []
        for src in sources:
            ref = create_authenticated_evidence_ref(file_rel_path, src["line"], repo_root, report)
            if ref:
                refs.append(ref)
        for t in taints:
            ref = create_authenticated_evidence_ref(file_rel_path, t["line"], repo_root, report)
            if ref:
                refs.append(ref)
        ref = create_authenticated_evidence_ref(file_rel_path, sink_line, repo_root, report)
        if ref:
            refs.append(ref)
        for a in auth_calls:
            ref = create_authenticated_evidence_ref(file_rel_path, a["line"], repo_root, report)
            if ref:
                refs.append(ref)

        file_routes = getattr(report, "routes", []) or []
        route_decorator = None
        min_dist = 9999
        for r in file_routes:
            if r.file == file_rel_path and r.line <= sink_line and r.pattern.startswith("/"):
                dist = sink_line - r.line
                if dist < min_dist:
                    min_dist = dist
                    route_decorator = r
        if route_decorator:
            ref = create_authenticated_evidence_ref(file_rel_path, route_decorator.line, repo_root, report)
            if ref:
                refs.append(ref)

        unique_refs = []
        seen_ref_keys = set()
        for ref in refs:
            key = (ref.file, ref.line, ref.type, ref.detail)
            if key not in seen_ref_keys:
                seen_ref_keys.add(key)
                unique_refs.append(ref)
        unique_refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))

        if len(unique_refs) > 5:
            unique_refs = unique_refs[:5]

        if not unique_refs:
            continue

        has_auth = any(
            "access control" in getattr(r, "detail", "").lower() or
            "session" in getattr(r, "detail", "").lower() or
            "authentication" in getattr(r, "detail", "").lower()
            for r in unique_refs
        )
        if cat == "sql_injection":
            if has_auth:
                title = "SQL Injection leading to Authentication Bypass"
                desc = f"Attacker-controlled input is interpolated into an SQL query on line {sink_line} and executed, leading to authentication bypass via session state establishment."
                severity = "CRITICAL"
                confidence = 0.95
                rationale = "An attacker can bypass authentication by manipulating the SQL query executed in the login handler."
            else:
                title = "Potential SQL Injection"
                desc = f"Attacker-controlled input is interpolated into an SQL query and executed on line {sink_line}."
                severity = "HIGH"
                confidence = 0.90
                rationale = "User-controlled input is concatenated or formatted directly into a database query string."
        elif cat == "command_injection":
            title = "Potential Remote Code Execution via Command Injection"
            desc = f"Attacker-controlled input is passed directly to command execution sink '{sink['method']}' on line {sink_line}."
            severity = "CRITICAL"
            confidence = 0.95
            rationale = "Execution of system commands with untrusted parameters can lead to remote code execution."
        elif cat == "path_traversal":
            title = "Potential Path Traversal / Arbitrary File Access"
            desc = f"Attacker-controlled input is passed to filesystem operation '{sink['method']}' on line {sink_line}."
            severity = "HIGH"
            confidence = 0.90
            rationale = "Accessing files using unvalidated user input exposes system files to path traversal."
        elif cat == "untrusted_input_execution":
            title = "Potential Server-Side Template Injection (SSTI)"
            desc = f"Attacker-controlled input is passed to template rendering function '{sink['method']}' on line {sink_line}."
            severity = "HIGH"
            confidence = 0.85
            rationale = "Rendering raw user input inside templates can lead to arbitrary code execution."
        else:
            title = "Potential Untrusted Input Execution"
            desc = f"Attacker-controlled input is passed to security-sensitive API '{sink['method']}' on line {sink_line}."
            severity = "MEDIUM"
            confidence = 0.80
            rationale = "User input reaches an execution sink without proper sanitization."

        identity = {
            "rule": "attack_chain",
            "file": file_rel_path,
            "category": cat,
            "lines": [r.line for r in unique_refs if r.line is not None],
            "has_auth": has_auth
        }
        hyp_id = generate_hypothesis_id(cat, identity, is_llm=False)

        hypotheses.append(SecurityHypothesis(
            id=hyp_id,
            title=title,
            description=desc,
            category=cat,
            severity=severity,
            confidence=confidence,
            evidence_references=unique_refs,
            rationale=rationale,
            affected_paths=[file_rel_path]
        ))

    return hypotheses

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

    # Run data-flow attack chain analysis on all candidate source files
    chain_files = set()
    all_files = set(inds_by_file.keys()) | set(routes_by_file.keys())
    for filepath in sorted(list(all_files)):
        chains = analyze_file_for_attack_chains(filepath, repo_root, report)
        if chains:
            candidates.extend(chains)
            chain_files.add(filepath)

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
                            "evidence": redact_secrets(ind.evidence)
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
                        "security_indicator", ind.file, ind.line, f"Subprocess call: {ind.evidence}", repo_root, report
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "route", route.file, route.line, f"Route: {route.method} {route.pattern}", repo_root, report
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
                            "evidence": redact_secrets(ind.evidence)
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
                        "security_indicator", ind.file, ind.line, f"Database indicator: {ind.evidence}", repo_root, report
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "route", route.file, route.line, f"Route: {route.method} {route.pattern}", repo_root, report
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
                            "evidence": redact_secrets(ind.evidence)
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
                        "security_indicator", ind.file, ind.line, f"Serialization call: {ind.evidence}", repo_root, report
                    )
                    ev_ref2 = validate_and_create_evidence_ref(
                        "entry_point", ep.file, ep.line, f"Entry point: {ep.type} ({ep.description})", repo_root, report
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
                    "evidence": redact_secrets(ind.evidence)
                },
                "frameworks": sorted_frameworks
            }
            hyp_id = generate_hypothesis_id("credential_exposure", identity, is_llm=False)
            
            ev_ref = validate_and_create_evidence_ref(
                "security_indicator", ind.file, ind.line, f"Cloud/Secrets indicator: {ind.evidence}", repo_root, report
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
    # Exposed Secrets (consolidated by file)
    secrets_inds_by_file = {}
    for ind in unique_inds:
        if ind.category == "secret_config":
            secrets_inds_by_file.setdefault(ind.file, []).append(ind)

    for filepath, file_secret_inds in secrets_inds_by_file.items():
        refs = []
        for ind in file_secret_inds:
            ref = validate_and_create_evidence_ref(
                "security_indicator", ind.file, ind.line, f"Exposed secret config: {ind.evidence}", repo_root, report
            )
            if ref:
                refs.append(ref)

        if refs:
            refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))
            lines = [r.line for r in refs if r.line is not None]
            identity = {"rule": "consolidated_secret", "file": filepath, "lines": lines}
            hyp_id = generate_hypothesis_id("credential_exposure", identity, is_llm=False)
            candidates.append(SecurityHypothesis(
                id=hyp_id,
                title="Potential Exposed Config Secrets",
                description=f"Config secret keys detected in {filepath} at lines: {', '.join(map(str, lines))}.",
                category="credential_exposure",
                severity="HIGH",
                confidence=0.90,
                evidence_references=refs,
                rationale="A plain text config secret/variable assignment was observed.",
                affected_paths=[filepath]
            ))

    # Insecure Auth/Authz (consolidated by file, suppressed if stronger attack chain exists)
    auth_inds_by_file = {}
    for ind in unique_inds:
        if ind.category in ("authentication", "authorization"):
            auth_inds_by_file.setdefault(ind.file, []).append(ind)

    for filepath, file_auth_inds in auth_inds_by_file.items():
        if filepath in chain_files:
            continue

        refs = []
        for ind in file_auth_inds:
            ref = validate_and_create_evidence_ref(
                "security_indicator", ind.file, ind.line, f"Access control: {ind.evidence}", repo_root, report
            )
            if ref:
                refs.append(ref)

        if refs:
            refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))
            lines = [r.line for r in refs if r.line is not None]
            identity = {"rule": "consolidated_auth", "file": filepath, "lines": lines}
            hyp_id = generate_hypothesis_id("insecure_auth", identity, is_llm=False)
            candidates.append(SecurityHypothesis(
                id=hyp_id,
                title="Potential Weak Access Control Checks",
                description=f"Access control or auth patterns found in {filepath} at lines: {', '.join(map(str, lines))}.",
                category="insecure_auth",
                severity="MEDIUM",
                confidence=0.75,
                evidence_references=refs,
                rationale="Sensitive role checks or auth variables are referenced in code.",
                affected_paths=[filepath]
            ))

    # Path Traversal (consolidated by file, suppressed if stronger attack chain exists)
    filesystem_inds_by_file = {}
    for ind in unique_inds:
        if ind.category == "filesystem":
            filesystem_inds_by_file.setdefault(ind.file, []).append(ind)

    for filepath, file_file_inds in filesystem_inds_by_file.items():
        if filepath in chain_files:
            continue

        refs = []
        for ind in file_file_inds:
            ref = validate_and_create_evidence_ref(
                "security_indicator", ind.file, ind.line, f"Filesystem access: {ind.evidence}", repo_root, report
            )
            if ref:
                refs.append(ref)

        if refs:
            refs.sort(key=lambda x: (x.file, x.line or 0, x.type, x.detail))
            lines = [r.line for r in refs if r.line is not None]
            identity = {"rule": "consolidated_file", "file": filepath, "lines": lines}
            hyp_id = generate_hypothesis_id("path_traversal", identity, is_llm=False)
            candidates.append(SecurityHypothesis(
                id=hyp_id,
                title="Potential Path Traversal / Arbitrary File Manipulation",
                description=f"Filesystem read/write operations detected in {filepath} at lines: {', '.join(map(str, lines))}.",
                category="path_traversal",
                severity="HIGH",
                confidence=0.80,
                evidence_references=refs,
                rationale="An open or write operation occurs in code; lack of verification can cause path traversal.",
                affected_paths=[filepath]
            ))

    # Insecure dependencies
    for m in unique_manifests:
        try:
            target_deps = [d for d in m.dependencies if d.lower() in ("express", "fastapi", "flask", "django", "requests", "boto3", "actix-web")]
            if target_deps:
                ref = validate_and_create_evidence_ref(
                    "file", m.file, None, f"Dependency manifest containing framework usage: {m.ecosystem}", repo_root, report
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
                    "route", r.file, r.line, f"Route: {r.method} {r.pattern}", repo_root, report
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
                    ref = validate_and_create_evidence_ref("file", conf_f, None, "Suspicious configuration file", repo_root, report)
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
                    ref = validate_and_create_evidence_ref("file", cicd_f, None, "CI/CD Pipeline file", repo_root, report)
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
                    ref = validate_and_create_evidence_ref("file", dock_f, None, "Container deployment file", repo_root, report)
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
                ref = validate_and_create_evidence_ref("entry_point", ep.file, ep.line, f"Entry point: {ep.type}", repo_root, report)
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
