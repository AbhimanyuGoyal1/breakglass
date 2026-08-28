"""Security indicator rules and pattern detection logic."""

import re
from typing import List, Tuple, Optional
from breakglass.inspection.models import SecurityIndicator, RouteCandidate


class IndicatorPattern:
    """Definition of a security indicator regex pattern."""
    def __init__(
        self,
        category: str,
        indicator_type: str,
        pattern: str,
        confidence: float = 0.8,
        flags: int = re.IGNORECASE,
        file_extensions: Optional[List[str]] = None
    ):
        self.category = category
        self.indicator_type = indicator_type
        self.pattern = pattern
        self.regex = re.compile(pattern, flags)
        self.confidence = confidence
        self.file_extensions = file_extensions


# Predefined security indicator patterns across ecosystems
INDICATOR_PATTERNS: List[IndicatorPattern] = [
    # Subprocess / System Command Execution
    IndicatorPattern(
        category="subprocess",
        indicator_type="subprocess_execution_indicator",
        pattern=r"\b(subprocess\.(Popen|run|call|check_output|check_call)|os\.(system|popen|exec[l|v]e?)|child_process\.(exec|spawn|execSync|spawnSync)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\.Command|(system|passthru|shell_exec|exec)\s*\()",
        confidence=0.9
    ),

    # Database / Storage
    IndicatorPattern(
        category="database",
        indicator_type="database_query_indicator",
        pattern=r"\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+[\s\S]+?\s+SET|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|db\.query|db\.execute|connection\.query|entityManager\.|prisma\.|mongoose\.|knex\(|gorm\.)",
        confidence=0.75
    ),
    IndicatorPattern(
        category="database",
        indicator_type="raw_sql_construction_indicator",
        pattern=r"(\bexecute\s*\(\s*f[\"']|\bquery\s*\(\s*f[\"']|\braw\s*\(\s*f[\"']|SELECT\s+.*?\+\s*\w+|SELECT\s+.*?%s|\bSQL\b.*?\+)",
        confidence=0.85
    ),

    # Authentication & Session
    IndicatorPattern(
        category="authentication",
        indicator_type="authentication_symbol_indicator",
        pattern=r"\b(login|authenticate|verify_password|check_password|bcrypt\.compare|argon2|jwt\.verify|jwt\.decode|passport\.authenticate|Session|login_user|logout|OAuth2|auth_token)\b",
        confidence=0.8
    ),

    # Authorization & Permission Controls
    IndicatorPattern(
        category="authorization",
        indicator_type="authorization_check_indicator",
        pattern=r"\b(check_permission|has_permission|is_admin|authorize|is_authorized|user\.can|guard\.|rbac|can_access|permission_required|require_role)\b",
        confidence=0.8
    ),

    # Filesystem Operations
    IndicatorPattern(
        category="filesystem",
        indicator_type="filesystem_access_indicator",
        pattern=r"\b(open\s*\(|readFile|writeFile|createReadStream|createWriteStream|fs\.(read|write|unlink|mkdir|rmdir|chmod)|FileInputStream|FileOutputStream|File\.read|File\.write)",
        confidence=0.7
    ),

    # File Upload / Download
    IndicatorPattern(
        category="file_upload",
        indicator_type="file_upload_handling_indicator",
        pattern=r"\b(multer|UploadedFile|request\.files|FileStorage|multipart\/form-data|FormFile|save_uploaded_file|parse_multipart)\b",
        confidence=0.85
    ),

    # Serialization / Deserialization & Unsafe Eval
    IndicatorPattern(
        category="serialization",
        indicator_type="unsafe_deserialization_indicator",
        pattern=r"\b(pickle\.loads?|yaml\.unsafe_load|yaml\.load\([^,)]*\)|eval\s*\(|exec\s*\(|marshal\.loads?|ObjectInputStream|unserialize\s*\(|JSON\.parse\s*\([^)]*eval)",
        confidence=0.9
    ),

    # Template Rendering
    IndicatorPattern(
        category="template",
        indicator_type="template_rendering_indicator",
        pattern=r"\b(render_template|render_template_string|Jinja2|ejs\.render|pug\.compile|handlebars\.compile|render\s*\(\s*['\"][^'\"]+\.(html|hbs|ejs|pug|j2)\b)",
        confidence=0.75
    ),

    # Outbound Network Request / HTTP Clients
    IndicatorPattern(
        category="network",
        indicator_type="outbound_http_indicator",
        pattern=r"\b(requests\.(get|post|put|delete|patch|head|request)|http\.Get|http\.Post|fetch\s*\(|axios\.(get|post|request)|urllib\.request|HttpClient|cURL|Got\.(get|post)|restTemplate)",
        confidence=0.75
    ),

    # Cloud SDK / Infrastructure Services
    IndicatorPattern(
        category="cloud_sdk",
        indicator_type="cloud_sdk_indicator",
        pattern=r"\b(boto3|@aws-sdk|google-cloud|azure-storage|S3Client|DynamoDB|SQSClient|CloudWatch|CosmosClient)\b",
        confidence=0.8
    ),

    # Secrets / Environment / Config References
    IndicatorPattern(
        category="secret_config",
        indicator_type="secret_config_reference_indicator",
        pattern=r"\b(process\.env|os\.getenv|os\.environ|config\.get|dotenv|API_KEY|SECRET_KEY|JWT_SECRET|DB_PASSWORD|PRIVATE_KEY)\b",
        confidence=0.7
    )
]

# HTTP Route candidate patterns across major web frameworks
ROUTE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Flask / FastAPI / Python decorator routes
    (re.compile(r"""@(app|router|api|blueprint|bp)\.(get|post|put|delete|patch|options|head|route)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE), "python_decorator"),
    # Express / Node.js app.get('/route', ...) / router.post(...)
    (re.compile(r"""\b(app|router)\.(get|post|put|delete|patch|options|head|all|use)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE), "node_express"),
    # Go (Gin, Echo, Chi, Gorilla, net/http) - supports arbitrary Go receiver identifiers
    (re.compile(r"""\b([a-zA-Z_][a-zA-Z0-9_]*)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|HandleFunc|Handle)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE), "go_web"),
    # Java Spring (@GetMapping("/route"), @RequestMapping(...))
    (re.compile(r"""@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(value\s*=\s*)?['"]([^'"]+)['"]""", re.IGNORECASE), "java_spring"),
    # Ruby Rails / Sinatra (get '/route', post '/route')
    (re.compile(r"""\b(get|post|put|delete|patch|match)\s+['"]([^'"]+)['"]""", re.IGNORECASE), "ruby_route")
]


def scan_line_for_indicators(
    line: str,
    line_num: int,
    file_rel_path: str
) -> List[SecurityIndicator]:
    """Scans a single line of text for security indicators."""
    indicators = []
    # Avoid scanning extremely long lines or minified code
    if len(line) > 1000:
        return indicators

    stripped = line.strip()
    if not stripped or stripped.startswith(("//", "#", "/*", "*", "<!--")):
        # Skip pure comment lines for security indicators to reduce noise
        return indicators

    for rule in INDICATOR_PATTERNS:
        match = rule.regex.search(line)
        if match:
            # Extract evidence snippet (max 120 chars)
            start = max(0, match.start() - 10)
            end = min(len(line), match.end() + 30)
            snippet = line[start:end].strip()

            indicators.append(
                SecurityIndicator(
                    category=rule.category,
                    indicator_type=rule.indicator_type,
                    file=file_rel_path,
                    line=line_num,
                    evidence=snippet,
                    confidence=rule.confidence
                )
            )

    return indicators


def scan_line_for_routes(
    line: str,
    line_num: int,
    file_rel_path: str
) -> List[RouteCandidate]:
    """Scans a line for HTTP API/route candidate definitions."""
    routes = []
    if len(line) > 1000:
        return routes

    for regex, framework in ROUTE_PATTERNS:
        match = regex.search(line)
        if match:
            groups = match.groups()
            if framework == "python_decorator":
                method = groups[1].upper() if groups[1] != "route" else "ALL"
                pattern = groups[2]
            elif framework == "node_express":
                method = groups[1].upper()
                pattern = groups[2]
            elif framework == "go_web":
                raw_method = groups[1].upper()
                method = "ALL" if raw_method in ("HANDLEFUNC", "HANDLE") else raw_method
                pattern = groups[2]
            elif framework == "java_spring":
                annotation = groups[0]
                if annotation.lower() in ("requestmapping", "@requestmapping"):
                    method = "ALL"
                else:
                    method = annotation.replace("Mapping", "").replace("@", "").upper()
                pattern = groups[2]
            elif framework == "ruby_route":
                method = groups[0].upper()
                pattern = groups[1]
            else:
                method = "GET"
                pattern = "/"

            routes.append(
                RouteCandidate(
                    file=file_rel_path,
                    line=line_num,
                    method=method,
                    pattern=pattern,
                    evidence=line.strip()[:100],
                    confidence=0.85
                )
            )

    return routes
