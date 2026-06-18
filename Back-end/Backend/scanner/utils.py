import shutil
import logging
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse, urlunparse

from .findings import normalize_finding
from .scan_config import sanitize_scan_config_for_storage



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("recon")



TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")




def normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()

    if not re.match(r"^https?://", raw):
        raw = "http://" + raw

    parsed = urlparse(raw)
    domain = parsed.hostname or parsed.path

    if domain and domain.startswith("www."):
        domain = domain[4:]

    return domain


def normalize_target(raw: str) -> dict:
    raw_text = str(raw or "").strip()
    if not raw_text:
        return {"domain": "", "target": "", "input": ""}

    parse_input = raw_text if re.match(r"^https?://", raw_text, re.I) else f"http://{raw_text}"
    parsed = urlparse(parse_input)
    hostname = (parsed.hostname or parsed.path or "").strip("[]").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    netloc = parsed.netloc or hostname
    if parsed.hostname:
        netloc = parsed.hostname
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
    if ":" in hostname and not hostname.count("."):
        netloc = f"[{hostname}]"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

    local_hostnames = {"localhost", "127.0.0.1", "::1"}
    is_localish = (
        hostname in local_hostnames
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or re.match(r"^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.", hostname)
    )
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else ("http" if is_localish else "https")
    if not re.match(r"^https?://", raw_text, re.I) and not is_localish:
        scheme = "https"

    target = f"{scheme}://{netloc}".rstrip("/")
    return {"domain": hostname, "target": target, "input": raw_text}




REQUIRED_TOOLS = {
    "subdomain": ["subfinder", "amass"],
    "ports": ["naabu", "nmap"],
    "fuzz": ["ffuf", "gobuster"],
    "extraction": ["katana", "gau"],
    "vulns": ["nuclei"],
    "targeted": ["dalfox"],
    "osint": ["theHarvester"],
    "screenshot": ["gowitness", "eyewitness"],
    "s3scanner": [],
    "crlfuzz": ["crlfuzz"],
}


def _find_local_tool(name: str) -> str | None:
    search_dirs = [
        TOOLS_DIR,
        os.getenv("SCANNER_TOOLS_DIR", ""),
        r"D:\recon\tools",
        r"D:\Projects\recon\tools",
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/.local/bin"),
    ]
    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for ext in [".exe", "", ".bat", ".cmd"]:
            path = os.path.join(d, name + ext)
            if os.path.isfile(path):
                return path
    return None


def check_tool(name: str) -> bool:
    if shutil.which(name) is not None:
        return True
    return _find_local_tool(name) is not None


def get_tool_path(name: str) -> str:
    system_path = shutil.which(name)
    if system_path:
        return system_path
    local_path = _find_local_tool(name)
    if local_path:
        return local_path
    return name  


def get_available_tool(category: str) -> str | None:
    for tool in REQUIRED_TOOLS.get(category, []):
        if check_tool(tool):
            return tool
    return None


def check_all_tools() -> dict:
    status = {}
    for category, tools in REQUIRED_TOOLS.items():
        status[category] = {}
        for tool in tools:
            status[category][tool] = check_tool(tool)

    
    sqlmap_path = os.path.join(TOOLS_DIR, "sqlmap-master", "sqlmap.py")
    status["targeted"]["sqlmap"] = os.path.exists(sqlmap_path)

    return status


FINDING_CONTAINER_FIELDS = (
    "vulns",
    "security_header_findings",
    "security_headers_findings",
    "sensitive_file_findings",
    "sensitive_files_findings",
    "sensitive_findings",
    "fuzz_findings",
    "port_findings",
    "crlf_findings",
    "takeover_findings",
    "nuclei_findings",
    "form_findings",
    "form_vulns",
    "targeted_findings",
    "targeted_vulns",
    "websocket_findings",
    "js_findings",
    "js_check_findings",
)

SCAN_FINDING_CONTAINERS = (
    ("findings",),
    ("js_checks", "findings"),
    ("js_secrets", "findings"),
    ("targeted_vulns", "findings"),
    ("sensitive_files", "findings"),
    ("security_headers", "findings"),
)

TELEMETRY_FIELD_NAMES = {
    "alive_telemetry": "alive",
    "port_telemetry": "ports",
    "ports_telemetry": "ports",
    "ports_scan_telemetry": "ports",
    "fuzz_telemetry": "fuzz",
    "nuclei_telemetry": "vuln",
    "takeover_telemetry": "subdomain_takeover",
    "form_telemetry": "form_scanner",
    "targeted_telemetry": "targeted_vulns",
    "crlf_telemetry": "crlfuzz",
    "websocket_telemetry": "websocket_scanner",
    "js_telemetry": "js_checks",
    "js_checks_telemetry": "js_checks",
    "sensitive_files_telemetry": "sensitive_files",
    "sensitive_file_telemetry": "sensitive_files",
    "security_headers_telemetry": "security_headers",
    "security_header_telemetry": "security_headers",
    "subdomain_telemetry": "subdomain",
}

SCAN_TELEMETRY_PATHS = (
    ("subdomain_telemetry", "subdomain"),
    ("targeted_vulns", "targeted_telemetry", "targeted_vulns"),
    ("js_checks", "telemetry", "js_checks"),
    ("js_checks", "js_telemetry", "js_checks"),
    ("js_secrets", "telemetry", "js_checks"),
    ("js_secrets", "js_telemetry", "js_checks"),
    ("sensitive_files", "telemetry", "sensitive_files"),
    ("security_headers", "telemetry", "security_headers"),
)


def _as_list(value) -> list:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _nested_get(data: dict, path: tuple[str, ...]):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


AI_REPORT_SNIPPET_LIMIT = 300
REPORT_REDACTION_PATTERNS = [
    re.compile(
        r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(
        r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid)"
        r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]


def _redact_report_text(value, limit: int | None = None) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = REPORT_REDACTION_PATTERNS[0].sub("<redacted-private-key>", text)
    text = REPORT_REDACTION_PATTERNS[2].sub("Bearer <redacted>", text)
    text = REPORT_REDACTION_PATTERNS[3].sub("<redacted-jwt>", text)
    text = REPORT_REDACTION_PATTERNS[1].sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] if limit else text


def _first_report_evidence_text(finding: dict) -> str:
    evidence = finding.get("evidence") or finding.get("evidence_items") or ""
    if isinstance(evidence, list) and evidence:
        first = evidence[0]
        if isinstance(first, dict):
            return str(first.get("value") or "")
        return str(first)
    if isinstance(evidence, dict):
        return str(evidence.get("value") or "")
    return str(evidence or "")


def _finding_text_blob(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    response_summary = finding.get("response_summary", {}) if isinstance(finding.get("response_summary"), dict) else {}
    pieces = [
        finding.get("id"),
        finding.get("name"),
        finding.get("description"),
        finding.get("url"),
        finding.get("matched_at"),
        finding.get("parameter"),
        _first_report_evidence_text(finding),
        response_summary.get("status_code"),
        response_summary.get("snippet"),
        response_summary.get("content_type"),
    ]
    for key in (
        "template-id", "template_id", "matcher-name", "classification_reason",
        "extracted_results", "source_line", "source_excerpt", "curl-command",
    ):
        pieces.append(raw.get(key))
    try:
        pieces.append(json.dumps(raw, ensure_ascii=False)[:2000])
    except Exception:
        pass
    return " ".join(str(piece or "") for piece in pieces)


def _short_evidence_summary(finding: dict, limit: int = AI_REPORT_SNIPPET_LIMIT) -> str:
    raw_text = (
        _first_report_evidence_text(finding)
        or finding.get("description")
        or (finding.get("response_summary", {}) or {}).get("snippet")
        or finding.get("name")
        or finding.get("id")
        or ""
    )
    return _redact_report_text(raw_text, limit)


def _finding_source_tool(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    return str(finding.get("source_tool") or raw.get("source_tool") or finding.get("scanner_name") or finding.get("scanner") or "")


def _finding_template_id(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    return str(raw.get("template-id") or raw.get("template_id") or finding.get("template-id") or "")


def _apply_error_disclosure_classification(finding: dict) -> dict:
    text_blob = _finding_text_blob(finding).lower()
    if not text_blob:
        return finding
    aspnet_markers = (
        "asp.net", "x-aspnet-version", "x-powered-by", "server error in '/' application",
        "string was not recognized as a valid datetime", "system.web", "stack trace",
    )
    generic_markers = ("http 500", "status_code\": 500", "internal server error", "exception", "stack trace")
    has_aspnet = any(marker in text_blob for marker in aspnet_markers)
    has_error = has_aspnet or any(marker in text_blob for marker in generic_markers)
    if not has_error:
        return finding
    if finding.get("status") not in {"recon", "candidate", "inconclusive"}:
        return finding

    raw = dict(finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {})
    finding["vuln_type"] = "aspnet_error_disclosure" if has_aspnet else "error_disclosure"
    finding["category"] = "exposure"
    finding["name"] = "ASP.NET Error Disclosure" if has_aspnet else "Error Disclosure"
    finding["status"] = "candidate" if has_aspnet or "500" in text_blob or "internal server error" in text_blob else "recon"
    finding["severity"] = "medium" if "stack trace" in text_blob or "server error in '/' application" in text_blob else "low"
    try:
        finding["confidence"] = max(float(finding.get("confidence") or 0), 0.6 if has_aspnet else 0.55)
    except (TypeError, ValueError):
        finding["confidence"] = 0.6 if has_aspnet else 0.55
    finding["description"] = (
        "Existing scanner evidence indicates framework/error disclosure. "
        "Treat as a validation candidate unless manually confirmed in an authorized workflow."
    )
    raw["classification_reason"] = "report_layer_error_disclosure_from_existing_evidence"
    raw["ai_ready_evidence_summary"] = _short_evidence_summary(finding)
    finding["raw"] = raw
    return finding


def _assign_evidence_ids(findings: list[dict]) -> list[dict]:
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        raw = dict(finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {})
        evidence_id = finding.get("evidence_id") or raw.get("evidence_id") or f"EVID-{index:04d}"
        finding["evidence_id"] = evidence_id
        raw["evidence_id"] = evidence_id
        finding["evidence_summary"] = finding.get("evidence_summary") or _short_evidence_summary(finding)
        finding["raw"] = raw
    return findings


def _ai_finding_summary(finding: dict) -> dict:
    return {
        "evidence_id": finding.get("evidence_id", ""),
        "id": finding.get("id", ""),
        "title": finding.get("name") or finding.get("id", ""),
        "status": finding.get("status", ""),
        "severity": finding.get("severity", ""),
        "confidence": finding.get("confidence", 0),
        "vuln_type": finding.get("vuln_type", ""),
        "category": finding.get("category", ""),
        "module_name": finding.get("module_name", ""),
        "source_tool": _finding_source_tool(finding),
        "template_id": _finding_template_id(finding),
        "url": finding.get("url") or finding.get("matched_at") or "",
        "parameter": finding.get("parameter", ""),
        "candidate_strength": finding.get("candidate_strength", ""),
        "examples_count": finding.get("examples_count", 1),
        "evidence_summary": finding.get("evidence_summary") or _short_evidence_summary(finding),
    }


def _telemetry_ai_summary(telemetry: dict) -> dict:
    summary = {}
    interesting = (
        "requests", "requests_sent", "urls_tested", "targets_tested", "forms_tested",
        "payloads_sent", "findings_count", "candidates_count", "confirmed_count",
        "blocked_count", "inconclusive_count", "errors_count", "timeout_count",
        "duration", "duration_seconds", "elapsed_ms", "module_noise_score",
    )
    for module_name, item in (telemetry or {}).items():
        if not isinstance(item, dict):
            summary[module_name] = {"status": "present", "value": item}
            continue
        compact = {key: item.get(key) for key in interesting if key in item and item.get(key) not in ("", None)}
        if "samples" in item and isinstance(item["samples"], list):
            compact["samples_count"] = len(item["samples"])
        summary[module_name] = compact or {"status": "present"}
    return summary


def _top_risk_summaries(*groups: list[dict]) -> list[dict]:
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings = [finding for group in groups for finding in group]
    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_rank.get(str(finding.get("severity", "info")).lower(), 0),
            float(finding.get("confidence") or 0),
        ),
        reverse=True,
    )
    return [_ai_finding_summary(finding) for finding in ordered[:10]]


def _build_ai_report_context(
    *,
    domain: str,
    scan_data: dict,
    summary: dict,
    confirmed_findings: list[dict],
    strong_candidate_findings: list[dict],
    weak_candidate_findings: list[dict],
    recon_findings: list[dict],
    blocked_findings: list[dict],
    inconclusive_findings: list[dict],
    telemetry: dict,
) -> dict:
    return {
        "schema_version": "ai-report-context-v1",
        "llm_instructions": [
            "Use only normalized JSON and evidence_id references.",
            "Do not invent vulnerabilities or promote candidates to confirmed.",
            "Confirmed findings come from scanner evidence only, not LLM opinion.",
            "Say unknown when evidence is insufficient.",
            "Keep recommendations tied to cited evidence IDs.",
        ],
        "scan_metadata": {
            "scan_id": scan_data.get("scan_id", ""),
            "target": domain,
            "profile": scan_data.get("profile", "unknown"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "scan_config": sanitize_scan_config_for_storage(scan_data.get("scan_config", {})),
        "summary": summary,
        "confirmed_findings": [_ai_finding_summary(finding) for finding in confirmed_findings],
        "strong_candidates": [_ai_finding_summary(finding) for finding in strong_candidate_findings],
        "weak_candidates": [_ai_finding_summary(finding) for finding in weak_candidate_findings],
        "recon_observations": [_ai_finding_summary(finding) for finding in recon_findings[:50]],
        "blocked_or_inconclusive": [
            *[_ai_finding_summary(finding) for finding in blocked_findings],
            *[_ai_finding_summary(finding) for finding in inconclusive_findings],
        ],
        "top_risks": _top_risk_summaries(confirmed_findings, strong_candidate_findings, weak_candidate_findings),
        "telemetry_summary": _telemetry_ai_summary(telemetry),
        "limitations": [
            "This context is scanner output, not official benchmark ground truth.",
            "Candidates and recon observations require validation before remediation priority decisions.",
            "Authentication-required workflow flaws may be missed by unauthenticated smoke scans.",
        ],
        "recommended_next_actions": [
            "Review confirmed findings first.",
            "Validate strong and weak candidates in an authorized lab/profile before promotion.",
            "Use evidence_id values when generating human-facing report claims.",
            "Add authenticated benchmark coverage for workflow and session findings.",
        ],
    }


def _report_finding_key(normalized: dict) -> tuple:
    return (
        str(normalized.get("module_name") or normalized.get("scanner_name") or normalized.get("scanner") or "").lower(),
        str(normalized.get("id") or normalized.get("type") or "").lower(),
        str(normalized.get("url") or normalized.get("matched_at") or normalized.get("matched") or "").lower().rstrip("/"),
        str(normalized.get("parameter") or normalized.get("param") or "").lower(),
        str(normalized.get("status") or "").lower(),
    )


def _restore_report_finding_extras(normalized: dict) -> dict:
    raw = normalized.get("raw", {}) if isinstance(normalized.get("raw"), dict) else {}
    for field_name in ("candidate_strength", "examples_count", "normalized_route", "grouped_examples"):
        if field_name in raw and field_name not in normalized:
            normalized[field_name] = raw[field_name]
    return normalized


def _collect_from_container(container, *, target: str, seen: set, collected: list[dict]) -> None:
    for finding in _as_list(container):
        if not isinstance(finding, dict):
            continue
        normalized = _apply_error_disclosure_classification(_restore_report_finding_extras(normalize_finding(finding)))
        if not normalized.get("target"):
            normalized["target"] = target
        key = _report_finding_key(normalized)
        if key in seen:
            continue
        seen.add(key)
        collected.append(normalized)


def _store_telemetry(modules: dict, module_hint: str, telemetry: dict) -> None:
    if not isinstance(telemetry, dict) or not telemetry:
        return
    module_name = str(telemetry.get("module_name") or module_hint or "unknown")
    existing = modules.get(module_name)
    if not existing:
        modules[module_name] = telemetry
        return
    if existing == telemetry:
        return
    if isinstance(existing, dict) and existing.get("module_name") == module_name and "samples" not in existing:
        modules[module_name] = {"module_name": module_name, "samples": [existing]}
        existing = modules[module_name]
    samples = existing.setdefault("samples", []) if isinstance(existing, dict) else []
    if telemetry not in samples and len(samples) < 20:
        samples.append(telemetry)


def _collect_report_telemetry(alive_hosts: list, scan_data: dict) -> dict:
    modules: dict = {}
    existing = scan_data.get("telemetry", {}) if isinstance(scan_data, dict) else {}
    if isinstance(existing, dict):
        for key, value in existing.items():
            if key == "modules" and isinstance(value, dict):
                for module_name, telemetry in value.items():
                    _store_telemetry(modules, str(module_name), telemetry)
            elif isinstance(value, dict):
                _store_telemetry(modules, key, value)
            else:
                modules[key] = value

    for path in SCAN_TELEMETRY_PATHS:
        *keys, module_hint = path
        value = _nested_get(scan_data, tuple(keys))
        _store_telemetry(modules, module_hint, value)

    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        for field_name, module_hint in TELEMETRY_FIELD_NAMES.items():
            _store_telemetry(modules, module_hint, host.get(field_name))

    return modules


def _is_nuclei_finding(finding: dict) -> bool:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    module_name = str(finding.get("module_name", "")).lower()
    scanner_name = str(finding.get("scanner_name") or finding.get("scanner") or "").lower()
    source_tool = str(finding.get("source_tool") or raw.get("source_tool") or "").lower()
    return module_name == "vuln" or scanner_name == "nuclei" or source_tool == "nuclei"


def _nuclei_findings(findings: list[dict]) -> list[dict]:
    return [finding for finding in findings if _is_nuclei_finding(finding)]


def _nuclei_finding_count(findings: list[dict]) -> int:
    return len(_nuclei_findings(findings))


def _is_security_header_finding(finding: dict) -> bool:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    module_name = str(finding.get("module_name") or finding.get("scanner_name") or "").lower()
    vuln_type = str(finding.get("vuln_type") or raw.get("type") or finding.get("id") or "").lower()
    parameter = str(finding.get("parameter") or raw.get("header") or "").lower()
    name = str(finding.get("name") or finding.get("type") or "").lower()
    return (
        module_name == "security_headers"
        or vuln_type in {"security_header", "header_disclosure", "cors"}
        or parameter in {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "access-control-allow-origin",
        }
        or name.startswith(("missing ", "header disclosure"))
    )


def _is_app_vulnerability_finding(finding: dict) -> bool:
    if _is_security_header_finding(finding) or _is_nuclei_finding(finding):
        return False
    if finding.get("status") not in {"confirmed", "candidate"}:
        return False
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    vuln_type = str(finding.get("vuln_type") or raw.get("type") or finding.get("id") or "").lower()
    return any(marker in vuln_type for marker in (
        "xss", "sql", "sqli", "lfi", "file_inclusion", "command_injection",
        "open_redirect", "ssrf", "idor", "csrf", "websocket",
    ))


_REPORT_DYNAMIC_VALUE_RE = re.compile(
    r"(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\d{4,})$"
)


def _normalized_report_route(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return (url or "").split("?", 1)[0].rstrip("/")
        path_segments = ["<id>" if _REPORT_DYNAMIC_VALUE_RE.match(part or "") else part for part in (parsed.path or "/").split("/")]
        normalized_path = ("/".join(path_segments) or "/").rstrip("/") or "/"
        query = parse_qs(parsed.query, keep_blank_values=True)
        normalized_query = "&".join(f"{key}=<value>" for key in sorted(query))
        return urlunparse(parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=normalized_path,
            params="",
            query=normalized_query,
            fragment="",
        )).rstrip("/")
    except Exception:
        return (url or "").split("?", 1)[0].rstrip("/")


def _normalized_report_base_path(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return (url or "").split("?", 1)[0].rstrip("/") or "/"
        path_segments = ["<id>" if _REPORT_DYNAMIC_VALUE_RE.match(part or "") else part for part in (parsed.path or "/").split("/")]
        normalized_path = ("/".join(path_segments) or "/").rstrip("/") or "/"
        return urlunparse(parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=normalized_path,
            params="",
            query="",
            fragment="",
        )).rstrip("/") or f"{parsed.scheme.lower()}://{parsed.netloc.lower()}/"
    except Exception:
        return (url or "").split("?", 1)[0].rstrip("/") or "/"


def _report_candidate_reason(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    evidence = finding.get("evidence") or []
    evidence_text = ""
    if isinstance(evidence, list) and evidence:
        first = evidence[0]
        evidence_text = str(first.get("comparison") or first.get("value") if isinstance(first, dict) else first)
    elif isinstance(evidence, dict):
        evidence_text = str(evidence.get("comparison") or evidence.get("value") or "")
    return str(
        raw.get("classification_reason")
        or raw.get("reason")
        or finding.get("reason")
        or evidence_text
        or finding.get("description")
        or ""
    ).lower()[:160]


def _report_candidate_strength(finding: dict) -> str:
    if finding.get("status") != "candidate":
        return ""
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    existing = str(finding.get("candidate_strength") or raw.get("candidate_strength") or "").lower()
    if existing in {"strong", "weak"}:
        return existing
    reason = str(raw.get("classification_reason") or "").lower()
    source_tool = str(finding.get("source_tool") or raw.get("source_tool") or finding.get("scanner_name") or "").lower()
    try:
        confidence = float(finding.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    weak_markers = (
        "gf_pattern", "parameter_name", "without_strong_parameter", "heuristic_only",
        "sql_error_without_payload_correlation", "weak_reference_parameter", "route_without",
        "without_ssrf_fetch", "without_lfi_payload",
    )
    if any(marker in reason for marker in weak_markers):
        return "weak"
    if confidence >= 0.65:
        return "strong"
    if source_tool in {"dalfox", "sqlmap"} and confidence >= 0.55 and "heuristic" not in reason:
        return "strong"
    return "weak"


def _report_candidate_example(finding: dict) -> dict:
    evidence = finding.get("evidence") or []
    evidence_text = ""
    if isinstance(evidence, list) and evidence:
        first = evidence[0]
        evidence_text = str(first.get("value") if isinstance(first, dict) else first)
    elif isinstance(evidence, dict):
        evidence_text = str(evidence.get("value") or "")
    return {
        "url": finding.get("url", ""),
        "parameter": finding.get("parameter", ""),
        "payload_used": finding.get("payload_used") or finding.get("payload") or "",
        "evidence": evidence_text[:220],
    }


def _group_report_candidates(findings: list[dict], max_weak_groups_per_base_path: int = 3) -> list[dict]:
    passthrough: list[dict] = []
    grouped: dict[tuple[str, str, str, str], dict] = {}
    weak_groups_per_path: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("status") != "candidate":
            passthrough.append(finding)
            continue
        raw = dict(finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {})
        strength = _report_candidate_strength(finding)
        base_path = _normalized_report_base_path(finding.get("url", ""))
        route = str(finding.get("normalized_route") or raw.get("normalized_route") or (
            base_path if strength == "weak" else _normalized_report_route(finding.get("url", ""))
        ))
        parameter = str(finding.get("parameter") or "").lower()
        vuln_type = str(finding.get("vuln_type") or finding.get("id") or "").lower()
        module_name = str(finding.get("module_name") or finding.get("scanner_name") or "").lower()
        reason = _report_candidate_reason(finding) if strength == "weak" else ""
        raw["candidate_strength"] = strength
        raw["normalized_route"] = route
        raw["normalized_base_path"] = base_path
        finding["candidate_strength"] = strength
        finding["normalized_route"] = route
        finding["raw"] = raw
        if not route:
            passthrough.append(finding)
            continue
        grouping_value = parameter if parameter else reason
        if not grouping_value and strength != "weak":
            passthrough.append(finding)
            continue
        key = (module_name, route, grouping_value, vuln_type)
        if key not in grouped:
            if strength == "weak":
                current_count = weak_groups_per_path.get(base_path, 0)
                if current_count >= max_weak_groups_per_base_path:
                    weak_groups_per_path[base_path] = current_count + 1
                    continue
                weak_groups_per_path[base_path] = current_count + 1
            raw.setdefault("examples_count", 1)
            raw.setdefault("grouped_examples", [_report_candidate_example(finding)])
            finding["examples_count"] = int(raw.get("examples_count") or 1)
            grouped[key] = finding
            continue
        current = grouped[key]
        current_raw = dict(current.get("raw", {}) if isinstance(current.get("raw"), dict) else {})
        examples = current_raw.get("grouped_examples") if isinstance(current_raw.get("grouped_examples"), list) else []
        if len(examples) < 10:
            examples.append(_report_candidate_example(finding))
        count = int(current_raw.get("examples_count") or current.get("examples_count") or 1) + 1
        current_raw["examples_count"] = count
        current_raw["grouped_examples"] = examples
        current["examples_count"] = count
        if _report_candidate_strength(current) == "weak" and strength == "strong":
            current["candidate_strength"] = "strong"
            current_raw["candidate_strength"] = "strong"
        try:
            if float(finding.get("confidence") or 0) > float(current.get("confidence") or 0):
                current["confidence"] = finding.get("confidence")
                if finding.get("severity"):
                    current["severity"] = finding.get("severity")
        except (TypeError, ValueError):
            pass
        base_description = current_raw.get("group_base_description") or current.get("description") or "Grouped candidate observation."
        current_raw["group_base_description"] = base_description
        current["description"] = f"{base_description} Grouped {count} similar candidate observations for normalized route {route}."
        current["raw"] = current_raw
    for finding in grouped.values():
        raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
        base_path = str(raw.get("normalized_base_path") or "")
        skipped = weak_groups_per_path.get(base_path, 0) - max_weak_groups_per_base_path
        if skipped > 0 and _report_candidate_strength(finding) == "weak":
            raw["suppressed_similar_weak_groups_for_path"] = skipped
            finding["raw"] = raw
    return passthrough + list(grouped.values())



def build_report(domain: str, subdomains: list, alive_hosts: list, scan_data: dict = None) -> dict:
    scan_data = scan_data or {}
    scan_config = sanitize_scan_config_for_storage(scan_data.get("scan_config", {}))
    scan_data["scan_config"] = scan_config

    ports_data = []
    fuzz_data = []
    vuln_data = []
    extraction_data = []
    
    
    processed_hosts = []
    for h in alive_hosts:
        host_entry = h.copy()
        normalized_vulns = [normalize_finding(v) for v in h.get("vulns", [])]
        if normalized_vulns:
            host_entry["vulns"] = normalized_vulns

        
        raw_host = host_entry.get("url", "").replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        
        if h.get("ports"):
            ports_data.append({
                "url": h["url"],
                "ports": h["ports"],
                "services": h.get("port_services", []),
                "findings": h.get("port_findings", []),
            })
        if h.get("endpoints"):
            fuzz_data.append({
                "url": h["url"],
                "endpoints": h["endpoints"],
                "findings": h.get("fuzz_findings", []),
            })
        if normalized_vulns:
            vuln_data.append({"url": h["url"], "vulns": normalized_vulns})
        if h.get("extracted_urls") or h.get("js_files"):
            extraction_data.append({
                "url": h["url"],
                "extracted_urls": h.get("extracted_urls", []),
                "js_files": h.get("js_files", []),
                "forms": h.get("forms", []),
            })

        

        
        js_secrets_data = scan_data.get("js_secrets", {})
        if js_secrets_data and "secrets" in js_secrets_data:
            host_secrets = [
                s for s in js_secrets_data["secrets"]
                if raw_host in s.get("url", "")
            ]
            host_entry["js_secrets"] = host_secrets

        
        targeted_data = scan_data.get("targeted_vulns", {})
        if targeted_data:
            host_tvulns = []
            for tv in targeted_data.get("findings", []):
                target_text = " ".join([
                    str(tv.get("url", "")),
                    str(tv.get("matched_at", "")),
                    str(tv.get("evidence", "")),
                    str(tv.get("details", "")),
                ])
                if raw_host and raw_host in target_text:
                    host_tvulns.append(tv)
            host_entry["targeted_vulns"] = host_tvulns

        processed_hosts.append(host_entry)

    
    all_secrets = scan_data.get("js_secrets", {}).get("secrets", [])
    all_targeted = (
        scan_data.get("targeted_vulns", {}).get("dalfox", []) +
        scan_data.get("targeted_vulns", {}).get("sqlmap", []) +
        scan_data.get("targeted_vulns", {}).get("lfi", [])
    )
    all_findings = _collect_report_findings(alive_hosts, scan_data)
    confirmed_findings = [f for f in all_findings if f.get("status") == "confirmed"]
    candidate_findings = [f for f in all_findings if f.get("status") == "candidate"]
    strong_candidate_findings = [f for f in candidate_findings if _report_candidate_strength(f) == "strong"]
    weak_candidate_findings = [f for f in candidate_findings if _report_candidate_strength(f) != "strong"]
    security_header_findings = [f for f in all_findings if _is_security_header_finding(f)]
    confirmed_app_findings = [f for f in confirmed_findings if _is_app_vulnerability_finding(f)]
    strong_app_candidate_findings = [f for f in strong_candidate_findings if _is_app_vulnerability_finding(f)]
    weak_app_candidate_findings = [f for f in weak_candidate_findings if _is_app_vulnerability_finding(f)]
    recon_findings = [f for f in all_findings if f.get("status") == "recon"]
    inconclusive_findings = [f for f in all_findings if f.get("status") == "inconclusive"]
    blocked_findings = [f for f in all_findings if f.get("status") == "blocked"]
    fuzz_findings = [f for f in all_findings if str(f.get("module_name") or "").lower() == "fuzz"]
    port_findings = [f for f in all_findings if str(f.get("module_name") or "").lower() == "ports"]
    legacy_vulns_count = sum(len(h.get("vulns", [])) for h in alive_hosts)
    nuclei_findings = _nuclei_findings(all_findings)
    nuclei_findings_count = len(nuclei_findings)

    
    enrichment = scan_data.get("enrichment", {})
    interesting_subdomains = enrichment.get("interesting_subdomains", [])
    subdomain_diff = scan_data.get("subdomain_diff", {})
    port_diff = scan_data.get("port_diff", {})
    s3_buckets = scan_data.get("s3_buckets", [])
    execution_modules = {}
    existing_telemetry = scan_data.get("telemetry", {}) if isinstance(scan_data, dict) else {}
    if isinstance(existing_telemetry, dict) and isinstance(existing_telemetry.get("modules"), dict):
        execution_modules = existing_telemetry.get("modules", {})
    telemetry = _collect_report_telemetry(alive_hosts, scan_data)
    if execution_modules:
        telemetry["modules"] = execution_modules
    scan_data["telemetry"] = telemetry
    nuclei_correlation = telemetry.get("nuclei_correlation", {}) if isinstance(telemetry, dict) else {}
    if not isinstance(nuclei_correlation, dict):
        nuclei_correlation = {}
    nuclei_telemetry = telemetry.get("vuln", {}) if isinstance(telemetry, dict) else {}
    if not isinstance(nuclei_telemetry, dict):
        nuclei_telemetry = {}
    correlated_findings_count = int(nuclei_correlation.get("correlated_findings_count") or 0)
    app_route_correlations = int(nuclei_correlation.get("app_route_correlations") or 0)
    security_header_correlations = int(nuclei_correlation.get("security_header_correlations") or 0)
    recon_correlations = int(nuclei_correlation.get("recon_correlations") or 0)

    summary = {
            "subdomains_found": len(set(subdomains)),
            "alive_hosts": len(alive_hosts),
            "open_services": sum(len(h.get("ports", [])) for h in alive_hosts),
            "endpoints_found": sum(len(h.get("endpoints", [])) for h in alive_hosts),
            "urls_extracted": sum(len(h.get("extracted_urls", [])) for h in alive_hosts),
            "js_files_found": sum(len(h.get("js_files", [])) for h in alive_hosts),
            "secrets_found": len(all_secrets),
            "targeted_vulns": len(all_targeted),
            "total_findings": len(all_findings),
            "confirmed_findings": len(confirmed_findings),
            "confirmed_app_vulns": len(confirmed_app_findings),
            "candidate_findings": len(candidate_findings),
            "strong_candidate_findings": len(strong_candidate_findings),
            "strong_app_candidates": len(strong_app_candidate_findings),
            "weak_candidate_findings": len(weak_candidate_findings),
            "weak_app_candidates": len(weak_app_candidate_findings),
            "security_header_findings": len(security_header_findings),
            "fuzz_findings": len(fuzz_findings),
            "port_findings": len(port_findings),
            "recon_items": len(recon_findings),
            "blocked_tests": len(blocked_findings),
            "inconclusive_tests": len(inconclusive_findings),
            "legacy_vulns_count": legacy_vulns_count,
            "nuclei_findings_count": nuclei_findings_count,
            "nuclei_findings": nuclei_findings_count,
            "nuclei_raw_findings_count": int(nuclei_telemetry.get("raw_findings_count") or 0),
            "nuclei_template_profile": nuclei_telemetry.get("template_profile") or "",
            "nuclei_requested_template_profile": nuclei_telemetry.get("requested_template_profile") or "",
            "nuclei_profile_safety_gate": nuclei_telemetry.get("profile_safety_gate") or "",
            "nuclei_target_type": nuclei_telemetry.get("target_type") or "",
            "nuclei_target_scope": nuclei_telemetry.get("target_scope") or "",
            "nuclei_targets_selected": int(nuclei_telemetry.get("targets_selected") or 0),
            "correlated_findings_count": correlated_findings_count,
            "correlated_findings": correlated_findings_count,
            "app_route_correlations": app_route_correlations,
            "security_header_correlations": security_header_correlations,
            "recon_correlations": recon_correlations,
            "confirmed_vulns": len(confirmed_findings),
            "candidate_issues": len(candidate_findings),
            "informational_findings": len(recon_findings),
            "waf_detected": sum(1 for h in alive_hosts if h.get("is_waf")),
            "interesting_subdomains": len(interesting_subdomains),
        }
    ai_report_context = _build_ai_report_context(
        domain=domain,
        scan_data=scan_data,
        summary=summary,
        confirmed_findings=confirmed_findings,
        strong_candidate_findings=strong_candidate_findings,
        weak_candidate_findings=weak_candidate_findings,
        recon_findings=recon_findings,
        blocked_findings=blocked_findings,
        inconclusive_findings=inconclusive_findings,
        telemetry=telemetry,
    )

    return {
        "schema_version": "phase1-evidence-v1",
        "scan_id": scan_data.get("scan_id", ""),
        "domain": domain,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "profile": scan_data.get("profile", "unknown"),
        "scan_config": scan_config,
        "summary": summary,

        
        "stages": {
            "subdomain_enumeration": {
                "count": len(set(subdomains)),
                "data": sorted(set(subdomains)),
                "interesting": interesting_subdomains,
                "new_since_last_scan": subdomain_diff.get("added", []),
                "removed_since_last_scan": subdomain_diff.get("removed", []),
            },
            "alive_probing": {
                "count": len(alive_hosts),
                "data": [
                    {
                        "url": h.get("url", ""),
                        "status": h.get("status", "unknown"),
                        "title": h.get("title", ""),
                        "tech": h.get("tech", []),
                        "response_time": h.get("response_time", 0),
                        "content_length": h.get("content_length", 0),
                        "is_waf": h.get("is_waf", False),
                        "waf_name": h.get("waf_name", ""),
                        "ports": h.get("ports", []),
                    }
                    for h in alive_hosts
                ]
            },
            "port_scanning": {
                "count": len(ports_data),
                "data": ports_data,
                "new_ports": port_diff.get("new_ports", {}),
            },
            "fuzzing": {
                "count": sum(len(e.get("endpoints", [])) for e in fuzz_data),
                "data": fuzz_data,
            },
            "extraction": {
                "count": sum(
                    len(e.get("extracted_urls", [])) + len(e.get("js_files", []))
                    for e in extraction_data
                ),
                "data": extraction_data,
            },
            "gf_patterns": {
                "summary": _build_gf_summary(alive_hosts),
            },
            "js_secrets": {
                "count": len(all_secrets),
                "data": all_secrets,
            },
            "targeted_vulns": {
                "count": len(all_targeted),
                "total": len(all_targeted),
                "xss": scan_data.get("targeted_vulns", {}).get("dalfox", []),
                "sqli": scan_data.get("targeted_vulns", {}).get("sqlmap", []),
            },
            "s3_buckets": {
                "count": len(s3_buckets),
                "data": s3_buckets,
            },
            "vulnerability_scanning": {
                "count": legacy_vulns_count,
                "normalized_finding_count": len(all_findings),
                "nuclei_findings_count": nuclei_findings_count,
                "nuclei_findings": nuclei_findings,
                "data": vuln_data,
            },
            "finding_summary": {
                "total": len(all_findings),
                "confirmed": len(confirmed_findings),
                "candidate": len(candidate_findings),
                "strong_candidate": len(strong_candidate_findings),
                "weak_candidate": len(weak_candidate_findings),
                "recon": len(recon_findings),
                "inconclusive": len(inconclusive_findings),
                "blocked": len(blocked_findings),
            },
        },

        
        "subdomains": sorted(set(subdomains)),
        "alive_hosts": processed_hosts,
        "findings": confirmed_findings,
        "confirmed_app_vulns": confirmed_app_findings,
        "candidates": candidate_findings,
        "strong_candidates": strong_candidate_findings,
        "strong_app_candidates": strong_app_candidate_findings,
        "weak_candidates": weak_candidate_findings,
        "weak_app_candidates": weak_app_candidate_findings,
        "security_headers": security_header_findings,
        "fuzz_findings": fuzz_findings,
        "port_findings": port_findings,
        "recon": recon_findings,
        "nuclei_findings": nuclei_findings,
        "inconclusive": inconclusive_findings,
        "blocked_tests": blocked_findings,
        "telemetry": telemetry,
        "ai_report_context": ai_report_context,
        "benchmark_ready": {
            "ground_truth_matching_fields": ["url", "parameter", "vuln_type", "status", "severity"],
            "requires_authorized_target": True,
        },
    }


def _collect_report_findings(alive_hosts: list, scan_data: dict | None = None) -> list[dict]:
    scan_data = scan_data or {}
    collected = []
    seen = set()
    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        target = host.get("subdomain") or host.get("url", "")
        for field_name in FINDING_CONTAINER_FIELDS:
            _collect_from_container(host.get(field_name), target=target, seen=seen, collected=collected)

    for path in SCAN_FINDING_CONTAINERS:
        _collect_from_container(_nested_get(scan_data, path), target="", seen=seen, collected=collected)

    return _assign_evidence_ids(_group_report_candidates(collected))


def _build_gf_summary(alive_hosts: list) -> dict:
    summary = {}
    for host in alive_hosts:
        for category, data in host.get("gf_patterns", {}).items():
            if category not in summary:
                summary[category] = {
                    "description": data["description"],
                    "color": data["color"],
                    "total_count": 0,
                    "sample_urls": [],
                }
            summary[category]["total_count"] += data["count"]
            
            remaining = 10 - len(summary[category]["sample_urls"])
            if remaining > 0:
                summary[category]["sample_urls"].extend(data["urls"][:remaining])
    return summary


def save_report(report: dict, output_dir: str = None) -> str:
    output_dir = output_dir or RESULTS_DIR
    os.makedirs(output_dir, exist_ok=True)
    domain = report.get("domain", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    log.info(f"Report saved -> {filepath}")
    return filepath

