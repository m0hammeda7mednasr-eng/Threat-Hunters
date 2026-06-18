from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse, urlunparse

import httpx

from .findings import Finding, dedupe_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import (
    extract_title,
    has_meaningful_diff,
    is_blocked_or_challenged,
    reflection_context,
    response_fingerprint,
)
from .scanner_types import EvidenceItem, utc_now
from .scan_config import external_tool_auth_policy, get_runtime_request_headers
from .utils import TOOLS_DIR, get_tool_path, log


MODULE_NAME = "targeted_vulns"
USER_AGENT = "Mozilla/5.0 Dragon-Recon/2.0"
BASE_HEADERS = {"User-Agent": USER_AGENT}
LOCAL_LAB_COMMAND_PROFILES = {"benchmark", "lab-only", "aggressive-lab-only"}
COMMAND_INJECTION_MARKER = "RECON_CMD_MARKER"
COMMAND_INJECTION_BASE_INPUT = "127.0.0.1"
COMMAND_INJECTION_PAYLOADS = [
    f"{COMMAND_INJECTION_BASE_INPUT}; echo {COMMAND_INJECTION_MARKER}",
    f"{COMMAND_INJECTION_BASE_INPUT} && echo {COMMAND_INJECTION_MARKER}",
    f"{COMMAND_INJECTION_BASE_INPUT} | echo {COMMAND_INJECTION_MARKER}",
]
SAFE_XSS_MARKER = "RECON_SAFE_REFLECT_MARKER"
SAFE_SQLI_PATHS = {"/showforum.asp", "/showthread.asp", "/templatize.asp"}
SAFE_TEMPLATE_PATHS = {"/templatize.asp"}
SAFE_TEMPLATE_INVALID_VALUES = [
    "html/__recontool_missing_template__.html",
    "./html/__recontool_missing_template__.html",
]

STATIC_EXTS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".mp4", ".mp3", ".avi", ".webm",
}


STATIC_EXTS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".mp4", ".mp3", ".avi", ".webm",
}

REFERENCE_URLS = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/Top10/",
    "https://cheatsheetseries.owasp.org/",
]

ROUTE_ALIASES = {
    "xss": "xss",
    "sqli": "sqli",
    "sql": "sqli",
    "lfi": "lfi",
    "path_traversal": "lfi",
    "redirect": "open_redirect",
    "open_redirect": "open_redirect",
    "ssrf": "ssrf",
    "rce": "command_injection",
    "command_injection": "command_injection",
    "stored_xss": "stored_xss",
}

ROUTE_ORDER = ("xss", "sqli", "lfi", "open_redirect", "ssrf", "command_injection", "stored_xss")

HIGH_PRIORITY_URL_SOURCES = {
    "user_seed",
    "form_discovered",
    "js_endpoint",
    "crawler_real_url",
    "explicit_target",
    "gf_pattern",
}

LOW_PRIORITY_URL_SOURCES = {
    "fuzz_discovered_real_response",
    "historical_url",
    "generated_url",
    "placeholder_url",
    "fuzz_template_url",
}

URL_SOURCE_PRIORITY = {
    "user_seed": 10,
    "explicit_target": 20,
    "form_discovered": 30,
    "js_endpoint": 40,
    "crawler_real_url": 50,
    "gf_pattern": 55,
    "fuzz_discovered_real_response": 70,
    "historical_url": 80,
    "generated_url": 90,
    "placeholder_url": 95,
    "fuzz_template_url": 100,
    "unknown": 110,
}

URL_SOURCE_FIELDS = {
    "seed_urls": "user_seed",
    "form_urls": "form_discovered",
    "form_actions": "form_discovered",
    "forms": "form_discovered",
    "js_endpoints": "js_endpoint",
    "javascript_endpoints": "js_endpoint",
    "api_endpoints": "js_endpoint",
    "extracted_urls": "crawler_real_url",
    "endpoints": "crawler_real_url",
    "urls": "crawler_real_url",
    "expanded_urls": "generated_url",
    "generated_urls": "generated_url",
    "historical_urls": "historical_url",
    "wayback_urls": "historical_url",
    "fuzz_urls": "fuzz_template_url",
    "fuzzed_urls": "fuzz_discovered_real_response",
}

PLACEHOLDER_URL_RE = re.compile(
    r"(?i)(\{\{\s*fuzz\s*\}\}|%fuzz%|__fuzz__|\bFUZZ\b|testFUZZ|PLACEHOLDER|"
    r"dragon[_-]?fuzz|recon[_-]?fuzz|fuzz[_-]?marker)"
)

MAX_WEAK_GENERATED_CANDIDATES = 25

PARAMETER_HINTS = {
    "xss": {
        "q", "query", "search", "searchterm", "search_term", "s", "keyword", "message",
        "msg", "comment", "name", "title", "callback", "return",
    },
    "sqli": {
        "id", "uid", "user", "userid", "item", "page_id", "product", "cat", "category",
        "sort", "order", "orderby", "order_by", "cylinder", "cylinders",
    },
    "lfi": {"file", "path", "page", "template", "include", "inc", "view", "doc", "document", "download", "folder"},
    "open_redirect": {"url", "uri", "redirect", "redirect_uri", "next", "return", "returnurl", "continue", "dest", "destination"},
    "ssrf": {"url", "uri", "target", "host", "endpoint", "webhook", "callback", "feed", "proxy", "ref", "referer"},
    "command_injection": {"cmd", "command", "exec", "execute", "ping", "host", "ip", "domain"},
    "stored_xss": {"mtxmessage", "message", "comment", "txtmessage"},
}

LOW_VALUE_LFI_ROUTE_PARAMS = {"page", "p", "size", "limit", "offset", "start", "rows", "per_page"}
SSRF_ROUTE_SUPPRESS_PARAMS = {
    "page", "p", "size", "limit", "offset", "start", "rows", "per_page",
    "search", "searchterm", "search_term", "q", "query", "sort", "orderby", "order_by",
}
WEAK_SSRF_REFERENCE_PARAMS = {"ref", "referer", "reference", "source"}
DYNAMIC_ROUTE_VALUE_RE = re.compile(
    r"(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|\d{4,})$"
)

LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../windows/win.ini",
    "file:///etc/passwd",
]

LFI_SIGNATURES = {
    "unix_passwd": re.compile(r"(?m)^(?:root:[^:\r\n]*:0:0:|daemon:x:\d+:\d+:|bin:x:\d+:\d+:)"),
    "windows_ini": re.compile(r"(?im)^(?:\[(?:fonts|extensions|mci extensions)\]|\[boot loader\])"),
    "php_source": re.compile(r"(?is)(?:<\?php|&lt;\?php).{0,400}(?:\$_(?:GET|POST|REQUEST)|include|require|mysql_|mysqli_)"),
}

SQL_ERROR_RE = re.compile(
    r"(?i)(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|You have an error in your SQL syntax)"
)

GENERIC_ERROR_MARKERS = [
    "404 not found",
    "page not found",
    "not found",
    "resource not found",
    "the requested url was not found",
    "server error",
    "an error occurred",
]

REDACTION_PATTERNS = [
    re.compile(
        r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(
        r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid|php[_-]?sessid)"
        r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]


def _redact_text(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = REDACTION_PATTERNS[0].sub("<redacted-private-key>", text)
    text = REDACTION_PATTERNS[2].sub("Bearer <redacted>", text)
    text = REDACTION_PATTERNS[3].sub("<redacted-jwt>", text)
    text = REDACTION_PATTERNS[1].sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    return text[:1600]


def _snippet(text: str, limit: int = 600) -> str:
    clean = _redact_text(text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:limit]


def _is_parameterized_dynamic_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in {"http", "https"} and not parsed.path.lower().endswith(tuple(STATIC_EXTS)))
    except Exception:
        return False


def _parameter_names(url: str) -> list[str]:
    try:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _first_parameter(url: str) -> str:
    params = _parameter_names(url)
    return params[0] if params else ""


def _url_with_payload(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [payload]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _url_without_parameter_values(url: str, parameter: str = "") -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url.rstrip("/")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if parameter and parameter in query:
        query[parameter] = ["<tested>"]
    else:
        query = {key: ["<tested>"] for key in sorted(query)}
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True))).rstrip("/")


def _normalized_path(path: str) -> str:
    raw_path = path or "/"
    segments = []
    for segment in raw_path.split("/"):
        if DYNAMIC_ROUTE_VALUE_RE.match(segment or ""):
            segments.append("<id>")
        else:
            segments.append(segment)
    normalized = "/".join(segments) or "/"
    return normalized.rstrip("/") or "/"


def _normalized_route_key(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return (url or "").split("?", 1)[0].rstrip("/")
        query = parse_qs(parsed.query, keep_blank_values=True)
        normalized_query = "&".join(f"{key}=<value>" for key in sorted(query))
        return urlunparse(parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=_normalized_path(parsed.path),
            params="",
            query=normalized_query,
            fragment="",
        )).rstrip("/")
    except Exception:
        return (url or "").split("?", 1)[0].rstrip("/")


def _first_evidence_value(finding: dict) -> str:
    evidence = finding.get("evidence") or finding.get("evidence_items") or ""
    if isinstance(evidence, list) and evidence:
        first = evidence[0]
        if isinstance(first, dict):
            return str(first.get("value") or "")
        return str(first)
    if isinstance(evidence, dict):
        return str(evidence.get("value") or "")
    return str(evidence or finding.get("description") or "")


def _route_candidate_skip_reason(category: str, parameter: str) -> str:
    normalized = (parameter or "").lower().replace("-", "_")
    if category == "lfi" and normalized in LOW_VALUE_LFI_ROUTE_PARAMS:
        return "low_value_numeric_parameter_without_lfi_payload_evidence"
    if category == "ssrf" and normalized in SSRF_ROUTE_SUPPRESS_PARAMS:
        return "low_value_parameter_without_ssrf_fetch_or_callback_evidence"
    return ""


def _candidate_strength(finding: dict) -> str:
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
        "sql_error_without_payload_correlation", "weak_reference_parameter",
        "route_without", "without_ssrf_fetch", "without_lfi_payload",
    )
    strong_markers = (
        "payload_correlated", "baseline", "control", "technique", "response_diff",
        "executable_context", "path_error_without_file_marker", "safe_reflection",
        "safe_sql", "safe_template",
    )
    if any(marker in reason for marker in weak_markers):
        return "weak"
    if confidence >= 0.65:
        return "strong"
    if source_tool in {"dalfox", "sqlmap"} and confidence >= 0.55 and "heuristic" not in reason:
        return "strong"
    if confidence >= 0.55 and any(marker in reason for marker in strong_markers):
        return "strong"
    return "weak"


def _mark_candidate_strength(finding: dict) -> dict:
    if finding.get("status") != "candidate":
        return finding
    raw = dict(finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {})
    strength = _candidate_strength(finding)
    finding["candidate_strength"] = strength
    raw["candidate_strength"] = strength
    finding["raw"] = raw
    return finding


def _candidate_example(finding: dict) -> dict:
    return {
        "url": _redact_text(finding.get("url", "")),
        "parameter": str(finding.get("parameter") or ""),
        "payload_used": _redact_text(finding.get("payload_used") or finding.get("payload") or ""),
        "evidence": _snippet(_first_evidence_value(finding), limit=220),
    }


def _merge_grouped_candidate(current: dict, incoming: dict, route: str) -> dict:
    raw = dict(current.get("raw", {}) if isinstance(current.get("raw"), dict) else {})
    examples = raw.get("grouped_examples") if isinstance(raw.get("grouped_examples"), list) else []
    if len(examples) < 10:
        examples.append(_candidate_example(incoming))
    count = int(raw.get("examples_count") or current.get("examples_count") or 1) + 1
    raw["examples_count"] = count
    raw["grouped_examples"] = examples
    raw["normalized_route"] = route
    current["examples_count"] = count
    current["normalized_route"] = route

    try:
        incoming_confidence = float(incoming.get("confidence") or 0)
        current_confidence = float(current.get("confidence") or 0)
    except (TypeError, ValueError):
        incoming_confidence = current_confidence = 0.0
    if incoming_confidence > current_confidence:
        current["confidence"] = incoming_confidence
        if incoming.get("severity"):
            current["severity"] = incoming["severity"]

    incoming_strength = _candidate_strength(incoming)
    current_strength = _candidate_strength(current)
    if current_strength == "weak" and incoming_strength == "strong":
        incoming_raw = incoming.get("raw", {}) if isinstance(incoming.get("raw"), dict) else {}
        current["candidate_strength"] = "strong"
        current["evidence"] = incoming.get("evidence") or current.get("evidence")
        current["evidence_items"] = incoming.get("evidence_items") or current.get("evidence_items")
        current["description"] = incoming.get("description") or current.get("description")
        current["payload_used"] = incoming.get("payload_used") or current.get("payload_used")
        current["payload"] = incoming.get("payload") or current.get("payload")
        current["response_summary"] = incoming.get("response_summary") or current.get("response_summary")
        raw["candidate_strength"] = "strong"
        if incoming_raw.get("classification_reason"):
            raw["classification_reason"] = incoming_raw.get("classification_reason")
            raw["validation_evidence_type"] = incoming_raw.get("classification_reason")
        if incoming_raw.get("original_url"):
            raw["original_url"] = incoming_raw.get("original_url")
    else:
        current["candidate_strength"] = current_strength or incoming_strength or "weak"
        raw["candidate_strength"] = current["candidate_strength"]

    base_description = raw.get("group_base_description") or current.get("description") or _first_evidence_value(current)
    raw["group_base_description"] = base_description
    current["description"] = (
        f"{base_description} Grouped {count} similar candidate observations for normalized route {route}."
    )
    current["raw"] = raw
    return current


def _group_repeated_candidates(findings: list[dict]) -> list[dict]:
    passthrough: list[dict] = []
    grouped: dict[tuple[str, str, str, str], dict] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding = _mark_candidate_strength(finding)
        if finding.get("status") != "candidate":
            passthrough.append(finding)
            continue
        route = _normalized_route_key(finding.get("url", ""))
        parameter = str(finding.get("parameter") or "").lower()
        if not route or not parameter:
            passthrough.append(finding)
            continue
        key = (
            str(finding.get("module_name") or finding.get("scanner_name") or MODULE_NAME).lower(),
            route,
            parameter,
            str(finding.get("vuln_type") or finding.get("id") or "").lower(),
        )
        if key not in grouped:
            raw = dict(finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {})
            raw["normalized_route"] = route
            raw["examples_count"] = 1
            raw["grouped_examples"] = [_candidate_example(finding)]
            raw.setdefault("candidate_strength", _candidate_strength(finding))
            finding["raw"] = raw
            finding["normalized_route"] = route
            finding["examples_count"] = 1
            finding["candidate_strength"] = raw["candidate_strength"]
            grouped[key] = finding
        else:
            grouped[key] = _merge_grouped_candidate(grouped[key], finding, route)
    return passthrough + list(grouped.values())


def _write_targets(urls: list[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt", prefix="recon_target_", encoding="utf-8")
    with tmp:
        tmp.write("\n".join(urls) + "\n")
    return tmp.name


def _new_telemetry(routed: dict[str, list[str]] | None = None, routing_stats: dict | None = None) -> dict:
    routed = routed or {category: [] for category in ROUTE_ORDER}
    routing_stats = routing_stats or {}
    unique_urls = sorted({url for urls in routed.values() for url in urls})
    parameter_pairs = {
        (category, url, parameter)
        for category, urls in routed.items()
        for url in urls
        for parameter in _parameter_names(url)
    }
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "urls_seen": int(routing_stats.get("urls_seen") or len(unique_urls)),
        "urls_tested": len(unique_urls),
        "targets_tested": len(unique_urls),
        "parameters_tested": len(parameter_pairs),
        "skipped_placeholder_urls": int(routing_stats.get("skipped_placeholder_urls") or 0),
        "skipped_generated_urls": int(routing_stats.get("skipped_generated_urls") or 0),
        "grouped_weak_candidates": 0,
        "weak_candidates_emitted": 0,
        "strong_candidates_emitted": 0,
        "confirmed_emitted": 0,
        "weak_generated_candidates_capped": 0,
        "dalfox_results_count": 0,
        "sqlmap_results_count": 0,
        "lfi_results_count": 0,
        "command_injection_results_count": 0,
        "command_injection_tests_sent": 0,
        "command_injection_confirmed": 0,
        "command_injection_candidates": 0,
        "command_injection_blocked": 0,
        "command_injection_inconclusive": 0,
        "command_injection_validator_allowed": False,
        "command_injection_validator_skipped": False,
        "command_injection_validator_skip_reason": "",
        "lfi_legacy_payloads_skipped": False,
        "lfi_legacy_payloads_skip_reason": "",
        "safe_validation_urls_tested": 0,
        "safe_validation_results_count": 0,
        "candidates_count": 0,
        "confirmed_count": 0,
        "inconclusive_count": 0,
        "blocked_count": 0,
        "errors_count": 0,
        "timeout_count": 0,
        "malformed_tool_output_count": 0,
        "external_tool_auth_allowed": False,
        "external_tool_auth_skipped": False,
        "external_tool_auth_skip_reason": "",
        "status_distribution": {},
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _refresh_telemetry_counts(telemetry: dict, findings: list[dict]) -> dict:
    status_counter = Counter(finding.get("status", "unknown") for finding in findings)
    telemetry["candidates_count"] = status_counter.get("candidate", 0)
    telemetry["confirmed_count"] = status_counter.get("confirmed", 0)
    telemetry["inconclusive_count"] = status_counter.get("inconclusive", 0)
    telemetry["blocked_count"] = status_counter.get("blocked", 0)
    telemetry["status_distribution"] = dict(status_counter)
    return telemetry


def _finish_telemetry(telemetry: dict, findings: list[dict]) -> dict:
    _refresh_telemetry_counts(telemetry, findings)
    weak_candidates = []
    strong_candidates = []
    grouped_weak = 0
    for finding in findings:
        if finding.get("status") != "candidate":
            continue
        strength = _candidate_strength(finding)
        if strength == "strong":
            strong_candidates.append(finding)
        else:
            weak_candidates.append(finding)
            try:
                grouped_weak += max(0, int(finding.get("examples_count") or 1) - 1)
            except (TypeError, ValueError):
                pass
    telemetry["weak_candidates_emitted"] = len(weak_candidates)
    telemetry["strong_candidates_emitted"] = len(strong_candidates)
    telemetry["confirmed_emitted"] = telemetry.get("confirmed_count", 0)
    telemetry["grouped_weak_candidates"] = grouped_weak
    command_findings = [
        finding for finding in findings
        if str(finding.get("vuln_type") or finding.get("id") or "").startswith("command_injection")
    ]
    telemetry["command_injection_confirmed"] = sum(1 for finding in command_findings if finding.get("status") == "confirmed")
    telemetry["command_injection_candidates"] = sum(1 for finding in command_findings if finding.get("status") == "candidate")
    telemetry["command_injection_blocked"] = sum(1 for finding in command_findings if finding.get("status") == "blocked")
    telemetry["command_injection_inconclusive"] = sum(1 for finding in command_findings if finding.get("status") == "inconclusive")
    telemetry.setdefault("urls_tested", telemetry.get("targets_tested", 0))
    total = max(1, telemetry.get("targets_tested", 0) + telemetry.get("parameters_tested", 0))
    telemetry["module_noise_score"] = round(min(1.0, telemetry.get("blocked_count", 0) / total), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _request_summary(url: str, payload: str = "", method: str = "GET") -> dict:
    return summarize_request(method=method, url=url, headers=BASE_HEADERS, body=_redact_text(payload))


def _tool_response_summary(evidence: str) -> dict:
    snippet = _snippet(evidence)
    return summarize_response(status_code=None, headers={}, body=snippet, snippet=snippet)


def _http_response_summary(response: httpx.Response, body: str) -> dict:
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=_redact_text(body[:800]),
        snippet=_snippet(body),
    )


def _runtime_headers(scan_config: dict | None = None) -> dict:
    return get_runtime_request_headers(scan_config, BASE_HEADERS)


EXTERNAL_TOOL_AUTH_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization"}


def _has_external_tool_auth_headers(headers: dict) -> bool:
    return any(str(name).lower() in EXTERNAL_TOOL_AUTH_HEADER_NAMES for name in (headers or {}))


def _strip_external_tool_auth_headers(headers: dict) -> dict:
    return {
        name: value
        for name, value in (headers or {}).items()
        if str(name).lower() not in EXTERNAL_TOOL_AUTH_HEADER_NAMES
    }


def _external_tool_headers(scan_config: dict | None, telemetry: dict | None = None) -> dict:
    headers = _runtime_headers(scan_config)
    if not _has_external_tool_auth_headers(headers):
        return headers

    policy = external_tool_auth_policy(scan_config)
    if policy.get("allowed"):
        if telemetry is not None:
            telemetry["external_tool_auth_allowed"] = True
        return headers

    if telemetry is not None:
        telemetry["external_tool_auth_skipped"] = True
        telemetry["external_tool_auth_skip_reason"] = policy.get("reason") or "disabled_by_policy"
    return _strip_external_tool_auth_headers(headers)


def _legacy_lfi_payloads_allowed(scan_config: dict | None) -> bool:
    if not isinstance(scan_config, dict):
        return False
    if str(scan_config.get("authorization_type") or "").lower() == "local_lab":
        return True
    target = str(scan_config.get("target") or scan_config.get("domain") or "")
    try:
        host = urlparse(target if "://" in target else f"http://{target}").hostname or ""
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host.lower() in {"localhost"}


def _dalfox_runtime_args(headers: dict) -> list[str]:
    args: list[str] = []
    for name, value in (headers or {}).items():
        if not value:
            continue
        lower = str(name).lower()
        if lower == "cookie":
            args.extend(["--cookie", str(value)])
        elif lower == "user-agent":
            args.extend(["--user-agent", str(value)])
        else:
            args.extend(["--header", f"{name}: {value}"])
    return args


def _sqlmap_runtime_args(headers: dict) -> list[str]:
    args: list[str] = []
    extra_headers: list[str] = []
    for name, value in (headers or {}).items():
        if not value:
            continue
        lower = str(name).lower()
        if lower == "cookie":
            args.extend(["--cookie", str(value)])
        elif lower == "user-agent":
            continue
        else:
            extra_headers.append(f"{name}: {value}")
    if extra_headers:
        args.extend(["--headers", "\n".join(extra_headers)])
    return args


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _is_local_host(host: str) -> bool:
    host = (host or "").strip().lower().strip("[]")
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_local_url(url: str) -> bool:
    try:
        return _is_local_host(urlparse(str(url or "")).hostname or "")
    except Exception:
        return False


def _priority_includes_command_injection(scan_config: dict | None = None) -> bool:
    if not isinstance(scan_config, dict):
        return False
    aliases = {"command_injection", "cmd_injection", "os_command_injection", "rce"}
    return any(str(item or "").strip().lower() in aliases for item in (scan_config.get("priority_vuln_types") or []))


def _command_injection_validator_policy(scan_config: dict | None, profile: str = "") -> dict:
    scan_config = scan_config if isinstance(scan_config, dict) else {}
    effective_profile = str(scan_config.get("profile") or profile or "").strip().lower()
    target = str(scan_config.get("target") or "")
    if not _truthy(scan_config.get("target_is_local")):
        return {"allowed": False, "reason": "target_is_local_required"}
    if target and not _is_local_url(target):
        return {"allowed": False, "reason": "target_url_not_local"}
    if not _truthy(scan_config.get("authorization_confirmed")):
        return {"allowed": False, "reason": "authorization_confirmation_required"}
    if effective_profile not in LOCAL_LAB_COMMAND_PROFILES:
        return {"allowed": False, "reason": "profile_not_local_lab"}
    if not _priority_includes_command_injection(scan_config):
        return {"allowed": False, "reason": "command_injection_priority_required"}
    return {"allowed": True, "reason": "local_lab_command_injection_enabled"}


def _command_injection_test_parameters(url: str) -> list[str]:
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return []
    selected = []
    for parameter, values in params.items():
        value = values[0] if values else ""
        if _parameter_matches_category("command_injection", parameter, value):
            selected.append(parameter)
    return selected


class _CommandFormParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {str(name).lower(): (value or "") for name, value in attrs}
        tag = tag.lower()
        if tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "get").lower()
            if not action or action == "#":
                action_url = self.base_url
            else:
                action_url = urljoin(self.base_url, action)
            self._current = {
                "action": action_url.split("#", 1)[0],
                "method": method if method in {"get", "post"} else "get",
                "inputs": [],
            }
            return
        if not self._current or tag not in {"input", "textarea", "select"}:
            return
        name = attrs_dict.get("name", "")
        if not name:
            return
        field_type = attrs_dict.get("type", tag).lower()
        value = attrs_dict.get("value", "")
        if field_type == "submit" and not value:
            value = name
        self._current["inputs"].append({
            "name": name,
            "value": value,
            "type": field_type,
        })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current:
            if self._current.get("inputs"):
                self.forms.append(self._current)
            self._current = None


def _extract_all_forms(html: str, page_url: str) -> list[dict]:
    parser = _CommandFormParser(page_url)
    parser.feed(html or "")
    return parser.forms


def _extract_command_forms(html: str, page_url: str) -> list[dict]:
    parser = _CommandFormParser(page_url)
    parser.feed(html or "")
    forms = []
    for form in parser.forms:
        testable = [
            field for field in form.get("inputs", [])
            if _parameter_matches_category("command_injection", field.get("name", ""), field.get("value", ""))
        ]
        if testable:
            form = dict(form)
            form["testable_parameters"] = [field["name"] for field in testable]
            forms.append(form)
    return forms


def _command_form_data(form: dict, parameter: str = "", value: str = COMMAND_INJECTION_BASE_INPUT) -> dict[str, str]:
    data: dict[str, str] = {}
    for field in form.get("inputs", []):
        name = field.get("name", "")
        if not name:
            continue
        field_type = str(field.get("type") or "").lower()
        if name == parameter:
            data[name] = value
        elif field_type == "submit":
            data[name] = str(field.get("value") or name or "Submit")
        else:
            data[name] = str(field.get("value") or COMMAND_INJECTION_BASE_INPUT)
    if parameter and parameter not in data:
        data[parameter] = value
    return data


async def _submit_command_request(
    client: httpx.AsyncClient,
    *,
    url: str,
    method: str,
    data: dict[str, str],
    timeout: float = 10.0,
) -> httpx.Response:
    if method.lower() == "post":
        return await client.post(url, data=data, timeout=timeout, follow_redirects=False)
    return await client.get(url, params=data, timeout=timeout, follow_redirects=False)


def _remediation_for(vuln_type: str, status: str) -> str:
    if status in {"blocked", "inconclusive"}:
        return "Review the recorded evidence in an authorized lab or lower-noise profile before treating this as exploitable."
    if vuln_type in {"reflected_xss", "xss_candidate"}:
        return "Encode untrusted output for the correct HTML/JavaScript context and validate input server-side."
    if vuln_type in {"sql_injection", "sql_injection_candidate"}:
        return "Use parameterized queries, avoid string-built SQL, and validate input type and length server-side."
    if vuln_type in {"local_file_inclusion", "lfi_candidate"}:
        return "Constrain file access to an allowlist, normalize paths server-side, and block traversal sequences."
    if vuln_type in {"open_redirect", "open_redirect_candidate"}:
        return "Allow only relative redirects or validate destinations against a strict allowlist."
    if vuln_type == "ssrf_candidate":
        return "Validate outbound-request parameters against an allowlist and block internal network destinations."
    if vuln_type in {"command_injection", "command_injection_candidate", "command_injection_inconclusive", "command_injection_blocked"}:
        return "Avoid shell invocation with user-controlled input and use safe APIs or strict allowlists."
    return "Review the evidence and validate safely before remediation."


def _default_reproduction(url: str, parameter: str, payload: str, status: str) -> list[str]:
    steps = [f"Send a GET request to {url or 'the affected endpoint'}."]
    if parameter:
        steps.append(f"Set parameter '{parameter}' to the documented test value.")
    if payload:
        steps.append("Use the redacted payload recorded in payload_used as the test shape.")
    if status == "confirmed":
        steps.append("Compare the response/tool evidence to the exact parameter and payload recorded in this finding.")
    else:
        steps.append("Treat this as a validation lead until a safe baseline/control/test comparison confirms it.")
    return steps


def _make_finding(
    *,
    finding_id: str,
    source_tool: str,
    url: str,
    parameter: str = "",
    method: str = "GET",
    category: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    payload: str = "",
    target: str = "",
    request_summary: dict | None = None,
    response_summary: dict | None = None,
    reproduction_steps: list[str] | None = None,
    remediation: str = "",
    references: list[str] | None = None,
    raw: dict | None = None,
    output_path: str = "",
) -> dict:
    redacted_payload = _redact_text(payload)
    evidence_text = _redact_text(evidence_text)
    raw = raw or {}
    raw["source_tool"] = source_tool
    raw = {key: _redact_text(value) if isinstance(value, str) else value for key, value in raw.items()}
    parsed = urlparse(url)
    finding = Finding(
        id=finding_id,
        scanner_name=source_tool,
        module_name=MODULE_NAME,
        scan_id=str(raw.get("scan_id", "")),
        target=target or parsed.netloc or url,
        url=url,
        method=(method or "GET").upper(),
        parameter=parameter,
        category=category,
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="targeted_evidence",
                value=evidence_text,
                location=parameter or url,
                comparison=str(raw.get("classification_reason", "")),
            )
        ],
        payload_used=redacted_payload,
        request_summary=request_summary or _request_summary(url, redacted_payload, method=(method or "GET").upper()),
        response_summary=response_summary or _tool_response_summary(evidence_text),
        reproduction_steps=reproduction_steps or _default_reproduction(url, parameter, redacted_payload, status),
        remediation=remediation or _remediation_for(vuln_type, status),
        references=references or REFERENCE_URLS,
        name=vuln_type.replace("_", " ").title(),
        description=evidence_text,
        matched_at=url,
        payload=redacted_payload,
        output_path=output_path,
        raw=raw,
    ).to_dict()
    finding["source_tool"] = source_tool
    finding["evidence_items"] = finding.get("evidence", [])
    return finding


def _finalize_findings(findings: list[dict]) -> list[dict]:
    finalized = _group_repeated_candidates(dedupe_findings([finding for finding in findings if finding]))
    for finding in finalized:
        raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
        finding["source_tool"] = finding.get("source_tool") or raw.get("source_tool") or finding.get("scanner_name") or "internal"
        finding["evidence_items"] = finding.get("evidence_items") or finding.get("evidence", [])
        if finding.get("status") == "candidate":
            finding = _mark_candidate_strength(finding)
            raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
            for extra_field in ("examples_count", "normalized_route"):
                if extra_field in raw and extra_field not in finding:
                    finding[extra_field] = raw[extra_field]
        if finding.get("payload_used"):
            finding["payload_used"] = _redact_text(finding["payload_used"])
            finding["payload"] = finding["payload_used"]
    return finalized


def _priority_categories(scan_config: dict | None = None) -> set[str]:
    raw_priorities = []
    if isinstance(scan_config, dict):
        raw_priorities = scan_config.get("priority_vuln_types") or []
    if not raw_priorities:
        return set(ROUTE_ORDER)

    mapped: set[str] = set()
    priority_aliases = {
        "xss": "xss",
        "reflected_xss": "xss",
        "sql": "sqli",
        "sqli": "sqli",
        "sql_injection": "sqli",
        "lfi": "lfi",
        "path_traversal": "lfi",
        "local_file_inclusion": "lfi",
        "open_redirect": "open_redirect",
        "redirect": "open_redirect",
        "ssrf": "ssrf",
        "ssrf_candidate": "ssrf",
        "command_injection": "command_injection",
        "rce": "command_injection",
        "stored_xss": "stored_xss",
    }
    for item in raw_priorities:
        category = priority_aliases.get(str(item).strip().lower())
        if category in ROUTE_ORDER:
            mapped.add(category)
    return mapped or set(ROUTE_ORDER)


def _normalize_parameter_name(parameter: str) -> str:
    return (parameter or "").strip().lower().replace("-", "_")


def _parameter_matches_category(category: str, parameter: str, value: str = "") -> bool:
    normalized = _normalize_parameter_name(parameter)
    value_text = str(value or "").strip()
    hints = PARAMETER_HINTS.get(category, set())

    if normalized in hints or any(hint in normalized for hint in hints if len(hint) >= 4):
        return True
    if category == "sqli":
        if normalized.endswith("id") or normalized in {"cylinders", "cylinder", "orderby", "order_by", "sort"}:
            return True
    if category == "xss" and any(marker in normalized for marker in ("search", "query", "message", "comment")):
        return True
    return False


def _route_url_by_parameters(url: str, allowed_categories: set[str]) -> set[str]:
    if not _is_parameterized_dynamic_url(url):
        return set()
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return set()

    categories: set[str] = set()
    normalized_path = (parsed.path or "").lower()
    for parameter, values in params.items():
        value = values[0] if values else ""
        if (
            "lfi" in allowed_categories
            and normalized_path in SAFE_TEMPLATE_PATHS
            and _normalize_parameter_name(parameter) == "item"
        ):
            categories.add("lfi")
        for category in allowed_categories:
            if category == "lfi" and _normalize_parameter_name(parameter) in LOW_VALUE_LFI_ROUTE_PARAMS:
                continue
            if category == "ssrf" and _normalize_parameter_name(parameter) in SSRF_ROUTE_SUPPRESS_PARAMS:
                continue
            if _parameter_matches_category(category, parameter, value):
                categories.add(category)
    return categories


def _normalize_url_source(source: str) -> str:
    normalized = str(source or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "seed": "user_seed",
        "scan_config_seed": "user_seed",
        "user": "user_seed",
        "form": "form_discovered",
        "form_action": "form_discovered",
        "javascript": "js_endpoint",
        "js": "js_endpoint",
        "crawler": "crawler_real_url",
        "crawl": "crawler_real_url",
        "extracted": "crawler_real_url",
        "gf": "gf_pattern",
        "generated": "generated_url",
        "expanded": "generated_url",
        "placeholder": "placeholder_url",
        "fuzz": "fuzz_template_url",
        "fuzz_template": "fuzz_template_url",
        "wayback": "historical_url",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in HIGH_PRIORITY_URL_SOURCES or normalized in LOW_PRIORITY_URL_SOURCES:
        return normalized
    return "unknown"


def _prefer_url_source(current: str, incoming: str) -> str:
    current = _normalize_url_source(current)
    incoming = _normalize_url_source(incoming)
    if URL_SOURCE_PRIORITY.get(incoming, 999) < URL_SOURCE_PRIORITY.get(current, 999):
        return incoming
    return current


def _source_from_value(value: object, default_source: str) -> str:
    source = default_source
    if isinstance(value, dict):
        source = (
            value.get("url_source")
            or value.get("route_source")
            or value.get("source")
            or value.get("source_type")
            or default_source
        )
        if value.get("placeholder") is True:
            source = "placeholder_url"
        elif value.get("generated") is True:
            source = "generated_url"
    return _normalize_url_source(source)


def _url_from_source_value(value: object) -> str:
    if isinstance(value, dict):
        for key in ("url", "matched_at", "request_url", "endpoint", "href", "action", "path"):
            candidate = value.get(key)
            if candidate:
                return str(candidate)
        return ""
    return str(value or "")


def _url_has_placeholder_marker(url: str) -> bool:
    decoded = unquote(str(url or ""))
    return bool(PLACEHOLDER_URL_RE.search(decoded))


def _skip_targeted_url_reason(url: str, source: str) -> str:
    source = _normalize_url_source(source)
    if source == "user_seed":
        return ""
    if source in {"placeholder_url", "fuzz_template_url"}:
        return "placeholder_or_fuzz_template_source"
    if _url_has_placeholder_marker(url):
        return "placeholder_marker_in_url"
    return ""


def _record_url_source(url_sources: dict[str, str], url: str, source: str) -> None:
    url = str(url or "").strip()
    if not url:
        return
    source = _normalize_url_source(source)
    if url in url_sources:
        url_sources[url] = _prefer_url_source(url_sources[url], source)
    else:
        url_sources[url] = source


def _add_routed_url(
    routed: dict[str, set[str]],
    route_sources: dict[str, dict[str, str]],
    category: str,
    url: str,
    source: str,
) -> None:
    routed[category].add(url)
    existing = route_sources[category].get(url, "unknown")
    route_sources[category][url] = _prefer_url_source(existing, source)


def _iter_candidate_url_sources(alive_hosts: list[dict], scan_config: dict | None = None):
    if isinstance(scan_config, dict):
        for url in scan_config.get("seed_urls") or []:
            yield str(url or ""), "user_seed"

    for host in alive_hosts:
        if not isinstance(host, dict):
            continue

        for field_name in ("url", "target", "base_url"):
            if host.get(field_name):
                yield str(host.get(field_name) or ""), "explicit_target"

        for field_name, default_source in URL_SOURCE_FIELDS.items():
            values = host.get(field_name) or []
            if isinstance(values, dict):
                values = values.values()
            if isinstance(values, (str, bytes)):
                values = [values]
            for value in values:
                yield _url_from_source_value(value), _source_from_value(value, default_source)


def _collect_gf_routed_urls(
    alive_hosts: list[dict],
    scan_config: dict | None = None,
) -> tuple[dict[str, list[str]], dict[str, dict[str, str]], dict]:
    routed = {category: set() for category in ROUTE_ORDER}
    route_sources = {category: {} for category in ROUTE_ORDER}
    allowed_categories = _priority_categories(scan_config)
    url_sources: dict[str, str] = {}
    gf_categories_by_url: dict[str, set[str]] = {}

    for host in alive_hosts:
        gf = host.get("gf_patterns", {}) if isinstance(host, dict) else {}
        for raw_category, data in gf.items():
            category = ROUTE_ALIASES.get(str(raw_category).lower())
            if category not in routed or category not in allowed_categories:
                continue
            for url in (data or {}).get("urls", []):
                if not url:
                    continue
                url = str(url)
                _record_url_source(url_sources, url, "gf_pattern")
                gf_categories_by_url.setdefault(url, set()).add(category)

    for url, source in _iter_candidate_url_sources(alive_hosts, scan_config):
        _record_url_source(url_sources, url, source)

    routing_stats = {
        "urls_seen": len(url_sources),
        "skipped_placeholder_urls": 0,
        "skipped_generated_urls": 0,
    }

    for url, source in sorted(url_sources.items()):
        skip_reason = _skip_targeted_url_reason(url, source)
        if skip_reason:
            routing_stats["skipped_placeholder_urls"] += 1
            if _normalize_url_source(source) in LOW_PRIORITY_URL_SOURCES:
                routing_stats["skipped_generated_urls"] += 1
            continue
            
        if "stored_xss" in allowed_categories:
            _add_routed_url(routed, route_sources, "stored_xss", url, source)
            
        if not _is_parameterized_dynamic_url(url):
            continue

        forced_categories = gf_categories_by_url.get(url, set())
        for category in forced_categories:
            if category in allowed_categories:
                _add_routed_url(routed, route_sources, category, url, source)
        for category in _route_url_by_parameters(url, allowed_categories):
            _add_routed_url(routed, route_sources, category, url, source)

    routed_lists = {category: sorted(urls) for category, urls in routed.items()}
    return routed_lists, route_sources, routing_stats


def _parameter_hint_score(category: str, parameter: str) -> tuple[float, str]:
    normalized = parameter.lower().replace("-", "_")
    hints = PARAMETER_HINTS.get(category, set())
    if normalized in hints:
        return 0.38, "parameter_name_matches_category_hint"
    if any(hint in normalized for hint in hints if len(hint) >= 4):
        return 0.32, "parameter_name_partially_matches_category_hint"
    return 0.25, "targeted_route_without_strong_parameter_name"


def _candidate_for_route(
    category: str,
    url: str,
    parameter: str,
    domain: str = "",
    source: str = "unknown",
) -> dict | None:
    if category == "stored_xss":
        return None
    skip_reason = _route_candidate_skip_reason(category, parameter)
    if skip_reason:
        return None

    source = _normalize_url_source(source)
    confidence, reason = _parameter_hint_score(category, parameter)
    if source in LOW_PRIORITY_URL_SOURCES:
        confidence = min(confidence, 0.28)
        reason = f"{reason}_from_low_priority_{source}"
    mapping = {
        "xss": ("xss_candidate", "injection", "low"),
        "sqli": ("sql_injection_candidate", "injection", "low"),
        "lfi": ("lfi_candidate", "file_inclusion", "low"),
        "open_redirect": ("open_redirect_candidate", "redirect", "low"),
        "ssrf": ("ssrf_candidate", "server-side request forgery", "low"),
        "command_injection": ("command_injection_candidate", "injection", "medium"),
        "stored_xss": ("stored_xss_candidate", "injection", "high"),
    }
    vuln_type, finding_category, severity = mapping[category]
    normalized_parameter = (parameter or "").lower().replace("-", "_")
    if category == "ssrf" and normalized_parameter in WEAK_SSRF_REFERENCE_PARAMS:
        confidence = min(confidence, 0.32)
        reason = "weak_reference_parameter_without_ssrf_fetch_or_callback_evidence"
    evidence = (
        f"Targeted routing marked parameter '{parameter}' on {url} as {category}-relevant. "
        "No exploit proof is present; this is a validation candidate only."
    )
    finding = _make_finding(
        finding_id=vuln_type,
        source_tool="internal",
        url=url,
        parameter=parameter,
        target=domain or urlparse(url).netloc,
        category=finding_category,
        vuln_type=vuln_type,
        status="candidate",
        severity=severity,
        confidence=confidence,
        evidence_text=evidence,
        raw={
            "classification_reason": reason,
            "route": category,
            "route_source": source,
            "url_source": source,
        },
    )
    return _mark_candidate_strength(finding)


def _make_route_candidates(
    routed: dict[str, list[str]],
    domain: str = "",
    route_sources: dict[str, dict[str, str]] | None = None,
) -> list[dict]:
    route_sources = route_sources or {category: {} for category in ROUTE_ORDER}
    findings = []
    for category, urls in routed.items():
        for url in urls:
            source = route_sources.get(category, {}).get(url, "unknown")
            for parameter in _parameter_names(url):
                candidate = _candidate_for_route(category, url, parameter, domain, source)
                if candidate:
                    findings.append(candidate)
    return findings


def _finding_param_key(finding: dict) -> tuple[str, str, str]:
    return (
        str(finding.get("category", "")),
        _url_without_parameter_values(finding.get("url", ""), finding.get("parameter", "")),
        str(finding.get("parameter", "")).lower(),
    )


def _suppress_weaker_internal_candidates(findings: list[dict]) -> list[dict]:
    stronger_keys = {
        _finding_param_key(finding)
        for finding in findings
        if finding.get("source_tool") != "internal" and finding.get("status") in {"candidate", "confirmed"}
    }
    filtered = []
    for finding in findings:
        if (
            finding.get("source_tool") == "internal"
            and finding.get("vuln_type", "").endswith("_candidate")
            and _finding_param_key(finding) in stronger_keys
        ):
            continue
        filtered.append(finding)
    return filtered


def _finding_url_source(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    return _normalize_url_source(raw.get("url_source") or raw.get("route_source") or finding.get("url_source") or "unknown")


def _cap_generated_weak_candidates(
    findings: list[dict],
    telemetry: dict,
    max_weak_generated: int = MAX_WEAK_GENERATED_CANDIDATES,
) -> list[dict]:
    capped: list[dict] = []
    generated_weak_emitted = 0
    generated_weak_skipped = 0

    for finding in findings:
        if finding.get("status") != "candidate":
            capped.append(finding)
            continue
        if _candidate_strength(finding) == "strong":
            capped.append(finding)
            continue
        if _finding_url_source(finding) not in LOW_PRIORITY_URL_SOURCES:
            capped.append(finding)
            continue

        if generated_weak_emitted < max_weak_generated:
            capped.append(finding)
            generated_weak_emitted += 1
        else:
            generated_weak_skipped += 1

    telemetry["weak_generated_candidates_capped"] = (
        int(telemetry.get("weak_generated_candidates_capped") or 0) + generated_weak_skipped
    )
    return capped


def _extract_first_url(text: str) -> str:
    match = re.search(r"https?://[^\s\"'<>]+", text or "")
    if not match:
        return ""
    return match.group(0).rstrip("]),,")


def _extract_payload_from_url(url: str, parameter: str) -> str:
    try:
        values = parse_qs(urlparse(url).query, keep_blank_values=True).get(parameter) or []
        return values[0] if values else ""
    except Exception:
        return ""


def _payload_is_encoded_or_escaped(evidence: str, payload: str) -> bool:
    lower = (evidence or "").lower()
    payload_lower = (payload or "").lower()
    if not payload_lower:
        return False
    evidence_without_urls = re.sub(r"https?://[^\s\"'<>]+", "", lower)
    if payload_lower in evidence_without_urls:
        return False
    encoded_markers = ["&lt;", "&gt;", "%3c", "%3e", "\u003c", "\x3c"]
    if any(marker in evidence_without_urls for marker in encoded_markers):
        return True
    if "<" in payload_lower or ">" in payload_lower:
        escaped_payload = payload_lower.replace("<", "&lt;").replace(">", "&gt;")
        return escaped_payload != payload_lower and escaped_payload in evidence_without_urls
    return False


def _classify_xss_evidence(line: str, url: str, parameter: str, payload: str) -> dict:
    lower = line.lower()
    context = reflection_context(line, payload) if payload else ""
    encoded = _payload_is_encoded_or_escaped(line, payload)
    strong_tool_proof = any(marker in lower for marker in ["[poc]", "vulnerable", "verified", "evidence", "proof"])
    weak_tool_signal = any(marker in lower for marker in ["reflected", "[r]", "weak", "grep", "candidate"])
    executable_context = context in {"script", "html_attribute"} or any(
        marker in lower for marker in ["<script", "onerror=", "onload=", "onclick=", "javascript:"]
    )

    if not url or not parameter:
        return {
            "status": "inconclusive",
            "severity": "info",
            "confidence": 0.25,
            "vuln_type": "targeted_vuln_inconclusive",
            "reason": "dalfox_output_without_correlated_url_or_parameter",
        }
    if encoded:
        return {
            "status": "candidate",
            "severity": "low",
            "confidence": 0.45,
            "vuln_type": "xss_candidate",
            "reason": "payload_reflected_but_encoded_or_escaped",
        }
    if strong_tool_proof and executable_context:
        return {
            "status": "confirmed",
            "severity": "high" if context == "script" or "<script" in lower else "medium",
            "confidence": 0.9,
            "vuln_type": "reflected_xss",
            "reason": "dalfox_strong_proof_with_executable_context",
        }
    if strong_tool_proof:
        return {
            "status": "confirmed",
            "severity": "medium",
            "confidence": 0.86,
            "vuln_type": "reflected_xss",
            "reason": "dalfox_strong_proof",
        }
    if weak_tool_signal or payload:
        return {
            "status": "candidate",
            "severity": "medium" if executable_context else "low",
            "confidence": 0.58 if executable_context else 0.48,
            "vuln_type": "xss_candidate",
            "reason": "weak_or_reflection_only_xss_signal",
        }
    return {
        "status": "candidate",
        "severity": "low",
        "confidence": 0.4,
        "vuln_type": "xss_candidate",
        "reason": "dalfox_candidate_without_execution_proof",
    }


def parse_dalfox_output(output: str, input_urls: list[str] | None = None, telemetry: dict | None = None) -> list[dict]:
    input_urls = input_urls or []
    telemetry = telemetry if telemetry is not None else _new_telemetry()
    findings = []
    for line in (output or "").splitlines():
        raw_line = line.strip()
        if not raw_line:
            continue
        lower = raw_line.lower()
        if not any(marker in lower for marker in ["[poc]", "[v]", "vulnerable", "reflected", "[r]", "weak", "xss"]):
            continue
        url = _extract_first_url(raw_line)
        if not url and input_urls:
            url = input_urls[0]
        parameter = _first_parameter(url)
        payload = _extract_payload_from_url(url, parameter)
        classification = _classify_xss_evidence(raw_line, url, parameter, payload)
        findings.append(_make_finding(
            finding_id=classification["vuln_type"],
            source_tool="dalfox",
            url=url,
            parameter=parameter,
            category="injection",
            vuln_type=classification["vuln_type"],
            status=classification["status"],
            severity=classification["severity"],
            confidence=classification["confidence"],
            evidence_text=f"Dalfox output correlated to parameter '{parameter or 'unknown'}': {_snippet(raw_line)}",
            payload=payload,
            raw={"classification_reason": classification["reason"], "source_line": raw_line},
        ))
    if output and not findings and any(marker in output.lower() for marker in ["error", "exception", "failed"]):
        telemetry["malformed_tool_output_count"] += 1
    return _finalize_findings(findings)


async def _run_dalfox(urls: list[str], profile: str, telemetry: dict, scan_config: dict | None = None) -> list[dict]:
    if not urls:
        return []

    urls_file = _write_targets(urls)
    cmd = [
        get_tool_path("dalfox"),
        "file", urls_file,
        "--silence",
        "--no-color",
        "--no-spinner",
        "--ignore-return", "302,404,400,500",
    ]
    cmd.extend(["--deep-domxss", "-w", "50"] if profile == "deep" else ["-w", "20"])
    cmd.extend(_dalfox_runtime_args(_external_tool_headers(scan_config, telemetry)))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        if stderr:
            stderr_text = _redact_text(stderr.decode(errors="replace"))
            if stderr_text.strip():
                telemetry["errors_count"] += 1
        return parse_dalfox_output(stdout.decode(errors="replace"), urls, telemetry)

    except asyncio.TimeoutError:
        telemetry["timeout_count"] += 1
        log.warning("[targeted_vulns] Dalfox timed out")
    except FileNotFoundError:
        for url in urls:
            for parameter in _parameter_names(url):
                _record_validation_result(
                    telemetry,
                    test_type="dalfox_xss",
                    url=url,
                    parameter=parameter,
                    status="skipped",
                    reason="missing_tool:dalfox",
                )
        log.warning("[targeted_vulns] Dalfox not found. Skipping XSS scan.")
    except Exception as exc:
        telemetry["errors_count"] += 1
        log.error(f"[targeted_vulns] Dalfox error: {exc}")
    finally:
        if os.path.exists(urls_file):
            os.remove(urls_file)

    return []


def _best_url_for_parameter(parameter: str, input_urls: list[str], url_hints: set[str]) -> str:
    for candidate in sorted(url_hints):
        if parameter in _parameter_names(candidate):
            return candidate
    for candidate in input_urls:
        if parameter in _parameter_names(candidate):
            return candidate
    return next(iter(sorted(url_hints)), input_urls[0] if input_urls else "")


def _sqlmap_severity(body: str) -> str:
    lower = body.lower()
    if any(marker in lower for marker in ["stacked queries", "os shell", "file write", "file read"]):
        return "critical"
    return "high"


def _classify_sqlmap_block(body: str, payloads: list[str], types: list[str], titles: list[str]) -> dict:
    lower = body.lower()
    has_payload = bool(payloads)
    has_technique = bool(types or titles)
    heuristic_only = any(marker in lower for marker in ["heuristic", "might be injectable", "appears to be injectable"]) and not has_technique
    timing = any("time-based" in item.lower() for item in [*types, *titles, body])
    boolean = any("boolean-based" in item.lower() for item in [*types, *titles, body])

    if has_payload and has_technique and (timing or boolean or "injectable" in lower or "payload:" in lower):
        return {
            "status": "confirmed",
            "severity": _sqlmap_severity(body),
            "confidence": 0.92 if timing or boolean else 0.88,
            "vuln_type": "sql_injection",
            "reason": "sqlmap_confirmed_injectable_parameter_with_payload_and_technique",
        }
    if has_payload and SQL_ERROR_RE.search(body):
        return {
            "status": "confirmed",
            "severity": "high",
            "confidence": 0.86,
            "vuln_type": "sql_injection",
            "reason": "payload_correlated_sql_error_signature",
        }
    if heuristic_only or has_payload or has_technique:
        return {
            "status": "candidate",
            "severity": "medium",
            "confidence": 0.55 if has_payload or has_technique else 0.42,
            "vuln_type": "sql_injection_candidate",
            "reason": "sqlmap_heuristic_or_partial_signal",
        }
    if SQL_ERROR_RE.search(body):
        return {
            "status": "candidate",
            "severity": "low",
            "confidence": 0.4,
            "vuln_type": "sql_injection_candidate",
            "reason": "sql_error_without_payload_correlation",
        }
    return {
        "status": "inconclusive",
        "severity": "info",
        "confidence": 0.2,
        "vuln_type": "targeted_vuln_inconclusive",
        "reason": "sqlmap_block_without_actionable_evidence",
    }


def parse_sqlmap_output_text(
    text: str,
    input_urls: list[str] | None = None,
    *,
    output_path: str = "",
    telemetry: dict | None = None,
) -> list[dict]:
    input_urls = input_urls or []
    telemetry = telemetry if telemetry is not None else _new_telemetry()
    findings = []
    text = text or ""
    url_hints = set(re.findall(r"https?://[^\s'\"<>]+", text))
    blocks = list(re.finditer(
        r"Parameter:\s*(?P<parameter>[^\s(]+)\s*\((?P<place>[^)]+)\)(?P<body>.*?)(?=\n\s*Parameter:|\n\s*---|\Z)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    ))

    for block in blocks:
        parameter = block.group("parameter").strip()
        body = block.group("body")
        payloads = [_redact_text(item.strip()) for item in re.findall(r"Payload:\s*(.+)", body, flags=re.IGNORECASE)]
        types = [item.strip() for item in re.findall(r"Type:\s*(.+)", body, flags=re.IGNORECASE)]
        titles = [item.strip() for item in re.findall(r"Title:\s*(.+)", body, flags=re.IGNORECASE)]
        matched_url = _best_url_for_parameter(parameter, input_urls, url_hints)
        classification = _classify_sqlmap_block(body, payloads, types, titles)
        evidence_parts = [f"SQLMap parameter block for '{parameter}'."]
        if types:
            evidence_parts.append("Types: " + "; ".join(_redact_text(item) for item in types))
        if titles:
            evidence_parts.append("Titles: " + "; ".join(_redact_text(item) for item in titles))
        if payloads:
            evidence_parts.append("Payload: " + payloads[0])
        if not (types or titles or payloads):
            evidence_parts.append(_snippet(body))

        findings.append(_make_finding(
            finding_id=classification["vuln_type"],
            source_tool="sqlmap",
            url=matched_url,
            parameter=parameter,
            category="injection",
            vuln_type=classification["vuln_type"],
            status=classification["status"],
            severity=classification["severity"],
            confidence=classification["confidence"],
            evidence_text=" ".join(part for part in evidence_parts if part),
            payload=payloads[0] if payloads else "",
            output_path=output_path,
            raw={
                "classification_reason": classification["reason"],
                "place": block.group("place").strip(),
                "types": types,
                "titles": titles,
            },
        ))

    if not findings:
        heuristic = re.search(
            r"parameter\s+['\"]?(?P<parameter>[A-Za-z0-9_.-]+)['\"]?.{0,120}(might be injectable|appears to be injectable|heuristic)",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        error_match = SQL_ERROR_RE.search(text)
        if heuristic:
            parameter = heuristic.group("parameter")
            matched_url = _best_url_for_parameter(parameter, input_urls, url_hints)
            findings.append(_make_finding(
                finding_id="sql_injection_candidate",
                source_tool="sqlmap",
                url=matched_url,
                parameter=parameter,
                category="injection",
                vuln_type="sql_injection_candidate",
                status="candidate",
                severity="medium",
                confidence=0.45,
                evidence_text="SQLMap heuristic output suggests possible SQL injection, but no confirmed technique/payload block was found.",
                raw={"classification_reason": "sqlmap_heuristic_only", "source_excerpt": _snippet(text)},
            ))
        elif error_match:
            parameter = _first_parameter(input_urls[0]) if input_urls else ""
            findings.append(_make_finding(
                finding_id="sql_injection_candidate",
                source_tool="sqlmap",
                url=input_urls[0] if input_urls else "",
                parameter=parameter,
                category="injection",
                vuln_type="sql_injection_candidate",
                status="candidate",
                severity="low",
                confidence=0.4,
                evidence_text="SQL error signature observed in tool output, but no payload correlation or baseline/control proof was present.",
                raw={"classification_reason": "sql_error_without_payload_correlation", "source_excerpt": _snippet(text)},
            ))
        elif text.strip():
            telemetry["malformed_tool_output_count"] += 1

    return _finalize_findings(findings)


def _parse_sqlmap_logs(output_dir: str, input_urls: list[str], telemetry: dict) -> list[dict]:
    findings: list[dict] = []
    log_paths = [p for p in Path(output_dir).rglob("*") if p.is_file() and p.name.lower() == "log"]

    for log_path in log_paths:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            telemetry["errors_count"] += 1
            continue
        findings.extend(parse_sqlmap_output_text(text, input_urls, output_path=str(log_path), telemetry=telemetry))

    return _finalize_findings(findings)


async def _run_sqlmap(urls: list[str], profile: str, telemetry: dict, scan_config: dict | None = None) -> list[dict]:
    if not urls:
        return []

    sqlmap_py = os.path.join(TOOLS_DIR, "sqlmap-master", "sqlmap.py")
    if not os.path.exists(sqlmap_py):
        for url in urls:
            for parameter in _parameter_names(url):
                _record_validation_result(
                    telemetry,
                    test_type="sqlmap_sql_injection",
                    url=url,
                    parameter=parameter,
                    status="skipped",
                    reason="missing_tool:sqlmap",
                )
        log.warning(f"[targeted_vulns] sqlmap not found at {sqlmap_py}. Skipping SQLi scan.")
        return []

    urls_file = _write_targets(urls)
    output_dir = tempfile.mkdtemp(prefix="sqlmap_out_")
    stdout_text = ""
    cmd = [
        sys.executable, sqlmap_py,
        "-m", urls_file,
        "--batch",
        "--smart",
        "--disable-coloring",
        "--random-agent",
        "--output-dir", output_dir,
    ]
    cmd.extend(["--level", "3", "--risk", "2"] if profile == "deep" else ["--level", "1", "--risk", "1"])
    cmd.extend(_sqlmap_runtime_args(_external_tool_headers(scan_config, telemetry)))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timeout = 600 if profile == "deep" else 300
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout_text = stdout.decode(errors="replace")
        if stderr:
            stderr_text = _redact_text(stderr.decode(errors="replace"))
            if stderr_text.strip():
                telemetry["errors_count"] += 1
    except asyncio.TimeoutError:
        telemetry["timeout_count"] += 1
        log.warning("[targeted_vulns] SQLMap timed out; parsing any partial output")
    except Exception as exc:
        telemetry["errors_count"] += 1
        log.error(f"[targeted_vulns] SQLMap error: {exc}")
    finally:
        if os.path.exists(urls_file):
            os.remove(urls_file)

    findings = _parse_sqlmap_logs(output_dir, urls, telemetry)
    if stdout_text:
        findings = _finalize_findings([*findings, *parse_sqlmap_output_text(stdout_text, urls, telemetry=telemetry)])
    shutil.rmtree(output_dir, ignore_errors=True)
    return findings


def _decode_response(response: httpx.Response) -> str:
    content = response.content[:20000]
    if b"\x00" in content[:200]:
        return ""
    try:
        return content.decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _is_binary_response(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return any(binary in content_type for binary in ("image/", "font/", "application/octet-stream", "video/", "audio/"))


def _looks_like_generic_error(status_code: int | None, body: str) -> bool:
    if status_code not in {200, 400, 404, 500}:
        return False
    lower = (body or "")[:12000].lower()
    title = extract_title(body).lower()
    return any(marker in lower or marker in title for marker in GENERIC_ERROR_MARKERS)


def _lfi_signature(body: str) -> tuple[str, str]:
    for name, pattern in LFI_SIGNATURES.items():
        match = pattern.search(body or "")
        if match:
            start = max(0, match.start() - 100)
            end = min(len(body), match.end() + 160)
            return name, body[start:end]
    return "", ""


def _classify_lfi_response(
    *,
    original_url: str,
    test_url: str,
    parameter: str,
    payload: str,
    response: httpx.Response,
    body: str,
    baseline: dict,
) -> dict | None:
    headers = dict(response.headers)
    signature_name, signature_context = _lfi_signature(body)
    current = response_fingerprint(response.status_code, headers, body)
    meaningful_diff = has_meaningful_diff(baseline, current, min_length_delta=40) if baseline else True
    if signature_name and meaningful_diff:
        return _make_finding(
            finding_id="local_file_inclusion",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            category="file_inclusion",
            vuln_type="local_file_inclusion",
            status="confirmed",
            severity="high",
            confidence=0.9,
            evidence_text=f"Traversal payload produced safe local-file marker '{signature_name}': {_snippet(signature_context)}",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "safe_file_marker_with_payload_correlated_response_diff", "original_url": original_url},
        )

    blocked, challenged, reasons = is_blocked_or_challenged(response.status_code, headers, body)
    if blocked or challenged:
        return _make_finding(
            finding_id="targeted_vuln_blocked",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            category="detection-testing",
            vuln_type="targeted_vuln_blocked",
            status="blocked",
            severity="info",
            confidence=0.3,
            evidence_text=f"LFI test response was blocked or challenged: {', '.join(reasons) or response.status_code}.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "blocked_or_challenged", "original_url": original_url},
        )

    if response.status_code in {404, 410} or _is_binary_response(response):
        return None

    if _looks_like_generic_error(response.status_code, body):
        return None

    if SQL_ERROR_RE.search(body) or any(marker in body.lower() for marker in ["failed to open stream", "no such file", "permission denied"]):
        return _make_finding(
            finding_id="lfi_candidate",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            category="file_inclusion",
            vuln_type="lfi_candidate",
            status="candidate",
            severity="low",
            confidence=0.48,
            evidence_text="Traversal payload changed the response or produced a file/path error, but no safe local-file marker was confirmed.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "path_error_without_file_marker", "original_url": original_url},
        )

    if meaningful_diff and response.status_code == 200:
        return _make_finding(
            finding_id="lfi_candidate",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            category="file_inclusion",
            vuln_type="lfi_candidate",
            status="candidate",
            severity="low",
            confidence=0.42,
            evidence_text="Traversal payload produced a meaningful response difference, but no file marker proof was present.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "response_diff_without_file_marker", "original_url": original_url},
        )

    if response.status_code == 200:
        return _make_finding(
            finding_id="lfi_inconclusive",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            category="file_inclusion",
            vuln_type="lfi_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="LFI test returned a normal 200 response without a safe local-file marker.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "normal_200_without_file_marker", "original_url": original_url},
        )

    return None


async def _baseline_response(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url, timeout=8.0, follow_redirects=False)
    except httpx.RequestError:
        return {}
    body = _decode_response(response)
    return response_fingerprint(response.status_code, dict(response.headers), body)


async def _safe_get(
    client: httpx.AsyncClient,
    url: str,
    telemetry: dict,
    *,
    timeout: float = 8.0,
) -> tuple[httpx.Response | None, str]:
    try:
        response = await client.get(url, timeout=timeout, follow_redirects=False)
    except httpx.TimeoutException:
        telemetry["timeout_count"] = int(telemetry.get("timeout_count") or 0) + 1
        return None, ""
    except (httpx.ConnectError, httpx.ReadError, httpx.RequestError):
        return None, ""
    except Exception as exc:
        telemetry["errors_count"] = int(telemetry.get("errors_count") or 0) + 1
        log.debug(f"[targeted_vulns] safe validation error for {url}: {exc}")
        return None, ""
    return response, _decode_response(response)


def _record_validation_result(
    telemetry: dict,
    *,
    test_type: str,
    url: str,
    parameter: str = "",
    status: str,
    reason: str = "",
    method: str = "GET",
    payloads_sent: int = 0,
    response_status: int | None = None,
    evidence: str = "",
) -> None:
    results = telemetry.setdefault("active_validation_results", [])
    results.append({
        "module": MODULE_NAME,
        "test_type": test_type,
        "method": method.upper(),
        "url": _redact_text(url),
        "parameter": parameter,
        "status": status,
        "reason": reason,
        "payloads_sent": payloads_sent,
        "response_status": response_status,
        "evidence": _snippet(evidence, limit=220),
    })


def _body_delta_ratio(left: str, right: str) -> float:
    left_len = max(1, len(left or ""))
    return abs(left_len - len(right or "")) / left_len


def _response_difference_reason(
    baseline_response: httpx.Response,
    baseline_body: str,
    test_response: httpx.Response,
    test_body: str,
) -> str:
    reasons: list[str] = []
    if baseline_response.status_code != test_response.status_code:
        reasons.append(f"status:{baseline_response.status_code}->{test_response.status_code}")
    baseline_title = extract_title(baseline_body)
    test_title = extract_title(test_body)
    if baseline_title != test_title:
        reasons.append("title_changed")
    delta = _body_delta_ratio(baseline_body, test_body)
    if delta >= 0.25:
        reasons.append(f"body_length_delta:{delta:.2f}")
    if SQL_ERROR_RE.search(test_body or "") and not SQL_ERROR_RE.search(baseline_body or ""):
        reasons.append("sql_error_marker")
    if _looks_like_generic_error(test_response.status_code, test_body) and not _looks_like_generic_error(
        baseline_response.status_code,
        baseline_body,
    ):
        reasons.append("generic_error_marker")
    return ",".join(reasons)


def _safe_sql_payloads(url: str, parameter: str) -> list[str]:
    parsed = urlparse(url)
    value = (parse_qs(parsed.query, keep_blank_values=True).get(parameter) or [""])[0]
    normalized_parameter = _normalize_parameter_name(parameter)
    if normalized_parameter == "id" and re.fullmatch(r"-?\d+", str(value or "0")):
        base = value or "0"
        return [f"{base} AND 1=1", f"{base} AND 1=2", f"{base}'"]
    if parsed.path.lower() in SAFE_SQLI_PATHS and normalized_parameter == "item":
        return [f"{value}'"]
    return []


async def _safe_validate_sqli_url(
    client: httpx.AsyncClient,
    url: str,
    telemetry: dict,
) -> list[dict]:
    parsed = urlparse(url)
    parameters = _parameter_names(url)
    if parsed.path.lower() not in SAFE_SQLI_PATHS:
        for parameter in parameters:
            _record_validation_result(
                telemetry,
                test_type="sql_injection",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="safe_sql_validator_not_enabled_for_path",
            )
        return []
    baseline_response, baseline_body = await _safe_get(client, url, telemetry)
    if baseline_response is None or _is_binary_response(baseline_response):
        for parameter in parameters:
            _record_validation_result(
                telemetry,
                test_type="sql_injection",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="baseline_response_unavailable_or_binary",
            )
        return []

    findings: list[dict] = []
    for parameter in parameters:
        payloads = _safe_sql_payloads(url, parameter)
        if not payloads:
            _record_validation_result(
                telemetry,
                test_type="sql_injection",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="no_safe_payload_for_parameter_shape",
            )
            continue
        probe_results: list[tuple[str, httpx.Response, str, str]] = []
        responses_seen = 0
        last_status = None
        for payload in payloads:
            test_url = _url_with_payload(url, parameter, payload)
            test_response, test_body = await _safe_get(client, test_url, telemetry)
            if test_response is None or _is_binary_response(test_response):
                continue
            responses_seen += 1
            last_status = test_response.status_code
            reason = _response_difference_reason(baseline_response, baseline_body, test_response, test_body)
            if reason:
                probe_results.append((payload, test_response, test_body, reason))

        sql_error_probe = next((item for item in probe_results if "sql_error_marker" in item[3]), None)
        if sql_error_probe:
            payload, response, body, reason = sql_error_probe
            _record_validation_result(
                telemetry,
                test_type="sql_injection",
                url=url,
                parameter=parameter,
                status="candidate",
                reason=reason,
                payloads_sent=len(payloads),
                response_status=response.status_code,
                evidence="SQL error marker observed during safe validation.",
            )
            findings.append(_make_finding(
                finding_id="sql_injection_candidate",
                source_tool="internal",
                url=_url_with_payload(url, parameter, payload),
                parameter=parameter,
                category="injection",
                vuln_type="sql_injection_candidate",
                status="candidate",
                severity="medium",
                confidence=0.72,
                evidence_text=f"Safe SQL validation changed the response with stable SQL error evidence ({reason}).",
                payload=payload,
                response_summary=_http_response_summary(response, body),
                raw={
                    "classification_reason": "safe_sql_error_marker",
                    "original_url": url,
                    "candidate_strength": "strong",
                },
            ))
            continue

        if len(probe_results) >= 2:
            reasons = sorted({item[3] for item in probe_results})
            payload, response, body, reason = probe_results[-1]
            _record_validation_result(
                telemetry,
                test_type="sql_injection",
                url=url,
                parameter=parameter,
                status="candidate",
                reason="; ".join(reasons[:3]),
                payloads_sent=len(payloads),
                response_status=response.status_code,
                evidence="Consistent response difference across safe SQL probes.",
            )
            findings.append(_make_finding(
                finding_id="sql_injection_candidate",
                source_tool="internal",
                url=_url_with_payload(url, parameter, payload),
                parameter=parameter,
                category="injection",
                vuln_type="sql_injection_candidate",
                status="candidate",
                severity="low",
                confidence=0.66,
                evidence_text=(
                    "Safe SQL validation produced consistent differential behavior across harmless comparison probes: "
                    f"{'; '.join(reasons[:3])}."
                ),
                payload=payload,
                response_summary=_http_response_summary(response, body),
                raw={
                    "classification_reason": "safe_sql_consistent_response_diff",
                    "original_url": url,
                    "candidate_strength": "strong",
                },
            ))
            continue

        _record_validation_result(
            telemetry,
            test_type="sql_injection",
            url=url,
            parameter=parameter,
            status="not_confirmed",
            reason="no_sql_error_or_consistent_differential_evidence",
            payloads_sent=len(payloads),
            response_status=last_status,
            evidence=f"{responses_seen} SQL probe response(s) compared with baseline.",
        )
    return _finalize_findings(findings)


async def _safe_validate_xss_url(
    client: httpx.AsyncClient,
    url: str,
    telemetry: dict,
) -> list[dict]:
    baseline_response, baseline_body = await _safe_get(client, url, telemetry)
    parameters = _parameter_names(url)
    if baseline_response is None or _is_binary_response(baseline_response):
        for parameter in parameters:
            _record_validation_result(
                telemetry,
                test_type="xss_reflection",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="baseline_response_unavailable_or_binary",
            )
        return []
    findings: list[dict] = []
    for parameter in parameters:
        marker_url = _url_with_payload(url, parameter, SAFE_XSS_MARKER)
        response, body = await _safe_get(client, marker_url, telemetry)
        if response is None or _is_binary_response(response):
            _record_validation_result(
                telemetry,
                test_type="xss_reflection",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="test_response_unavailable_or_binary",
                payloads_sent=1,
            )
            continue
        if SAFE_XSS_MARKER in body and SAFE_XSS_MARKER not in baseline_body:
            context = reflection_context(body, SAFE_XSS_MARKER)
            _record_validation_result(
                telemetry,
                test_type="xss_reflection",
                url=url,
                parameter=parameter,
                status="candidate",
                reason=f"marker_reflected_context:{context or 'unknown'}",
                payloads_sent=1,
                response_status=response.status_code,
                evidence="Harmless XSS marker reflected in response.",
            )
            findings.append(_make_finding(
                finding_id="xss_candidate",
                source_tool="internal",
                url=str(response.url) or marker_url,
                parameter=parameter,
                category="injection",
                vuln_type="xss_candidate",
                status="candidate",
                severity="low",
                confidence=0.68,
                evidence_text=(
                    "Harmless marker was reflected in the response body during safe validation; "
                    f"context={context or 'unknown'}."
                ),
                payload=SAFE_XSS_MARKER,
                response_summary=_http_response_summary(response, body),
                raw={
                    "classification_reason": "safe_reflection_marker_observed",
                    "original_url": url,
                    "reflection_context": context,
                    "candidate_strength": "strong",
                },
            ))
        else:
            _record_validation_result(
                telemetry,
                test_type="xss_reflection",
                url=url,
                parameter=parameter,
                status="not_confirmed",
                reason="marker_not_reflected",
                payloads_sent=1,
                response_status=response.status_code,
                evidence="Harmless XSS marker was not reflected in the response body.",
            )
    return _finalize_findings(findings)


async def _safe_validate_template_url(
    client: httpx.AsyncClient,
    url: str,
    telemetry: dict,
) -> list[dict]:
    parsed = urlparse(url)
    parameters = _parameter_names(url)
    if parsed.path.lower() not in SAFE_TEMPLATE_PATHS:
        for parameter in parameters:
            _record_validation_result(
                telemetry,
                test_type="template_lfi",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="safe_template_validator_not_enabled_for_path",
            )
        return []
    baseline_response, baseline_body = await _safe_get(client, url, telemetry)
    if baseline_response is None or _is_binary_response(baseline_response):
        for parameter in parameters:
            _record_validation_result(
                telemetry,
                test_type="template_lfi",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="baseline_response_unavailable_or_binary",
            )
        return []

    findings: list[dict] = []
    for parameter in parameters:
        if _normalize_parameter_name(parameter) != "item":
            _record_validation_result(
                telemetry,
                test_type="template_lfi",
                url=url,
                parameter=parameter,
                status="skipped",
                reason="parameter_not_template_selector",
            )
            continue
        probe_results: list[tuple[str, httpx.Response, str, str]] = []
        last_status = None
        for payload in SAFE_TEMPLATE_INVALID_VALUES:
            test_url = _url_with_payload(url, parameter, payload)
            response, body = await _safe_get(client, test_url, telemetry)
            if response is None or _is_binary_response(response):
                continue
            last_status = response.status_code
            reason = _response_difference_reason(baseline_response, baseline_body, response, body)
            if reason:
                probe_results.append((payload, response, body, reason))
        if len(probe_results) < 2:
            _record_validation_result(
                telemetry,
                test_type="template_lfi",
                url=url,
                parameter=parameter,
                status="not_confirmed",
                reason="missing_template_probe_did_not_produce_consistent_difference",
                payloads_sent=len(SAFE_TEMPLATE_INVALID_VALUES),
                response_status=last_status,
            )
            continue
        payload, response, body, reason = probe_results[0]
        reasons = sorted({item[3] for item in probe_results})
        _record_validation_result(
            telemetry,
            test_type="template_lfi",
            url=url,
            parameter=parameter,
            status="candidate",
            reason="; ".join(reasons[:3]),
            payloads_sent=len(SAFE_TEMPLATE_INVALID_VALUES),
            response_status=response.status_code,
            evidence="Missing template names produced consistent response differences.",
        )
        findings.append(_make_finding(
            finding_id="lfi_candidate",
            source_tool="internal",
            url=_url_with_payload(url, parameter, payload),
            parameter=parameter,
            category="file_inclusion",
            vuln_type="lfi_candidate",
            status="candidate",
            severity="low",
            confidence=0.67,
            evidence_text=(
                "Safe template validation changed the response for deliberately missing same-site template names: "
                f"{'; '.join(reasons[:3])}."
            ),
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={
                "classification_reason": "safe_template_invalid_path_differential",
                "original_url": url,
                "candidate_strength": "strong",
            },
        ))
    return _finalize_findings(findings)


async def _run_safe_candidate_validators(
    routed: dict[str, list[str]],
    profile: str,
    telemetry: dict,
    scan_config: dict | None = None,
) -> list[dict]:
    del profile
    candidate_urls = sorted(set(routed.get("xss", []) + routed.get("sqli", []) + routed.get("lfi", [])))
    if not candidate_urls:
        return []
    telemetry["safe_validation_urls_tested"] = len(candidate_urls)
    async with httpx.AsyncClient(verify=False, headers=_runtime_headers(scan_config)) as client:
        tasks = []
        for url in candidate_urls:
            tasks.append(_safe_validate_xss_url(client, url, telemetry))
            tasks.append(_safe_validate_sqli_url(client, url, telemetry))
            tasks.append(_safe_validate_template_url(client, url, telemetry))
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            telemetry["errors_count"] = int(telemetry.get("errors_count") or 0) + 1
    finalized = _finalize_findings(findings)
    telemetry["safe_validation_results_count"] = len(finalized)
    return finalized


async def _test_lfi_url(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, telemetry: dict) -> list[dict]:
    findings: list[dict] = []
    baseline = await _baseline_response(client, url)
    for parameter in _parameter_names(url):
        for payload in LFI_PAYLOADS:
            test_url = _url_with_payload(url, parameter, payload)
            async with semaphore:
                try:
                    response = await client.get(test_url, timeout=10.0, follow_redirects=False)
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                    continue
                except Exception as exc:
                    telemetry["errors_count"] += 1
                    log.debug(f"[targeted_vulns] LFI test error for {test_url}: {exc}")
                    continue
            body = _decode_response(response)
            finding = _classify_lfi_response(
                original_url=url,
                test_url=test_url,
                parameter=parameter,
                payload=payload,
                response=response,
                body=body,
                baseline=baseline,
            )
            if finding:
                findings.append(finding)
                if finding.get("status") == "confirmed":
                    return _finalize_findings(findings)
    return _finalize_findings(findings)


async def _run_lfi_tester(urls: list[str], profile: str, telemetry: dict, scan_config: dict | None = None) -> list[dict]:
    if not urls:
        return []
    if not _legacy_lfi_payloads_allowed(scan_config):
        telemetry["lfi_legacy_payloads_skipped"] = True
        telemetry["lfi_legacy_payloads_skip_reason"] = "public_target_safe_validation_only"
        return []

    semaphore = asyncio.Semaphore(20 if profile == "deep" else 10)
    async with httpx.AsyncClient(
        verify=False,
        headers=_runtime_headers(scan_config),
    ) as client:
        results = await asyncio.gather(
            *[_test_lfi_url(client, url, semaphore, telemetry) for url in urls],
            return_exceptions=True,
        )

    findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            telemetry["errors_count"] += 1
    return _finalize_findings(findings)


def _classify_command_injection_response(
    *,
    original_url: str,
    test_url: str,
    parameter: str,
    payload: str,
    method: str = "GET",
    response: httpx.Response,
    body: str,
    baseline_body: str,
) -> dict | None:
    headers = dict(response.headers)
    blocked, challenged, reasons = is_blocked_or_challenged(response.status_code, headers, body)
    if blocked or challenged:
        return _make_finding(
            finding_id="command_injection_blocked",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            method=method,
            category="detection-testing",
            vuln_type="command_injection_blocked",
            status="blocked",
            severity="info",
            confidence=0.3,
            evidence_text=f"Command-injection test response was blocked or challenged: {', '.join(reasons) or response.status_code}.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "blocked_or_challenged", "original_url": original_url},
        )

    if response.status_code in {404, 410} or _is_binary_response(response):
        return None

    if _looks_like_generic_error(response.status_code, body):
        return _make_finding(
            finding_id="command_injection_inconclusive",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            method=method,
            category="injection",
            vuln_type="command_injection_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.25,
            evidence_text="Command-injection test returned a generic error page; no marker proof was confirmed.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "generic_error_without_command_marker", "original_url": original_url},
        )

    baseline_has_marker = COMMAND_INJECTION_MARKER in (baseline_body or "")
    response_has_marker = COMMAND_INJECTION_MARKER in (body or "")
    if response_has_marker and not baseline_has_marker:
        return _make_finding(
            finding_id="command_injection",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            method=method,
            category="injection",
            vuln_type="command_injection",
            status="confirmed",
            severity="high",
            confidence=0.9,
            evidence_text=f"Safe command marker appeared only after injecting parameter '{parameter}'.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "safe_echo_marker_observed_after_payload_only", "original_url": original_url},
        )

    if baseline_has_marker:
        return _make_finding(
            finding_id="command_injection_inconclusive",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            method=method,
            category="injection",
            vuln_type="command_injection_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="Command marker already appeared in the baseline response; no payload-correlated proof was possible.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "baseline_contains_command_marker", "original_url": original_url},
        )

    if response.status_code == 200:
        return _make_finding(
            finding_id="command_injection_inconclusive",
            source_tool="internal",
            url=test_url,
            parameter=parameter,
            method=method,
            category="injection",
            vuln_type="command_injection_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="Command-injection test returned a normal 200 response without the safe command marker.",
            payload=payload,
            response_summary=_http_response_summary(response, body),
            raw={"classification_reason": "normal_200_without_command_marker", "original_url": original_url},
        )

    return None


async def _command_baseline_body(client: httpx.AsyncClient, url: str) -> str:
    try:
        response = await client.get(url, timeout=8.0, follow_redirects=False)
    except httpx.RequestError:
        return ""
    return _decode_response(response)


async def _test_command_injection_forms(
    client: httpx.AsyncClient,
    url: str,
    forms: list[dict],
    semaphore: asyncio.Semaphore,
    telemetry: dict,
) -> list[dict]:
    findings: list[dict] = []
    for form in forms:
        method = str(form.get("method") or "get").upper()
        action = str(form.get("action") or url)
        for parameter in form.get("testable_parameters") or []:
            first_non_confirmed: dict | None = None
            try:
                baseline_response = await _submit_command_request(
                    client,
                    url=action,
                    method=method,
                    data=_command_form_data(form, parameter, COMMAND_INJECTION_BASE_INPUT),
                    timeout=8.0,
                )
                baseline_body = _decode_response(baseline_response)
            except httpx.RequestError:
                baseline_body = ""
            for payload in COMMAND_INJECTION_PAYLOADS:
                async with semaphore:
                    telemetry["command_injection_tests_sent"] = telemetry.get("command_injection_tests_sent", 0) + 1
                    try:
                        response = await _submit_command_request(
                            client,
                            url=action,
                            method=method,
                            data=_command_form_data(form, parameter, payload),
                            timeout=10.0,
                        )
                    except httpx.TimeoutException:
                        telemetry["timeout_count"] += 1
                        continue
                    except (httpx.ConnectError, httpx.RequestError):
                        continue
                    except Exception as exc:
                        telemetry["errors_count"] += 1
                        log.debug(f"[targeted_vulns] Command injection form test error for {action}: {exc}")
                        continue
                body = _decode_response(response)
                finding = _classify_command_injection_response(
                    original_url=url,
                    test_url=action,
                    parameter=parameter,
                    payload=payload,
                    method=method,
                    response=response,
                    body=body,
                    baseline_body=baseline_body,
                )
                if not finding:
                    continue
                if finding.get("status") == "confirmed":
                    return _finalize_findings([finding])
                if first_non_confirmed is None:
                    first_non_confirmed = finding
            if first_non_confirmed:
                findings.append(first_non_confirmed)
    return _finalize_findings(findings)


async def _test_command_injection_get(
    client: httpx.AsyncClient,
    url: str,
    baseline_body: str,
    semaphore: asyncio.Semaphore,
    telemetry: dict,
) -> list[dict]:
    findings: list[dict] = []
    for parameter in _command_injection_test_parameters(url):
        first_non_confirmed: dict | None = None
        for payload in COMMAND_INJECTION_PAYLOADS:
            test_url = _url_with_payload(url, parameter, payload)
            async with semaphore:
                telemetry["command_injection_tests_sent"] = telemetry.get("command_injection_tests_sent", 0) + 1
                try:
                    response = await client.get(test_url, timeout=10.0, follow_redirects=False)
                except httpx.TimeoutException:
                    telemetry["timeout_count"] += 1
                    continue
                except (httpx.ConnectError, httpx.RequestError):
                    continue
                except Exception as exc:
                    telemetry["errors_count"] += 1
                    log.debug(f"[targeted_vulns] Command injection GET test error for {test_url}: {exc}")
                    continue
            body = _decode_response(response)
            finding = _classify_command_injection_response(
                original_url=url,
                test_url=test_url,
                parameter=parameter,
                payload=payload,
                method="GET",
                response=response,
                body=body,
                baseline_body=baseline_body,
            )
            if not finding:
                continue
            if finding.get("status") == "confirmed":
                return _finalize_findings([finding])
            if first_non_confirmed is None:
                first_non_confirmed = finding
        if first_non_confirmed:
            findings.append(first_non_confirmed)
    return _finalize_findings(findings)


async def _test_command_injection_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    telemetry: dict,
) -> list[dict]:
    page_body = ""
    page_url = url
    try:
        page_response = await client.get(url, timeout=8.0, follow_redirects=False)
        page_url = str(page_response.url) or url
        page_body = _decode_response(page_response)
    except httpx.RequestError:
        pass

    forms = _extract_command_forms(page_body, page_url)
    if forms:
        form_findings = await _test_command_injection_forms(client, url, forms, semaphore, telemetry)
        if form_findings:
            return form_findings

    baseline_body = page_body or await _command_baseline_body(client, url)
    return await _test_command_injection_get(client, url, baseline_body, semaphore, telemetry)


async def _run_command_injection_tester(
    urls: list[str],
    profile: str,
    telemetry: dict,
    scan_config: dict | None = None,
) -> list[dict]:
    if not urls:
        return []

    policy = _command_injection_validator_policy(scan_config, profile)
    if not policy.get("allowed"):
        telemetry["command_injection_validator_skipped"] = True
        telemetry["command_injection_validator_skip_reason"] = policy.get("reason") or "disabled_by_policy"
        return []

    local_urls = [url for url in urls if _is_local_url(url)]
    if not local_urls:
        telemetry["command_injection_validator_skipped"] = True
        telemetry["command_injection_validator_skip_reason"] = "no_local_command_injection_urls"
        return []

    telemetry["command_injection_validator_allowed"] = True
    semaphore = asyncio.Semaphore(2)
    async with httpx.AsyncClient(
        verify=False,
        headers=_runtime_headers(scan_config),
    ) as client:
        results = await asyncio.gather(
            *[_test_command_injection_url(client, url, semaphore, telemetry) for url in local_urls],
            return_exceptions=True,
        )

    findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            telemetry["errors_count"] += 1
    return _finalize_findings(findings)


def _suppress_confirmed_command_candidates(findings: list[dict]) -> list[dict]:
    confirmed_keys = {
        _finding_param_key(finding)
        for finding in findings
        if finding.get("vuln_type") == "command_injection" and finding.get("status") == "confirmed"
    }
    if not confirmed_keys:
        return findings
    filtered = []
    for finding in findings:
        if (
            finding.get("vuln_type") == "command_injection_candidate"
            and _finding_param_key(finding) in confirmed_keys
        ):
            continue
        filtered.append(finding)
    return filtered



STORED_XSS_MARKER_BASE = "RECON_STORED_XSS_"

def _priority_includes_stored_xss(scan_config: dict | None = None) -> bool:
    if not isinstance(scan_config, dict):
        return False
    aliases = {"xss", "stored_xss", "cross_site_scripting"}
    return any(str(item or "").strip().lower() in aliases for item in (scan_config.get("priority_vuln_types") or []))

def _stored_xss_validator_policy(scan_config: dict | None, profile: str = "") -> dict:
    scan_config = scan_config if isinstance(scan_config, dict) else {}
    effective_profile = str(scan_config.get("profile") or profile or "").strip().lower()
    target = str(scan_config.get("target") or "")
    if not _truthy(scan_config.get("target_is_local")):
        return {"allowed": False, "reason": "target_is_local_required"}
    if target and not _is_local_url(target):
        return {"allowed": False, "reason": "target_url_not_local"}
    if not _truthy(scan_config.get("authorization_confirmed")):
        return {"allowed": False, "reason": "authorization_confirmation_required"}
    if effective_profile not in LOCAL_LAB_COMMAND_PROFILES:
        return {"allowed": False, "reason": "profile_not_local_lab"}
    if not _priority_includes_stored_xss(scan_config):
        return {"allowed": False, "reason": "stored_xss_priority_required"}
    return {"allowed": True, "reason": "local_lab_stored_xss_enabled"}

async def _test_stored_xss_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    telemetry: dict,
) -> list[dict]:
    import uuid
    marker = f"{STORED_XSS_MARKER_BASE}{uuid.uuid4().hex[:8]}"
    payload = f"<script>{marker}</script>"
    findings: list[dict] = []
    
    try:
        page_response = await client.get(url, timeout=8.0, follow_redirects=False)
        page_body = _decode_response(page_response)
        page_url = str(page_response.url) or url
    except Exception as exc:
        import traceback
        traceback.print_exc()
        telemetry["errors_count"] = telemetry.get("errors_count", 0) + 1
        return []

    if marker in page_body:
        return []

    forms = _extract_all_forms(page_body, page_url)
    target_form = None
    target_param = ""
    for form in forms:
        for input_field in form.get("inputs", []):
            name = input_field.get("name", "").lower()
            if name == "mtxmessage" or "message" in name or "comment" in name:
                target_form = form
                target_param = input_field.get("name", "")
                break
        if target_form:
            break

    if not target_form:
        return []

    telemetry["stored_xss_forms_seen"] = telemetry.get("stored_xss_forms_seen", 0) + 1

    data = {}
    clear_data = {}
    has_clear = False
    submit_url = str(target_form.get("action") or page_url)
    submit_method = str(target_form.get("method") or "post").upper()

    for input_field in target_form.get("inputs", []):
        name = input_field.get("name", "")
        if not name:
            continue
        val = str(input_field.get("value") or "")
        lower_name = name.lower()
        if lower_name == "btnclear":
            has_clear = True
            clear_data[name] = val or "Clear Guestbook"
            continue
            
        if name == target_param:
            data[name] = payload
            clear_data[name] = "clean"
        elif lower_name == "txtname":
            data[name] = "ReconTool"
            clear_data[name] = "ReconTool"
        elif str(input_field.get("type")).lower() == "submit":
            data[name] = val or "Submit"
            clear_data[name] = val or "Submit"
        else:
            data[name] = val
            clear_data[name] = val

    if target_param not in data:
        data[target_param] = payload

    telemetry["stored_xss_tests_sent"] = telemetry.get("stored_xss_tests_sent", 0) + 1
    try:
        submit_response = await _submit_command_request(
            client,
            url=submit_url,
            method=submit_method,
            data=data,
            timeout=10.0,
        )
        revisit_response = await client.get(url, timeout=10.0, follow_redirects=False)
        revisit_body = _decode_response(revisit_response)
        
        blocked, challenged, reasons = is_blocked_or_challenged(revisit_response.status_code, dict(revisit_response.headers), revisit_body)
        
        finding = None
        if blocked or challenged:
            telemetry["stored_xss_blocked"] = telemetry.get("stored_xss_blocked", 0) + 1
            finding = _make_finding(
                finding_id="stored_xss_blocked",
                source_tool="internal",
                url=submit_url,
                parameter=target_param,
                method=submit_method,
                category="detection-testing",
                vuln_type="stored_xss_blocked",
                status="blocked",
                severity="info",
                confidence=0.3,
                evidence_text=f"Stored XSS test response was blocked or challenged: {', '.join(reasons) or revisit_response.status_code}.",
                payload=payload,
                response_summary=_http_response_summary(revisit_response, revisit_body),
                raw={"classification_reason": "blocked_or_challenged", "original_url": url},
            )
        elif revisit_response.status_code in {301, 302, 303, 307} and "login" in revisit_response.headers.get("location", "").lower():
            pass
        elif marker in revisit_body:
            telemetry["stored_xss_confirmed"] = telemetry.get("stored_xss_confirmed", 0) + 1
            finding = _make_finding(
                finding_id="stored_xss",
                source_tool="internal",
                url=submit_url,
                parameter=target_param,
                method=submit_method,
                category="injection",
                vuln_type="stored_xss",
                status="confirmed",
                severity="medium",
                confidence=0.9,
                evidence_text=f"Stored XSS marker '{marker}' observed on revisit page after submitting payload.",
                payload=payload,
                response_summary=_http_response_summary(revisit_response, revisit_body),
                raw={"classification_reason": "marker_found_on_revisit", "original_url": url},
            )
        else:
            telemetry["stored_xss_inconclusive"] = telemetry.get("stored_xss_inconclusive", 0) + 1
            finding = _make_finding(
                finding_id="stored_xss_inconclusive",
                source_tool="internal",
                url=submit_url,
                parameter=target_param,
                method=submit_method,
                category="injection",
                vuln_type="stored_xss_inconclusive",
                status="inconclusive",
                severity="info",
                confidence=0.2,
                evidence_text="Stored XSS form submitted, but marker was not found on revisit.",
                payload=payload,
                response_summary=_http_response_summary(revisit_response, revisit_body),
                raw={"classification_reason": "marker_not_found_on_revisit", "original_url": url},
            )

        if finding:
            findings.append(finding)

    except Exception as exc:
        import traceback
        traceback.print_exc()
        telemetry["errors_count"] = telemetry.get("errors_count", 0) + 1

    if has_clear:
        telemetry["stored_xss_cleanup_attempted"] = telemetry.get("stored_xss_cleanup_attempted", 0) + 1
        try:
            clear_resp = await _submit_command_request(
                client,
                url=submit_url,
                method=submit_method,
                data=clear_data,
                timeout=5.0,
            )
            clear_revisit = await client.get(url, timeout=5.0, follow_redirects=False)
            clear_body = _decode_response(clear_revisit)
            if marker not in clear_body:
                telemetry["stored_xss_cleanup_success"] = telemetry.get("stored_xss_cleanup_success", 0) + 1
        except Exception:
            pass

    return findings

async def _run_stored_xss_tester(
    urls: list[str],
    profile: str,
    telemetry: dict,
    scan_config: dict | None = None,
) -> list[dict]:
    if not urls:
        return []

    policy = _stored_xss_validator_policy(scan_config, profile)
    if not policy.get("allowed"):
        telemetry["stored_xss_validator_skipped"] = True
        telemetry["stored_xss_validator_skip_reason"] = policy.get("reason") or "disabled_by_policy"
        return []

    local_urls = [url for url in urls if _is_local_url(url)]
    if not local_urls:
        telemetry["stored_xss_validator_skipped"] = True
        telemetry["stored_xss_validator_skip_reason"] = "no_local_stored_xss_urls"
        return []

    telemetry["stored_xss_validator_allowed"] = True
    semaphore = asyncio.Semaphore(2)
    async with httpx.AsyncClient(
        verify=False,
        headers=_runtime_headers(scan_config),
    ) as client:
        results = await asyncio.gather(
            *[_test_stored_xss_url(client, url, semaphore, telemetry) for url in local_urls],
            return_exceptions=True,
        )

    findings: list[dict] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
        elif isinstance(result, Exception):
            telemetry["errors_count"] = telemetry.get("errors_count", 0) + 1
    return _finalize_findings(findings)


async def run_targeted_vulns(domain: str, alive_hosts: list, profile: str, scan_config: dict | None = None) -> dict:
    log.info(f"[{domain}] [Targeted Vulns] Routing URLs by GF, seed, and extracted URL category...")
    routed, route_sources, routing_stats = _collect_gf_routed_urls(alive_hosts, scan_config)
    telemetry = _new_telemetry(routed, routing_stats)

    if not any(routed.values()):
        log.info(f"[{domain}] [Targeted Vulns] No parameterized URLs routed from GF, seeds, or extraction. Skipping.")
        telemetry = _finish_telemetry(telemetry, [])
        return {
            "dalfox": [],
            "sqlmap": [],
            "lfi": [],
            "command_injection": [],
            "findings": [],
            "targeted_findings": [],
            "targeted_telemetry": telemetry,
            "routed_counts": {category: 0 for category in routed},
            "total_urls_tested": 0,
        }

    log.info(
        f"[{domain}] [Targeted Vulns] Routed URLs - "
        f"XSS: {len(routed['xss'])}, SQLi: {len(routed['sqli'])}, LFI: {len(routed['lfi'])}, "
        f"Command Injection: {len(routed['command_injection'])}, "
        f"Stored XSS: {len(routed.get('stored_xss', []))}"
    )

    route_candidates = _make_route_candidates(routed, domain, route_sources)
    safe_validation_task = _run_safe_candidate_validators(routed, profile, telemetry, scan_config=scan_config)
    if str(profile or "").lower() == "deep":
        dalfox_task = _run_dalfox(routed["xss"], profile, telemetry, scan_config=scan_config)
        sqlmap_task = _run_sqlmap(routed["sqli"], profile, telemetry, scan_config=scan_config)
        lfi_task = _run_lfi_tester(routed["lfi"], profile, telemetry, scan_config=scan_config)
        command_task = _run_command_injection_tester(routed["command_injection"], profile, telemetry, scan_config=scan_config)
        stored_task = _run_stored_xss_tester(routed.get("stored_xss", []), profile, telemetry, scan_config=scan_config)
        dalfox_res, sqlmap_res, lfi_res, safe_validation_res, command_res, stored_res = await asyncio.gather(
            dalfox_task,
            sqlmap_task,
            lfi_task,
            safe_validation_task,
            command_task,
            stored_task,
        )
    else:
        telemetry["external_tools_skipped"] = True
        telemetry["external_tools_skip_reason"] = "light_profile_uses_internal_safe_validators_only"
        dalfox_res = []
        sqlmap_res = []
        lfi_res = []
        command_res = []
        stored_res = []
        safe_validation_res = await safe_validation_task

    dalfox_res = _finalize_findings(dalfox_res)
    sqlmap_res = _finalize_findings(sqlmap_res)
    lfi_res = _finalize_findings(lfi_res)
    safe_validation_res = _finalize_findings(safe_validation_res)
    command_res = _finalize_findings(command_res)
    stored_res = _finalize_findings(stored_res)
    telemetry["dalfox_results_count"] = len(dalfox_res)
    telemetry["sqlmap_results_count"] = len(sqlmap_res)
    telemetry["lfi_results_count"] = len(lfi_res)
    telemetry["safe_validation_results_count"] = len(safe_validation_res)
    telemetry["command_injection_results_count"] = len(command_res)
    telemetry["stored_xss_results_count"] = len(stored_res)

    all_findings = _finalize_findings(_suppress_confirmed_command_candidates(_suppress_weaker_internal_candidates([
        *route_candidates,
        *dalfox_res,
        *sqlmap_res,
        *lfi_res,
        *safe_validation_res,
        *command_res,
        *stored_res,
    ])))
    all_findings = _cap_generated_weak_candidates(all_findings, telemetry)
    telemetry = _finish_telemetry(telemetry, all_findings)

    log.info(
        f"[{domain}] [Targeted Vulns] Complete. "
        f"XSS: {len(dalfox_res)}, SQLi: {len(sqlmap_res)}, LFI: {len(lfi_res)}, "
        f"safe validation: {len(safe_validation_res)}, "
        f"Command Injection: {len(command_res)}, "
        f"Stored XSS: {len(stored_res)}, "
        f"candidates: {telemetry['candidates_count']}, confirmed: {telemetry['confirmed_count']}"
    )

    return {
        "dalfox": dalfox_res,
        "sqlmap": sqlmap_res,
        "lfi": lfi_res,
        "safe_validation": safe_validation_res,
        "command_injection": command_res,
        "stored_xss": stored_res,
        "findings": all_findings,
        "targeted_findings": all_findings,
        "targeted_telemetry": telemetry,
        "routed_counts": {category: len(urls) for category, urls in routed.items()},
        "total_urls_tested": sum(len(urls) for urls in routed.values()),
    }
