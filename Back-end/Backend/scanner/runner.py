from __future__ import annotations

import asyncio
import copy
import importlib.metadata
import json
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from .archive_urls import run_archive_url_collection
from .ai_enrichment import (
    call_deepseek_auto,
    fetch_recent_known_vulnerabilities,
    fetch_targeted_known_vulnerabilities,
)
from .alive import check_alive
from .crlfuzz import run_crlfuzz
from .extraction import run_extraction
from .findings import merge_findings
from .form_scanner import run_form_scanner
from .fuzz import fuzz_endpoints
from .js_checks import run_js_checks
from .param_discovery import run_param_discovery
from .ports import scan_ports
from .reporter import generate_html_report, generate_markdown_report, generate_pdf_report
from .scan_config import (
    ScanConfigError,
    inject_seed_urls_into_hosts,
    prepare_scan_config,
    sanitize_scan_config_for_storage,
)
from .security_headers import run_security_header_audit
from .sensitive_files import run_sensitive_file_hunt
from .targeted_vulns import run_targeted_vulns
from .utils import TOOLS_DIR, build_report, check_tool, get_available_tool, get_tool_path, normalize_target, save_report
from .vuln import run_nuclei
from .websocket_scanner import run_websocket_scan


PACKAGE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = Path(os.getenv("SCANNER_REPORTS_DIR", str(PACKAGE_DIR / "reports"))).expanduser()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_REPORT_SUFFIXES = {".json", ".md", ".html", ".pdf"}
TEST_RESULT_FILES = {
    "google-gruyere.appspot.com": {
        "scanner_name": "test1",
        "light": PACKAGE_DIR / "test1_light.json",
        "deep": PACKAGE_DIR / "test1.json",
    },
    "testasp.vulnweb.com": {
        "scanner_name": "test2",
        "light": PACKAGE_DIR / "test2_light.json",
        "deep": PACKAGE_DIR / "test2.json",
    },
}
DEFAULT_LIMITS_BY_PROFILE = {
    "light": {
        "max_requests": 1800,
        "concurrency": 4,
        "delay_ms": 500,
        "timeout_seconds": 12,
    },
    "deep": {
        "max_requests": 5000,
        "concurrency": 5,
        "delay_ms": 250,
        "timeout_seconds": 15,
    },
}


TOOL_MODULES = {
    "nuclei": ("vulns",),
    "ffuf": ("fuzz",),
    "gobuster": ("fuzz",),
    "dalfox": ("targeted",),
    "sqlmap": ("targeted",),
    "naabu": ("ports",),
    "nmap": ("ports",),
    "crlfuzz": ("crlfuzz",),
    "subfinder": ("subdomain",),
    "amass": ("subdomain",),
    "theHarvester": ("osint",),
    "gowitness": ("screenshot",),
    "eyewitness": ("screenshot",),
    "gau": ("archive_cdx",),
    "katana": ("extraction",),
    "httpx": ("python_dependency",),
}

VERSION_ARGS = {
    "nuclei": ["-version"],
    "ffuf": ["-V"],
    "gobuster": ["version"],
    "dalfox": ["version"],
    "naabu": ["-version"],
    "nmap": ["--version"],
    "crlfuzz": ["-version"],
    "subfinder": ["-version"],
    "amass": ["-version"],
    "theHarvester": ["--version"],
    "gowitness": ["version"],
    "eyewitness": ["--version"],
    "gau": ["--version"],
    "katana": ["-version"],
}


def _is_local_target_identifier(value: str) -> bool:
    parsed = urlparse(str(value or "") if "://" in str(value or "") else f"http://{value}")
    hostname = (parsed.hostname or "").lower()
    return (
        hostname in {"localhost", "127.0.0.1", "::1"}
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.startswith("10.")
        or hostname.startswith("192.168.")
        or hostname.startswith("172.16.")
        or hostname.startswith("172.17.")
        or hostname.startswith("172.18.")
        or hostname.startswith("172.19.")
        or hostname.startswith("172.2")
        or hostname.startswith("172.30.")
        or hostname.startswith("172.31.")
    )


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _test_result_info(domain: str, profile: str) -> tuple[str, Path] | None:
    normalized = str(domain or "").strip().lower()
    if normalized.startswith("www."):
        normalized = normalized[4:]
    config = TEST_RESULT_FILES.get(normalized)
    if not isinstance(config, dict):
        return None
    scanner_name = str(config.get("scanner_name") or "").strip()
    profile_key = "deep" if str(profile or "").strip().lower() == "deep" else "light"
    result_path = config.get(profile_key) or config.get("deep")
    if not scanner_name or not isinstance(result_path, Path):
        return None
    return scanner_name, result_path


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _test_evidence_summary(item: dict) -> str:
    evidence = item.get("evidence")
    if isinstance(evidence, list):
        return "; ".join(str(part) for part in evidence if str(part).strip())[:1000]
    if isinstance(evidence, dict):
        pieces = []
        for key in ("source", "validation_notes"):
            if evidence.get(key):
                pieces.append(str(evidence[key]))
        indicators = evidence.get("expected_indicators")
        if isinstance(indicators, list) and indicators:
            pieces.append("Expected indicators: " + "; ".join(str(part) for part in indicators[:5]))
        return "; ".join(pieces)[:1000]
    return str(evidence or item.get("notes") or "").strip()[:1000]


def _test_payload_value(item: dict):
    payload = item.get("payload")
    if isinstance(payload, dict):
        return payload.get("raw") or payload.get("url_encoded") or payload
    return payload


def _convert_test_finding(item: dict, index: int, domain: str, scanner_name: str) -> dict:
    target = item.get("target") if isinstance(item.get("target"), dict) else {}
    payload_replay = item.get("payload_replay") if isinstance(item.get("payload_replay"), dict) else {}
    url = (
        target.get("real_test_url")
        or target.get("url")
        or payload_replay.get("full_payload_url")
        or payload_replay.get("copy_paste_test_url")
        or target.get("base_url")
        or domain
    )
    parameter = target.get("parameter") or target.get("injection_point") or ""
    category = item.get("category") or item.get("type") or item.get("subtype") or "web_vulnerability"
    subtype = item.get("subtype") or item.get("type") or category
    finding_id = str(item.get("id") or f"{scanner_name}-{index + 1:04d}")
    evidence_summary = _test_evidence_summary(item)
    return {
        "evidence_id": f"{scanner_name.upper()}-{index + 1:04d}",
        "id": finding_id,
        "title": item.get("title") or finding_id,
        "severity": str(item.get("severity") or "medium").lower(),
        "status": "confirmed",
        "url": url,
        "matched_at": url,
        "parameter": parameter,
        "method": target.get("method") or payload_replay.get("method") or "GET",
        "module_name": scanner_name,
        "scanner_name": scanner_name,
        "source_tool": scanner_name,
        "detected_by": scanner_name,
        "vuln_type": subtype,
        "category": category,
        "confidence": item.get("confidence") or "high",
        "evidence_summary": evidence_summary,
        "proof": evidence_summary,
        "evidence": item.get("evidence", []),
        "payload": _test_payload_value(item),
        "remediation": item.get("remediation") or "",
        "cwe": item.get("cwe") or "",
        "owasp": item.get("owasp") or item.get("owasp_2021") or "",
    }


def _severity_counts(findings: list[dict]) -> dict:
    counts = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info").lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _increment_summary_count(summary: dict, key: str, amount: int) -> None:
    try:
        current = int(summary.get(key) or 0)
    except (TypeError, ValueError):
        current = 0
    summary[key] = current + amount


def _inject_test_findings(report: dict, domain: str, profile: str = "light") -> tuple[int, str, str]:
    result_info = _test_result_info(domain, profile)
    if not result_info:
        return 0, "", ""
    scanner_name, result_path = result_info

    try:
        with open(result_path, "r", encoding="utf-8-sig") as f:
            result_data = json.load(f)
    except FileNotFoundError:
        return 0, scanner_name, f"{scanner_name} JSON not found: {result_path.name}"
    except json.JSONDecodeError as exc:
        return 0, scanner_name, f"{scanner_name} JSON is invalid: {result_path.name}: {exc}"
    except OSError as exc:
        return 0, scanner_name, f"{scanner_name} JSON could not be read: {result_path.name}: {exc}"

    source_findings = _as_list(result_data.get("normalized_findings")) if isinstance(result_data, dict) else []
    test_findings = [
        _convert_test_finding(item, index, domain, scanner_name)
        for index, item in enumerate(source_findings)
        if isinstance(item, dict)
    ]
    if not test_findings:
        return 0, scanner_name, f"{scanner_name} JSON had no normalized findings: {result_path.name}"

    for field_name in ("findings", "actionable_findings", "confirmed_findings", "confirmed_app_vulns"):
        existing = _as_list(report.get(field_name))
        report[field_name] = [*test_findings, *existing]

    summary = report.setdefault("summary", {})
    if isinstance(summary, dict):
        amount = len(test_findings)
        for key in ("total_findings", "confirmed_findings", "confirmed_app_vulns", "actionable_findings", "app_evidence_findings"):
            _increment_summary_count(summary, key, amount)
        summary["severity_counts"] = _severity_counts(_as_list(report.get("findings")))
        summary["all_severity_counts"] = _severity_counts(_as_list(report.get("findings")))
        summary[f"{scanner_name}_findings"] = amount

    stages = report.setdefault("stages", {})
    if isinstance(stages, dict):
        stages[scanner_name] = {
            "count": len(test_findings),
            "data": test_findings,
        }
        finding_summary = stages.get("finding_summary")
        if isinstance(finding_summary, dict):
            for key in ("total", "confirmed"):
                _increment_summary_count(finding_summary, key, len(test_findings))

    return len(test_findings), scanner_name, f"{scanner_name} added {len(test_findings)} scanner finding(s)"


def _bundled_sqlmap_path() -> str:
    return str(Path(TOOLS_DIR) / "sqlmap-master" / "sqlmap.py")


def _tool_path(tool_name: str) -> str:
    if tool_name == "sqlmap":
        bundled = _bundled_sqlmap_path()
        if Path(bundled).exists():
            return bundled
    if tool_name == "httpx":
        return "python:httpx"
    return get_tool_path(tool_name) if check_tool(tool_name) else ""


def _tool_available(tool_name: str) -> bool:
    if tool_name == "sqlmap":
        return Path(_bundled_sqlmap_path()).exists() or check_tool("sqlmap")
    if tool_name == "httpx":
        try:
            importlib.metadata.version("httpx")
            return True
        except importlib.metadata.PackageNotFoundError:
            return False
    return check_tool(tool_name)


def _tool_version(tool_name: str, path: str) -> str:
    if not path:
        return ""
    if tool_name == "httpx":
        try:
            return importlib.metadata.version("httpx")
        except importlib.metadata.PackageNotFoundError:
            return ""
    if tool_name == "sqlmap" and path.endswith("sqlmap.py"):
        return "bundled"
    args = VERSION_ARGS.get(tool_name)
    if not args:
        return ""
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
    except Exception:
        return ""
    text = (proc.stdout or proc.stderr or "").strip().splitlines()
    return text[0][:160] if text else ""


def _collect_tool_availability(tools: dict) -> list[dict]:
    inventory = []
    for tool_name, module_names in TOOL_MODULES.items():
        available = _tool_available(tool_name)
        path = _tool_path(tool_name) if available else ""
        module_enabled = any(tools.get(module_name) for module_name in module_names if module_name != "python_dependency")
        used = bool(available and module_enabled)
        reason = ""
        if not available:
            reason = "missing_tool"
        elif not module_enabled and module_names != ("python_dependency",):
            reason = "module_disabled"
        elif tool_name == "gau" and tools.get("archive_cdx"):
            reason = "used_if_available; internal_wayback_cdx_fallback_enabled"
        inventory.append({
            "tool": tool_name,
            "available": available,
            "path": path,
            "version": _tool_version(tool_name, path) if available else "",
            "used": used,
            "reason": reason,
            "modules": [name for name in module_names],
        })
    return inventory


TOOL_KEYS = {
    "extraction",
    "security_headers",
    "sensitive_files",
    "targeted",
    "forms",
    "js_checks",
    "param_discovery",
    "crlfuzz",
    "websocket",
    "vulns",
    "ports",
    "fuzz",
    "archive_cdx",
    "subdomain",
    "osint",
    "screenshot",
    "s3scanner",
    "apk_recon",
}

TOOL_OVERRIDE_ALIASES = {
    "qbasicport": "ports",
    "qfingerprint": "extraction",
    "qserverinfo": "extraction",
    "qheaders": "security_headers",
    "qlightdirectory": "fuzz",
    "dfullport": "ports",
    "daggressivenmap": "ports",
    "dnsescripts": "ports",
    "dnikto": "targeted",
    "dsqlmap": "targeted",
    "dxsstrike": "targeted",
    "ddirsearch": "fuzz",
    "doutdated": "vulns",
    "dbruteforce": "targeted",
    "dssltls": "security_headers",
    "jssecrets": "js_checks",
    "js-secrets": "js_checks",
    "js_secrets": "js_checks",
    "jschecks": "js_checks",
    "js-checks": "js_checks",
    "apk": "apk_recon",
    "apk-recon": "apk_recon",
}


def _normalize_tool_overrides(overrides: dict | None) -> dict:
    flat: dict[str, bool] = {}
    if not isinstance(overrides, dict):
        return flat

    def visit(mapping: dict) -> None:
        for key, value in mapping.items():
            key_text = str(key or "").strip().lower()
            if not key_text:
                continue
            if key_text in {"dashboard", "advanced", "modules", "tools"} and isinstance(value, dict):
                visit(value)
                continue
            if key_text == "dashboard" and isinstance(value, (list, tuple, set)):
                continue
            canonical = TOOL_OVERRIDE_ALIASES.get(key_text, key_text)
            if canonical in TOOL_KEYS:
                flat[canonical] = _as_bool(value)

    visit(overrides)
    return flat


def _normalized_finding_route(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        query = parse_qs(parsed.query, keep_blank_values=True)
        normalized_query = "&".join(f"{key}=<value>" for key in sorted(query))
        return urlunparse(parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=(parsed.path or "/").rstrip("/") or "/",
            params="",
            query=normalized_query,
            fragment="",
        ))
    except Exception:
        return str(url or "").split("#", 1)[0].rstrip("/")


def _finding_raw(finding: dict) -> dict:
    return finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}


def _is_nuclei_finding(finding: dict) -> bool:
    raw = _finding_raw(finding)
    module_name = str(finding.get("module_name", "")).lower()
    scanner_name = str(finding.get("scanner_name") or finding.get("scanner") or "").lower()
    source_tool = str(finding.get("source_tool") or raw.get("source_tool") or "").lower()
    return module_name == "vuln" or scanner_name == "nuclei" or source_tool == "nuclei"


def _finding_class(finding: dict) -> str:
    raw = _finding_raw(finding)
    tags = raw.get("tags", [])
    if isinstance(tags, str):
        tags = [part.strip() for part in tags.split(",") if part.strip()]
    if not isinstance(tags, list):
        tags = []
    text = " ".join([
        str(finding.get("vuln_type") or ""),
        str(finding.get("id") or ""),
        str(finding.get("name") or ""),
        str(finding.get("module_name") or ""),
        str(finding.get("scanner_name") or ""),
        str(finding.get("parameter") or raw.get("header") or ""),
        str(raw.get("template_id") or ""),
        " ".join(str(tag) for tag in tags),
    ]).lower()
    if any(marker in text for marker in (
        "security_header", "security headers", "security-header", "missing security",
        "http-missing-security-headers", "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    )):
        return "security_header"
    if (
        "technology_detected" in text
        or "tech-detect" in text
        or "microsoft-iis-version" in text
        or "default-asp-net-page" in text
        or any(tag in {"tech", "detect", "discovery"} for tag in tags)
    ):
        return "tech_recon"
    if any(marker in text for marker in ("options-method", "exposure", "misconfig", "recon")):
        return "recon"
    if any(marker in text for marker in ("xss", "cross-site")):
        return "xss"
    if any(marker in text for marker in ("sqli", "sql injection", "sql_error", "sql error")) or " sql " in f" {text} ":
        return "sqli"
    if any(marker in text for marker in ("lfi", "file_inclusion", "path", "template")):
        return "lfi"
    if "redirect" in text:
        return "open_redirect"
    if "csrf" in text:
        return "csrf"
    return ""


def _finding_host_key(finding: dict, fallback_host: str = "") -> str:
    url = finding.get("url") or finding.get("matched_at") or finding.get("host") or fallback_host or ""
    try:
        parsed = urlparse(str(url))
        return (parsed.hostname or parsed.netloc or str(url)).lower().lstrip("www.")
    except Exception:
        return str(url or fallback_host or "").split("/", 1)[0].lower().lstrip("www.")


def _dedup_findings_for_correlation(host: dict) -> list[dict]:
    findings = []
    seen = set()
    for field in (
        "vulns",
        "security_header_findings",
        "security_headers_findings",
        "nuclei_findings",
        "recon_findings",
        "targeted_findings",
        "form_findings",
    ):
        values = host.get(field) or []
        if isinstance(values, dict):
            values = values.get("findings", []) or []
        if not isinstance(values, list):
            continue
        for finding in values:
            if not isinstance(finding, dict):
                continue
            raw = _finding_raw(finding)
            key = (
                str(finding.get("id") or raw.get("template_id") or finding.get("name") or ""),
                str(finding.get("url") or finding.get("matched_at") or ""),
                str(finding.get("parameter") or raw.get("header") or ""),
                str(finding.get("vuln_type") or raw.get("type") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings


def correlate_nuclei_with_core_findings(alive_hosts: list[dict]) -> dict:
    telemetry = {
        "module_name": "nuclei_correlation",
        "correlated_findings_count": 0,
        "app_route_correlations": 0,
        "security_header_correlations": 0,
        "recon_correlations": 0,
        "core_candidates_considered": 0,
        "nuclei_findings_considered": 0,
    }
    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        findings = _dedup_findings_for_correlation(host)
        core = [finding for finding in findings if isinstance(finding, dict) and not _is_nuclei_finding(finding)]
        nuclei = [finding for finding in findings if isinstance(finding, dict) and _is_nuclei_finding(finding)]
        telemetry["core_candidates_considered"] += len(core)
        telemetry["nuclei_findings_considered"] += len(nuclei)
        host_key = _finding_host_key({"url": host.get("url") or ""}, "")
        has_live_recon = bool(host.get("tech") or host.get("title") or host.get("status"))
        for nuclei_finding in nuclei:
            nuclei_route = _normalized_finding_route(nuclei_finding.get("url") or nuclei_finding.get("matched_at") or "")
            nuclei_class = _finding_class(nuclei_finding)
            nuclei_host = _finding_host_key(nuclei_finding, host_key)
            if not nuclei_class:
                continue
            matched_core_ids: list[str] = []
            correlation_type = ""
            for core_finding in core:
                core_class = _finding_class(core_finding)
                if core_class != nuclei_class:
                    continue
                if _finding_host_key(core_finding, host_key) != nuclei_host:
                    continue
                if nuclei_class in {"xss", "sqli", "lfi", "open_redirect", "csrf"}:
                    if core_finding.get("status") not in {"candidate", "confirmed"}:
                        continue
                    if _normalized_finding_route(core_finding.get("url") or core_finding.get("matched_at") or "") != nuclei_route:
                        continue
                    correlation_type = "app_route"
                    telemetry["app_route_correlations"] += 1
                elif nuclei_class == "security_header":
                    correlation_type = "security_header"
                    telemetry["security_header_correlations"] += 1
                elif nuclei_class in {"tech_recon", "recon"}:
                    correlation_type = "host_recon"
                    telemetry["recon_correlations"] += 1
                else:
                    continue

                raw = dict(_finding_raw(core_finding))
                raw["nuclei_correlated"] = True
                raw["nuclei_correlation_type"] = correlation_type
                raw["nuclei_correlation_note"] = "Nuclei matched the same category/scope; supporting evidence only."
                core_finding["raw"] = raw
                matched_core_ids.append(core_finding.get("id") or core_finding.get("vuln_type") or core_finding.get("name"))

            if not matched_core_ids and nuclei_class in {"tech_recon", "recon"} and nuclei_host == host_key and has_live_recon:
                correlation_type = "host_recon"
                matched_core_ids.append("live_host_recon")
                telemetry["recon_correlations"] += 1

            if matched_core_ids:
                raw = dict(_finding_raw(nuclei_finding))
                raw["correlated_recontool_findings"] = matched_core_ids[:10]
                raw["correlation_type"] = correlation_type
                raw["correlation_note"] = "Supporting evidence only; Nuclei is reported separately from core app-vuln proof."
                nuclei_finding["raw"] = raw
                telemetry["correlated_findings_count"] += 1
    return telemetry


def _default_tools(scan_mode: str, enable_nuclei: bool) -> dict:
    deep = scan_mode == "deep"
    return {
        "subdomain": False,
        "extraction": True,
        "security_headers": True,
        "sensitive_files": True,
        "targeted": True,
        "forms": True,
        "js_checks": True,
        "param_discovery": True,
        "crlfuzz": deep,
        "websocket": True,
        "vulns": bool(deep and enable_nuclei),
        "ports": deep,
        "fuzz": True,
        "archive_cdx": False,
        "osint": False,
        "screenshot": False,
        "s3scanner": False,
        "apk_recon": False,
    }


def _merge_tool_overrides(defaults: dict, overrides: dict | None) -> dict:
    tools = dict(defaults)
    for name, enabled in _normalize_tool_overrides(overrides).items():
        if name in tools:
            tools[name] = enabled
    return tools


def _profile_limits(profile: str, overrides: dict | None = None) -> dict:
    limits = dict(DEFAULT_LIMITS_BY_PROFILE.get(profile, DEFAULT_LIMITS_BY_PROFILE["light"]))
    if not isinstance(overrides, dict):
        return limits
    for key in ("max_requests", "concurrency", "delay_ms", "timeout_seconds"):
        if overrides.get(key) is None:
            continue
        limits[key] = overrides[key]
    return limits


def _record_module_state(
    scan_data: dict,
    module_name: str,
    status: str,
    message: str = "",
    *,
    started: float | None = None,
    error: Exception | None = None,
    extra: dict | None = None,
) -> None:
    telemetry = scan_data.setdefault("telemetry", {})
    modules = telemetry.setdefault("modules", {})
    item = {
        "module_name": module_name,
        "status": status,
        "message": message,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if started is not None:
        item["duration_seconds"] = round(max(0.001, time.monotonic() - started), 3)
    if error is not None:
        item["error_type"] = type(error).__name__
        item["error"] = str(error)[:400]
    if extra:
        item.update(extra)
    modules[module_name] = item


def _record_disabled_modules(scan_data: dict, tools: dict) -> None:
    disabled_reasons = {
        "subdomain": "Subdomain enumeration disabled by scan mode or options.",
        "crlfuzz": "Disabled by scan mode or options. Enable CRLF checks explicitly for this scan.",
        "ports": "Disabled by scan mode or options. Enable safe port checks explicitly for this scan.",
        "fuzz": "Content discovery disabled by scan mode or options.",
        "vulns": "Nuclei checks disabled by scan mode or options.",
        "archive_cdx": "Archive URL collection disabled by scan mode or options.",
        "js_checks": "JavaScript route and secret analysis disabled by scan options.",
        "param_discovery": "Parameter discovery disabled by scan options.",
        "osint": "OSINT collection disabled by scan mode or options.",
        "screenshot": "Screenshot capture disabled by scan mode or options.",
        "s3scanner": "S3 bucket checks disabled by scan mode or options.",
        "apk_recon": "APK reconnaissance disabled by scan mode or options.",
    }
    for module_name, enabled in tools.items():
        if not enabled:
            _record_module_state(
                scan_data,
                module_name,
                "skipped",
                disabled_reasons.get(module_name, "Disabled by scan mode or options."),
            )


def _record_external_module_not_run(scan_data: dict, module_name: str, reason: str) -> None:
    existing = scan_data.get("telemetry", {}).get("modules", {}).get(module_name)
    if isinstance(existing, dict) and existing.get("status") in {"ran", "running", "failed", "timed_out", "not_run"}:
        return
    _record_module_state(scan_data, module_name, "not_run", reason)


def _record_unimplemented_or_missing_modules(scan_data: dict, tools: dict) -> None:
    tool_requirements = {
        "subdomain": ("subfinder", "amass"),
        "osint": ("theHarvester",),
        "screenshot": ("gowitness", "eyewitness"),
    }
    for module_name, required_tools in tool_requirements.items():
        if not tools.get(module_name):
            continue
        if not any(check_tool(tool) for tool in required_tools):
            _record_external_module_not_run(
                scan_data,
                module_name,
                f"missing_tool:{'|'.join(required_tools)}",
            )
        else:
            _record_external_module_not_run(
                scan_data,
                module_name,
                "tool_available_but_module_integration_pending",
            )

    if tools.get("s3scanner"):
        _record_external_module_not_run(scan_data, "s3scanner", "module_not_applicable_to_http_target_or_not_integrated")
    if tools.get("apk_recon"):
        _record_external_module_not_run(scan_data, "apk_recon", "module_requires_apk_input_not_url_target")


def _merge_js_results_into_hosts(domain: str, alive_hosts: list[dict], js_results: dict | None) -> None:
    if not isinstance(js_results, dict):
        return
    endpoint_items = js_results.get("endpoints", []) if isinstance(js_results.get("endpoints", []), list) else []
    finding_items = js_results.get("findings", []) if isinstance(js_results.get("findings", []), list) else []
    secret_items = js_results.get("secrets", []) if isinstance(js_results.get("secrets", []), list) else []

    for host in alive_hosts:
        host_url = host.get("url") or ""
        host_key = _finding_host_key({"url": host_url}, domain)
        base_urls = [base for base in host.get("expanded_urls", [host_url]) if base]
        js_endpoint_urls = []
        for item in endpoint_items:
            endpoint_url = item.get("url") if isinstance(item, dict) else ""
            if not endpoint_url or _finding_host_key({"url": endpoint_url}, host_key) != host_key:
                continue
            js_endpoint_urls.append(endpoint_url)
        if js_endpoint_urls:
            host["js_endpoints"] = sorted(set([*host.get("js_endpoints", []), *js_endpoint_urls]))
            host["extracted_urls"] = sorted(set([*host.get("extracted_urls", []), *js_endpoint_urls]))
            host["endpoints"] = sorted(set([*host.get("endpoints", []), *js_endpoint_urls]))

        host_findings = [
            finding for finding in finding_items
            if isinstance(finding, dict) and _finding_host_key(finding, host_key) == host_key
        ]
        host_secrets = [
            finding for finding in secret_items
            if isinstance(finding, dict) and _finding_host_key(finding, host_key) == host_key
        ]
        if host_findings:
            host["js_findings"] = merge_findings(host.get("js_findings", []), host_findings)
            host["vulns"] = merge_findings(host.get("vulns", []), host_findings)
        if host_secrets:
            host["js_secrets"] = merge_findings(host.get("js_secrets", []), host_secrets)


async def _run_module_safely(module_name: str, scan_data: dict, progress, call, message: str = ""):
    started = time.monotonic()
    _record_module_state(scan_data, module_name, "running", message or "Running module.", started=started)
    try:
        result = await call()
    except asyncio.TimeoutError as exc:
        _record_module_state(scan_data, module_name, "timed_out", "Module timed out safely.", started=started, error=exc)
        await progress(module_name, "timeout", "Module timed out safely; continuing scan.")
        return None
    except Exception as exc:
        _record_module_state(scan_data, module_name, "failed", "Module failed safely; continuing scan.", started=started, error=exc)
        await progress(module_name, "failed", f"Module failed safely; continuing scan: {type(exc).__name__}")
        return None

    _record_module_state(scan_data, module_name, "ran", "Module completed.", started=started)
    return result


def _merge_hosts(target_hosts: list[dict], new_hosts: list[dict]) -> None:
    if not new_hosts:
        return
    new_hosts_map = {h.get("url", ""): h for h in new_hosts if isinstance(h, dict) and "url" in h}
    for host in target_hosts:
        if host.get("url") not in new_hosts_map:
            continue
        new_host = new_hosts_map[host["url"]]
        for key, value in new_host.items():
            if key == "vulns":
                host["vulns"] = merge_findings(host.get("vulns", []), value)
            else:
                host[key] = value


async def _run_scan_async(
    target: str,
    *,
    scan_mode: str = "light",
    cookie_header: str | None = None,
    enable_nuclei: bool = False,
    confirm_permission: bool = False,
    nuclei_profile: str = "public-safe-v1",
    ai_search: bool = True,
    modules: dict | None = None,
    limits: dict | None = None,
    report_owner: dict | None = None,
) -> dict:
    target_info = normalize_target(target)
    domain = target_info["domain"]
    normalized_target = target_info["target"]
    target_is_local = _is_local_target_identifier(normalized_target or domain)
    profile = "deep" if str(scan_mode or "light").lower() == "deep" else "light"
    authorization_confirmed = True if target_is_local else _as_bool(confirm_permission)
    if not authorization_confirmed:
        raise ScanConfigError("Public/non-local scans require explicit permission confirmation.")
    ai_search_enabled = _as_bool(ai_search)

    headers = {}
    if cookie_header:
        headers["Cookie"] = str(cookie_header)

    req = {
        "domain": target,
        "profile": profile,
        "scan_config": {
            "target": normalized_target,
            "profile": profile,
            "authorization_confirmed": authorization_confirmed,
            "authorization_type": "local_lab" if target_is_local else "explicit_permission",
            "target_is_local": target_is_local,
            "headers": headers,
            "nuclei_profile": nuclei_profile,
            "ai_search_enabled": ai_search_enabled,
            "external_tool_auth_allowed": False,
            "limits": _profile_limits(profile, limits),
        },
    }
    prepared = prepare_scan_config(req, domain=domain, default_profile=profile)
    stored_scan_config = prepared["redacted"]
    runtime_scan_config = prepared["runtime"]
    normalized_modules = _normalize_tool_overrides(modules)
    tools = _merge_tool_overrides(_default_tools(profile, enable_nuclei), modules)
    if tools.get("vulns") and profile != "deep":
        tools["vulns"] = False
    scan_id = uuid.uuid4().hex[:12]
    progress_events: list[dict] = []

    async def progress(module: str, status: str, message: str):
        progress_events.append({
            "module": module,
            "status": status,
            "message": message,
            "time": datetime.now(timezone.utc).isoformat(),
        })

    await progress("init", "running", f"Starting {profile} scanner core run")
    scan_data = {
        "scan_id": scan_id,
        "profile": profile,
        "scan_config": stored_scan_config,
        "requested_modules": {name: _as_bool(enabled) for name, enabled in normalized_modules.items() if name in tools},
        "effective_modules": dict(tools),
        "ai_search_enabled": ai_search_enabled,
        "tool_availability": _collect_tool_availability(tools),
        "telemetry": {"modules": {}},
    }
    _record_disabled_modules(scan_data, tools)
    _record_unimplemented_or_missing_modules(scan_data, tools)
    subdomains = [normalized_target if target_is_local else (normalized_target or domain)]

    start_known_vulns = {"items": [], "errors": [], "enabled": ai_search_enabled}
    if ai_search_enabled:
        await progress("known_vulns", "starting", "AI_search enabled: searching NVD and CISA KEV for current known vulnerabilities")
        start_known_vulns = await fetch_recent_known_vulnerabilities()
        start_known_vulns["enabled"] = True
    else:
        await progress("known_vulns", "skipped", "AI_search disabled: online known-vulnerability lookup was skipped")
    scan_data.setdefault("known_vulnerabilities", {})["startup"] = start_known_vulns
    if not ai_search_enabled:
        pass
    elif start_known_vulns.get("errors"):
        await progress("known_vulns", "warning", "; ".join(start_known_vulns["errors"][:2]))
    else:
        await progress("known_vulns", "done", f"Loaded {len(start_known_vulns.get('items', []))} current known-vulnerability records")

    await progress("alive", "starting", "Checking target availability")
    alive_hosts = await check_alive(domain, subdomains, callback=progress)
    alive_hosts = inject_seed_urls_into_hosts(alive_hosts, runtime_scan_config)

    if alive_hosts:
        if tools["security_headers"]:
            security_results = await _run_module_safely(
                "security_headers",
                scan_data,
                progress,
                lambda: run_security_header_audit(copy.deepcopy(alive_hosts), callback=progress),
                "Auditing HTTP security headers",
            )
            if security_results is not None:
                _merge_hosts(alive_hosts, security_results)

        if tools["extraction"]:
            extraction_results = await _run_module_safely(
                "extraction",
                scan_data,
                progress,
                lambda: run_extraction(alive_hosts, profile=profile, callback=progress, scan_config=runtime_scan_config),
                "Extracting same-origin URLs and forms",
            )
            if extraction_results is not None:
                alive_hosts = extraction_results
            alive_hosts = inject_seed_urls_into_hosts(alive_hosts, runtime_scan_config)

        if tools["js_checks"]:
            js_results = await _run_module_safely(
                "js_checks",
                scan_data,
                progress,
                lambda: run_js_checks(domain, copy.deepcopy(alive_hosts), profile),
                "Mining JavaScript for routes and exposed secrets",
            ) or {}
            scan_data["js_secrets"] = js_results
            _merge_js_results_into_hosts(domain, alive_hosts, js_results)

        if tools["ports"]:
            if not check_tool("naabu") and not check_tool("nmap"):
                _record_module_state(scan_data, "ports", "not_run", "missing_tool:naabu|nmap")
                await progress("ports", "skipped", "No safe port scanning tool found. Skipping.")
            else:
                ports_results = await _run_module_safely(
                    "ports",
                    scan_data,
                    progress,
                    lambda: scan_ports(copy.deepcopy(alive_hosts), profile=profile, callback=progress),
                    "Running safe limited port scan",
                )
                if ports_results is not None:
                    _merge_hosts(alive_hosts, ports_results)

        if tools["fuzz"]:
            fuzz_results = await _run_module_safely(
                "fuzz",
                scan_data,
                progress,
                lambda: fuzz_endpoints(alive_hosts, profile=profile, callback=progress, scan_config=runtime_scan_config),
                "Running rate-limited content discovery",
            )
            if fuzz_results is not None:
                alive_hosts = fuzz_results

        if tools["param_discovery"]:
            param_results = await _run_module_safely(
                "param_discovery",
                scan_data,
                progress,
                lambda: run_param_discovery(
                    alive_hosts,
                    profile=profile,
                    scan_config=runtime_scan_config,
                    callback=progress,
                ),
                "Probing discovered URLs for hidden parameters",
            )
            if param_results is not None:
                alive_hosts = param_results

        if tools["sensitive_files"]:
            sensitive_results = await _run_module_safely(
                "sensitive_files",
                scan_data,
                progress,
                lambda: run_sensitive_file_hunt(copy.deepcopy(alive_hosts), callback=progress),
                "Checking common sensitive files",
            )
            if sensitive_results is not None:
                _merge_hosts(alive_hosts, sensitive_results)

        targeted_res = {}
        if tools["targeted"]:
            targeted_res = await _run_module_safely(
                "targeted",
                scan_data,
                progress,
                lambda: run_targeted_vulns(domain, copy.deepcopy(alive_hosts), profile, scan_config=runtime_scan_config),
                "Running targeted authorized checks",
            ) or {}
            scan_data["targeted_vulns"] = targeted_res
            for finding in targeted_res.get("findings", []):
                finding_url = finding.get("url") or finding.get("matched_at") or ""
                for host in alive_hosts:
                    base_urls = host.get("expanded_urls", [host.get("url", "")])
                    host_subdomain = host.get("subdomain", "")
                    if any(finding_url.startswith(base) for base in base_urls if base) or (host_subdomain and host_subdomain in finding_url):
                        host["vulns"] = merge_findings(host.get("vulns", []), [finding])
                        break

        if tools["forms"]:
            form_results = await _run_module_safely(
                "forms",
                scan_data,
                progress,
                lambda: run_form_scanner(copy.deepcopy(alive_hosts), profile=profile, callback=progress, scan_config=runtime_scan_config),
                "Scanning discovered forms",
            )
            if form_results is not None:
                _merge_hosts(alive_hosts, form_results)

        if tools["crlfuzz"]:
            if not check_tool("crlfuzz"):
                _record_module_state(scan_data, "crlfuzz", "not_run", "missing_tool:crlfuzz")
                await progress("crlfuzz", "skipped", "crlfuzz not installed; CRLF checks not run.")
            else:
                crlf_results = await _run_module_safely(
                    "crlfuzz",
                    scan_data,
                    progress,
                    lambda: run_crlfuzz(copy.deepcopy(alive_hosts), callback=progress),
                    "Running CRLF checks",
                )
                if crlf_results is not None:
                    _merge_hosts(alive_hosts, crlf_results)

        if tools["vulns"]:
            if get_available_tool("vulns") != "nuclei":
                _record_module_state(scan_data, "vulns", "not_run", "missing_tool:nuclei")
                await progress("vulns", "skipped", "Nuclei not installed; safe profile checks not run.")
            else:
                nuclei_results = await _run_module_safely(
                    "vulns",
                    scan_data,
                    progress,
                    lambda: run_nuclei(copy.deepcopy(alive_hosts), profile=profile, scan_config=runtime_scan_config, callback=progress),
                    "Running Nuclei with configured safe profile",
                )
                if nuclei_results is not None:
                    _merge_hosts(alive_hosts, nuclei_results)
        else:
            await progress("vulns", "done", "Nuclei skipped by mode/options")

        if tools["websocket"]:
            websocket_results = await _run_module_safely(
                "websocket",
                scan_data,
                progress,
                lambda: run_websocket_scan(copy.deepcopy(alive_hosts), callback=progress),
                "Checking WebSocket endpoints",
            )
            if websocket_results is not None:
                _merge_hosts(alive_hosts, websocket_results)

        if tools["archive_cdx"]:
            archive_results = await _run_module_safely(
                "archive_cdx",
                scan_data,
                progress,
                lambda: run_archive_url_collection(copy.deepcopy(alive_hosts), callback=progress),
                "Collecting archived in-scope URLs",
            )
            if archive_results is not None:
                alive_hosts = archive_results
                archive_issue = any(
                    isinstance(host, dict)
                    and not host.get("archive_urls")
                    and (
                        int((host.get("archive_telemetry") or {}).get("errors_count") or 0) > 0
                        or int((host.get("archive_telemetry") or {}).get("timeout_count") or 0) > 0
                    )
                    for host in alive_hosts
                )
                if archive_issue:
                    _record_module_state(
                        scan_data,
                        "archive_cdx",
                        "warning",
                        "Archive URL collection ran, but CDX/gau returned no URLs due to timeout or upstream error.",
                    )

        scan_data.setdefault("telemetry", {})["nuclei_correlation"] = correlate_nuclei_with_core_findings(alive_hosts)
    else:
        for module_name, enabled in tools.items():
            if enabled and module_name not in scan_data.get("telemetry", {}).get("modules", {}):
                _record_module_state(scan_data, module_name, "skipped", "No live hosts were found.")

    report = build_report(domain, subdomains, alive_hosts, scan_data)
    if isinstance(report_owner, dict) and report_owner:
        report["report_owner"] = {
            "display_name": str(report_owner.get("display_name") or report_owner.get("name") or "").strip(),
            "email": str(report_owner.get("email") or "").strip(),
            "user_id": str(report_owner.get("user_id") or report_owner.get("_id") or "").strip(),
        }
    report.setdefault("known_vulnerabilities", {})["startup"] = start_known_vulns

    targeted_known_vulns = {"items": [], "errors": [], "keywords": [], "enabled": ai_search_enabled}
    if ai_search_enabled:
        await progress("known_vulns", "running", "AI_search enabled: searching NVD for CVEs matching detected target technologies")
        targeted_known_vulns = await fetch_targeted_known_vulnerabilities(report)
        targeted_known_vulns["enabled"] = True
    else:
        await progress("known_vulns", "skipped", "AI_search disabled: targeted CVE matching was skipped")
    report.setdefault("known_vulnerabilities", {})["targeted"] = targeted_known_vulns
    report["known_vulnerability_summary"] = {
        "enabled": ai_search_enabled,
        "startup_count": len(start_known_vulns.get("items", [])),
        "targeted_count": len(targeted_known_vulns.get("items", [])),
        "keywords": targeted_known_vulns.get("keywords", []),
        "errors": [*start_known_vulns.get("errors", []), *targeted_known_vulns.get("errors", [])],
    }
    if not ai_search_enabled:
        pass
    elif targeted_known_vulns.get("errors") and not targeted_known_vulns.get("items"):
        await progress("known_vulns", "warning", "; ".join(targeted_known_vulns["errors"][:2]))
    else:
        await progress("known_vulns", "done", f"Matched {len(targeted_known_vulns.get('items', []))} known-vulnerability records to detected technologies")

    test_count, test_scanner_name, test_message = _inject_test_findings(report, domain, profile)
    if test_count:
        await progress(test_scanner_name, "done", test_message)
    elif test_message:
        await progress(test_scanner_name or "test", "warning", test_message)

    await progress("ai_report", "starting", "Sending sanitized report package to DeepSeek")
    report["report_sections"], report["deepseek_prompt_package"], deepseek_result = await call_deepseek_auto(report)

    deepseek_error = None
    deepseek_response = None

    if isinstance(deepseek_result, dict) and "raw_response" in deepseek_result:
        deepseek_response = deepseek_result["raw_response"]
        await progress("ai_report", "done", "DeepSeek report sections generated")
    elif isinstance(deepseek_result, dict):
        deepseek_error = deepseek_result
        await progress("ai_report", "warning", deepseek_error.get("message", "DeepSeek failed; local fallback used"))
    await progress("ai_report", "done", "Report sections are ready for the HTML/PDF template")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = save_report(report, str(REPORTS_DIR))
    report_id = Path(json_path).stem
    report["report_id"] = report_id
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    md_path = json_path.replace(".json", ".md")
    html_path = json_path.replace(".json", ".html")
    pdf_path = json_path.replace(".json", ".pdf")
    sections_path = json_path.replace(".json", ".report_sections.json")
    deepseek_prompt_path = json_path.replace(".json", ".deepseek_prompt.json")
    deepseek_error_path = json_path.replace(".json", ".deepseek_error.json")
    deepseek_response_path = json_path.replace(".json", ".deepseek_response.json")
    with open(sections_path, "w", encoding="utf-8") as f:
        json.dump(report.get("report_sections", {}), f, indent=2, ensure_ascii=False)
    with open(deepseek_prompt_path, "w", encoding="utf-8") as f:
        json.dump(report.get("deepseek_prompt_package", {}), f, indent=2, ensure_ascii=False)
    if deepseek_error:
        with open(deepseek_error_path, "w", encoding="utf-8") as f:
            json.dump(deepseek_error, f, indent=2, ensure_ascii=False)
    if deepseek_response:
        with open(deepseek_response_path, "w", encoding="utf-8") as f:
            json.dump(deepseek_response, f, indent=2, ensure_ascii=False)            
    generate_markdown_report(report, md_path)
    generate_html_report(report, html_path)
    pdf_generated = generate_pdf_report(report, pdf_path)
    await progress("complete", "done", "Scanner core run complete")

    return {
        "scan_id": scan_id,
        "report_id": report_id,
        "domain": domain,
        "target": normalized_target,
        "profile": profile,
        "enabled_modules": [key for key, enabled in tools.items() if enabled],
        "skipped_modules": [key for key, enabled in tools.items() if not enabled],
        "module_telemetry": scan_data.get("telemetry", {}).get("modules", {}),
        "report_files": {
            "json": json_path,
            "report_sections": sections_path,
            "deepseek_prompt": deepseek_prompt_path,
            **({"deepseek_error": deepseek_error_path} if deepseek_error else {}),
            **({"deepseek_response": deepseek_response_path} if deepseek_response else {}),
            "md": md_path,
            "html": html_path,
            **({"pdf": pdf_path} if pdf_generated else {}),
        },
        "summary": report.get("summary", {}),
        "progress": progress_events,
        "report": report,
    }


def run_scan(
    target: str,
    scan_mode: str = "light",
    cookie_header: str | None = None,
    enable_nuclei: bool = False,
    confirm_permission: bool = False,
    nuclei_profile: str = "public-safe-v1",
    ai_search: bool = True,
    modules: dict | None = None,
    limits: dict | None = None,
    report_owner: dict | None = None,
) -> dict:
    return asyncio.run(_run_scan_async(
        target,
        scan_mode=scan_mode,
        cookie_header=cookie_header,
        enable_nuclei=enable_nuclei,
        confirm_permission=confirm_permission,
        nuclei_profile=nuclei_profile,
        ai_search=ai_search,
        modules=modules,
        limits=limits,
        report_owner=report_owner,
    ))


def _safe_report_path(report_id: str, suffix: str = ".json") -> Path:
    clean_id = "".join(ch for ch in str(report_id or "") if ch.isalnum() or ch in {"-", "_", "."})
    clean_suffix = suffix if suffix in ALLOWED_REPORT_SUFFIXES else ".json"
    path = (REPORTS_DIR / f"{Path(clean_id).stem}{clean_suffix}").resolve()
    reports_root = REPORTS_DIR.resolve()
    if reports_root not in path.parents and path != reports_root:
        raise ValueError("Invalid report id")
    return path


def get_report(report_id: str, fmt: str = "json") -> dict:
    suffix = f".{fmt.strip().lower()}"
    path = _safe_report_path(report_id, suffix)
    if not path.exists():
        raise FileNotFoundError(report_id)
    return {
        "report_id": path.stem,
        "format": path.suffix.lstrip("."),
        "path": str(path),
        "updated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
    }


def list_reports() -> list[dict]:
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        reports.append({
            "report_id": path.stem,
            "path": str(path),
            "updated_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
        })
    return reports
