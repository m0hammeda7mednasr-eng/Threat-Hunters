from __future__ import annotations

import asyncio
import copy
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from .alive import check_alive
from .crlfuzz import run_crlfuzz
from .extraction import run_extraction
from .findings import merge_findings
from .form_scanner import run_form_scanner
from .fuzz import fuzz_endpoints
from .ports import scan_ports
from .reporter import generate_html_report, generate_markdown_report
from .scan_config import (
    ScanConfigError,
    inject_seed_urls_into_hosts,
    prepare_scan_config,
    sanitize_scan_config_for_storage,
)
from .security_headers import run_security_header_audit
from .sensitive_files import run_sensitive_file_hunt
from .targeted_vulns import run_targeted_vulns
from .utils import build_report, check_tool, get_available_tool, normalize_target, save_report
from .vuln import run_nuclei
from .websocket_scanner import run_websocket_scan


PACKAGE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = Path(os.getenv("SCANNER_REPORTS_DIR", str(PACKAGE_DIR / "reports"))).expanduser()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_REPORT_SUFFIXES = {".json", ".md", ".html"}
DEFAULT_LIMITS_BY_PROFILE = {
    "light": {
        "max_requests": 1000,
        "concurrency": 3,
        "delay_ms": 500,
        "timeout_seconds": 10,
    },
    "deep": {
        "max_requests": 5000,
        "concurrency": 5,
        "delay_ms": 250,
        "timeout_seconds": 15,
    },
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
        "extraction": True,
        "security_headers": True,
        "sensitive_files": True,
        "targeted": True,
        "forms": True,
        "crlfuzz": deep,
        "websocket": True,
        "vulns": bool(deep and enable_nuclei),
        "ports": deep,
        "fuzz": deep,
        "archive_cdx": False,
    }


def _merge_tool_overrides(defaults: dict, overrides: dict | None) -> dict:
    tools = dict(defaults)
    if not isinstance(overrides, dict):
        return tools
    for name, enabled in overrides.items():
        if name in tools:
            tools[name] = _as_bool(enabled)
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
    for module_name, enabled in tools.items():
        if not enabled:
            _record_module_state(scan_data, module_name, "skipped", "Disabled by scan mode or options.")


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
    modules: dict | None = None,
    limits: dict | None = None,
) -> dict:
    target_info = normalize_target(target)
    domain = target_info["domain"]
    normalized_target = target_info["target"]
    target_is_local = _is_local_target_identifier(normalized_target or domain)
    profile = "deep" if str(scan_mode or "light").lower() == "deep" else "light"
    authorization_confirmed = True if target_is_local else _as_bool(confirm_permission)
    if not authorization_confirmed:
        raise ScanConfigError("Public/non-local scans require explicit permission confirmation.")

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
            "external_tool_auth_allowed": False,
            "limits": _profile_limits(profile, limits),
        },
    }
    prepared = prepare_scan_config(req, domain=domain, default_profile=profile)
    stored_scan_config = prepared["redacted"]
    runtime_scan_config = prepared["runtime"]
    tools = _merge_tool_overrides(_default_tools(profile, enable_nuclei), modules)
    if tools.get("vulns") and not (profile == "deep" and enable_nuclei):
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
        "requested_modules": {name: _as_bool(enabled) for name, enabled in (modules or {}).items() if name in tools},
        "effective_modules": dict(tools),
        "telemetry": {"modules": {}},
    }
    _record_disabled_modules(scan_data, tools)
    subdomains = [normalized_target if target_is_local else (normalized_target or domain)]

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
                lambda: run_extraction(alive_hosts, profile=profile, callback=progress),
                "Extracting same-origin URLs and forms",
            )
            if extraction_results is not None:
                alive_hosts = extraction_results
            alive_hosts = inject_seed_urls_into_hosts(alive_hosts, runtime_scan_config)

        if tools["ports"]:
            if not check_tool("naabu") and not check_tool("nmap"):
                _record_module_state(scan_data, "ports", "skipped", "No safe port scanning tool found (naabu or nmap).")
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
            if not get_available_tool("fuzz"):
                _record_module_state(scan_data, "fuzz", "skipped", "No fuzzing tool found (ffuf or gobuster).")
                await progress("fuzz", "skipped", "No fuzzing tool found. Skipping.")
            else:
                fuzz_results = await _run_module_safely(
                    "fuzz",
                    scan_data,
                    progress,
                    lambda: fuzz_endpoints(alive_hosts, profile=profile, callback=progress, scan_config=runtime_scan_config),
                    "Running rate-limited content discovery",
                )
                if fuzz_results is not None:
                    alive_hosts = fuzz_results

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
            _record_module_state(scan_data, "archive_cdx", "skipped", "Archive CDX collection is not implemented in this package export.")

        scan_data.setdefault("telemetry", {})["nuclei_correlation"] = correlate_nuclei_with_core_findings(alive_hosts)
    else:
        for module_name, enabled in tools.items():
            if enabled and module_name not in scan_data.get("telemetry", {}).get("modules", {}):
                _record_module_state(scan_data, module_name, "skipped", "No live hosts were found.")

    report = build_report(domain, subdomains, alive_hosts, scan_data)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = save_report(report, str(REPORTS_DIR))
    md_path = json_path.replace(".json", ".md")
    html_path = json_path.replace(".json", ".html")
    generate_markdown_report(report, md_path)
    generate_html_report(report, html_path)
    await progress("complete", "done", "Scanner core run complete")

    report_id = Path(json_path).stem
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
            "md": md_path,
            "html": html_path,
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
    modules: dict | None = None,
    limits: dict | None = None,
) -> dict:
    return asyncio.run(_run_scan_async(
        target,
        scan_mode=scan_mode,
        cookie_header=cookie_header,
        enable_nuclei=enable_nuclei,
        confirm_permission=confirm_permission,
        nuclei_profile=nuclei_profile,
        modules=modules,
        limits=limits,
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
