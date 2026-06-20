from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .findings import Finding, merge_findings
from .scanner_types import EvidenceItem, body_hash, normalize_severity, response_summary, utc_now
from .utils import get_available_tool, get_tool_path, log


MODULE_NAME = "vuln"
SOURCE_TOOL = "nuclei"

REFERENCES = [
    "https://docs.projectdiscovery.io/tools/nuclei/overview",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/Top10/",
]

STATIC_EXTS = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".mp4",
    ".mp3",
    ".avi",
    ".webm",
}

SECRET_PATTERNS = [
    re.compile(r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY.*?-----END .*?PRIVATE KEY-----"),
    re.compile(r"(?i)\b(authorization|cookie|set-cookie|sessionid|x-api-key)\s*[:=]\s*[^\r\n;]+"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|access[_-]?key)"
        r"\s*[:=]\s*['\"]?[^'\"\s,;]{6,}"
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
]

STRONG_CONTENT_MARKERS = [
    "db_password",
    "api_key",
    "secret_key",
    "aws_secret_access_key",
    "-----begin",
    "create table",
    "insert into",
    "mysql dump",
    "sqlite format 3",
    "[core]",
    "index of /",
    "uid=",
    "root:x:",
    "vulnerable",
    "proof",
    "confirmed",
]

TECH_TAGS = {"tech", "technology", "fingerprint", "detect", "detection"}
TAKEOVER_TAGS = {"takeover", "subdomain-takeover", "dns"}
HEADER_TAGS = {"header", "headers", "security-header", "missing-header"}
EXPOSURE_TAGS = {"exposure", "exposures", "file", "files", "config", "backup", "secret", "secrets", "disclosure"}
INJECTION_TAGS = {"xss", "sqli", "sql", "rce", "lfi", "ssrf", "ssti", "injection"}
NUCLEI_PUBLIC_SAFE_PROFILE = "public-safe-v1"
NUCLEI_LAB_APP_PROFILE = "lab-app-v1"
NUCLEI_SAFE_TEMPLATE_PROFILE = NUCLEI_PUBLIC_SAFE_PROFILE
NUCLEI_PUBLIC_SAFE_TEMPLATE_RELATIVE_PATHS = [
    "http/technologies/tech-detect.yaml",
    "http/technologies/microsoft/microsoft-iis-version.yaml",
    "http/technologies/default-asp-net-page.yaml",
    "http/misconfiguration/http-missing-security-headers.yaml",
    "http/vulnerabilities/generic/cors-misconfig.yaml",
    "http/miscellaneous/options-method.yaml",
    "http/misconfiguration/aspx-debug-mode.yaml",
    "http/exposures/logs/microsoft-runtime-error.yaml",
    "http/exposures/apis/aspnet-soap-webservices-asmx.yaml",
    "http/misconfiguration/x-backend-server-header-detect.yaml",
]
NUCLEI_LAB_APP_TEMPLATE_RELATIVE_PATHS = [
    *NUCLEI_PUBLIC_SAFE_TEMPLATE_RELATIVE_PATHS,
    "http/vulnerabilities/generic/error-based-sql-injection.yaml",
    "http/vulnerabilities/generic/xss-uri-reflected.yaml",
    "http/vulnerabilities/generic/top-xss-params.yaml",
]
NUCLEI_SAFE_TEMPLATE_RELATIVE_PATHS = NUCLEI_PUBLIC_SAFE_TEMPLATE_RELATIVE_PATHS
NUCLEI_SAFE_EXCLUDE_TAGS = (
    "intrusive,dos,fuzz,bruteforce,brute-force,default-login,credential-stuffing,"
    "upload,file-upload,destructive,rce,sqli,sql-injection,xss,lfi,ssrf,ssti,oast,dast"
)
NUCLEI_LAB_APP_EXCLUDE_TAGS = (
    "intrusive,dos,bruteforce,brute-force,default-login,credential-stuffing,"
    "upload,file-upload,destructive,rce,ssrf,ssti,oast,dast,interactsh"
)
NUCLEI_SAFE_SEVERITIES = "info,low"
NUCLEI_LAB_APP_SEVERITIES = "info,low,medium,high,critical"
NUCLEI_SAFE_RATE_LIMIT = "5"
NUCLEI_SAFE_MAX_TARGETS = 10
NUCLEI_LAB_APP_MAX_TARGETS = 20
NUCLEI_SAFE_CONCURRENCY = "5"
NUCLEI_SAFE_REQUEST_TIMEOUT = "10"
NUCLEI_SAFE_RETRIES = "0"
NUCLEI_SAFE_PROCESS_TIMEOUT = 120

NUCLEI_PROFILES = {
    NUCLEI_PUBLIC_SAFE_PROFILE: {
        "name": NUCLEI_PUBLIC_SAFE_PROFILE,
        "template_paths": NUCLEI_PUBLIC_SAFE_TEMPLATE_RELATIVE_PATHS,
        "severity": NUCLEI_SAFE_SEVERITIES,
        "exclude_tags": NUCLEI_SAFE_EXCLUDE_TAGS,
        "target_scope": "host_root",
        "max_targets": NUCLEI_SAFE_MAX_TARGETS,
        "allowed_target_type": "public_or_lab",
    },
    NUCLEI_LAB_APP_PROFILE: {
        "name": NUCLEI_LAB_APP_PROFILE,
        "template_paths": NUCLEI_LAB_APP_TEMPLATE_RELATIVE_PATHS,
        "severity": NUCLEI_LAB_APP_SEVERITIES,
        "exclude_tags": NUCLEI_LAB_APP_EXCLUDE_TAGS,
        "target_scope": "host_and_app_routes",
        "max_targets": NUCLEI_LAB_APP_MAX_TARGETS,
        "allowed_target_type": "local_lab_only",
    },
}


def _first_parameter(url: str) -> str:
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=True)
        return next(iter(params.keys()), "")
    except Exception:
        return ""


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]
        return [value] if value else []
    return [value]


def _redact_text(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}=<redacted>" if match.groups() else "<redacted-secret>", text)
    text = re.sub(r"(?i)(curl\s+.*?\s+-H\s+['\"](?:authorization|cookie|x-api-key):)\s*[^'\"]+", r"\1 <redacted>", text)
    return text[:1200]


def _redact_list(values: list) -> list[str]:
    return [_redact_text(value) for value in values if _redact_text(value)]


def _info(data: dict) -> dict:
    return data.get("info") if isinstance(data.get("info"), dict) else {}


def _tags(data: dict) -> set[str]:
    info = _info(data)
    raw_tags = []
    raw_tags.extend(_as_list(info.get("tags")))
    raw_tags.extend(_as_list(data.get("tags")))
    raw_tags.extend(_as_list(data.get("type")))
    raw_tags.extend(_as_list(data.get("template-path")))
    raw_tags.extend(_as_list(data.get("template-id")))
    return {str(tag).lower().strip() for tag in raw_tags if str(tag).strip()}


def _classification(data: dict) -> dict:
    info = _info(data)
    classification = info.get("classification")
    return classification if isinstance(classification, dict) else {}


def _references(data: dict) -> list[str]:
    info = _info(data)
    refs = []
    refs.extend(_as_list(info.get("reference")))
    refs.extend(_as_list(info.get("references")))
    refs.extend(_as_list(_classification(data).get("cve-id")))
    refs.extend(REFERENCES)
    seen = set()
    clean = []
    for item in refs:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        clean.append(text)
    return clean


def _matched_url(data: dict) -> str:
    return (
        data.get("matched-at")
        or data.get("matched")
        or data.get("url")
        or data.get("host")
        or data.get("ip")
        or ""
    )


def _evidence_values(data: dict) -> list[str]:
    values = []
    values.extend(_as_list(data.get("extracted-results")))
    values.extend(_as_list(data.get("extractor-name")))
    values.extend(_as_list(data.get("matcher-name")))
    for key in ("matched-line", "request", "response", "curl-command"):
        value = data.get(key)
        if value:
            values.append(value)
    return _redact_list(values)


def _raw_response(data: dict) -> str:
    return _redact_text(data.get("response") or data.get("matched-line") or "")


def _raw_request(data: dict) -> str:
    return _redact_text(data.get("request") or data.get("curl-command") or "")


def _has_cve(data: dict) -> bool:
    tags = _tags(data)
    classification = _classification(data)
    template_id = str(data.get("template-id") or "").lower()
    cves = _as_list(classification.get("cve-id"))
    return bool(cves) or "cve" in tags or "cve-" in template_id


def _is_technology_detection(data: dict) -> bool:
    tags = _tags(data)
    template_id = str(data.get("template-id") or "").lower()
    severity = normalize_severity(_info(data).get("severity"))
    return severity == "info" and (bool(tags & TECH_TAGS) or "detect" in template_id or "tech" in template_id)


def _is_missing_header(data: dict) -> bool:
    text = " ".join([
        str(data.get("template-id", "")),
        str(_info(data).get("name", "")),
        str(_info(data).get("description", "")),
        " ".join(_tags(data)),
    ]).lower()
    return ("missing" in text and "header" in text) or "security-header" in text


def _is_takeover(data: dict) -> bool:
    tags = _tags(data)
    text = f"{data.get('template-id', '')} {_info(data).get('name', '')}".lower()
    return bool(tags & TAKEOVER_TAGS) or "takeover" in text


def _is_exposed_file(data: dict) -> bool:
    tags = _tags(data)
    text = f"{data.get('template-id', '')} {_info(data).get('name', '')} {_info(data).get('description', '')}".lower()
    return bool(tags & EXPOSURE_TAGS) or any(marker in text for marker in ["exposed", "backup", "config", "env", "secret", "disclosure"])


def _is_injection_or_rce(data: dict) -> bool:
    tags = _tags(data)
    text = f"{data.get('template-id', '')} {_info(data).get('name', '')}".lower()
    return bool(tags & INJECTION_TAGS) or any(marker in text for marker in ["xss", "sqli", "rce", "ssrf", "lfi", "ssti"])


def _strong_evidence(data: dict) -> bool:
    evidence = " ".join(_evidence_values(data)).lower()
    response = _raw_response(data).lower()
    matcher = str(data.get("matcher-name") or "").lower()
    extracted = _as_list(data.get("extracted-results"))
    if any(marker in evidence or marker in response for marker in STRONG_CONTENT_MARKERS):
        return True
    if extracted and any(marker in matcher for marker in ["proof", "confirmed", "vulnerable", "extract", "body"]):
        return True
    if data.get("matcher-status") is True and response and extracted:
        return True
    return False


def _vuln_type_and_category(data: dict) -> tuple[str, str]:
    if _is_technology_detection(data):
        return "technology_detected", "network_recon"
    if _is_missing_header(data):
        return "security_header", "misconfiguration"
    if _is_takeover(data):
        return "subdomain_takeover", "takeover"
    if _has_cve(data):
        return "known_cve", "known vulnerability"
    if _is_injection_or_rce(data):
        tags = _tags(data)
        if "xss" in tags:
            return "xss", "injection"
        if "sqli" in tags or "sql" in tags:
            return "sql_injection", "injection"
        if "rce" in tags:
            return "command_injection", "injection"
        if "ssrf" in tags:
            return "ssrf", "server-side request forgery"
        return "injection_candidate", "injection"
    if _is_exposed_file(data):
        return "sensitive_file", "exposure"
    return "nuclei_finding", "vulnerability_scan"


def _status_severity_confidence(data: dict, vuln_type: str) -> tuple[str, str, float]:
    severity = normalize_severity(_info(data).get("severity") or "info")
    if severity == "unknown":
        severity = "info"
    strong = _strong_evidence(data)

    if severity == "info" or vuln_type == "technology_detected":
        return "recon", "info", 0.35

    if vuln_type == "security_header":
        return "recon", "info", 0.3

    if vuln_type == "subdomain_takeover":
        return "candidate", severity, 0.58

    if vuln_type == "known_cve":
        return ("confirmed", severity, 0.88) if strong else ("candidate", severity, 0.6)

    if vuln_type in {"xss", "sql_injection", "command_injection", "ssrf", "injection_candidate"}:
        return ("confirmed", severity, 0.86) if strong else ("candidate", severity, 0.58)

    if vuln_type == "sensitive_file":
        return ("confirmed", severity, 0.88) if strong else ("candidate", severity, 0.55)

    return ("confirmed", severity, 0.84) if strong else ("candidate", severity, 0.52)


def _request_summary(data: dict, url: str) -> dict:
    raw_request = _raw_request(data)
    curl_command = _redact_text(data.get("curl-command") or "")
    if not raw_request and not curl_command:
        return {}
    return {
        "method": "HTTP",
        "url": url,
        "headers": {},
        "body_hash": body_hash(raw_request),
        "timestamp": utc_now(),
        "raw": raw_request[:800],
        "curl_command": curl_command[:800],
    }


def _response_summary(data: dict) -> dict:
    raw_response = _raw_response(data)
    if not raw_response:
        return {}
    return response_summary(status_code=None, headers={}, body=raw_response, snippet=raw_response[:500])


def _remediation(vuln_type: str, data: dict) -> str:
    if vuln_type == "technology_detected":
        return "Review the detected technology as inventory; apply normal patch and exposure management."
    if vuln_type == "security_header":
        return "Review header configuration in the dedicated security headers module before treating this as a vulnerability."
    if vuln_type == "known_cve":
        return "Validate the affected product/version with a safe dedicated check, then patch or mitigate according to the vendor advisory."
    if vuln_type == "subdomain_takeover":
        return "Verify the DNS/resource ownership condition manually and remove dangling DNS records or reclaim the resource."
    if vuln_type == "sensitive_file":
        return "Remove the exposed file, restrict direct access, and rotate any secrets that may have been exposed."
    if vuln_type in {"xss", "sql_injection", "command_injection", "ssrf", "injection_candidate"}:
        return "Validate with a safe proof in an authorized environment, then fix the underlying input handling and access controls."
    return "Review the Nuclei evidence and validate with a safe, dedicated check before treating it as confirmed."


def _evidence_text(data: dict, status: str) -> str:
    info = _info(data)
    values = _evidence_values(data)
    parts = [
        f"Nuclei template {data.get('template-id', 'unknown-template')} matched {_matched_url(data) or data.get('host', '')}.",
        f"Template name: {info.get('name', 'Nuclei Finding')}.",
        f"Status assigned by ReconTool: {status}.",
    ]
    if values:
        parts.append("Evidence: " + "; ".join(values[:4]))
    elif info.get("description"):
        parts.append("Template description: " + _redact_text(info.get("description")))
    return " ".join(part for part in parts if part).strip()


def normalize_nuclei_result(data: dict) -> dict:
    info = _info(data)
    url = _matched_url(data)
    vuln_type, category = _vuln_type_and_category(data)
    status, severity, confidence = _status_severity_confidence(data, vuln_type)
    evidence_text = _evidence_text(data, status)
    template_id = data.get("template-id") or "nuclei-finding"
    timestamp = data.get("timestamp") or utc_now()

    raw = {
        "source_tool": SOURCE_TOOL,
        "template_id": template_id,
        "template_path": data.get("template-path", ""),
        "template_url": data.get("template-url", ""),
        "matcher_name": data.get("matcher-name", ""),
        "extractor_name": data.get("extractor-name", ""),
        "type": data.get("type", ""),
        "tags": sorted(_tags(data)),
        "classification": _classification(data),
        "curl_command": _redact_text(data.get("curl-command") or ""),
        "host": data.get("host", ""),
    }

    return Finding(
        id=str(template_id),
        scanner_name=SOURCE_TOOL,
        module_name=MODULE_NAME,
        url=url,
        parameter=_first_parameter(url),
        severity=severity,
        evidence=evidence_text,
        name=info.get("name") or str(template_id),
        description=info.get("description") or evidence_text,
        matched_at=url,
        raw=raw,
        target=data.get("host") or urlparse(url).netloc,
        method="HTTP",
        category=category,
        vuln_type=vuln_type,
        status=status,
        confidence=confidence,
        evidence_items=[
            EvidenceItem(
                type="nuclei_match",
                value=evidence_text,
                location=url,
                comparison=str(data.get("matcher-name") or ""),
            )
        ],
        request_summary=_request_summary(data, url),
        response_summary=_response_summary(data),
        reproduction_steps=[
            f"Review the Nuclei template '{template_id}' and the recorded evidence.",
            "Validate the finding with a safe, authorized check before treating candidate results as exploitable.",
        ],
        remediation=_remediation(vuln_type, data),
        references=_references(data),
        created_at=timestamp,
        updated_at=timestamp,
    ).to_dict()


def _new_telemetry() -> dict:
    return {
        "module_name": MODULE_NAME,
        "source_tool": SOURCE_TOOL,
        "template_profile": NUCLEI_SAFE_TEMPLATE_PROFILE,
        "requested_template_profile": "",
        "profile_safety_gate": "not_evaluated",
        "target_type": "unknown",
        "target_scope": "",
        "targets_selected": 0,
        "selected_template_count": 0,
        "selected_templates": [],
        "enabled": False,
        "skipped": False,
        "skip_reason": "",
        "started_at": utc_now(),
        "completed_at": "",
        "templates_run": None,
        "findings_count": 0,
        "raw_findings_count": 0,
        "duplicate_findings_removed": 0,
        "severity_distribution": {},
        "status_distribution": {},
        "execution_errors": [],
        "malformed_jsonl_lines": 0,
        "timeout_count": 0,
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _record_finding_telemetry(telemetry: dict, finding: dict) -> None:
    telemetry["findings_count"] += 1
    severity_counter = Counter(telemetry.get("severity_distribution", {}))
    severity_counter[finding.get("severity", "unknown")] += 1
    telemetry["severity_distribution"] = dict(severity_counter)
    status_counter = Counter(telemetry.get("status_distribution", {}))
    status_counter[finding.get("status", "unknown")] += 1
    telemetry["status_distribution"] = dict(status_counter)


def _finish_telemetry(telemetry: dict) -> dict:
    telemetry["completed_at"] = utc_now()
    telemetry["module_noise_score"] = 0.0
    return telemetry


def parse_nuclei_jsonl(output: str, telemetry: dict | None = None) -> list[dict]:
    if telemetry is None:
        telemetry = _new_telemetry()
    else:
        defaults = _new_telemetry()
        defaults.update(telemetry)
        telemetry.clear()
        telemetry.update(defaults)
    findings = []
    for line_number, line in enumerate((output or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            telemetry["malformed_jsonl_lines"] += 1
            telemetry["execution_errors"].append(f"malformed jsonl line {line_number}")
            continue
        if not isinstance(data, dict):
            telemetry["malformed_jsonl_lines"] += 1
            telemetry["execution_errors"].append(f"non-object jsonl line {line_number}")
            continue
        finding = normalize_nuclei_result(data)
        findings.append(finding)
        _record_finding_telemetry(telemetry, finding)
    telemetry["raw_findings_count"] = len(findings)
    return _dedupe_findings(findings, telemetry)


def _dedupe_findings(findings: list[dict], telemetry: dict | None = None) -> list[dict]:
    unique = []
    seen = set()
    for finding in findings:
        evidence_hash = body_hash(json.dumps(finding.get("evidence", []), sort_keys=True))
        key = (
            finding.get("id"),
            finding.get("url"),
            finding.get("vuln_type"),
            evidence_hash,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    if telemetry is not None:
        telemetry["duplicate_findings_removed"] = int(telemetry.get("duplicate_findings_removed") or 0) + max(
            0,
            len(findings) - len(unique),
        )
        telemetry["findings_count"] = len(unique)
    return unique


def _host_key(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _belongs_to_host(finding: dict, host: dict) -> bool:
    finding_url = finding.get("url") or finding.get("matched_at") or ""
    finding_host = _host_key(finding_url)
    host_urls = host.get("expanded_urls", [host.get("url", "")])
    for candidate in host_urls:
        if candidate and finding_url.startswith(candidate):
            return True
        if finding_host and _host_key(candidate) == finding_host:
            return True
    host_name = host.get("subdomain", "")
    return bool(host_name and host_name.lower() in finding_url.lower())


async def _execute_nuclei(urls: list[str], phase_name: str, args: list[str], callback=None) -> tuple[list[dict], dict]:
    telemetry = _new_telemetry()
    telemetry["enabled"] = True
    if not urls:
        return [], _finish_telemetry(telemetry)

    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt", encoding="utf-8") as target_handle:
        target_handle.write("\n".join(urls))
        target_file = target_handle.name

    cmd = [
        get_tool_path("nuclei"),
        "-l",
        target_file,
        "-rl",
        NUCLEI_SAFE_RATE_LIMIT,
        "-c",
        NUCLEI_SAFE_CONCURRENCY,
        "-timeout",
        NUCLEI_SAFE_REQUEST_TIMEOUT,
        "-retries",
        NUCLEI_SAFE_RETRIES,
        "-H",
        "User-Agent: Mozilla/5.0",
        "-silent",
        "-jsonl",
        "-or",
        "-ni",
    ] + args

    log.info(f"[vuln] Starting {phase_name} on {len(urls)} targets...")
    if callback:
        await callback("vulns", "running", f"Running Nuclei {phase_name} on {len(urls)} targets...")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=NUCLEI_SAFE_PROCESS_TIMEOUT)
        stderr_text = stderr.decode(errors="replace").strip()
        if stderr_text:
            telemetry["execution_errors"].append(_redact_text(stderr_text[:500]))
        findings = parse_nuclei_jsonl(stdout.decode(errors="replace"), telemetry)
        return findings, _finish_telemetry(telemetry)
    except asyncio.TimeoutError:
        telemetry["timeout_count"] += 1
        telemetry["execution_errors"].append(f"{phase_name} timed out")
        log.warning(f"[vuln] Nuclei {phase_name} timed out")
        return [], _finish_telemetry(telemetry)
    except Exception as exc:
        telemetry["execution_errors"].append(_redact_text(str(exc)))
        log.error(f"[vuln] Nuclei {phase_name} failed: {exc}")
        return [], _finish_telemetry(telemetry)
    finally:
        if os.path.exists(target_file):
            os.remove(target_file)


def _merge_telemetry(items: list[dict]) -> dict:
    merged = _new_telemetry()
    for item in items:
        for field in (
            "template_profile",
            "requested_template_profile",
            "profile_safety_gate",
            "target_type",
            "target_scope",
        ):
            if item.get(field):
                merged[field] = item.get(field)
        merged["targets_selected"] = max(
            int(merged.get("targets_selected") or 0),
            int(item.get("targets_selected") or 0),
        )
        merged["enabled"] = bool(merged.get("enabled") or item.get("enabled"))
        merged["skipped"] = bool(merged.get("skipped") and item.get("skipped"))
        merged["selected_template_count"] = max(
            int(merged.get("selected_template_count") or 0),
            int(item.get("selected_template_count") or 0),
        )
        if item.get("selected_templates") and not merged.get("selected_templates"):
            merged["selected_templates"] = item.get("selected_templates")
        merged["raw_findings_count"] += int(item.get("raw_findings_count", 0))
        merged["findings_count"] += int(item.get("findings_count", 0))
        merged["duplicate_findings_removed"] += int(item.get("duplicate_findings_removed", 0))
        merged["malformed_jsonl_lines"] += int(item.get("malformed_jsonl_lines", 0))
        merged["timeout_count"] += int(item.get("timeout_count", 0))
        merged["execution_errors"].extend(item.get("execution_errors", []))
        for field in ("severity_distribution", "status_distribution"):
            counter = Counter(merged.get(field, {}))
            counter.update(item.get(field, {}))
            merged[field] = dict(counter)
    return _finish_telemetry(merged)


def _skip_nuclei_hosts(alive_hosts: list[dict], reason: str) -> list[dict]:
    telemetry = _finish_telemetry({
        **_new_telemetry(),
        "skipped": True,
        "skip_reason": reason,
    })
    for host in alive_hosts:
        if isinstance(host, dict):
            host["nuclei_telemetry"] = telemetry
    return alive_hosts


def _host_root(url: str) -> str:
    try:
        parsed = urlparse(str(url or ""))
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    except Exception:
        return ""


def _normalize_route_url(url: str) -> str:
    try:
        parsed = urlparse(str(url or ""))
        if not parsed.scheme or not parsed.netloc:
            return ""
        query = parse_qs(parsed.query, keep_blank_values=True)
        normalized_query = "&".join(f"{key}={values[0] if values else ''}" for key, values in sorted(query.items()))
        return parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            path=parsed.path or "/",
            params="",
            query=normalized_query,
            fragment="",
        ).geturl().rstrip("/")
    except Exception:
        return ""


def _profile_targets(alive_hosts: list[dict], profile_config: dict) -> list[str]:
    roots: list[str] = []
    routes: list[str] = []
    for host in alive_hosts:
        if not isinstance(host, dict):
            continue
        for url in host.get("expanded_urls", [host.get("url")]) or []:
            root = _host_root(str(url or ""))
            if root:
                roots.append(root)
        if profile_config.get("target_scope") != "host_and_app_routes":
            continue
        for field in ("endpoints", "extracted_urls"):
            values = host.get(field) or []
            if not isinstance(values, list):
                continue
            for value in values:
                route = _normalize_route_url(str(value or ""))
                if route and not any(route.lower().endswith(ext) for ext in STATIC_EXTS):
                    routes.append(route)
        for form in host.get("forms") or []:
            if not isinstance(form, dict):
                continue
            route = _normalize_route_url(form.get("action") or form.get("url") or "")
            if route:
                routes.append(route)
    max_targets = int(profile_config.get("max_targets") or NUCLEI_SAFE_MAX_TARGETS)
    return sorted(set(roots + routes))[:max_targets]


def _nuclei_templates_root() -> Path:
    configured = os.environ.get("NUCLEI_TEMPLATES_DIR") or os.environ.get("NUCLEI_TEMPLATES_PATH")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / "nuclei-templates"


def _nuclei_template_paths(profile_config: dict | None = None) -> list[str]:
    root = _nuclei_templates_root()
    paths = []
    relative_paths = (profile_config or {}).get("template_paths") or NUCLEI_PUBLIC_SAFE_TEMPLATE_RELATIVE_PATHS
    for relative_path in relative_paths:
        candidate = root / relative_path
        if candidate.exists():
            paths.append(str(candidate))
    return paths


def _safe_nuclei_template_paths() -> list[str]:
    return _nuclei_template_paths(NUCLEI_PROFILES[NUCLEI_PUBLIC_SAFE_PROFILE])


def _nuclei_args(profile_config: dict | None = None) -> list[str]:
    profile_config = profile_config or NUCLEI_PROFILES[NUCLEI_PUBLIC_SAFE_PROFILE]
    args: list[str] = []
    for template_path in _nuclei_template_paths(profile_config):
        args.extend(["-t", template_path])
    args.extend([
        "-severity",
        str(profile_config.get("severity") or NUCLEI_SAFE_SEVERITIES),
        "-exclude-tags",
        str(profile_config.get("exclude_tags") or NUCLEI_SAFE_EXCLUDE_TAGS),
    ])
    return args


def _safe_nuclei_args() -> list[str]:
    return _nuclei_args(NUCLEI_PROFILES[NUCLEI_PUBLIC_SAFE_PROFILE])


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _resolve_nuclei_profile(scan_config: dict | None) -> tuple[dict, dict]:
    scan_config = scan_config if isinstance(scan_config, dict) else {}
    target_is_local = _as_bool(scan_config.get("target_is_local"))
    auth_type = str(scan_config.get("authorization_type") or "").strip().lower()
    lab_flag = _as_bool(scan_config.get("lab_mode")) or auth_type in {"local_lab", "lab", "local"}
    requested = str(
        scan_config.get("nuclei_profile")
        or scan_config.get("nuclei_template_profile")
        or NUCLEI_PUBLIC_SAFE_PROFILE
    ).strip().lower()
    if requested not in NUCLEI_PROFILES:
        requested = NUCLEI_PUBLIC_SAFE_PROFILE

    gate = {
        "requested_template_profile": requested,
        "profile_safety_gate": "public_safe_default",
        "target_type": "lab" if target_is_local and lab_flag else ("local" if target_is_local else "public"),
    }
    if requested == NUCLEI_LAB_APP_PROFILE:
        if target_is_local and lab_flag:
            gate["profile_safety_gate"] = "lab_profile_allowed"
            return NUCLEI_PROFILES[NUCLEI_LAB_APP_PROFILE], gate
        gate["profile_safety_gate"] = "lab_profile_blocked_public_or_unmarked"
        return NUCLEI_PROFILES[NUCLEI_PUBLIC_SAFE_PROFILE], gate
    return NUCLEI_PROFILES[NUCLEI_PUBLIC_SAFE_PROFILE], gate


async def run_nuclei(
    alive_hosts: list[dict],
    profile: str = "light",
    scan_config: dict | None = None,
    callback=None,
) -> list[dict]:
    profile = str(profile or "light").strip().lower()
    if profile != "deep":
        if callback:
            await callback("vulns", "done", "Nuclei is disabled outside Deep mode.")
        return _skip_nuclei_hosts(alive_hosts, "profile_not_deep")

    tool = get_available_tool("vulns")
    if not tool or tool != "nuclei":
        log.warning("[vuln] Nuclei not installed. Skipping.")
        if callback:
            await callback("vulns", "warning", "Nuclei not installed. Skipping.")
        return _skip_nuclei_hosts(alive_hosts, "nuclei_not_installed")

    if scan_config and scan_config.get("headers"):
        log.info("[vuln] Runtime auth headers are not passed to Nuclei in safe public mode.")

    profile_config, gate = _resolve_nuclei_profile(scan_config)
    targets = _profile_targets(alive_hosts, profile_config)
    if not targets:
        return _skip_nuclei_hosts(alive_hosts, "no_safe_targets")
    template_paths = _nuclei_template_paths(profile_config)
    if not template_paths:
        return _skip_nuclei_hosts(alive_hosts, "safe_templates_not_found")

    findings, telemetry = await _execute_nuclei(
        targets,
        f"Controlled Safe Scan ({profile_config['name']})",
        _nuclei_args(profile_config),
        callback=callback,
    )
    telemetry.update(gate)
    telemetry["template_profile"] = profile_config["name"]
    telemetry["target_scope"] = str(profile_config.get("target_scope") or "")
    telemetry["targets_selected"] = len(targets)
    telemetry["selected_template_count"] = len(template_paths)
    telemetry["selected_templates"] = [Path(path).name for path in template_paths]

    all_findings = _dedupe_findings(findings, telemetry)
    telemetry = _merge_telemetry([telemetry])

    for host in alive_hosts:
        host_findings = [finding for finding in all_findings if _belongs_to_host(finding, host)]
        host["nuclei_telemetry"] = telemetry
        if not host_findings:
            continue
        host["nuclei_findings"] = merge_findings(host.get("nuclei_findings", []), host_findings)
        host["vulns"] = merge_findings(host.get("vulns", []), host_findings)
        log.info(f"[vuln] {host.get('url', host.get('subdomain', 'host'))} -> normalized {len(host_findings)} Nuclei findings")

    total_findings = len(all_findings)
    log.info(f"[vuln] Nuclei complete. Normalized {total_findings} findings.")
    if callback:
        await callback("vulns", "done", f"Normalized {total_findings} Nuclei findings")

    return alive_hosts

