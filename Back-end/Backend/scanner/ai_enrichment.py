from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HTTP_TIMEOUT = httpx.Timeout(6.0, connect=3.0, read=6.0, write=3.0, pool=3.0)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEEPSEEK_CONFIG_EXAMPLE = PROJECT_ROOT / "deepseek.config.example.json"
DEEPSEEK_CONFIG_LOCAL = PROJECT_ROOT / "deepseek.config.local.json"
DEFAULT_DEEPSEEK_CONFIG = {
    "enabled": False,
    "base_url": "https://api.deepseek.com",
    "api_key": "",
    "model": "deepseek-v4-pro",
    "timeout_seconds": 90,
    "max_output_tokens": 8000,
}
PLACEHOLDER_KEY_VALUES = {"", "PASTE_REAL_KEY_HERE", "PASTE_KEY_HERE", "your_key_here"}
SENSITIVE_KEY_RE = re.compile(
    r"(cookie|set-cookie|authorization|auth|token|secret|password|passwd|api[_-]?key|x-api-key|session|jwt|bearer)",
    re.I,
)
SENSITIVE_VALUE_RE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/=-]{12,}|sk-[A-Za-z0-9_-]{12,}|[A-Za-z0-9+/=_-]{32,})",
    re.I,
)
SENSITIVE_HEADER_VALUE_RE = re.compile(r"\b(?:authorization|cookie|set-cookie|x-api-key)\s*:\s*[^;,\n\r]+", re.I)
SENSITIVE_QUERY_KEYS = {"token", "access_token", "auth", "authorization", "api_key", "apikey", "key", "secret", "password", "session", "jwt"}

TECH_KEYWORDS = {
    "asp.net": "ASP.NET",
    "aspnet": "ASP.NET",
    "microsoft-iis": "Microsoft IIS",
    "microsoft iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "php": "PHP",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "tomcat": "Apache Tomcat",
    "jetty": "Eclipse Jetty",
    "express": "Express.js",
    "node": "Node.js",
    "django": "Django",
    "flask": "Flask",
    "laravel": "Laravel",
    "spring": "Spring Framework",
}

REPORT_LANGUAGE_REPLACEMENTS = [
    (re.compile(r"\b(?:test|demo|lab|training|sample)\s+(?:site|application|app|environment|target)\b", re.I), "assessed web application"),
    (re.compile(r"\bintentionally vulnerable\b", re.I), "externally exposed"),
    (re.compile(r"\b(?:sandbox|practice)\s+(?:site|application|app|environment|target)\b", re.I), "assessed web application"),
]


def load_deepseek_config(config_path: str | Path | None = None) -> dict:
    path = Path(config_path) if config_path else DEEPSEEK_CONFIG_LOCAL
    config = dict(DEFAULT_DEEPSEEK_CONFIG)
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict):
                config.update(loaded)
        except Exception as exc:
            config["enabled"] = False
            config["config_error"] = f"Could not read DeepSeek config: {_error_message(exc)}"
    config["enabled"] = bool(config.get("enabled"))
    config["base_url"] = str(config.get("base_url") or DEFAULT_DEEPSEEK_CONFIG["base_url"]).strip().rstrip("/")
    config["api_key"] = str(config.get("api_key") or "").strip()
    config["model"] = str(config.get("model") or DEFAULT_DEEPSEEK_CONFIG["model"]).strip()
    try:
        config["timeout_seconds"] = max(5, int(config.get("timeout_seconds") or DEFAULT_DEEPSEEK_CONFIG["timeout_seconds"]))
    except (TypeError, ValueError):
        config["timeout_seconds"] = DEFAULT_DEEPSEEK_CONFIG["timeout_seconds"]
    try:
        config["max_output_tokens"] = max(256, int(config.get("max_output_tokens") or DEFAULT_DEEPSEEK_CONFIG["max_output_tokens"]))
    except (TypeError, ValueError):
        config["max_output_tokens"] = DEFAULT_DEEPSEEK_CONFIG["max_output_tokens"]
    config["has_real_key"] = config["api_key"] not in PLACEHOLDER_KEY_VALUES and len(config["api_key"]) >= 12
    config["config_path"] = str(path)
    return config


def _deepseek_chat_url(config: dict) -> str:
    base_url = str(config.get("base_url") or DEFAULT_DEEPSEEK_CONFIG["base_url"]).strip().rstrip("/")
    if base_url.endswith("/chat/completions"):
        return base_url
    if base_url.endswith("/v1"):
        return f"{base_url}/chat/completions"
    return f"{base_url}/chat/completions"


def _sanitize_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except Exception:
        return _clean_text(SENSITIVE_VALUE_RE.sub("[redacted]", value), 700)
    if not parts.scheme or not parts.netloc:
        return _clean_text(SENSITIVE_VALUE_RE.sub("[redacted]", value), 700)
    safe_query = [
        (key, val)
        for key, val in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in SENSITIVE_QUERY_KEYS and not SENSITIVE_KEY_RE.search(key)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_query), ""))


def sanitize_scan_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_text = str(key)
            if SENSITIVE_KEY_RE.search(key_text):
                continue
            sanitized[key_text] = sanitize_scan_evidence(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_scan_evidence(item) for item in value[:100]]
    if isinstance(value, str):
        text = _sanitize_url(value) if value.startswith(("http://", "https://")) else value
        text = SENSITIVE_HEADER_VALUE_RE.sub("[redacted-header]", text)
        text = SENSITIVE_VALUE_RE.sub("[redacted]", text)
        return _clean_text(text, 1200)
    return value


def _clean_text(value: Any, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _sanitize_report_language(value: Any, limit: int = 500) -> str:
    text = _clean_text(value, limit)
    for pattern, replacement in REPORT_LANGUAGE_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text[:limit]


def _sha256_json(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _extract_cvss(metrics: dict) -> tuple[str, float]:
    for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue
        metric = entries[0]
        cvss = metric.get("cvssData") or {}
        severity = cvss.get("baseSeverity") or metric.get("baseSeverity") or "Unknown"
        try:
            score = float(cvss.get("baseScore") or metric.get("baseScore") or 0)
        except (TypeError, ValueError):
            score = 0.0
        return str(severity), score
    return "Unknown", 0.0


def _parse_cwe(cve: dict) -> str:
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value:
                return str(value)
    return "Unknown"


def _parse_description(cve: dict) -> str:
    for description in cve.get("descriptions") or []:
        if description.get("lang") == "en":
            return _clean_text(description.get("value"), 700)
    return ""


def _parse_nvd_items(payload: dict, source: str, limit: int = 10) -> list[dict]:
    items = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        if not cve.get("id"):
            continue
        severity, score = _extract_cvss(cve.get("metrics") or {})
        cisa = cve.get("cisaExploitAdd")
        items.append({
            "id": cve.get("id"),
            "source": source,
            "severity": severity,
            "score": score,
            "cwe": _parse_cwe(cve),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "kev": bool(cisa),
            "kev_date": cisa,
            "description": _parse_description(cve),
            "references": [
                ref.get("url")
                for ref in (cve.get("references") or {}).get("referenceData", [])[:3]
                if ref.get("url")
            ],
        })
    items.sort(key=lambda item: (bool(item.get("kev")), float(item.get("score") or 0)), reverse=True)
    return items[:limit]


async def _get_json(client: httpx.AsyncClient, url: str, *, params: dict | None = None) -> dict:
    response = await client.get(url, params=params)
    response.raise_for_status()
    return response.json()


def _error_message(exc: Exception) -> str:
    detail = str(exc).strip()
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


async def fetch_recent_known_vulnerabilities(limit: int = 12) -> dict:
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=14)
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 50,
        "noRejected": "",
    }
    result = {
        "source": "nvd_recent_critical",
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "query": params,
        "items": [],
        "errors": [],
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        async def load_nvd_recent() -> None:
            try:
                payload = await _get_json(client, NVD_URL, params=params)
                result["items"].extend(_parse_nvd_items(payload, "NVD recent critical", limit=limit))
            except Exception as exc:
                result["errors"].append(f"NVD recent lookup failed: {_error_message(exc)}")

        async def load_cisa_kev() -> None:
            try:
                kev_payload = await _get_json(client, CISA_KEV_URL)
                kev_items = []
                for item in (kev_payload.get("vulnerabilities") or [])[:limit]:
                    kev_items.append({
                        "id": item.get("cveID"),
                        "source": "CISA KEV",
                        "severity": "Known exploited",
                        "score": 0,
                        "vendor": item.get("vendorProject"),
                        "product": item.get("product"),
                        "published": item.get("dateAdded"),
                        "kev": True,
                        "description": _clean_text(item.get("shortDescription"), 700),
                        "required_action": item.get("requiredAction"),
                        "due_date": item.get("dueDate"),
                    })
                result["items"].extend(kev_items)
            except Exception as exc:
                result["errors"].append(f"CISA KEV lookup failed: {_error_message(exc)}")

        try:
            await asyncio.wait_for(asyncio.gather(load_nvd_recent(), load_cisa_kev()), timeout=10.0)
        except TimeoutError:
            result["errors"].append("Known-vulnerability startup lookup timed out.")
    result["items"] = sorted(
        result["items"],
        key=lambda item: (bool(item.get("kev")), float(item.get("score") or 0)),
        reverse=True,
    )[:limit]
    return result


def _cisa_item_matches(item: dict, keywords: list[str]) -> str:
    haystack = " ".join(
        str(item.get(key) or "")
        for key in ("vendorProject", "product", "shortDescription", "knownRansomwareCampaignUse")
    ).lower()
    for keyword in keywords:
        if keyword.lower() in haystack:
            return keyword
    return ""


async def _fetch_matching_cisa_kev(client: httpx.AsyncClient, keywords: list[str], limit: int = 10) -> list[dict]:
    payload = await _get_json(client, CISA_KEV_URL)
    matches = []
    for item in payload.get("vulnerabilities") or []:
        keyword = _cisa_item_matches(item, keywords)
        if not keyword:
            continue
        matches.append({
            "id": item.get("cveID"),
            "source": "CISA KEV",
            "severity": "Known exploited",
            "score": 0,
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "published": item.get("dateAdded"),
            "kev": True,
            "matched_keyword": keyword,
            "description": _clean_text(item.get("shortDescription"), 700),
            "required_action": item.get("requiredAction"),
            "due_date": item.get("dueDate"),
        })
        if len(matches) >= limit:
            break
    return matches


def extract_report_keywords(report: dict) -> list[str]:
    keywords: list[str] = []

    def add(value: Any) -> None:
        text = _clean_text(value, 120).lower()
        for needle, keyword in TECH_KEYWORDS.items():
            if needle in text and keyword not in keywords:
                keywords.append(keyword)

    for host in report.get("alive_hosts") or []:
        if not isinstance(host, dict):
            continue
        add(host.get("server"))
        add(host.get("title"))
        add(" ".join(host.get("tech") or []))
        response_summary = host.get("response_summary") if isinstance(host.get("response_summary"), dict) else {}
        headers = response_summary.get("headers") if isinstance(response_summary.get("headers"), dict) else {}
        add(headers.get("server"))
        add(headers.get("x-powered-by"))

    for stage_host in ((report.get("stages") or {}).get("alive_probing") or {}).get("data") or []:
        if not isinstance(stage_host, dict):
            continue
        add(stage_host.get("title"))
        add(" ".join(stage_host.get("tech") or []))

    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        add(finding.get("title") or finding.get("name"))
        add(finding.get("evidence_summary") or finding.get("proof"))

    return keywords[:6]


async def fetch_targeted_known_vulnerabilities(report: dict, limit_per_keyword: int = 5) -> dict:
    keywords = extract_report_keywords(report)
    result = {
        "source": "nvd_targeted_keyword",
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "keywords": keywords,
        "items": [],
        "errors": [],
    }
    if not keywords:
        result["errors"].append("No technology keywords were detected for targeted CVE lookup.")
        return result

    seen = set()
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        async def lookup_keyword(keyword: str) -> list[dict]:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 20,
                "noRejected": "",
            }
            try:
                payload = await _get_json(client, NVD_URL, params=params)
                items = _parse_nvd_items(payload, f"NVD keyword: {keyword}", limit=limit_per_keyword)
                for item in items:
                    item["matched_keyword"] = keyword
                return items
            except Exception as exc:
                result["errors"].append(f"NVD keyword lookup failed for {keyword}: {_error_message(exc)}")
                return []

        async def lookup_cisa() -> list[dict]:
            try:
                return await _fetch_matching_cisa_kev(client, keywords, limit=10)
            except Exception as exc:
                result["errors"].append(f"CISA KEV targeted lookup failed: {_error_message(exc)}")
                return []

        try:
            keyword_results = await asyncio.wait_for(
                asyncio.gather(
                    *(lookup_keyword(keyword) for keyword in keywords),
                    lookup_cisa(),
                ),
                timeout=10.0,
            )
        except TimeoutError:
            result["errors"].append("Known-vulnerability targeted lookup timed out.")
            keyword_results = []

        for items in keyword_results:
            for item in items:
                cve_id = item.get("id")
                if cve_id and cve_id not in seen:
                    result["items"].append(item)
                    seen.add(cve_id)
    result["items"].sort(key=lambda item: (bool(item.get("kev")), float(item.get("score") or 0)), reverse=True)
    result["items"] = result["items"][:15]
    return result


def compact_report_for_writer(report: dict) -> dict:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    findings = []
    for finding in (report.get("findings") or [])[:20]:
        if not isinstance(finding, dict):
            continue
        findings.append({
            "evidence_id": finding.get("evidence_id") or finding.get("id"),
            "title": finding.get("title") or finding.get("name") or finding.get("id"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "url": finding.get("url") or finding.get("matched_at"),
            "parameter": finding.get("parameter"),
            "evidence_summary": finding.get("evidence_summary") or finding.get("proof"),
            "remediation": finding.get("remediation"),
        })
    compact = {
        "target": report.get("target") or report.get("domain"),
        "scan_time": report.get("scan_time"),
        "profile": report.get("profile"),
        "risk_score": report.get("risk_score"),
        "risk_label": report.get("risk_label"),
        "summary": summary,
        "findings": findings,
        "recommendations": report.get("recommendations", [])[:10],
        "known_vulnerabilities": report.get("known_vulnerabilities", {}),
    }
    return sanitize_scan_evidence(compact)


def build_deepseek_prompt_package(report: dict) -> dict:
    compact = compact_report_for_writer(report)
    return {
        "instructions": (
            "Use only the supplied scanner evidence and known-vulnerability context. "
            "Do not invent vulnerabilities or imply exploitability without evidence. "
            "Do not describe the target as a test site, demo site, lab, training system, intentionally vulnerable app, or sample environment. "
            "Treat the target as a normal externally exposed web application. "
            "Write in a polished Threat Hunters report voice, suitable for a client-facing PDF. "
            "Return strict JSON only. Include all 8 report sections using these keys: "
            "reader_summary string, bottom_line string, executive_summary string, "
            "confirmed_application_vulnerabilities string, candidate_findings string, "
            "security_header_configuration string, recon_observations string, "
            "target_profile_telemetry string, supplementary_scans string, "
            "recommendations array, key_risks array, limitations string."
        ),
        "scanner_evidence": compact,
        "expected_output_schema": {
            "reader_summary": "string",
            "bottom_line": "string",
            "executive_summary": "string",
            "confirmed_application_vulnerabilities": "string",
            "candidate_findings": "string",
            "security_header_configuration": "string",
            "recon_observations": "string",
            "target_profile_telemetry": "string",
            "supplementary_scans": "string",
            "key_risks": ["string"],
            "recommendations": ["string"],
            "limitations": "string",
        },
        "evidence_fingerprint_sha256": _sha256_json(compact),
    }

async def call_deepseek_auto(report: dict) -> tuple[dict, dict, dict | None]:
    config = load_deepseek_config()
    prompt_package = build_deepseek_prompt_package(report)

    if not config.get("enabled") or not config.get("has_real_key"):
        return generate_report_sections(report), prompt_package, {
            "provider": "deepseek",
            "message": "DeepSeek disabled or API key missing. Local fallback used.",
        }

    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": config.get("model") or DEFAULT_DEEPSEEK_CONFIG["model"],
        "messages": [
            {
                "role": "system",
                "content": "You write strict JSON security report sections from supplied scanner evidence only."
            },
            {
                "role": "user",
                "content": json.dumps(prompt_package, ensure_ascii=False)
            }
        ],
        "temperature": 0.2,
        "max_tokens": config.get("max_output_tokens", 8000),
        "stream": False,
        "response_format": {"type": "json_object"}
    }

    base_url = config.get("base_url", "https://api.deepseek.com").rstrip("/")
    url = f"{base_url}/chat/completions"

    try:
        async with httpx.AsyncClient(timeout=config.get("timeout_seconds", 90)) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            raw_response = response.json()

        parsed = parse_deepseek_report_sections(raw_response)
        parsed["model"] = raw_response.get("model") or config.get("model") or DEFAULT_DEEPSEEK_CONFIG["model"]
        parsed["generated_by"] = "DeepSeek Chat Completions API"

        return generate_report_sections(report, parsed), prompt_package, {
            "raw_response": raw_response
        }

    except Exception as exc:
        return generate_report_sections(report), prompt_package, {
            "provider": "deepseek",
            "message": "DeepSeek API failed. Local fallback used.",
            "error": str(exc),
        }    


def _parse_json_response(text: str) -> dict:
    cleaned = str(text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?", "", cleaned).strip()
        cleaned = re.sub(r"```$", "", cleaned).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end > start:
        cleaned = cleaned[start:end + 1]
    return json.loads(cleaned)


def extract_deepseek_content(raw_response: dict) -> str:
    choices = raw_response.get("choices") if isinstance(raw_response, dict) else None
    if not choices:
        return ""
    first_choice = choices[0] if isinstance(choices[0], dict) else {}
    message = first_choice.get("message") if isinstance(first_choice.get("message"), dict) else {}
    return str(message.get("content") or "")


def parse_deepseek_report_sections(raw_response: dict) -> dict:
    parsed = _parse_json_response(extract_deepseek_content(raw_response))
    if not isinstance(parsed, dict):
        raise ValueError("DeepSeek response did not contain a JSON object.")
    required = ("executive_summary", "key_risks", "recommendations", "limitations")
    missing = [key for key in required if key not in parsed]
    if missing:
        raise ValueError(f"DeepSeek response missing required keys: {', '.join(missing)}")
    if not isinstance(parsed.get("key_risks"), list) or not isinstance(parsed.get("recommendations"), list):
        raise ValueError("DeepSeek response key_risks and recommendations must be arrays.")
    return parsed


def generate_report_sections(report: dict, external_sections: dict | None = None) -> dict:
    compact = compact_report_for_writer(report)
    generated_at = datetime.now(timezone.utc).isoformat()
    if isinstance(external_sections, dict) and external_sections:
        narrative = {
            "reader_summary": _sanitize_report_language(external_sections.get("reader_summary"), 1400),
            "bottom_line": _sanitize_report_language(external_sections.get("bottom_line"), 800),
            "executive_summary": _sanitize_report_language(external_sections.get("executive_summary"), 1800),
            "confirmed_application_vulnerabilities": _sanitize_report_language(external_sections.get("confirmed_application_vulnerabilities"), 1200),
            "candidate_findings": _sanitize_report_language(external_sections.get("candidate_findings"), 1200),
            "security_header_configuration": _sanitize_report_language(external_sections.get("security_header_configuration"), 1200),
            "recon_observations": _sanitize_report_language(external_sections.get("recon_observations"), 1200),
            "target_profile_telemetry": _sanitize_report_language(external_sections.get("target_profile_telemetry"), 1200),
            "supplementary_scans": _sanitize_report_language(external_sections.get("supplementary_scans"), 1200),
            "key_risks": [_sanitize_report_language(item, 500) for item in external_sections.get("key_risks", [])[:8]],
            "recommendations": [_sanitize_report_language(item, 500) for item in external_sections.get("recommendations", [])[:10]],
            "limitations": _sanitize_report_language(external_sections.get("limitations"), 1000),
        }
        return {
            "provider": "external_writer",
            "model": _clean_text(external_sections.get("model") or "manual", 120),
            "generated_at": generated_at,
            **narrative,
            "generation_proof": {
                "provider": "external_writer",
                "generated_by": _clean_text(external_sections.get("generated_by") or "manual_report_sections_json", 160),
                "generated_at": generated_at,
                "evidence_fingerprint_sha256": _sha256_json(compact),
                "narrative_fingerprint_sha256": _sha256_json(narrative),
            },
        }

    summary = compact.get("summary") if isinstance(compact.get("summary"), dict) else {}
    risk_label = compact.get("risk_label") or summary.get("risk_label") or "Unknown risk"
    total = int(summary.get("total_findings") or 0)
    confirmed_app = int(summary.get("confirmed_app_vulns") or 0)
    confirmed_total = int(summary.get("confirmed_findings") or 0)
    candidates = int(summary.get("candidate_findings") or 0)
    known_items = ((compact.get("known_vulnerabilities") or {}).get("targeted") or {}).get("items") or []
    top_known = [item.get("id") for item in known_items[:5] if item.get("id")]
    executive_summary = (
        f"{risk_label}: the assessment identified {total} normalized security observations across the target, "
        f"including {confirmed_app} confirmed application vulnerabilities, {confirmed_total} total confirmed findings, "
        f"and {candidates} candidate issues requiring analyst validation. "
        "The immediate priority is to reduce exposed attack surface, address reproducible findings, and verify platform components against current vulnerability intelligence."
    )
    if top_known:
        executive_summary += f" Relevant public CVE context was identified for detected technologies: {', '.join(top_known)}."
    recommendations = list(compact.get("recommendations") or [])
    if known_items:
        recommendations.insert(0, "Review detected platform versions against the matched NVD/CISA CVEs before closing remediation.")
    narrative = {
        "reader_summary": _sanitize_report_language(
            f"The scanner assessed {compact.get('target') or 'the target'} using a non-damaging workflow. "
            f"It recorded {confirmed_app} confirmed application vulnerabilities, {confirmed_total} total confirmed findings, and {candidates} candidate findings that need triage.",
            1400,
        ),
        "bottom_line": _sanitize_report_language("Remediate confirmed findings first, apply configuration hardening, manually validate candidates, and re-scan after fixes.", 800),
        "executive_summary": _sanitize_report_language(executive_summary, 1800),
        "confirmed_application_vulnerabilities": _sanitize_report_language(f"Confirmed application vulnerabilities recorded by the scanner: {confirmed_app}.", 1200),
        "candidate_findings": _sanitize_report_language(f"Candidate findings requiring analyst validation: {candidates}.", 1200),
        "security_header_configuration": _sanitize_report_language(f"Confirmed header/configuration findings: {int(summary.get('security_header_findings') or 0)}.", 1200),
        "recon_observations": _sanitize_report_language(f"Recon observations recorded: {int(summary.get('recon_items') or summary.get('informational_findings') or 0)}.", 1200),
        "target_profile_telemetry": _sanitize_report_language(f"Profile {compact.get('profile') or 'unknown'} completed with {int(summary.get('modules_executed') or 0)} executed module(s).", 1200),
        "supplementary_scans": _sanitize_report_language(f"Nuclei findings: {int(summary.get('nuclei_findings_count') or summary.get('nuclei_findings') or 0)}. JS secrets: {int(summary.get('secrets_found') or 0)}.", 1200),
        "key_risks": [
            _sanitize_report_language("Evidence-backed findings should drive the first remediation cycle because they represent the clearest externally observable risk."),
            _sanitize_report_language("Candidate findings should be validated by an analyst before closure or escalation to confirmed exploitability."),
            _sanitize_report_language("Known exploited CVEs affecting exposed platform components should be patched, mitigated, or formally risk accepted."),
        ],
        "recommendations": [_sanitize_report_language(item, 500) for item in recommendations[:8]],
        "limitations": _sanitize_report_language("This local narrative was generated from scanner evidence and public vulnerability intelligence available during this run.", 1000),
    }
    return {
        "provider": "local_template_writer",
        "model": None,
        "generated_at": generated_at,
        **narrative,
        "generation_proof": {
            "provider": "local_template_writer",
            "generated_by": "local_report_section_builder",
            "generated_at": generated_at,
            "evidence_fingerprint_sha256": _sha256_json(compact),
            "narrative_fingerprint_sha256": _sha256_json(narrative),
        },
    }
