from __future__ import annotations

import asyncio
import re
from collections import Counter
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .findings import Finding, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import (
    extract_title,
    has_meaningful_diff,
    is_blocked_or_challenged,
    response_fingerprint,
)
from .scanner_types import EvidenceItem, utc_now
from .scan_config import get_runtime_request_headers
from .utils import log


MODULE_NAME = "form_scanner"
USER_AGENT = "Mozilla/5.0 Dragon-Recon/2.0"
BASE_HEADERS = {"User-Agent": USER_AGENT}

XSS_MARKER = "DRAGON_XSS_MARKER"
REDIRECT_TEST_URL = "https://recontool.invalid/redirect-proof"

XSS_PAYLOADS = [
    XSS_MARKER,
    f'"><recontool-xss data-marker="{XSS_MARKER}">',
    f"';{XSS_MARKER}//",
]

SQLI_ERROR_PAYLOADS = ["'", "\""]
SQLI_BOOLEAN_TRUE_PAYLOADS = ["1 AND 1=1", "' OR '1'='1"]
SQLI_BOOLEAN_FALSE_PAYLOADS = ["1 AND 1=2", "' OR '1'='2"]
SQLI_TIMING_PAYLOADS = ["1' AND SLEEP(2)--"]

REDIRECT_PAYLOADS = [
    REDIRECT_TEST_URL,
    "//recontool.invalid/redirect-proof",
]

SQLI_ERROR_RE = re.compile(
    r"(?i)(you have an error in your sql syntax|warning:\s*mysql|unclosed quotation mark|"
    r"quoted string not properly terminated|sqlstate|ora-\d{4,5}|microsoft ole db provider|"
    r"odbc microsoft access|jdbc|sqlite3?\.operationalerror|pg::syntaxerror|column not found|"
    r"postgresql.*error|mysql_fetch|syntax error at or near)"
)

REDIRECT_FIELD_RE = re.compile(r"(redirect|return|next|url|uri|continue|dest|destination|target)", re.I)
CSRF_FIELD_RE = re.compile(r"(csrf|xsrf|token|nonce|authenticity|requestverificationtoken)", re.I)
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|pwd|email|user|username|login|account|amount|transfer|payment|card|"
    r"delete|update|admin|role|permission|profile)",
    re.I,
)
XSS_FIELD_RE = re.compile(r"(q|query|search|message|msg|comment|name|title|body|content|callback)", re.I)
SQLI_FIELD_RE = re.compile(r"(id|uid|user|account|order|sort|cat|category|product|item|page)", re.I)

GENERIC_ERROR_MARKERS = [
    "404 not found",
    "page not found",
    "not found",
    "resource not found",
    "the requested url was not found",
    "server error",
    "an error occurred",
]
LOGIN_REQUIRED_MARKERS = ["login required", "please log in", "sign in", "session expired", "type=\"password\""]

XSS_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")
BASELINE_REQUESTS = 3
TIME_SQLI_DELTA_SECONDS = 1.5

REFERENCE_URLS = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/Top10/",
    "https://cheatsheetseries.owasp.org/",
]

REDACTION_PATTERNS = [
    re.compile(
        r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid)"
        r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
    ),
]


def _redact_text(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = REDACTION_PATTERNS[0].sub("<redacted-private-key>", text)
    text = REDACTION_PATTERNS[1].sub("Bearer <redacted>", text)
    text = REDACTION_PATTERNS[2].sub("<redacted-jwt>", text)
    text = REDACTION_PATTERNS[3].sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    return text[:1600]


def _snippet(text: str, limit: int = 600) -> str:
    return re.sub(r"\s+", " ", _redact_text(text)).strip()[:limit]


def _header_value(headers: dict, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _safe_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return str(url or "")
    query = parse_qs(parsed.query, keep_blank_values=True)
    safe_parts = []
    for key, values in query.items():
        value = values[0] if values else ""
        if SENSITIVE_FIELD_RE.search(key) or CSRF_FIELD_RE.search(key):
            value = "<redacted>"
        safe_parts.append(f"{key}={value}")
    return parsed._replace(query="&".join(safe_parts)).geturl()


def _extract_forms(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms: list[dict] = []

    for index, form in enumerate(soup.find_all("form"), start=1):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(base_url, action) if action else base_url

        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            field_name = tag.get("name")
            field_type = tag.get("type", tag.name if tag.name in {"textarea", "select"} else "text").lower()
            field_value = tag.get("value", "test")

            if not field_name:
                continue
            is_control = field_type in ("submit", "button", "image", "reset")
            if field_type == "file":
                continue
            inputs.append({
                "name": field_name,
                "type": field_type,
                "value": field_value,
                "tag": tag.name,
                "is_control": is_control,
            })

        if inputs:
            forms.append({
                "id": f"form-{index}",
                "action": action_url,
                "method": method if method in {"get", "post"} else "get",
                "inputs": inputs,
                "page": base_url,
                "has_csrf_token": any(CSRF_FIELD_RE.search(field["name"]) for field in inputs),
            })

    return forms


def _form_data(inputs: list[dict]) -> dict[str, str]:
    return {field["name"]: str(field.get("value", "test")) for field in inputs}


def _input_names(form: dict) -> list[str]:
    return [field.get("name", "") for field in form.get("inputs", []) if field.get("name") and not field.get("is_control")]


def _form_signature(form: dict) -> str:
    return f"{form.get('method', 'get').upper()} {form.get('action', '')} fields={','.join(_input_names(form))}"


def _is_sensitive_form(form: dict) -> bool:
    text = " ".join([form.get("action", ""), form.get("page", ""), " ".join(_input_names(form))])
    if form.get("method") == "post" and SENSITIVE_FIELD_RE.search(text):
        return True
    return bool(re.search(r"(login|admin|account|checkout|payment|transfer|delete|update)", text, re.I))


def _record_form_inventory(telemetry: dict, form: dict) -> None:
    inventory = telemetry.setdefault("form_inventory", [])
    signature = _form_signature(form)
    if any(item.get("signature") == signature for item in inventory):
        return
    inventory.append({
        "signature": signature,
        "page": _safe_url(form.get("page", "")),
        "action": _safe_url(form.get("action", "")),
        "method": str(form.get("method") or "get").upper(),
        "has_csrf_token": bool(form.get("has_csrf_token")),
        "inputs": [
            {
                "name": field.get("name", ""),
                "type": field.get("type", "text"),
                "tested": bool(field.get("name") and field.get("type", "text") not in {"hidden", "password"} and not field.get("is_control")),
            }
            for field in form.get("inputs", [])
        ],
    })


def _status_for_form_test(findings: list[dict], action: str, parameter: str, vuln_markers: tuple[str, ...]) -> tuple[str, str]:
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("parameter") or "") != str(parameter or ""):
            continue
        finding_url = str(finding.get("url") or finding.get("matched_at") or "")
        if action and finding_url and action.rstrip("/") not in finding_url.rstrip("/") and finding_url.rstrip("/") not in action.rstrip("/"):
            continue
        vuln_type = str(finding.get("vuln_type") or finding.get("id") or "").lower()
        if not any(marker in vuln_type for marker in vuln_markers):
            continue
        return str(finding.get("status") or "candidate"), str(
            (finding.get("raw") or {}).get("classification_reason")
            if isinstance(finding.get("raw"), dict)
            else ""
        ) or finding.get("description", "")
    return "not_confirmed", "payloads_sent_no_confirming_evidence"


def _record_form_validation_results(telemetry: dict, form: dict, findings: list[dict]) -> None:
    results = telemetry.setdefault("active_validation_results", [])
    action = form.get("action", "")
    method = str(form.get("method") or "get").upper()
    for field in form.get("inputs", []):
        parameter = field.get("name", "")
        field_type = str(field.get("type") or "text").lower()
        if not parameter:
            continue
        if field.get("is_control") or field_type in {"hidden", "password", "file"}:
            results.append({
                "module": MODULE_NAME,
                "test_type": "form_field",
                "method": method,
                "url": _safe_url(action),
                "parameter": parameter,
                "status": "skipped",
                "reason": f"field_type_not_tested:{field_type}",
                "payloads_sent": 0,
                "evidence": "Control, hidden, password, and file inputs are not actively fuzzed.",
            })
            continue

        xss_status, xss_reason = _status_for_form_test(findings, action, parameter, ("xss", "reflected_xss"))
        results.append({
            "module": MODULE_NAME,
            "test_type": "form_xss",
            "method": method,
            "url": _safe_url(action),
            "parameter": parameter,
            "status": xss_status,
            "reason": xss_reason,
            "payloads_sent": len(XSS_PAYLOADS),
            "evidence": "XSS marker payload group executed against form field.",
        })

        sqli_status, sqli_reason = _status_for_form_test(findings, action, parameter, ("sql", "sqli"))
        results.append({
            "module": MODULE_NAME,
            "test_type": "form_sql_injection",
            "method": method,
            "url": _safe_url(action),
            "parameter": parameter,
            "status": sqli_status,
            "reason": sqli_reason,
            "payloads_sent": len(SQLI_ERROR_PAYLOADS) + len(SQLI_BOOLEAN_TRUE_PAYLOADS) + len(SQLI_TIMING_PAYLOADS),
            "evidence": "SQL error, boolean, and timing payload groups executed where profile allowed.",
        })

        if REDIRECT_FIELD_RE.search(parameter):
            redirect_status, redirect_reason = _status_for_form_test(findings, action, parameter, ("redirect",))
            results.append({
                "module": MODULE_NAME,
                "test_type": "form_open_redirect",
                "method": method,
                "url": _safe_url(action),
                "parameter": parameter,
                "status": redirect_status,
                "reason": redirect_reason,
                "payloads_sent": len(REDIRECT_PAYLOADS),
                "evidence": "Controlled external redirect payload group executed.",
            })


def _new_telemetry() -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "forms_discovered": 0,
        "inputs_discovered": 0,
        "forms_tested": 0,
        "payloads_sent": 0,
        "candidates_count": 0,
        "confirmed_count": 0,
        "inconclusive_count": 0,
        "blocked_count": 0,
        "errors_count": 0,
        "timeout_count": 0,
        "status_distribution": {},
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
        "form_inventory": [],
        "active_validation_results": [],
    }


def _finish_telemetry(telemetry: dict, findings: list[dict]) -> dict:
    statuses = Counter(finding.get("status", "unknown") for finding in findings)
    telemetry["candidates_count"] = statuses.get("candidate", 0)
    telemetry["confirmed_count"] = statuses.get("confirmed", 0)
    telemetry["inconclusive_count"] = statuses.get("inconclusive", 0)
    telemetry["blocked_count"] = statuses.get("blocked", 0)
    telemetry["status_distribution"] = dict(statuses)
    total = max(1, telemetry.get("payloads_sent", 0) + telemetry.get("forms_tested", 0))
    telemetry["module_noise_score"] = round(min(1.0, telemetry.get("blocked_count", 0) / total), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _request_summary(url: str, method: str = "GET", data: dict | None = None) -> dict:
    body = ""
    if data:
        body = "&".join(
            f"{key}={'<redacted>' if SENSITIVE_FIELD_RE.search(key) or CSRF_FIELD_RE.search(key) else _redact_text(value)}"
            for key, value in data.items()
        )
    return summarize_request(method=method, url=_safe_url(url), headers=BASE_HEADERS, body=body)


def _response_summary(response: httpx.Response | None, body: str = "") -> dict:
    if response is None:
        return {}
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=_redact_text(body[:800]),
        snippet=_snippet(body),
    )


def _remediation_for(vuln_type: str, status: str) -> str:
    if vuln_type in {"form_discovered", "input_discovered"}:
        return "No remediation is required for discovery alone. Review the form inventory and continue safe validation as needed."
    if vuln_type in {"form_scan_blocked", "form_scan_inconclusive"} or status in {"blocked", "inconclusive"}:
        return "Review the behavior in an authorized lab or lower-noise profile before treating it as exploitable."
    if vuln_type in {"reflected_xss", "xss_candidate"}:
        return "Encode untrusted output for the correct HTML/JavaScript context and validate input server-side."
    if vuln_type in {"sql_injection", "sql_injection_candidate"}:
        return "Use parameterized queries, avoid string-built SQL, and validate input type and length server-side."
    if vuln_type in {"open_redirect", "open_redirect_candidate"}:
        return "Allow only relative redirects or validate redirect destinations against a strict allowlist."
    if vuln_type == "csrf_missing_candidate":
        return "For state-changing forms, add per-request CSRF tokens and verify them server-side."
    return "Review the evidence and apply the relevant secure coding or configuration fix."


def _default_reproduction(url: str, method: str, parameter: str, payload: str, status: str) -> list[str]:
    steps = [f"Send a {method.upper() or 'GET'} request to {url or 'the affected form action'}."]
    if parameter:
        steps.append(f"Set field '{parameter}' to the documented test value.")
    if payload:
        steps.append("Use the redacted payload shape recorded in payload_used.")
    if status == "confirmed":
        steps.append("Compare the response with the exact evidence and baseline/control context recorded here.")
    else:
        steps.append("Treat this as a validation lead until a safe baseline/control/test comparison confirms it.")
    return steps


def _make_finding(
    *,
    finding_id: str,
    url: str,
    method: str,
    parameter: str = "",
    category: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    payload: str = "",
    request_summary: dict | None = None,
    response_summary: dict | None = None,
    raw: dict | None = None,
    target: str = "",
) -> dict:
    raw = raw or {}
    evidence_text = _redact_text(evidence_text)
    payload = _redact_text(payload)
    parsed = urlparse(url or raw.get("page", ""))
    finding = Finding(
        id=finding_id,
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        target=target or parsed.netloc or url,
        url=_safe_url(url),
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
                type="form_evidence",
                value=evidence_text,
                location=parameter or url,
                comparison=str(raw.get("classification_reason", "")),
            )
        ],
        payload_used=payload,
        request_summary=request_summary or _request_summary(url, method, None),
        response_summary=response_summary or {},
        reproduction_steps=_default_reproduction(_safe_url(url), method, parameter, payload, status),
        remediation=_remediation_for(vuln_type, status),
        references=REFERENCE_URLS,
        name=vuln_type.replace("_", " ").title(),
        description=evidence_text,
        matched_at=_safe_url(url),
        payload=payload,
        raw={key: _redact_text(value) if isinstance(value, str) else value for key, value in raw.items()},
    ).to_dict()
    finding["evidence_items"] = finding.get("evidence", [])
    return finding


def _discovery_findings_for_form(form: dict, target: str = "") -> list[dict]:
    findings = [
        _make_finding(
            finding_id="form_discovered",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            category="form_recon",
            vuln_type="form_discovered",
            status="recon",
            severity="info",
            confidence=0.2,
            evidence_text=(
                f"Form discovered on {form.get('page', '')}. "
                f"Action: {form.get('action', '')}. Method: {form.get('method', 'get').upper()}. "
                f"Inputs: {', '.join(_input_names(form)) or 'none'}."
            ),
            raw={
                "classification_reason": "form_inventory",
                "page": form.get("page", ""),
                "has_csrf_token": bool(form.get("has_csrf_token")),
                "form_signature": _form_signature(form),
            },
            target=target,
        )
    ]

    for field in form.get("inputs", []):
        findings.append(_make_finding(
            finding_id="input_discovered",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field.get("name", ""),
            category="form_recon",
            vuln_type="input_discovered",
            status="recon",
            severity="info",
            confidence=0.2,
            evidence_text=f"Input field '{field.get('name', '')}' of type '{field.get('type', 'text')}' was found in a form.",
            raw={
                "classification_reason": "input_inventory",
                "page": form.get("page", ""),
                "field_type": field.get("type", "text"),
                "tag": field.get("tag", ""),
            },
            target=target,
        ))

    if _is_sensitive_form(form) and not form.get("has_csrf_token"):
        severity = "medium" if any(field.get("type") == "password" for field in form.get("inputs", [])) else "low"
        findings.append(_make_finding(
            finding_id="csrf_missing_candidate",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            category="csrf",
            vuln_type="csrf_missing_candidate",
            status="candidate",
            severity=severity,
            confidence=0.45,
            evidence_text=(
                "Sensitive-looking form does not expose an obvious CSRF token field. "
                "This is a configuration candidate, not confirmed exploitability."
            ),
            raw={
                "classification_reason": "sensitive_form_without_visible_csrf_token",
                "page": form.get("page", ""),
                "form_signature": _form_signature(form),
            },
            target=target,
        ))

    return findings


async def _submit_form(
    client: httpx.AsyncClient,
    form: dict,
    data: dict[str, str],
    *,
    timeout: float,
    follow_redirects: bool,
) -> httpx.Response:
    if form["method"] == "post":
        return await client.post(form["action"], data=data, timeout=timeout, follow_redirects=follow_redirects)
    return await client.get(form["action"], params=data, timeout=timeout, follow_redirects=follow_redirects)


async def _baseline_response(client: httpx.AsyncClient, form: dict) -> tuple[dict, str]:
    data = _form_data(form["inputs"])
    response = await _submit_form(client, form, data, timeout=10.0, follow_redirects=True)
    body = response.text[:20000]
    return response_fingerprint(response.status_code, dict(response.headers), body), body


async def _measure_baseline(client: httpx.AsyncClient, form: dict, samples: int = BASELINE_REQUESTS) -> list[float]:
    timings: list[float] = []
    data = _form_data(form["inputs"])

    for _ in range(samples):
        try:
            start = asyncio.get_running_loop().time()
            await _submit_form(client, form, data, timeout=10.0, follow_redirects=True)
            timings.append(asyncio.get_running_loop().time() - start)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            continue

    return timings


def _allows_xss_reflection_check(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    if content_type.startswith(("application/json", "image/", "font/", "application/octet-stream")):
        return False
    return not content_type or any(allowed in content_type for allowed in XSS_CONTENT_TYPES)


def _looks_like_generic_error(status_code: int | None, body: str) -> bool:
    if status_code not in {200, 400, 404, 500}:
        return False
    lower = (body or "")[:12000].lower()
    title = extract_title(body).lower()
    return any(marker in lower or marker in title for marker in GENERIC_ERROR_MARKERS)


def _looks_login_required(body: str) -> bool:
    lower = (body or "")[:12000].lower()
    return any(marker in lower for marker in LOGIN_REQUIRED_MARKERS) and ("<form" in lower or "password" in lower)


def _blocked_or_inconclusive_finding(
    *,
    form: dict,
    field_name: str,
    payload: str,
    response: httpx.Response,
    body: str,
) -> dict | None:
    blocked, challenged, reasons = is_blocked_or_challenged(response.status_code, dict(response.headers), body)
    if blocked or challenged:
        return _make_finding(
            finding_id="form_scan_blocked",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="detection-testing",
            vuln_type="form_scan_blocked",
            status="blocked",
            severity="info",
            confidence=0.3,
            evidence_text=f"Form test response was blocked or challenged: {', '.join(reasons) or response.status_code}.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "blocked_or_challenged", "page": form.get("page", "")},
        )
    if _looks_like_generic_error(response.status_code, body) or _looks_login_required(body):
        return _make_finding(
            finding_id="form_scan_inconclusive",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="form_recon",
            vuln_type="form_scan_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="Form test was inconclusive; generic error, login-required, or unstable response prevented proof.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "generic_error_or_login_required", "page": form.get("page", "")},
        )
    return None


def _reflection_context(body: str, marker: str) -> tuple[str, str]:
    if not marker or marker not in body:
        return "", ""
    index = body.find(marker)
    before = body[max(0, index - 160):index]
    after = body[index + len(marker):index + len(marker) + 160]
    window = before + marker + after
    lower_before = before.lower()
    lower_after = after.lower()
    lower_window = window.lower()
    if any(marker_text in lower_window for marker_text in ["&lt;", "&gt;", "%3c", "%3e", "\\u003c", "\\x3c"]):
        return "encoded", window
    if "<script" in lower_before and "</script" in lower_after:
        return "script", window
    if re.search(r"<[^>]+\son[a-z]+\s*=\s*['\"]?[^>]*$", lower_before):
        return "event_handler", window
    if re.search(r"<[^>]+(?:href|src|value|data-[\w-]+)\s*=\s*['\"]?[^>]*$", lower_before):
        return "html_attribute", window
    if "<" in lower_before and ">" in lower_after:
        return "html_body", window
    return "text", window


def _classify_xss_response(
    *,
    form: dict,
    field_name: str,
    payload: str,
    response: httpx.Response,
    body: str,
    baseline_body: str,
) -> dict | None:
    preliminary = _blocked_or_inconclusive_finding(
        form=form,
        field_name=field_name,
        payload=payload,
        response=response,
        body=body,
    )
    if preliminary:
        return preliminary
    if not _allows_xss_reflection_check(response):
        return None

    marker = XSS_MARKER
    if marker not in body and payload not in body:
        if XSS_FIELD_RE.search(field_name):
            return _make_finding(
                finding_id="xss_candidate",
                url=form.get("action", ""),
                method=form.get("method", "get"),
                parameter=field_name,
                category="injection",
                vuln_type="xss_candidate",
                status="candidate",
                severity="low",
                confidence=0.3,
                evidence_text=f"Field '{field_name}' is XSS-relevant by name, but no executable reflection was observed.",
                payload=payload,
                request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
                response_summary=_response_summary(response, body),
                raw={"classification_reason": "xss_parameter_name_only", "page": form.get("page", "")},
            )
        return None

    if marker in baseline_body:
        return _make_finding(
            finding_id="form_scan_inconclusive",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="form_recon",
            vuln_type="form_scan_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="XSS marker appeared in baseline content, so payload reflection could not be correlated.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "marker_present_in_baseline", "page": form.get("page", "")},
        )

    context, window = _reflection_context(body, marker if marker in body else payload)
    if context in {"script", "event_handler"}:
        return _make_finding(
            finding_id="reflected_xss",
            url=str(response.url) or form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="reflected_xss",
            status="confirmed",
            severity="high" if context == "script" else "medium",
            confidence=0.9,
            evidence_text=f"Marker was reflected unencoded in executable {context} context: {_snippet(window)}",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "unencoded_marker_in_executable_context", "page": form.get("page", ""), "context": context},
        )

    return _make_finding(
        finding_id="xss_candidate",
        url=str(response.url) or form.get("action", ""),
        method=form.get("method", "get"),
        parameter=field_name,
        category="injection",
        vuln_type="xss_candidate",
        status="candidate",
        severity="medium" if context == "html_attribute" else "low",
        confidence=0.6 if context == "html_attribute" else 0.45,
        evidence_text=f"Marker was reflected in {context or 'unknown'} context without executable proof: {_snippet(window)}",
        payload=payload,
        request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
        response_summary=_response_summary(response, body),
        raw={"classification_reason": f"xss_reflection_{context or 'unknown'}", "page": form.get("page", ""), "context": context},
    )


def _classify_sqli_error_response(
    *,
    form: dict,
    field_name: str,
    payload: str,
    response: httpx.Response,
    body: str,
    baseline_body: str,
) -> dict | None:
    preliminary = _blocked_or_inconclusive_finding(
        form=form,
        field_name=field_name,
        payload=payload,
        response=response,
        body=body,
    )
    if preliminary:
        return preliminary

    baseline_has_error = bool(SQLI_ERROR_RE.search(baseline_body or ""))
    match = SQLI_ERROR_RE.search(body or "")
    if match and not baseline_has_error and payload:
        return _make_finding(
            finding_id="sql_injection",
            url=str(response.url) or form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection",
            status="confirmed",
            severity="high",
            confidence=0.88,
            evidence_text=f"Database error appeared only after payload for field '{field_name}': {_snippet(match.group(0))}",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "payload_correlated_db_error", "page": form.get("page", "")},
        )
    if match:
        return _make_finding(
            finding_id="sql_injection_candidate",
            url=str(response.url) or form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection_candidate",
            status="candidate",
            severity="low",
            confidence=0.4,
            evidence_text="SQL error-like text was observed, but it was not clearly correlated to the payload.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "sql_error_without_payload_correlation", "page": form.get("page", "")},
        )
    if SQLI_FIELD_RE.search(field_name):
        return _make_finding(
            finding_id="sql_injection_candidate",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection_candidate",
            status="candidate",
            severity="low",
            confidence=0.32,
            evidence_text=f"Field '{field_name}' is SQLi-relevant by name, but no payload-correlated SQLi proof was observed.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "sqli_parameter_name_only", "page": form.get("page", "")},
        )
    return None


def _classify_boolean_sqli(
    *,
    form: dict,
    field_name: str,
    true_payload: str,
    false_payload: str,
    baseline_fp: dict,
    true_response: httpx.Response,
    true_body: str,
    false_response: httpx.Response,
    false_body: str,
) -> dict | None:
    true_fp = response_fingerprint(true_response.status_code, dict(true_response.headers), true_body)
    false_fp = response_fingerprint(false_response.status_code, dict(false_response.headers), false_body)
    true_like_baseline = not has_meaningful_diff(baseline_fp, true_fp, min_length_delta=80)
    false_differs = has_meaningful_diff(true_fp, false_fp, min_length_delta=80)
    if true_like_baseline and false_differs:
        return _make_finding(
            finding_id="sql_injection",
            url=str(false_response.url) or form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection",
            status="confirmed",
            severity="high",
            confidence=0.86,
            evidence_text=(
                "Boolean SQLi control/test behavior was consistent: true payload resembled baseline, "
                "false payload produced a meaningful response difference."
            ),
            payload=f"{true_payload} / {false_payload}",
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: false_payload}),
            response_summary=_response_summary(false_response, false_body),
            raw={"classification_reason": "boolean_control_test_diff", "page": form.get("page", "")},
        )
    if false_differs:
        return _make_finding(
            finding_id="sql_injection_candidate",
            url=str(false_response.url) or form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection_candidate",
            status="candidate",
            severity="medium",
            confidence=0.55,
            evidence_text="Boolean SQLi payloads changed the response, but baseline/control proof was incomplete.",
            payload=f"{true_payload} / {false_payload}",
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: false_payload}),
            response_summary=_response_summary(false_response, false_body),
            raw={"classification_reason": "boolean_diff_without_full_baseline_confirmation", "page": form.get("page", "")},
        )
    return None


def _classify_timing_sqli(
    *,
    form: dict,
    field_name: str,
    payload: str,
    baseline_timings: list[float],
    injected_timings: list[float],
    response: httpx.Response | None = None,
    body: str = "",
) -> dict | None:
    if not baseline_timings or len(injected_timings) < 2:
        return None
    baseline_avg = sum(baseline_timings) / len(baseline_timings)
    injected_avg = sum(injected_timings) / len(injected_timings)
    repeated = all(elapsed >= baseline_avg + TIME_SQLI_DELTA_SECONDS for elapsed in injected_timings)
    if repeated:
        return _make_finding(
            finding_id="sql_injection",
            url=str(response.url) if response is not None else form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection",
            status="confirmed",
            severity="high",
            confidence=0.9,
            evidence_text=f"Repeated timing evidence: baseline avg {baseline_avg:.2f}s, injected avg {injected_avg:.2f}s.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "repeated_timing_delta_above_baseline", "page": form.get("page", "")},
        )
    if injected_avg >= baseline_avg + TIME_SQLI_DELTA_SECONDS:
        return _make_finding(
            finding_id="sql_injection_candidate",
            url=str(response.url) if response is not None else form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="injection",
            vuln_type="sql_injection_candidate",
            status="candidate",
            severity="medium",
            confidence=0.6,
            evidence_text=f"Timing response exceeded baseline once/unstably: baseline avg {baseline_avg:.2f}s, injected avg {injected_avg:.2f}s.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "unstable_timing_delta", "page": form.get("page", "")},
        )
    return None


def _is_controlled_external_redirect(location: str) -> bool:
    if not location:
        return False
    lower = location.lower()
    parsed = urlparse(location)
    return (
        parsed.netloc.lower() == "recontool.invalid"
        or lower.startswith("//recontool.invalid/")
        or lower.startswith("https://recontool.invalid/")
    )


def _classify_open_redirect_response(
    *,
    form: dict,
    field_name: str,
    payload: str,
    response: httpx.Response,
    baseline_response: httpx.Response | None = None,
    body: str = "",
) -> dict | None:
    preliminary = _blocked_or_inconclusive_finding(
        form=form,
        field_name=field_name,
        payload=payload,
        response=response,
        body=body,
    )
    if preliminary:
        return preliminary

    location = response.headers.get("location", "")
    baseline_location = baseline_response.headers.get("location", "") if baseline_response is not None else ""
    if response.status_code in range(300, 400) and _is_controlled_external_redirect(location) and not _is_controlled_external_redirect(baseline_location):
        return _make_finding(
            finding_id="open_redirect",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="redirect",
            vuln_type="open_redirect",
            status="confirmed",
            severity="medium",
            confidence=0.9,
            evidence_text=f"30x Location header points to controlled external test host: {_redact_text(location)}",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "controlled_external_redirect_location", "page": form.get("page", "")},
        )
    if REDIRECT_FIELD_RE.search(field_name):
        return _make_finding(
            finding_id="open_redirect_candidate",
            url=form.get("action", ""),
            method=form.get("method", "get"),
            parameter=field_name,
            category="redirect",
            vuln_type="open_redirect_candidate",
            status="candidate",
            severity="low",
            confidence=0.38,
            evidence_text=f"Redirect-like field '{field_name}' exists, but no controlled external redirect was confirmed.",
            payload=payload,
            request_summary=_request_summary(form.get("action", ""), form.get("method", "get"), {field_name: payload}),
            response_summary=_response_summary(response, body),
            raw={"classification_reason": "redirect_field_without_location_proof", "page": form.get("page", "")},
        )
    return None


async def _send_test_payload(
    client: httpx.AsyncClient,
    form: dict,
    field_name: str,
    payload: str,
    telemetry: dict,
    *,
    timeout: float = 10.0,
    follow_redirects: bool = True,
) -> tuple[httpx.Response | None, str, float | None]:
    data = _form_data(form["inputs"])
    data[field_name] = payload
    telemetry["payloads_sent"] += 1
    started = asyncio.get_running_loop().time()
    try:
        response = await _submit_form(client, form, data, timeout=timeout, follow_redirects=follow_redirects)
    except httpx.TimeoutException:
        telemetry["timeout_count"] += 1
        return None, "", None
    except (httpx.ConnectError, httpx.RequestError):
        return None, "", None
    except Exception as exc:
        telemetry["errors_count"] += 1
        log.debug(f"[form_scanner] Form payload test error: {exc}")
        return None, "", None
    elapsed = asyncio.get_running_loop().time() - started
    try:
        body = response.text[:20000]
    except Exception:
        body = ""
    return response, body, elapsed


async def _test_form(
    client: httpx.AsyncClient,
    form: dict,
    semaphore: asyncio.Semaphore,
    *,
    baseline_samples: int,
    xss_payloads: list[str],
    sqli_error_payloads: list[str],
    sqli_boolean_true_payloads: list[str],
    sqli_boolean_false_payloads: list[str],
    sqli_timing_payloads: list[str],
    redirect_payloads: list[str],
    telemetry: dict,
) -> list[dict]:
    async with semaphore:
        findings: list[dict] = []
        telemetry["forms_tested"] += 1

        try:
            baseline_fp, baseline_body = await _baseline_response(client, form)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            baseline_fp, baseline_body = {}, ""
        except Exception as exc:
            telemetry["errors_count"] += 1
            log.debug(f"[form_scanner] Baseline error: {exc}")
            baseline_fp, baseline_body = {}, ""

        baseline_timings = await _measure_baseline(client, form, samples=baseline_samples)
        baseline_redirect_response = None
        try:
            baseline_redirect_response = await _submit_form(
                client,
                form,
                _form_data(form["inputs"]),
                timeout=8.0,
                follow_redirects=False,
            )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass

        for field in form.get("inputs", []):
            field_name = field.get("name", "")
            field_type = field.get("type", "text")
            if not field_name or field_type in {"hidden", "password"} or field.get("is_control"):
                continue

            xss_done = False
            for payload in xss_payloads:
                response, body, _ = await _send_test_payload(client, form, field_name, payload, telemetry, follow_redirects=True)
                if response is None:
                    continue
                finding = _classify_xss_response(
                    form=form,
                    field_name=field_name,
                    payload=payload,
                    response=response,
                    body=body,
                    baseline_body=baseline_body,
                )
                
                if not finding or finding.get("status") != "confirmed":
                    try:
                        get_resp = await client.get(form.get("page", ""), timeout=10.0, follow_redirects=True)
                        get_body = get_resp.text[:20000]
                        stored_finding = _classify_xss_response(
                            form=form,
                            field_name=field_name,
                            payload=payload,
                            response=get_resp,
                            body=get_body,
                            baseline_body=baseline_body,
                        )
                        if stored_finding and stored_finding.get("status") == "confirmed":
                            stored_finding["finding_id"] = "stored_xss"
                            stored_finding["vuln_type"] = "stored_xss"
                            stored_finding["evidence_text"] = stored_finding.get("evidence_text", "").replace("reflected", "stored and reflected")
                            finding = stored_finding
                    except Exception as exc:
                        log.debug(f"[form_scanner] Stored XSS verification failed: {exc}")

                if finding:
                    findings.append(finding)
                    if finding.get("status") in {"confirmed", "blocked", "inconclusive"}:
                        xss_done = True
                        break
            if xss_done:
                continue

            sqli_done = False
            for payload in sqli_error_payloads:
                response, body, _ = await _send_test_payload(client, form, field_name, payload, telemetry, timeout=10.0, follow_redirects=True)
                if response is None:
                    continue
                finding = _classify_sqli_error_response(
                    form=form,
                    field_name=field_name,
                    payload=payload,
                    response=response,
                    body=body,
                    baseline_body=baseline_body,
                )
                if finding:
                    findings.append(finding)
                    if finding.get("status") in {"confirmed", "blocked", "inconclusive"}:
                        sqli_done = True
                        break
            if sqli_done:
                continue

            for true_payload, false_payload in zip(sqli_boolean_true_payloads, sqli_boolean_false_payloads):
                true_response, true_body, _ = await _send_test_payload(client, form, field_name, true_payload, telemetry, timeout=10.0, follow_redirects=True)
                false_response, false_body, _ = await _send_test_payload(client, form, field_name, false_payload, telemetry, timeout=10.0, follow_redirects=True)
                if true_response is None or false_response is None:
                    continue
                finding = _classify_boolean_sqli(
                    form=form,
                    field_name=field_name,
                    true_payload=true_payload,
                    false_payload=false_payload,
                    baseline_fp=baseline_fp,
                    true_response=true_response,
                    true_body=true_body,
                    false_response=false_response,
                    false_body=false_body,
                )
                if finding:
                    findings.append(finding)
                    if finding.get("status") == "confirmed":
                        sqli_done = True
                        break
            if sqli_done:
                continue

            for payload in sqli_timing_payloads:
                injected_timings: list[float] = []
                last_response = None
                last_body = ""
                samples = 2 if baseline_samples > 1 else 1
                for _ in range(samples):
                    response, body, elapsed = await _send_test_payload(client, form, field_name, payload, telemetry, timeout=12.0, follow_redirects=True)
                    if response is not None:
                        last_response = response
                        last_body = body
                    if elapsed is not None:
                        injected_timings.append(elapsed)
                finding = _classify_timing_sqli(
                    form=form,
                    field_name=field_name,
                    payload=payload,
                    baseline_timings=baseline_timings,
                    injected_timings=injected_timings,
                    response=last_response,
                    body=last_body,
                )
                if finding:
                    findings.append(finding)
                    break

            if REDIRECT_FIELD_RE.search(field_name):
                for payload in redirect_payloads:
                    response, body, _ = await _send_test_payload(
                        client,
                        form,
                        field_name,
                        payload,
                        telemetry,
                        timeout=10.0,
                        follow_redirects=False,
                    )
                    if response is None:
                        continue
                    finding = _classify_open_redirect_response(
                        form=form,
                        field_name=field_name,
                        payload=payload,
                        response=response,
                        baseline_response=baseline_redirect_response,
                        body=body,
                    )
                    if finding:
                        findings.append(finding)
                        if finding.get("status") in {"confirmed", "blocked", "inconclusive"}:
                            break

        return findings


def _dedupe_form_findings(findings: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("module_name"),
            finding.get("id"),
            finding.get("url"),
            finding.get("parameter"),
            finding.get("status"),
            finding.get("payload_used") if finding.get("status") == "confirmed" else "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


async def run_form_scanner(alive_hosts: list[dict], profile: str = "light", callback=None, scan_config: dict | None = None) -> list[dict]:
    if not alive_hosts:
        return alive_hosts

    if callback:
        await callback("form_scan", "starting", "Extracting HTML forms and running safe form checks...")

    is_deep = profile == "deep"
    semaphore = asyncio.Semaphore(5 if is_deep else 3)
    baseline_samples = BASELINE_REQUESTS if is_deep else 1
    max_endpoints_per_host = 20 if is_deep else 5
    max_forms_per_page = 8 if is_deep else 3
    max_fields_per_form = 12 if is_deep else 6
    xss_payloads = XSS_PAYLOADS if is_deep else XSS_PAYLOADS[:2]
    sqli_error_payloads = SQLI_ERROR_PAYLOADS
    sqli_boolean_true_payloads = SQLI_BOOLEAN_TRUE_PAYLOADS if is_deep else SQLI_BOOLEAN_TRUE_PAYLOADS[:1]
    sqli_boolean_false_payloads = SQLI_BOOLEAN_FALSE_PAYLOADS if is_deep else SQLI_BOOLEAN_FALSE_PAYLOADS[:1]
    sqli_timing_payloads = SQLI_TIMING_PAYLOADS if is_deep else []
    redirect_payloads = REDIRECT_PAYLOADS if is_deep else REDIRECT_PAYLOADS[:1]
    telemetry = _new_telemetry()

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers=get_runtime_request_headers(scan_config, BASE_HEADERS),
        timeout=15.0,
    ) as client:
        for host in alive_hosts:
            host_url = host.get("url", "")
            if not host_url:
                continue

            host_findings: list[dict] = []
            urls_to_scan = [host_url] + host.get("endpoints", [])[:max_endpoints_per_host]
            target = host.get("subdomain") or urlparse(host_url).netloc

            for page_url in urls_to_scan:
                try:
                    response = await client.get(page_url, timeout=10.0)
                    body = response.text[:20000]
                    content_type = response.headers.get("content-type", "").lower()
                    blocked, challenged, reasons = is_blocked_or_challenged(response.status_code, dict(response.headers), body)
                    if blocked or challenged:
                        host_findings.append(_make_finding(
                            finding_id="form_scan_blocked",
                            url=page_url,
                            method="GET",
                            category="detection-testing",
                            vuln_type="form_scan_blocked",
                            status="blocked",
                            severity="info",
                            confidence=0.3,
                            evidence_text=f"Form discovery page was blocked or challenged: {', '.join(reasons) or response.status_code}.",
                            request_summary=_request_summary(page_url, "GET", None),
                            response_summary=_response_summary(response, body),
                            raw={"classification_reason": "blocked_or_challenged_page_fetch"},
                            target=target,
                        ))
                        continue
                    if response.status_code != 200 or content_type.startswith(("application/json", "image/", "font/")):
                        continue

                    forms = _extract_forms(body, page_url)[:max_forms_per_page]
                    for form in forms:
                        form["inputs"] = form["inputs"][:max_fields_per_form]
                        form["has_csrf_token"] = any(CSRF_FIELD_RE.search(field["name"]) for field in form["inputs"])
                        _record_form_inventory(telemetry, form)
                    if not forms:
                        continue

                    telemetry["forms_discovered"] += len(forms)
                    telemetry["inputs_discovered"] += sum(len(form["inputs"]) for form in forms)
                    log.info(f"[form_scanner] Found {len(forms)} form(s) at {page_url}")

                    if callback:
                        await callback("form_scan", "running", f"Testing {len(forms)} form(s) at {host.get('subdomain', page_url)}...")

                    for form in forms:
                        host_findings.extend(_discovery_findings_for_form(form, target=target))

                    form_results = await asyncio.gather(
                        *[
                            _test_form(
                                client,
                                form,
                                semaphore,
                                baseline_samples=baseline_samples,
                                xss_payloads=xss_payloads,
                                sqli_error_payloads=sqli_error_payloads,
                                sqli_boolean_true_payloads=sqli_boolean_true_payloads,
                                sqli_boolean_false_payloads=sqli_boolean_false_payloads,
                                sqli_timing_payloads=sqli_timing_payloads,
                                redirect_payloads=redirect_payloads,
                                telemetry=telemetry,
                            )
                            for form in forms
                        ],
                        return_exceptions=True,
                    )

                    for form, result in zip(forms, form_results):
                        if isinstance(result, list):
                            host_findings.extend(result)
                            _record_form_validation_results(telemetry, form, result)
                        elif isinstance(result, Exception):
                            telemetry["errors_count"] += 1
                            telemetry.setdefault("active_validation_results", []).append({
                                "module": MODULE_NAME,
                                "test_type": "form_payload_validation",
                                "method": str(form.get("method") or "get").upper(),
                                "url": _safe_url(form.get("action", "")),
                                "parameter": "",
                                "status": "error",
                                "reason": type(result).__name__,
                                "payloads_sent": 0,
                                "evidence": str(result)[:220],
                            })

                except httpx.TimeoutException:
                    telemetry["timeout_count"] += 1
                    continue
                except (httpx.ConnectError, httpx.RequestError):
                    continue
                except Exception as exc:
                    telemetry["errors_count"] += 1
                    log.debug(f"[form_scanner] Error scanning {page_url}: {exc}")

            host_findings = _dedupe_form_findings(host_findings)
            host["form_findings"] = host_findings
            host["form_vulns"] = merge_findings([], host_findings)
            promoted = [finding for finding in host_findings if finding.get("status") in {"candidate", "confirmed", "blocked", "inconclusive"}]
            if promoted:
                host["vulns"] = merge_findings(host.get("vulns", []), promoted)

    all_findings = _dedupe_form_findings([finding for host in alive_hosts for finding in host.get("form_findings", [])])
    telemetry = _finish_telemetry(telemetry, all_findings)
    for host in alive_hosts:
        host["form_telemetry"] = telemetry

    log.info(
        "[form_scanner] Complete. "
        f"forms={telemetry['forms_discovered']}, inputs={telemetry['inputs_discovered']}, "
        f"candidates={telemetry['candidates_count']}, confirmed={telemetry['confirmed_count']}"
    )
    if callback:
        await callback(
            "form_scan",
            "done",
            f"Form scan complete: {telemetry['forms_discovered']} forms, "
            f"{telemetry['confirmed_count']} confirmed, {telemetry['candidates_count']} candidates",
        )

    return alive_hosts
