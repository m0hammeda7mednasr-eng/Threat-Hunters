from __future__ import annotations

import asyncio
import os
import re
import tempfile
from collections import Counter
from urllib.parse import parse_qs, urlparse

import httpx

from .findings import Finding, dedupe_findings, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import extract_title, has_meaningful_diff, is_blocked_or_challenged, response_fingerprint
from .scanner_types import EvidenceItem, utc_now
from .utils import check_tool, get_tool_path, log


MODULE_NAME = "crlfuzz"
SOURCE_TOOL = "crlfuzz"
USER_AGENT = "Mozilla/5.0 Dragon-Recon/2.0"
BASE_HEADERS = {"User-Agent": USER_AGENT}

CRLF_MARKER = "DRAGON_CRLF_MARKER"
CONTROLLED_HEADER_NAME = "X-ReconTool-CRLF"
CONTROLLED_HEADER_VALUE = CRLF_MARKER

REFERENCE_URLS = [
    "https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://portswigger.net/web-security/host-header/exploiting",
]

GENERIC_ERROR_MARKERS = [
    "400 bad request",
    "404 not found",
    "page not found",
    "not found",
    "server error",
    "an error occurred",
    "invalid request",
    "malformed request",
]

INJECTABLE_PARAM_RE = re.compile(r"(url|uri|redirect|return|next|continue|callback|path|file|host|dest|destination|target|q|search)", re.I)
HEADER_PROOF_RE = re.compile(
    r"(?i)(?:^|[\s\"'`\[{(])(?P<name>x-[a-z0-9_.-]*(?:recontool|crlf|injected|test)[a-z0-9_.-]*)\s*:\s*(?P<value>[^\r\n\"'`<>]+)"
)
SECRET_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid)"
    r"\s*[:=]\s*['\"]?[^'\"\s,;]+"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
)


def _redact_text(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = JWT_RE.sub("<redacted-jwt>", text)
    text = SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    return text[:1600]


def _snippet(text: str, limit: int = 600) -> str:
    return re.sub(r"\s+", " ", _redact_text(text)).strip()[:limit]


def _parameter_names(url: str) -> list[str]:
    try:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _first_parameter(url: str) -> str:
    params = _parameter_names(url)
    return params[0] if params else ""


def _safe_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return str(url or "")
    params = parse_qs(parsed.query, keep_blank_values=True)
    query = "&".join(f"{key}=<tested>" for key in params)
    return parsed._replace(query=query).geturl()


def _extract_first_url(text: str) -> str:
    match = re.search(r"https?://[^\s\"'<>]+", text or "")
    if not match:
        return ""
    return match.group(0).rstrip("]),,")


def _payload_from_line(line: str) -> str:
    payload_match = re.search(r"(?i)(payload|vector|test)\s*[:=]\s*(?P<payload>[^\s\"'<>]+)", line or "")
    if payload_match:
        return _redact_text(payload_match.group("payload"))
    crlf_match = re.search(r"(%0d%0a|%0a|\\r\\n|\\n|\\x0d\\x0a)[^\s\"'<>]*", line or "", re.I)
    if crlf_match:
        return _redact_text(crlf_match.group(0))
    return ""


def _new_telemetry(url_count: int = 0) -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "urls_tested": url_count,
        "payloads_sent": 0,
        "candidates_count": 0,
        "confirmed_count": 0,
        "inconclusive_count": 0,
        "blocked_count": 0,
        "errors_count": 0,
        "timeout_count": 0,
        "malformed_tool_output_count": 0,
        "status_distribution": {},
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _finish_telemetry(telemetry: dict, findings: list[dict]) -> dict:
    statuses = Counter(finding.get("status", "unknown") for finding in findings)
    telemetry["candidates_count"] = statuses.get("candidate", 0)
    telemetry["confirmed_count"] = statuses.get("confirmed", 0)
    telemetry["inconclusive_count"] = statuses.get("inconclusive", 0)
    telemetry["blocked_count"] = statuses.get("blocked", 0)
    telemetry["status_distribution"] = dict(statuses)
    total = max(1, int(telemetry.get("payloads_sent", 0)) + int(telemetry.get("urls_tested", 0)))
    telemetry["module_noise_score"] = round(min(1.0, telemetry["blocked_count"] / total), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _request_summary(url: str, payload: str = "") -> dict:
    return summarize_request(method="GET", url=_safe_url(url), headers=BASE_HEADERS, body=_redact_text(payload))


def _response_summary(response: httpx.Response | None, body: str = "") -> dict:
    if response is None:
        snippet = _snippet(body)
        return summarize_response(status_code=None, headers={}, body=snippet, snippet=snippet)
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=_redact_text((body or "")[:800]),
        snippet=_snippet(body),
    )


def _remediation_for(vuln_type: str, status: str) -> str:
    if status in {"blocked", "inconclusive"}:
        return "Review the evidence in an authorized lab or lower-noise profile before treating this as exploitable."
    if vuln_type in {"crlf_injection", "crlf_injection_candidate", "http_response_splitting", "http_response_splitting_candidate"}:
        return "Reject or encode CR/LF characters in user-controlled data before it reaches response headers; use framework header APIs that validate header values."
    return "Review the CRLF evidence and validate safely before remediation."


def _default_reproduction(url: str, parameter: str, payload: str, status: str) -> list[str]:
    steps = [f"Send a GET request to {_safe_url(url) or 'the affected endpoint'}."]
    if parameter:
        steps.append(f"Set parameter '{parameter}' to the documented CRLF test value.")
    if payload:
        steps.append("Use the redacted payload shape recorded in payload_used.")
    if status == "confirmed":
        steps.append("Confirm that the injected header appears in the parsed response headers and is absent from the baseline response.")
    else:
        steps.append("Treat this as a validation lead until header-level evidence confirms injection.")
    return steps


def _make_finding(
    *,
    finding_id: str,
    url: str,
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
    evidence_text = _redact_text(evidence_text)
    payload = _redact_text(payload)
    raw = raw or {}
    parsed = urlparse(url)
    finding = Finding(
        id=finding_id,
        scanner_name=SOURCE_TOOL,
        module_name=MODULE_NAME,
        target=target or parsed.netloc or url,
        url=_safe_url(url),
        method="GET",
        parameter=parameter,
        category=category,
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="crlf_evidence",
                value=evidence_text,
                location=parameter or url,
                comparison=str(raw.get("classification_reason", "")),
            )
        ],
        payload_used=payload,
        request_summary=request_summary or _request_summary(url, payload),
        response_summary=response_summary or _response_summary(None, evidence_text),
        reproduction_steps=_default_reproduction(url, parameter, payload, status),
        remediation=_remediation_for(vuln_type, status),
        references=REFERENCE_URLS,
        name=vuln_type.replace("_", " ").title(),
        description=evidence_text,
        matched_at=_safe_url(url),
        payload=payload,
        raw={key: _redact_text(value) if isinstance(value, str) else value for key, value in raw.items()},
    ).to_dict()
    finding["source_tool"] = SOURCE_TOOL
    finding["evidence_items"] = finding.get("evidence", [])
    return finding


def _header_items(response: httpx.Response | None) -> list[tuple[str, str]]:
    if response is None:
        return []
    try:
        return [(str(key), str(value)) for key, value in response.headers.items()]
    except Exception:
        return []


def _baseline_has_injected_header(baseline_response: httpx.Response | None) -> bool:
    for name, value in _header_items(baseline_response):
        if name.lower() == CONTROLLED_HEADER_NAME.lower() or CRLF_MARKER.lower() in value.lower():
            return True
    return False


def _injected_header_evidence(response: httpx.Response | None) -> tuple[str, str]:
    for name, value in _header_items(response):
        if name.lower() == CONTROLLED_HEADER_NAME.lower() and CONTROLLED_HEADER_VALUE.lower() in value.lower():
            return name, value
        if CRLF_MARKER.lower() in value.lower() and name.lower() not in {"content-type", "server", "date", "content-length"}:
            return name, value
    return "", ""


def _looks_like_generic_error(status_code: int | None, body: str) -> bool:
    if status_code not in {400, 404, 405, 500}:
        return False
    lower = (body or "")[:12000].lower()
    title = extract_title(body).lower()
    return any(marker in lower or marker in title for marker in GENERIC_ERROR_MARKERS)


def _body_has_marker_only(response: httpx.Response | None, body: str) -> bool:
    header_name, _ = _injected_header_evidence(response)
    return bool(CRLF_MARKER in (body or "") and not header_name)


def _redirect_only(response: httpx.Response | None) -> bool:
    return bool(response is not None and 300 <= response.status_code < 400 and response.headers.get("location"))


def _classify_crlf_response(
    *,
    url: str,
    parameter: str = "",
    payload: str = "",
    baseline_response: httpx.Response | None = None,
    test_response: httpx.Response | None = None,
    baseline_body: str = "",
    test_body: str = "",
) -> dict | None:
    if test_response is None:
        return None

    blocked, challenged, reasons = is_blocked_or_challenged(test_response.status_code, dict(test_response.headers), test_body)
    if blocked or challenged:
        return _make_finding(
            finding_id="crlf_scan_blocked",
            url=url,
            parameter=parameter,
            category="detection-testing",
            vuln_type="crlf_scan_blocked",
            status="blocked",
            severity="info",
            confidence=0.3,
            evidence_text=f"CRLF test response was blocked or challenged: {', '.join(reasons) or test_response.status_code}.",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "blocked_or_challenged"},
        )

    if _looks_like_generic_error(test_response.status_code, test_body):
        return _make_finding(
            finding_id="crlf_scan_inconclusive",
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type="crlf_scan_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.2,
            evidence_text="CRLF payload returned a generic error page; header injection was not proven.",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "generic_error_without_header_proof"},
        )

    header_name, header_value = _injected_header_evidence(test_response)
    if header_name and not _baseline_has_injected_header(baseline_response):
        response_splitting = header_name.lower() != CONTROLLED_HEADER_NAME.lower()
        vuln_type = "http_response_splitting" if response_splitting else "crlf_injection"
        return _make_finding(
            finding_id=vuln_type,
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type=vuln_type,
            status="confirmed",
            severity="high" if response_splitting else "medium",
            confidence=0.92,
            evidence_text=(
                f"Injected marker appeared in parsed response header '{header_name}: {_redact_text(header_value)}' "
                "and was absent from the baseline response."
            ),
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "injected_marker_in_response_header", "header_name": header_name},
        )

    if header_name:
        return _make_finding(
            finding_id="crlf_injection_candidate",
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type="crlf_injection_candidate",
            status="candidate",
            severity="medium",
            confidence=0.68,
            evidence_text="A marker-like response header was present, but baseline/control evidence was incomplete or already contained the marker.",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "partial_header_marker_evidence", "header_name": header_name},
        )

    if _body_has_marker_only(test_response, test_body):
        return _make_finding(
            finding_id="crlf_injection_candidate",
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type="crlf_injection_candidate",
            status="candidate",
            severity="low",
            confidence=0.45,
            evidence_text="CRLF marker appeared only in the response body, not in parsed response headers.",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "body_reflection_only"},
        )

    if _redirect_only(test_response):
        return _make_finding(
            finding_id="http_response_splitting_candidate",
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type="http_response_splitting_candidate",
            status="candidate",
            severity="low",
            confidence=0.4,
            evidence_text=f"CRLF payload produced redirect behavior without injected-header proof. Location: {_redact_text(test_response.headers.get('location', ''))}",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "redirect_without_header_proof"},
        )

    if baseline_response is not None:
        baseline_fp = response_fingerprint(baseline_response.status_code, dict(baseline_response.headers), baseline_body)
        test_fp = response_fingerprint(test_response.status_code, dict(test_response.headers), test_body)
        if has_meaningful_diff(baseline_fp, test_fp, min_length_delta=80):
            return _make_finding(
                finding_id="crlf_injection_candidate",
                url=url,
                parameter=parameter,
                category="header_injection",
                vuln_type="crlf_injection_candidate",
                status="candidate",
                severity="low",
                confidence=0.38,
                evidence_text="CRLF payload changed the response, but no header-level injection proof was present.",
                payload=payload,
                request_summary=_request_summary(url, payload),
                response_summary=_response_summary(test_response, test_body),
                raw={"classification_reason": "response_diff_without_header_proof"},
            )

    if parameter and INJECTABLE_PARAM_RE.search(parameter):
        return _make_finding(
            finding_id="crlf_injection_candidate",
            url=url,
            parameter=parameter,
            category="header_injection",
            vuln_type="crlf_injection_candidate",
            status="candidate",
            severity="low",
            confidence=0.35,
            evidence_text=f"Parameter '{parameter}' is CRLF-relevant by name, but no header-level proof was observed.",
            payload=payload,
            request_summary=_request_summary(url, payload),
            response_summary=_response_summary(test_response, test_body),
            raw={"classification_reason": "parameter_name_only"},
        )

    return None


def _line_header_proof(line: str) -> tuple[str, str]:
    match = HEADER_PROOF_RE.search(line or "")
    if not match:
        return "", ""
    return match.group("name"), match.group("value")


def parse_crlfuzz_output(output: str, telemetry: dict | None = None) -> list[dict]:
    telemetry = telemetry if telemetry is not None else _new_telemetry()
    findings: list[dict] = []

    for raw_line in (output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        url = _extract_first_url(line)
        payload = _payload_from_line(line)
        parameter = _first_parameter(url)
        lower = line.lower()
        header_name, header_value = _line_header_proof(line)

        if header_name and (CRLF_MARKER.lower() in header_value.lower() or "injected" in lower or "response splitting" in lower):
            findings.append(_make_finding(
                finding_id="crlf_injection",
                url=url,
                parameter=parameter,
                category="header_injection",
                vuln_type="crlf_injection",
                status="confirmed",
                severity="medium",
                confidence=0.86,
                evidence_text=f"Tool output contains header-level proof: {_snippet(line)}",
                payload=payload,
                raw={"classification_reason": "tool_output_header_proof", "source_line": line, "header_name": header_name},
            ))
            continue

        if any(marker in lower for marker in ["vulnerable", "crlf", "response splitting", "injection", "payload"]):
            if not url:
                telemetry["malformed_tool_output_count"] += 1
                continue
            status = "inconclusive" if any(marker in lower for marker in ["error", "failed", "timeout", "unknown"]) else "candidate"
            findings.append(_make_finding(
                finding_id="crlf_scan_inconclusive" if status == "inconclusive" else "crlf_injection_candidate",
                url=url,
                parameter=parameter,
                category="header_injection",
                vuln_type="crlf_scan_inconclusive" if status == "inconclusive" else "crlf_injection_candidate",
                status=status,
                severity="info" if status == "inconclusive" else "low",
                confidence=0.25 if status == "inconclusive" else 0.48,
                evidence_text=f"crlfuzz output lacks parsed header proof: {_snippet(line)}",
                payload=payload,
                raw={"classification_reason": "tool_output_without_header_proof", "source_line": line},
            ))
            continue

        telemetry["malformed_tool_output_count"] += 1

    return dedupe_findings(findings)


def _host_matches_finding(host: dict, finding: dict) -> bool:
    finding_url = finding.get("url", "")
    if host.get("url") and finding_url.startswith(host["url"]):
        return True
    subdomain = host.get("subdomain", "")
    if subdomain and subdomain.lower() in finding_url.lower():
        return True
    for candidate in host.get("expanded_urls", []) or []:
        if candidate and finding_url.startswith(candidate):
            return True
    return False


async def run_crlfuzz(alive_hosts: list[dict], callback=None) -> list[dict]:
    telemetry = _new_telemetry()
    if not check_tool("crlfuzz"):
        log.warning("[crlfuzz] crlfuzz not found. Skipping.")
        telemetry = _finish_telemetry(telemetry, [])
        for host in alive_hosts:
            host.setdefault("crlf_findings", [])
            host["crlf_telemetry"] = telemetry
        if callback:
            await callback("crlfuzz", "warning", "crlfuzz not found. Skipping.")
        return alive_hosts

    if callback:
        await callback("crlfuzz", "running", "Scanning for CRLF injection indicators...")

    urls = sorted({
        url
        for host in alive_hosts
        for url in [*host.get("expanded_urls", [host.get("url")]), *host.get("endpoints", [])]
        if url
    })
    telemetry = _new_telemetry(len(urls))
    if not urls:
        telemetry = _finish_telemetry(telemetry, [])
        for host in alive_hosts:
            host.setdefault("crlf_findings", [])
            host["crlf_telemetry"] = telemetry
        return alive_hosts

    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt", prefix="crlf_targets_", encoding="utf-8")
    with tmp:
        tmp.write("\n".join(urls) + "\n")
    targets_file = tmp.name

    cmd = [get_tool_path("crlfuzz"), "-l", targets_file, "-s"]
    crlf_results: list[dict] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        stderr_text = _redact_text(stderr.decode(errors="replace"))
        if stderr_text.strip():
            telemetry["errors_count"] += 1
        crlf_results = parse_crlfuzz_output(stdout.decode(errors="replace"), telemetry)
        telemetry["payloads_sent"] = len(urls)
    except asyncio.TimeoutError:
        telemetry["timeout_count"] += 1
        log.warning("[crlfuzz] crlfuzz timed out")
    except Exception as exc:
        telemetry["errors_count"] += 1
        log.error(f"[crlfuzz] crlfuzz error: {exc}")
    finally:
        if os.path.exists(targets_file):
            os.remove(targets_file)

    crlf_results = dedupe_findings(crlf_results)
    telemetry = _finish_telemetry(telemetry, crlf_results)

    for host in alive_hosts:
        findings = [finding for finding in crlf_results if _host_matches_finding(host, finding)]
        host["crlf_findings"] = findings
        host["crlf_telemetry"] = telemetry
        if findings:
            host["vulns"] = merge_findings(host.get("vulns", []), findings)

    if callback:
        await callback(
            "crlfuzz",
            "done",
            f"CRLF scan complete. Confirmed={telemetry['confirmed_count']}, candidates={telemetry['candidates_count']}",
        )

    return alive_hosts

