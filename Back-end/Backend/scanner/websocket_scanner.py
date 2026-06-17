from __future__ import annotations

import asyncio
import base64
import os
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

import httpx

from .findings import Finding, dedupe_findings, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import is_blocked_or_challenged
from .scanner_types import EvidenceItem, utc_now
from .utils import log


MODULE_NAME = "websocket_scanner"
SCANNER_NAME = "websocket-scanner"
SOURCE_TOOL = "internal"
USER_AGENT = "Mozilla/5.0 Dragon-Recon/2.0"
CONTROLLED_ORIGIN = "https://recontool-controlled-origin.example"

BASE_HEADERS = {"User-Agent": USER_AGENT}
WS_URL_RE = re.compile(r"wss?://[^\s'\"<>\\)]+", re.IGNORECASE)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)/(admin|account|auth|billing|chat|internal|messages?|notification|payment|private|session|token|user|wallet)\b"
)
AUTH_REQUIRED_MARKERS = [
    "authentication required",
    "authorization required",
    "login required",
    "please log in",
    "unauthorized",
    "forbidden",
]
GENERIC_ERROR_MARKERS = [
    "bad request",
    "upgrade required",
    "not found",
    "server error",
    "invalid request",
    "malformed request",
]
SENSITIVE_DATA_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|cookie|password|private[_-]?key|secret|sessionid)\b"
)
SECRET_RE = re.compile(
    r"(?i)(['\"]?\b(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid)\b['\"]?"
    r"\s*[:=]\s*['\"]?)[^'\"\s,;}]+"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
)


def _generate_ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _redact_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = JWT_RE.sub("<redacted-jwt>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = SECRET_RE.sub(lambda match: match.group(1) + "<redacted>", text)
    return text


def _redact_obj(value: object) -> object:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}:
                redacted[key_text] = "<redacted>"
            else:
                redacted[key_text] = _redact_obj(item)
        return redacted
    if isinstance(value, list):
        return [_redact_obj(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_obj(item) for item in value)
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _snippet(text: str, limit: int = 600) -> str:
    return _redact_text((text or "")[:limit])


def _safe_url(url: str) -> str:
    parsed = urlparse(url or "")
    if not parsed.query:
        return url or ""
    query = parse_qs(parsed.query, keep_blank_values=True)
    sensitive_names = ("token", "key", "secret", "pass", "pwd", "session", "auth")
    safe_parts = []
    for key, values in query.items():
        value = values[0] if values else ""
        if any(marker in key.lower() for marker in sensitive_names):
            value = "<redacted>"
        safe_parts.append(f"{key}={value}")
    return parsed._replace(query="&".join(safe_parts)).geturl()


def _ws_to_http(ws_url: str) -> str:
    if ws_url.startswith("wss://"):
        return "https://" + ws_url[len("wss://"):]
    if ws_url.startswith("ws://"):
        return "http://" + ws_url[len("ws://"):]
    return ws_url


def _extract_ws_strings(text: str) -> set[str]:
    normalized = (text or "").replace("\\/", "/")
    return {match.group(0).rstrip(".,;") for match in WS_URL_RE.finditer(normalized)}


def _new_telemetry(endpoint_count: int = 0) -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "endpoints_discovered": endpoint_count,
        "endpoints_tested": endpoint_count,
        "handshakes_attempted": 0,
        "handshakes_successful": 0,
        "messages_sent": 0,
        "candidates_count": 0,
        "confirmed_count": 0,
        "inconclusive_count": 0,
        "blocked_count": 0,
        "errors_count": 0,
        "timeout_count": 0,
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
    total = max(
        1,
        int(telemetry.get("endpoints_tested", 0))
        + int(telemetry.get("handshakes_attempted", 0))
        + int(telemetry.get("messages_sent", 0)),
    )
    telemetry["module_noise_score"] = round(min(1.0, telemetry.get("blocked_count", 0) / total), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _request_summary(ws_url: str, *, origin: str = "", message: str = "") -> dict:
    headers = {
        **BASE_HEADERS,
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
    }
    if origin:
        headers["Origin"] = origin
    return summarize_request(method="GET", url=_safe_url(ws_url), headers=headers, body=_redact_text(message))


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
    if status in {"recon", "inconclusive", "blocked"}:
        return "Review the WebSocket endpoint in an authorized lab before treating this as exploitable."
    if vuln_type in {"websocket_origin_validation_candidate", "websocket_origin_validation_missing"}:
        return "Validate the Origin header during WebSocket upgrades and allow only trusted origins for authenticated or sensitive endpoints."
    if vuln_type == "websocket_sensitive_data_exposure":
        return "Require authentication and authorization before returning WebSocket data, and avoid sending secrets over unauthenticated channels."
    if vuln_type == "websocket_message_injection_candidate":
        return "Validate and encode WebSocket message fields according to the server-side action they trigger."
    return "Review the WebSocket evidence and validate safely before remediation."


def _reproduction_steps(ws_url: str, status: str, origin: str = "", message: str = "") -> list[str]:
    steps = [f"Send a WebSocket upgrade request to {_safe_url(ws_url) or 'the affected endpoint'}."]
    if origin:
        steps.append("Repeat the upgrade with the controlled Origin recorded in payload_used.")
    if message:
        steps.append("Send the redacted message shape recorded in message_used in an authorized lab.")
    if status == "confirmed":
        steps.append("Confirm the response evidence is tied to the same endpoint/request and absent from the control behavior.")
    else:
        steps.append("Treat this as recon or a validation lead until stronger endpoint-specific proof is available.")
    return steps


def _make_finding(
    *,
    finding_id: str,
    ws_url: str,
    category: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    origin: str = "",
    message: str = "",
    request_summary: dict | None = None,
    response_summary: dict | None = None,
    raw: dict | None = None,
    target: str = "",
) -> dict:
    evidence_text = _redact_text(evidence_text)
    origin = _redact_text(origin)
    message = _redact_text(message)
    parsed = urlparse(ws_url)
    payload = origin or message
    finding = Finding(
        id=finding_id,
        scanner_name=SCANNER_NAME,
        module_name=MODULE_NAME,
        target=target or parsed.netloc or ws_url,
        url=_safe_url(ws_url),
        method="GET",
        category=category,
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="websocket_evidence",
                value=evidence_text,
                location=_safe_url(ws_url),
                comparison=str((raw or {}).get("classification_reason", "")),
            )
        ],
        payload_used=payload,
        request_summary=request_summary or _request_summary(ws_url, origin=origin, message=message),
        response_summary=response_summary or _response_summary(None, evidence_text),
        reproduction_steps=_reproduction_steps(ws_url, status, origin, message),
        remediation=_remediation_for(vuln_type, status),
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://portswigger.net/web-security/websockets",
            "https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html",
        ],
        name=vuln_type.replace("_", " ").title(),
        description=evidence_text,
        matched_at=_safe_url(ws_url),
        payload=payload,
        raw=_redact_obj(raw or {}),
    ).to_dict()
    finding["source_tool"] = SOURCE_TOOL
    finding["message_used"] = message
    finding["evidence_items"] = finding.get("evidence", [])
    return finding


def _is_successful_handshake(response: httpx.Response | None) -> bool:
    if response is None or response.status_code != 101:
        return False
    headers = " ".join(f"{key}: {value}" for key, value in response.headers.items()).lower()
    return "websocket" in headers or response.status_code == 101


def _is_auth_required(response: httpx.Response | None, body: str = "") -> bool:
    if response is None:
        return False
    if response.status_code == 401:
        return True
    if response.headers.get("www-authenticate"):
        return True
    lower_body = (body or "")[:20000].lower()
    return any(marker in lower_body for marker in AUTH_REQUIRED_MARKERS)


def _looks_like_generic_error(response: httpx.Response | None, body: str = "") -> bool:
    if response is None:
        return False
    if response.status_code in {400, 404, 405, 426, 500, 502}:
        return True
    lower_body = (body or "")[:20000].lower()
    return any(marker in lower_body for marker in GENERIC_ERROR_MARKERS)


def _sensitive_path(ws_url: str) -> bool:
    parsed = urlparse(ws_url or "")
    path = parsed.path or ""
    return bool(SENSITIVE_PATH_RE.search(path))


def _contains_sensitive_data(text: str) -> bool:
    return bool(text and SENSITIVE_DATA_RE.search(text))


def _origin_policy_expected(ws_url: str, host_context: dict | None = None) -> bool:
    host_context = host_context or {}
    context_flags = (
        host_context.get("auth_required"),
        host_context.get("requires_auth"),
        host_context.get("authenticated_area"),
        host_context.get("sensitive"),
    )
    return bool(any(context_flags) or _sensitive_path(ws_url))


def _discovery_finding(ws_url: str, host: str = "", source: str = "crawl") -> dict:
    return _make_finding(
        finding_id="websocket_endpoint_discovered",
        ws_url=ws_url,
        category="websocket",
        vuln_type="websocket_endpoint_discovered",
        status="recon",
        severity="info",
        confidence=0.35,
        evidence_text=f"WebSocket endpoint was discovered from {source}. Endpoint existence alone is not a vulnerability.",
        raw={"classification_reason": "endpoint_discovered", "source": source},
        target=host,
    )


def _classify_websocket_observation(
    *,
    ws_url: str,
    host: str = "",
    baseline_response: httpx.Response | None = None,
    controlled_origin_response: httpx.Response | None = None,
    baseline_body: str = "",
    controlled_origin_body: str = "",
    controlled_origin: str = CONTROLLED_ORIGIN,
    auth_supplied: bool = False,
    host_context: dict | None = None,
    origin_policy_expected: bool = False,
    message_used: str = "",
    message_response: str = "",
    message_injection_proof: bool = False,
    sensitive_data_without_auth: bool = False,
    error: str = "",
) -> list[dict]:
    findings: list[dict] = []
    expected_origin_validation = bool(origin_policy_expected or _origin_policy_expected(ws_url, host_context))

    if error:
        return [
            _make_finding(
                finding_id="websocket_scan_inconclusive",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_scan_inconclusive",
                status="inconclusive",
                severity="info",
                confidence=0.2,
                evidence_text=f"WebSocket handshake could not be completed reliably: {_redact_text(error)}.",
                raw={"classification_reason": "handshake_error", "error": error},
                target=host,
            )
        ]

    if baseline_response is None:
        return [_discovery_finding(ws_url, host, source="input")]

    blocked, challenged, reasons = is_blocked_or_challenged(
        baseline_response.status_code,
        dict(baseline_response.headers),
        baseline_body,
    )
    if blocked or challenged:
        return [
            _make_finding(
                finding_id="websocket_scan_blocked",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_scan_blocked",
                status="blocked",
                severity="info",
                confidence=0.3,
                evidence_text=f"WebSocket handshake was blocked or challenged: {', '.join(reasons) or baseline_response.status_code}.",
                request_summary=_request_summary(ws_url),
                response_summary=_response_summary(baseline_response, baseline_body),
                raw={"classification_reason": "blocked_or_challenged"},
                target=host,
            )
        ]

    if _is_auth_required(baseline_response, baseline_body):
        return [
            _make_finding(
                finding_id="websocket_scan_inconclusive",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_scan_inconclusive",
                status="inconclusive",
                severity="info",
                confidence=0.28,
                evidence_text="WebSocket endpoint appears to require authentication; no vulnerability was proven.",
                request_summary=_request_summary(ws_url),
                response_summary=_response_summary(baseline_response, baseline_body),
                raw={"classification_reason": "auth_required"},
                target=host,
            )
        ]

    if not _is_successful_handshake(baseline_response):
        status_text = "redirect" if baseline_response.status_code in {301, 302, 303, 307, 308} else "non-upgrade response"
        reason = "generic_error" if _looks_like_generic_error(baseline_response, baseline_body) else "handshake_not_completed"
        return [
            _make_finding(
                finding_id="websocket_scan_inconclusive",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_scan_inconclusive",
                status="inconclusive",
                severity="info",
                confidence=0.2,
                evidence_text=f"WebSocket handshake did not complete ({status_text}, HTTP {baseline_response.status_code}).",
                request_summary=_request_summary(ws_url),
                response_summary=_response_summary(baseline_response, baseline_body),
                raw={"classification_reason": reason},
                target=host,
            )
        ]

    findings.append(
        _make_finding(
            finding_id="websocket_endpoint_discovered",
            ws_url=ws_url,
            category="websocket",
            vuln_type="websocket_endpoint_discovered",
            status="recon",
            severity="info",
            confidence=0.5,
            evidence_text="Endpoint completed a valid HTTP 101 WebSocket upgrade. Endpoint existence alone is not a vulnerability.",
            request_summary=_request_summary(ws_url),
            response_summary=_response_summary(baseline_response, baseline_body),
            raw={"classification_reason": "successful_handshake"},
            target=host,
        )
    )

    if not auth_supplied:
        sensitive = _sensitive_path(ws_url)
        findings.append(
            _make_finding(
                finding_id="websocket_unauthenticated_candidate",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_unauthenticated_candidate",
                status="candidate",
                severity="medium" if sensitive else "low",
                confidence=0.62 if sensitive else 0.45,
                evidence_text=(
                    "WebSocket handshake succeeded without authentication headers on a sensitive-looking path."
                    if sensitive
                    else "WebSocket handshake succeeded without authentication headers; security impact is not proven."
                ),
                request_summary=_request_summary(ws_url),
                response_summary=_response_summary(baseline_response, baseline_body),
                raw={"classification_reason": "unauthenticated_handshake", "sensitive_path": sensitive},
                target=host,
            )
        )

    if controlled_origin_response is not None and _is_successful_handshake(controlled_origin_response):
        if expected_origin_validation:
            findings.append(
                _make_finding(
                    finding_id="websocket_origin_validation_missing",
                    ws_url=ws_url,
                    category="websocket",
                    vuln_type="websocket_origin_validation_missing",
                    status="confirmed",
                    severity="medium",
                    confidence=0.88,
                    evidence_text=(
                        f"Endpoint accepted a WebSocket upgrade with controlled Origin {controlled_origin}; "
                        "context indicates Origin validation should apply."
                    ),
                    origin=controlled_origin,
                    request_summary=_request_summary(ws_url, origin=controlled_origin),
                    response_summary=_response_summary(controlled_origin_response, controlled_origin_body),
                    raw={"classification_reason": "controlled_origin_accepted_with_expected_validation"},
                    target=host,
                )
            )
        else:
            findings.append(
                _make_finding(
                    finding_id="websocket_origin_validation_candidate",
                    ws_url=ws_url,
                    category="websocket",
                    vuln_type="websocket_origin_validation_candidate",
                    status="candidate",
                    severity="low",
                    confidence=0.58,
                    evidence_text=(
                        f"Endpoint accepted a WebSocket upgrade with controlled Origin {controlled_origin}, "
                        "but the need for Origin restrictions was not proven."
                    ),
                    origin=controlled_origin,
                    request_summary=_request_summary(ws_url, origin=controlled_origin),
                    response_summary=_response_summary(controlled_origin_response, controlled_origin_body),
                    raw={"classification_reason": "controlled_origin_accepted_without_context"},
                    target=host,
                )
            )

    if sensitive_data_without_auth or ((not auth_supplied) and _contains_sensitive_data(f"{baseline_body}\n{message_response}")):
        findings.append(
            _make_finding(
                finding_id="websocket_sensitive_data_exposure",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_sensitive_data_exposure",
                status="confirmed",
                severity="high",
                confidence=0.9,
                evidence_text="Mocked/local WebSocket evidence showed sensitive-looking data returned without authentication.",
                message=message_used,
                request_summary=_request_summary(ws_url, message=message_used),
                response_summary=_response_summary(None, message_response or baseline_body),
                raw={"classification_reason": "sensitive_data_without_auth"},
                target=host,
            )
        )

    if message_injection_proof:
        findings.append(
            _make_finding(
                finding_id="websocket_message_injection_candidate",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_message_injection_candidate",
                status="confirmed",
                severity="medium",
                confidence=0.86,
                evidence_text="Mocked/local WebSocket evidence showed message content changed server-side behavior in a controlled proof.",
                message=message_used,
                request_summary=_request_summary(ws_url, message=message_used),
                response_summary=_response_summary(None, message_response),
                raw={"classification_reason": "mocked_message_injection_proof"},
                target=host,
            )
        )
    elif message_used and message_response and _redact_text(message_used) in _redact_text(message_response):
        findings.append(
            _make_finding(
                finding_id="websocket_endpoint_discovered",
                ws_url=ws_url,
                category="websocket",
                vuln_type="websocket_endpoint_discovered",
                status="recon",
                severity="info",
                confidence=0.4,
                evidence_text="WebSocket message echo behavior was observed without security impact proof.",
                message=message_used,
                request_summary=_request_summary(ws_url, message=message_used),
                response_summary=_response_summary(None, message_response),
                raw={"classification_reason": "message_echo_only"},
                target=host,
            )
        )

    return dedupe_findings(findings)


async def _fetch_js_ws_urls(
    client: httpx.AsyncClient,
    js_url: str,
    host_subdomain: str,
    semaphore: asyncio.Semaphore,
) -> list[tuple[str, str, str]]:
    async with semaphore:
        try:
            resp = await client.get(js_url, timeout=10.0, follow_redirects=True)
            content_type = resp.headers.get("content-type", "").lower()
            if resp.status_code >= 400 or ("javascript" not in content_type and not js_url.lower().endswith(".js")):
                return []
            return [(url, host_subdomain, f"js:{_safe_url(js_url)}") for url in _extract_ws_strings(resp.text[:500000])]
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return []
        except Exception as exc:
            log.debug(f"[websocket] Failed to inspect JS {js_url}: {exc}")
            return []


async def _test_websocket(
    client: httpx.AsyncClient,
    ws_url: str,
    host: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    async with semaphore:
        http_url = _ws_to_http(ws_url)
        target_host = urlparse(http_url).netloc or host

        upgrade_headers = {
            **BASE_HEADERS,
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Host": target_host,
            "Sec-WebSocket-Key": _generate_ws_key(),
            "Sec-WebSocket-Version": "13",
        }

        try:
            baseline = await client.get(http_url, headers=upgrade_headers, timeout=8.0, follow_redirects=False)
            origin_response = None
            if _is_successful_handshake(baseline):
                origin_headers = {
                    **upgrade_headers,
                    "Origin": CONTROLLED_ORIGIN,
                    "Sec-WebSocket-Key": _generate_ws_key(),
                }
                origin_response = await client.get(http_url, headers=origin_headers, timeout=8.0, follow_redirects=False)
            return {
                "url": ws_url,
                "host": host,
                "baseline_response": baseline,
                "controlled_origin_response": origin_response,
                "error": "",
                "timeout": False,
            }
        except httpx.TimeoutException as exc:
            return {"url": ws_url, "host": host, "error": f"timeout: {exc}", "timeout": True}
        except (httpx.ConnectError, httpx.RequestError) as exc:
            return {"url": ws_url, "host": host, "error": str(exc), "timeout": False}
        except Exception as exc:
            log.debug(f"[websocket] Error testing {ws_url}: {exc}")
            return {"url": ws_url, "host": host, "error": str(exc), "timeout": False}


async def _extract_ws_urls(alive_hosts: list[dict]) -> list[tuple[str, str, str]]:
    ws_endpoints: set[tuple[str, str, str]] = set()

    for host in alive_hosts:
        host_sub = host.get("subdomain", "")
        for url in host.get("extracted_urls", []) + host.get("endpoints", []):
            if isinstance(url, str) and url.startswith(("ws://", "wss://")):
                ws_endpoints.add((url, host_sub, "crawl"))

    js_tasks = []
    semaphore = asyncio.Semaphore(10)
    async with httpx.AsyncClient(
        verify=False,
        headers=BASE_HEADERS,
    ) as client:
        for host in alive_hosts:
            host_sub = host.get("subdomain", "")
            for js_url in host.get("js_files", [])[:50]:
                js_tasks.append(_fetch_js_ws_urls(client, js_url, host_sub, semaphore))

        if js_tasks:
            results = await asyncio.gather(*js_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    ws_endpoints.update(result)

    return sorted(ws_endpoints)


def _host_matches_finding(host: dict, host_sub: str, ws_url: str) -> bool:
    if host_sub and host.get("subdomain") == host_sub:
        return True
    host_url = host.get("url", "")
    host_name = urlparse(host_url).netloc or host.get("subdomain", "")
    ws_host = urlparse(ws_url).netloc
    return bool(host_name and ws_host and host_name.lower() == ws_host.lower())


async def run_websocket_scan(alive_hosts: list[dict], callback=None) -> list[dict]:
    ws_endpoints = await _extract_ws_urls(alive_hosts)
    telemetry = _new_telemetry(len(ws_endpoints))

    if not ws_endpoints:
        log.info("[websocket] No WebSocket endpoints found in crawled data or JS files.")
        telemetry = _finish_telemetry(telemetry, [])
        for host in alive_hosts:
            host.setdefault("websocket_findings", [])
            host["websocket_telemetry"] = telemetry
        if callback:
            await callback("websocket", "done", "No WebSocket endpoints discovered")
        return alive_hosts

    if callback:
        await callback("websocket", "running", f"Testing {len(ws_endpoints)} WebSocket endpoints...")

    log.info(f"[websocket] Testing {len(ws_endpoints)} WebSocket endpoints...")
    semaphore = asyncio.Semaphore(10)

    async with httpx.AsyncClient(verify=False, headers=BASE_HEADERS) as client:
        results = await asyncio.gather(
            *[_test_websocket(client, url, host, semaphore) for url, host, _source in ws_endpoints],
            return_exceptions=True,
        )

    host_findings: dict[tuple[str, str], list[dict]] = {}
    all_findings: list[dict] = []

    for (url, host_sub, source), result in zip(ws_endpoints, results):
        telemetry["handshakes_attempted"] += 1
        endpoint_findings = [_discovery_finding(url, host_sub, source)]

        if isinstance(result, Exception):
            telemetry["errors_count"] += 1
            endpoint_findings.extend(
                _classify_websocket_observation(ws_url=url, host=host_sub, error=str(result))
            )
        elif isinstance(result, dict):
            if result.get("timeout"):
                telemetry["timeout_count"] += 1
            if result.get("error"):
                telemetry["errors_count"] += 1

            baseline_response = result.get("baseline_response")
            if _is_successful_handshake(baseline_response):
                telemetry["handshakes_successful"] += 1

            endpoint_findings.extend(
                _classify_websocket_observation(
                    ws_url=url,
                    host=host_sub,
                    baseline_response=baseline_response,
                    controlled_origin_response=result.get("controlled_origin_response"),
                    controlled_origin=CONTROLLED_ORIGIN,
                    host_context={"sensitive": _sensitive_path(url)},
                    error=result.get("error", ""),
                )
            )
        else:
            telemetry["errors_count"] += 1
            endpoint_findings.extend(
                _classify_websocket_observation(ws_url=url, host=host_sub, error="malformed handshake result")
            )

        endpoint_findings = dedupe_findings(endpoint_findings)
        all_findings.extend(endpoint_findings)
        host_findings.setdefault((host_sub, url), []).extend(endpoint_findings)

    all_findings = dedupe_findings(all_findings)
    telemetry = _finish_telemetry(telemetry, all_findings)

    for host in alive_hosts:
        findings = []
        for (url, host_sub, _source) in ws_endpoints:
            if _host_matches_finding(host, host_sub, url):
                findings.extend(host_findings.get((host_sub, url), []))
        findings = dedupe_findings(findings)
        host["websocket_findings"] = findings
        host["websocket_telemetry"] = telemetry
        if findings:
            host["vulns"] = merge_findings(host.get("vulns", []), findings)

    log.info(
        "[websocket] Complete. "
        f"endpoints={telemetry['endpoints_discovered']}, "
        f"handshakes={telemetry['handshakes_successful']}, "
        f"confirmed={telemetry['confirmed_count']}, candidates={telemetry['candidates_count']}"
    )
    if callback:
        await callback(
            "websocket",
            "done",
            (
                f"WebSocket scan complete: {telemetry['handshakes_successful']} handshakes, "
                f"{telemetry['confirmed_count']} confirmed, {telemetry['candidates_count']} candidates"
            ),
        )

    return alive_hosts

