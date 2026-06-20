from __future__ import annotations

import asyncio

import httpx

from .findings import Finding, merge_findings
from .http_observer import summarize_httpx_response, summarize_request
from .utils import log


MODULE_NAME = "security_headers"
TEST_ORIGIN = "https://recontool.local"
BASE_HEADERS = {"User-Agent": "Mozilla/5.0 Dragon-Recon/2.0"}


REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "Missing HSTS header. Browsers are not instructed to require HTTPS for future requests.",
        "check": lambda v: v is not None,
        "remediation": "Serve HTTPS and add Strict-Transport-Security with an appropriate max-age after confirming all subdomains support HTTPS.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Missing Content-Security-Policy. CSP reduces impact from script injection and content loading mistakes.",
        "check": lambda v: v is not None,
        "remediation": "Add a restrictive Content-Security-Policy appropriate for the application and monitor violations before enforcing.",
        "references": ["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options or CSP frame-ancestors. The page may be frameable by another site.",
        "check": lambda v: v is not None,
        "remediation": "Add CSP frame-ancestors or X-Frame-Options DENY/SAMEORIGIN unless framing is intentionally required.",
        "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing X-Content-Type-Options: nosniff. Browser may MIME-sniff responses.",
        "check": lambda v: v is not None,
        "remediation": "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing Referrer-Policy. Referrer information may leak to third parties.",
        "check": lambda v: v is not None,
        "remediation": "Add a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer depending on business needs.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "Permissions-Policy": {
        "severity": "info",
        "description": "Missing Permissions-Policy header.",
        "check": lambda v: v is not None,
        "remediation": "Add a Permissions-Policy header that disables browser capabilities the application does not need.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
}


INFORMATIONAL_HEADERS = {
    "Server": {
        "severity": "info",
        "description": "Server version disclosure in response headers.",
        "check": lambda v: v and len(v) > 5,
    },
    "X-Powered-By": {
        "severity": "info",
        "description": "Technology fingerprint disclosed via X-Powered-By header.",
        "check": lambda v: v is not None,
    },
    "X-AspNet-Version": {
        "severity": "info",
        "description": "ASP.NET version disclosed via X-AspNet-Version header.",
        "check": lambda v: v is not None,
    },
}


def _make_finding(
    *,
    url: str,
    header_name: str,
    finding_id: str,
    name: str,
    description: str,
    severity: str,
    status: str,
    confidence: float,
    evidence_text: str,
    request_summary: dict,
    response_summary: dict,
    remediation: str,
    references: list[str],
    vuln_type: str = "security_header",
) -> dict:
    return Finding(
        id=finding_id,
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=url,
        method="GET",
        parameter=header_name,
        category="misconfiguration" if vuln_type in {"security_header", "cors"} else "information_disclosure",
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        request_summary=request_summary,
        response_summary=response_summary,
        remediation=remediation,
        references=references,
        name=name,
        description=description,
        matched_at=url,
        raw={"type": vuln_type, "header": header_name},
    ).to_dict()


def _missing_header_finding(
    *,
    url: str,
    header_name: str,
    config: dict,
    request_summary: dict,
    response_summary: dict,
) -> dict:
    return _make_finding(
        url=url,
        header_name=header_name,
        finding_id=f"missing-{header_name.lower()}",
        name=f"Missing {header_name}",
        description=config["description"],
        severity=config["severity"],
        status="confirmed",
        confidence=0.95,
        evidence_text=f"Header not present in HTTP response: {header_name}",
        request_summary=request_summary,
        response_summary=response_summary,
        remediation=config["remediation"],
        references=config["references"],
    )


def _informational_header_finding(
    *,
    url: str,
    header_name: str,
    header_value: str,
    config: dict,
    request_summary: dict,
    response_summary: dict,
) -> dict:
    return _make_finding(
        url=url,
        header_name=header_name,
        finding_id=f"disclosed-{header_name.lower()}",
        name=f"Header Disclosure: {header_name}",
        description=config["description"],
        severity=config["severity"],
        status="recon",
        confidence=0.9,
        evidence_text=f"{header_name}: {header_value}",
        request_summary=request_summary,
        response_summary=response_summary,
        remediation="Remove exact version details from response headers where practical. Do not rely on header hiding as a primary control.",
        references=["https://owasp.org/www-project-secure-headers/"],
        vuln_type="header_disclosure",
    )


def _wildcard_cors_finding(
    *,
    url: str,
    acao: str,
    acac: str,
    request_summary: dict,
    response_summary: dict,
) -> dict:
    credentials_enabled = acac.lower() == "true"
    return _make_finding(
        url=url,
        header_name="Access-Control-Allow-Origin",
        finding_id="cors-wildcard-origin",
        name="Wildcard CORS Origin",
        description=(
            "The response allows any Origin with Access-Control-Allow-Origin: *. "
            "No credentialed cross-origin access was proven."
        ),
        severity="medium" if credentials_enabled else "low",
        status="candidate",
        confidence=0.6 if credentials_enabled else 0.45,
        evidence_text=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac or '<absent>'}",
        request_summary=request_summary,
        response_summary=response_summary,
        remediation="Restrict Access-Control-Allow-Origin to trusted origins and avoid wildcard origins for sensitive APIs.",
        references=["https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/docs/Web/HTTP/CORS"],
        vuln_type="cors",
    )


async def _check_reflected_origin_cors(client: httpx.AsyncClient, url: str) -> dict | None:
    req_headers = {**BASE_HEADERS, "Origin": TEST_ORIGIN}
    req_summary = summarize_request(method="GET", url=url, headers=req_headers)
    try:
        resp = await client.get(url, headers={"Origin": TEST_ORIGIN}, timeout=8.0, follow_redirects=True)
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        return None

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    if acao.strip().lower() != TEST_ORIGIN or acac.strip().lower() != "true":
        return None

    return _make_finding(
        url=url,
        header_name="Access-Control-Allow-Origin",
        finding_id="cors-reflected-origin-credentials",
        name="Reflected Origin With Credentials",
        description="The endpoint reflects an arbitrary Origin and permits credentialed cross-origin requests.",
        severity="high",
        status="confirmed",
        confidence=0.9,
        evidence_text=f"Origin {TEST_ORIGIN} was reflected and Access-Control-Allow-Credentials was true.",
        request_summary=req_summary,
        response_summary=summarize_httpx_response(resp),
        remediation="Do not reflect arbitrary Origin values. Validate Origin against a strict allowlist and only enable credentials for trusted origins.",
        references=["https://developer.mozilla.org/docs/Web/HTTP/CORS", "https://owasp.org/www-project-secure-headers/"],
        vuln_type="cors",
    )


async def _check_headers(
    client: httpx.AsyncClient,
    host: dict,
    semaphore: asyncio.Semaphore,
) -> dict:
    async with semaphore:
        url = host.get("url", "")
        findings = []

        try:
            resp = await client.get(url, timeout=8.0, follow_redirects=True)
            headers = resp.headers
            req_summary = summarize_request(method="GET", url=url, headers=BASE_HEADERS)
            resp_summary = summarize_httpx_response(resp)

            for header_name, config in REQUIRED_HEADERS.items():
                header_val = headers.get(header_name)
                if header_name == "X-Frame-Options":
                    csp = headers.get("Content-Security-Policy", "")
                    if "frame-ancestors" in csp.lower():
                        continue
                if not config["check"](header_val):
                    findings.append(_missing_header_finding(
                        url=url,
                        header_name=header_name,
                        config=config,
                        request_summary=req_summary,
                        response_summary=resp_summary,
                    ))

            for header_name, config in INFORMATIONAL_HEADERS.items():
                header_val = headers.get(header_name)
                if config["check"](header_val):
                    findings.append(_informational_header_finding(
                        url=url,
                        header_name=header_name,
                        header_value=header_val,
                        config=config,
                        request_summary=req_summary,
                        response_summary=resp_summary,
                    ))

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "")
            if acao.strip() == "*":
                findings.append(_wildcard_cors_finding(
                    url=url,
                    acao=acao,
                    acac=acac,
                    request_summary=req_summary,
                    response_summary=resp_summary,
                ))

            reflected_cors = await _check_reflected_origin_cors(client, url)
            if reflected_cors:
                findings.append(reflected_cors)

        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass
        except Exception as e:
            log.debug(f"[security_headers] Error checking {url}: {e}")

        host["security_header_findings"] = findings
        return host


async def run_security_header_audit(alive_hosts: list[dict], callback=None) -> list[dict]:
    if not alive_hosts:
        return alive_hosts

    if callback:
        await callback("sec_headers", "running", f"Auditing security headers on {len(alive_hosts)} hosts...")

    log.info(f"[security_headers] Auditing {len(alive_hosts)} hosts...")
    semaphore = asyncio.Semaphore(30)

    async with httpx.AsyncClient(
        verify=False,
        headers=BASE_HEADERS,
        follow_redirects=True,
    ) as client:
        tasks = [_check_headers(client, host, semaphore) for host in alive_hosts]
        updated_hosts = await asyncio.gather(*tasks, return_exceptions=True)

    total_findings = 0
    for i, result in enumerate(updated_hosts):
        if not isinstance(result, dict):
            continue

        alive_hosts[i] = result
        findings = result.get("security_header_findings", [])
        total_findings += len(findings)

        promoted = [
            f for f in findings
            if f.get("status") in {"confirmed", "candidate"} and f.get("severity") in {"high", "medium"}
        ]
        if promoted:
            alive_hosts[i]["vulns"] = merge_findings(alive_hosts[i].get("vulns", []), promoted)

    log.info(f"[security_headers] Complete. Found {total_findings} unique header issues across {len(alive_hosts)} hosts.")
    if callback:
        await callback("sec_headers", "done", f"Header audit: {total_findings} issues across {len(alive_hosts)} hosts")

    return alive_hosts


