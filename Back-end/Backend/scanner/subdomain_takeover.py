from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .findings import Finding, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import extract_title, is_blocked_or_challenged
from .scanner_types import EvidenceItem, body_hash, utc_now
from .utils import log


MODULE_NAME = "subdomain_takeover"
USER_AGENT = "Mozilla/5.0 Dragon-Recon/2.0"
PROBE_HEADERS = {"User-Agent": USER_AGENT}

REFERENCES = [
    "https://github.com/EdOverflow/can-i-take-over-xyz",
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/www-community/attacks/Subdomain_Takeover",
]


@dataclass(frozen=True)
class ProviderFingerprint:
    cname_pattern: str
    body_pattern: str
    service_name: str
    strong_unclaimed_patterns: tuple[str, ...] = ()

    def cname_matches(self, value: str) -> bool:
        return bool(value and re.search(self.cname_pattern, value, re.IGNORECASE))

    def body_matches(self, value: str) -> bool:
        return bool(value and re.search(self.body_pattern, value, re.IGNORECASE))

    def strong_body_matches(self, value: str) -> bool:
        return any(re.search(pattern, value or "", re.IGNORECASE) for pattern in self.strong_unclaimed_patterns)


TAKEOVER_FINGERPRINTS = [
    ProviderFingerprint(r"\.github\.io$", r"There isn't a GitHub Pages site here", "GitHub Pages", (r"There isn't a GitHub Pages site here",)),
    ProviderFingerprint(r"\.herokuapps?\.com$", r"No such app", "Heroku", (r"No such app",)),
    ProviderFingerprint(r"\.fastly\.net$", r"Fastly error: unknown domain", "Fastly", (r"Fastly error: unknown domain",)),
    ProviderFingerprint(r"\.shopify\.com$", r"Sorry, this shop is currently unavailable", "Shopify", (r"Sorry, this shop is currently unavailable",)),
    ProviderFingerprint(r"\.azurewebsites\.net$", r"404 Web Site not found", "Azure", (r"404 Web Site not found",)),
    ProviderFingerprint(r"\.cloudfront\.net$", r"The request could not be satisfied", "CloudFront"),
    ProviderFingerprint(r"\.s3\.amazonaws\.com$", r"The specified bucket does not exist", "Amazon S3", (r"The specified bucket does not exist",)),
    ProviderFingerprint(r"\.s3-website", r"The specified bucket does not exist", "Amazon S3", (r"The specified bucket does not exist",)),
    ProviderFingerprint(r"bitbucket\.io$", r"Repository not found", "Bitbucket", (r"Repository not found",)),
    ProviderFingerprint(r"\.pantheonsite\.io$", r"The gods are wise", "Pantheon"),
    ProviderFingerprint(r"\.tumblr\.com$", r"Whatever you were looking for doesn't currently exist", "Tumblr", (r"doesn't currently exist",)),
    ProviderFingerprint(r"\.wordpress\.com$", r"Do you want to register", "WordPress"),
    ProviderFingerprint(r"helpjuice\.com$", r"We could not find what you're looking for", "HelpJuice"),
    ProviderFingerprint(r"helpscoutdocs\.com$", r"No settings were found for this company", "HelpScout", (r"No settings were found for this company",)),
    ProviderFingerprint(r"\.ghost\.io$", r"The thing you were looking for is no longer here", "Ghost", (r"no longer here",)),
    ProviderFingerprint(r"\.surge\.sh$", r"project not found", "Surge.sh", (r"project not found",)),
    ProviderFingerprint(r"\.netlify\.app$", r"Not Found", "Netlify"),
    ProviderFingerprint(r"cargocollective\.com$", r"404 Not Found", "Cargo"),
    ProviderFingerprint(r"statuspage\.io$", r"You are being", "Statuspage"),
    ProviderFingerprint(r"unbouncepages\.com$", r"The requested URL", "Unbounce"),
    ProviderFingerprint(r"fly\.dev$", r"404", "Fly.io"),
    ProviderFingerprint(r"launchrock\.com$", r"It looks like you may have taken a wrong turn somewhere", "LaunchRock"),
    ProviderFingerprint(r"uservoice\.com$", r"This UserVoice subdomain is currently available", "UserVoice", (r"subdomain is currently available",)),
    ProviderFingerprint(r"freshdesk\.com$", r"There is no helpdesk here with that URL", "Freshdesk", (r"There is no helpdesk here with that URL",)),
    ProviderFingerprint(r"readme\.io$", r"Project doesnt exist", "Readme.io", (r"Project doesnt exist", r"Project doesn't exist")),
    ProviderFingerprint(r"webflow\.io$", r"The page you are looking for doesn't exist", "Webflow"),
    ProviderFingerprint(r"strikingly\.com$", r"page not found", "Strikingly"),
]

SECRET_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|sessionid|api[_-]?key|token|password|secret)\s*[:=]\s*[^\r\n;]+"
)


def _redact(value: object) -> str:
    text = str(value or "")
    text = SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    return text[:1200]


def _snippet(body: str, pattern: str = "") -> str:
    text = body or ""
    if pattern:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 120)
            end = min(len(text), match.end() + 120)
            return _redact(text[start:end].replace("\r", " ").replace("\n", " "))[:500]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return _redact(" ".join(lines[:3]))[:500]


def _provider_by_cname(cname: str) -> ProviderFingerprint | None:
    for provider in TAKEOVER_FINGERPRINTS:
        if provider.cname_matches(cname):
            return provider
    return None


def _provider_by_body(body: str) -> ProviderFingerprint | None:
    for provider in TAKEOVER_FINGERPRINTS:
        if provider.body_matches(body):
            return provider
    return None


async def _resolve_cname(subdomain: str) -> dict:
    result = {
        "subdomain": subdomain,
        "cname": "",
        "error": "",
        "status": "ok",
    }
    nslookup = shutil.which("nslookup")
    if not nslookup:
        result["status"] = "unavailable"
        result["error"] = "nslookup unavailable"
        return result

    try:
        proc = await asyncio.create_subprocess_exec(
            nslookup,
            "-type=CNAME",
            subdomain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
        output = (stdout + b"\n" + stderr).decode(errors="replace")
    except asyncio.TimeoutError:
        result["status"] = "timeout"
        result["error"] = "dns timeout"
        return result
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)[:300]
        return result

    patterns = [
        r"canonical name\s*=\s*(?P<cname>[^\s]+)",
        r"canonical name\s*:\s*(?P<cname>[^\s]+)",
        r"CNAME\s+(?P<cname>[^\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result["cname"] = match.group("cname").strip().rstrip(".")
            break
    return result


def _new_telemetry(total: int) -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "subdomains_checked": total,
        "dns_lookups_attempted": 0,
        "cname_records_found": 0,
        "provider_fingerprints_found": 0,
        "candidates_count": 0,
        "confirmed_count": 0,
        "inconclusive_count": 0,
        "blocked_count": 0,
        "errors_count": 0,
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _record_finding(telemetry: dict, finding: dict) -> None:
    status = finding.get("status")
    if status == "candidate":
        telemetry["candidates_count"] += 1
    elif status == "confirmed":
        telemetry["confirmed_count"] += 1
    elif status == "inconclusive":
        telemetry["inconclusive_count"] += 1
    elif status == "blocked":
        telemetry["blocked_count"] += 1


def _finish_telemetry(telemetry: dict) -> dict:
    telemetry["completed_at"] = utc_now()
    telemetry["module_noise_score"] = 0.0
    return telemetry


def _response_summary(response: httpx.Response | None, body: str = "") -> dict:
    if response is None:
        return {}
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=_redact(body[:512]),
        snippet=_snippet(body),
    )


def _request_summary(url: str) -> dict:
    return summarize_request(method="GET", url=url, headers=PROBE_HEADERS)


def _finding_values(
    *,
    subdomain: str,
    url: str,
    provider: ProviderFingerprint | None,
    cname: str,
    response: httpx.Response | None,
    body: str,
    blocked: bool,
    challenged: bool,
    block_reasons: list[str],
    dns_error: str = "",
) -> dict | None:
    provider_name = provider.service_name if provider else ""
    cname_provider = _provider_by_cname(cname) if cname else None
    cname_matches_provider = bool(provider and cname_provider and cname_provider.service_name == provider.service_name)
    strong_proof = bool(provider and provider.strong_body_matches(body))
    provider_fingerprint = bool(provider and provider.body_matches(body))

    if blocked or challenged:
        return {
            "vuln_type": "subdomain_takeover_candidate",
            "status": "blocked",
            "severity": "info",
            "confidence": 0.3,
            "reason": f"HTTP probing was blocked/challenged: {', '.join(block_reasons) or 'blocked response'}.",
        }

    if dns_error:
        return {
            "vuln_type": "dangling_dns",
            "status": "inconclusive",
            "severity": "info",
            "confidence": 0.25,
            "reason": f"DNS lookup was inconclusive: {dns_error}.",
        }

    if cname and provider and cname_matches_provider and strong_proof:
        return {
            "vuln_type": "subdomain_takeover_confirmed",
            "status": "confirmed",
            "severity": "high",
            "confidence": 0.9,
            "reason": f"CNAME points to {provider_name} and HTTP response contains strong unclaimed-resource proof.",
        }

    if cname and cname_provider and provider_fingerprint:
        return {
            "vuln_type": "subdomain_takeover_candidate",
            "status": "candidate",
            "severity": "medium",
            "confidence": 0.7,
            "reason": f"CNAME points to {cname_provider.service_name} and matching provider fingerprint was observed, but proof is not strong enough to confirm takeover.",
        }

    if cname and cname_provider:
        return {
            "vuln_type": "cname_to_unclaimed_service",
            "status": "candidate",
            "severity": "medium",
            "confidence": 0.5,
            "reason": f"CNAME target matches known third-party provider pattern for {cname_provider.service_name}.",
        }

    if provider_fingerprint:
        return {
            "vuln_type": "third_party_service_fingerprint",
            "status": "candidate",
            "severity": "low",
            "confidence": 0.5,
            "reason": f"HTTP response contains {provider_name} provider fingerprint without matching DNS proof.",
        }

    return None


def _make_finding(
    *,
    subdomain: str,
    url: str,
    provider: ProviderFingerprint | None,
    cname: str,
    response: httpx.Response | None,
    body: str,
    classification: dict,
    dns_error: str = "",
) -> dict:
    provider_name = provider.service_name if provider else (_provider_by_cname(cname).service_name if _provider_by_cname(cname) else "")
    title = extract_title(body)
    status_code = response.status_code if response is not None else None
    evidence_parts = [
        f"Subdomain: {subdomain}.",
        f"Provider: {provider_name or 'unknown'}.",
        f"CNAME: {cname or 'not observed'}.",
        f"HTTP status: {status_code if status_code is not None else 'not available'}.",
        f"Title: {_redact(title) or 'not observed'}.",
        f"Reason: {classification['reason']}",
    ]
    if provider:
        evidence_parts.append(f"Provider fingerprint: {_redact(provider.body_pattern)}.")
    if body:
        evidence_parts.append(f"Safe snippet: {_snippet(body, provider.body_pattern if provider else '')}.")
    if dns_error:
        evidence_parts.append(f"DNS detail: {_redact(dns_error)}.")
    evidence_text = " ".join(evidence_parts)

    return Finding(
        id=classification["vuln_type"],
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=url or f"https://{subdomain}",
        target=subdomain,
        method="GET",
        category="takeover" if classification["status"] in {"candidate", "confirmed"} else "network_recon",
        vuln_type=classification["vuln_type"],
        status=classification["status"],
        severity=classification["severity"],
        confidence=classification["confidence"],
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="takeover_evidence",
                value=evidence_text,
                location=subdomain,
                comparison=classification["reason"],
            )
        ],
        request_summary=_request_summary(url) if url else {},
        response_summary=_response_summary(response, body),
        remediation=(
            "Remove dangling DNS records or configure/reclaim the referenced third-party resource. "
            "Do not attempt to claim resources unless you own the asset and have explicit authorization."
        ),
        references=REFERENCES,
        name=classification["vuln_type"].replace("_", " ").title(),
        description=evidence_text,
        matched_at=url or subdomain,
        raw={
            "subdomain": subdomain,
            "provider": provider_name,
            "cname": cname,
            "http_status": status_code,
            "dns_error": _redact(dns_error),
            "classification_reason": classification["reason"],
        },
    ).to_dict()


async def _check_takeover(client: httpx.AsyncClient, subdomain: str, semaphore: asyncio.Semaphore, telemetry: dict) -> dict | None:
    telemetry["dns_lookups_attempted"] += 1
    dns_result = await _resolve_cname(subdomain)
    cname = dns_result.get("cname", "")
    dns_error = dns_result.get("error", "") if dns_result.get("status") in {"timeout", "error"} else ""
    if cname:
        telemetry["cname_records_found"] += 1

    cname_provider = _provider_by_cname(cname) if cname else None
    if dns_error:
        classification = _finding_values(
            subdomain=subdomain,
            url=f"https://{subdomain}",
            provider=cname_provider,
            cname=cname,
            response=None,
            body="",
            blocked=False,
            challenged=False,
            block_reasons=[],
            dns_error=dns_error,
        )
        if classification:
            finding = _make_finding(
                subdomain=subdomain,
                url=f"https://{subdomain}",
                provider=cname_provider,
                cname=cname,
                response=None,
                body="",
                classification=classification,
                dns_error=dns_error,
            )
            _record_finding(telemetry, finding)
            return finding

    best_candidate = None
    async with semaphore:
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                response = await client.get(url, timeout=7.0, follow_redirects=True)
                body = response.text[:10000]
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
                telemetry["errors_count"] += 1
                if not best_candidate and cname_provider:
                    classification = {
                        "vuln_type": "cname_to_unclaimed_service",
                        "status": "candidate",
                        "severity": "medium",
                        "confidence": 0.45,
                        "reason": f"CNAME points to {cname_provider.service_name}; HTTP probe failed: {type(exc).__name__}.",
                    }
                    best_candidate = _make_finding(
                        subdomain=subdomain,
                        url=url,
                        provider=cname_provider,
                        cname=cname,
                        response=None,
                        body="",
                        classification=classification,
                    )
                continue

            blocked, challenged, block_reasons = is_blocked_or_challenged(response.status_code, dict(response.headers), body)
            body_provider = _provider_by_body(body)
            provider = body_provider or cname_provider
            if body_provider:
                telemetry["provider_fingerprints_found"] += 1

            classification = _finding_values(
                subdomain=subdomain,
                url=url,
                provider=provider,
                cname=cname,
                response=response,
                body=body,
                blocked=blocked,
                challenged=challenged,
                block_reasons=block_reasons,
            )
            if not classification:
                continue
            finding = _make_finding(
                subdomain=subdomain,
                url=url,
                provider=provider,
                cname=cname,
                response=response,
                body=body,
                classification=classification,
            )
            if finding["status"] == "confirmed":
                _record_finding(telemetry, finding)
                return finding
            best_candidate = best_candidate or finding

    if best_candidate:
        _record_finding(telemetry, best_candidate)
    return best_candidate


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("target") or finding.get("raw", {}).get("subdomain"),
            finding.get("raw", {}).get("provider"),
            finding.get("vuln_type"),
            body_hash(str(finding.get("evidence", ""))),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


async def run_takeover_check(alive_hosts: list[dict], callback=None) -> list[dict]:
    if not alive_hosts:
        return alive_hosts

    if callback:
        await callback("takeover", "running", f"Checking {len(alive_hosts)} hosts for subdomain takeover...")

    log.info(f"[takeover] Checking {len(alive_hosts)} subdomains for takeover indicators...")

    telemetry = _new_telemetry(len(alive_hosts))
    semaphore = asyncio.Semaphore(25)
    async with httpx.AsyncClient(
        verify=False,
        headers=PROBE_HEADERS,
        follow_redirects=False,
    ) as client:
        tasks = [_check_takeover(client, host["subdomain"], semaphore, telemetry) for host in alive_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    by_subdomain: dict[str, list[dict]] = {}
    for host, result in zip(alive_hosts, results):
        if isinstance(result, Exception):
            telemetry["errors_count"] += 1
            log.debug(f"[takeover] Error checking {host.get('subdomain')}: {result}")
            continue
        if isinstance(result, dict) and result:
            by_subdomain.setdefault(host.get("subdomain", ""), []).append(result)

    total_findings = 0
    for host in alive_hosts:
        findings = _dedupe_findings(by_subdomain.get(host.get("subdomain", ""), []))
        if not findings:
            host["takeover_findings"] = host.get("takeover_findings", [])
            host["takeover_telemetry"] = _finish_telemetry(telemetry)
            continue
        total_findings += len(findings)
        host["takeover_findings"] = merge_findings(host.get("takeover_findings", []), findings)
        host["vulns"] = merge_findings(host.get("vulns", []), findings)
        host["takeover_telemetry"] = _finish_telemetry(telemetry)
        log.warning(f"[takeover] Potential takeover indicator: {host.get('subdomain')} -> {len(findings)} finding(s)")

    telemetry = _finish_telemetry(telemetry)
    for host in alive_hosts:
        host["takeover_telemetry"] = telemetry

    log.info(f"[takeover] Complete. {total_findings} takeover finding(s) recorded.")

    if callback:
        await callback("takeover", "done", f"Found {total_findings} subdomain takeover finding(s)")

    return alive_hosts

