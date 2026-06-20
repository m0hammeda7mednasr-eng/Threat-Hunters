from __future__ import annotations

import asyncio
import re
import time
from collections import Counter
from urllib.parse import urlparse

import httpx

from .http_observer import summarize_request, summarize_response
from .proxy_manager import get_client
from .response_analysis import extract_title, is_blocked_or_challenged
from .scanner_types import body_hash, utc_now
from .utils import log


CONCURRENCY = 50
TIMEOUT = 10
MODULE_NAME = "alive"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
)
PROBE_HEADERS = {
    "User-Agent": USER_AGENT,
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
}

WAF_HEADER_MARKERS = [
    "cf-ray",
    "cf-cache-status",
    "x-sucuri-id",
    "x-sucuri-cache",
    "x-akamai",
    "x-iinfo",
    "x-cdn",
    "x-waf",
    "x-firewall",
]

WAF_BODY_MARKERS = [
    "cloudflare",
    "sucuri",
    "akamai",
    "imperva",
    "incapsula",
    "mod_security",
    "modsecurity",
    "barracuda",
    "request blocked",
    "access denied",
]


def _classify_page(url: str, html: str) -> str:
    text = (url + " " + html).lower()
    checks = [
        ("admin", ["admin", "administrator", "dashboard", "control panel", "wp-admin"]),
        ("login", ["login", "log in", "sign in", "signin", "wp-login", "user/password"]),
        ("docs", ["documentation", "docs", "swagger", "openapi", "api docs", "redoc"]),
        ("status", ["status", "health", "uptime", "status page"]),
        ("api", ["api reference", "graphql", "/api/", "api explorer"]),
    ]
    for label, keys in checks:
        if any(key in text for key in keys):
            return label.upper()
    return ""


def _header_value(headers: dict, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _safe_text(response: httpx.Response) -> str:
    try:
        return response.text[:51200]
    except Exception:
        try:
            return response.content[:51200].decode("utf-8", errors="replace")
        except Exception:
            return ""


def _content_length(response: httpx.Response, body: str) -> int:
    header_length = _header_value(dict(response.headers), "content-length")
    try:
        return int(header_length)
    except (TypeError, ValueError):
        return len(response.content) if getattr(response, "content", None) is not None else len(body)


def _redirect_chain(response: httpx.Response) -> list[dict]:
    chain = []
    for item in getattr(response, "history", []) or []:
        chain.append({
            "url": str(item.url),
            "status_code": item.status_code,
            "location": _header_value(dict(item.headers), "location"),
        })
    if chain:
        chain.append({
            "url": str(response.url),
            "status_code": response.status_code,
            "location": "",
        })
    return chain


def _redirect_metadata(original_url: str, response: httpx.Response) -> dict:
    final_url = str(response.url)
    original = urlparse(original_url)
    final = urlparse(final_url)
    chain = _redirect_chain(response)
    return {
        "original_url": original_url,
        "final_url": final_url,
        "redirect_chain": chain,
        "redirect_count": max(0, len(chain) - 1),
        "cross_domain_redirect": bool(final.netloc and original.netloc and final.netloc.lower() != original.netloc.lower()),
        "http_to_https_upgrade": original.scheme == "http" and final.scheme == "https",
        "https_to_http_downgrade": original.scheme == "https" and final.scheme == "http",
        "redirect_loop": False,
        "too_many_redirects": False,
    }


def _tech_hints(response: httpx.Response, body: str) -> tuple[list[str], bool, str]:
    headers = dict(response.headers)
    tech = []
    is_cdn = False
    waf_name = ""

    server = _header_value(headers, "server")
    if server:
        tech.append(server)
        server_lower = server.lower()
        if any(cdn in server_lower for cdn in ["cloudflare", "akamai", "cloudfront", "sucuri", "imperva", "incapsula"]):
            is_cdn = True
            waf_name = server
            tech.append("CDN/WAF Detected")

    x_powered = _header_value(headers, "x-powered-by")
    if x_powered:
        tech.append(x_powered)

    lower_headers = " ".join(f"{key}: {value}" for key, value in headers.items()).lower()
    lower_body = body[:20000].lower()
    for marker in WAF_HEADER_MARKERS:
        if marker in lower_headers:
            is_cdn = True
            waf_name = waf_name or marker
            tech.append("WAF/Control Header")
            break
    for marker in WAF_BODY_MARKERS:
        if marker in lower_body:
            is_cdn = True
            waf_name = waf_name or marker
            tech.append("WAF/Control Page")
            break

    return sorted(set(tech)), is_cdn, waf_name


def _observation_status(status_code: int | None, blocked: bool, challenged: bool) -> str:
    if blocked or challenged:
        return "blocked"
    if status_code is None:
        return "error"
    if 200 <= status_code < 500:
        return "recon"
    return "inconclusive"


def _response_summary(response: httpx.Response, body: str, response_time_ms: int) -> dict:
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=body[:512],
        elapsed_ms=response_time_ms,
        snippet=body[:500],
    )


def _make_error_observation(url: str, error_type: str, message: str, elapsed_ms: int | None = None) -> dict:
    parsed = urlparse(url)
    return {
        "module_name": MODULE_NAME,
        "input_host": parsed.netloc or parsed.path,
        "original_url": url,
        "url": url,
        "final_url": "",
        "scheme": parsed.scheme,
        "final_host": "",
        "status": "error",
        "status_code": None,
        "title": "",
        "content_type": "",
        "content_length": 0,
        "body_hash": "",
        "response_time_ms": elapsed_ms,
        "redirect_chain": [],
        "cross_domain_redirect": False,
        "http_to_https_upgrade": False,
        "https_to_http_downgrade": False,
        "redirect_loop": False,
        "too_many_redirects": error_type == "too_many_redirects",
        "server": "",
        "tech": [],
        "is_cdn": False,
        "is_waf": False,
        "waf_name": "",
        "blocked": False,
        "challenged": False,
        "blocked_or_challenge_indicators": [],
        "tls_error": error_type == "tls_error",
        "probe_error": error_type,
        "probe_error_detail": message[:300],
        "request_summary": summarize_request(method="GET", url=url, headers=PROBE_HEADERS),
        "response_summary": {},
    }


async def _probe_url(client: httpx.AsyncClient, url: str, domain: str, semaphore: asyncio.Semaphore) -> dict:
    del domain  # kept in signature for compatibility and future scope checks.
    async with semaphore:
        started = time.perf_counter()
        request_method = "HEAD"
        request_headers = PROBE_HEADERS

        async def fallback_get():
            fallback_headers = {"User-Agent": "Mozilla/5.0"}
            async with httpx.AsyncClient(verify=False, headers=fallback_headers) as fallback_client:
                return await fallback_client.get(url, timeout=TIMEOUT, follow_redirects=True), fallback_headers

        try:
            response = await client.head(url, timeout=TIMEOUT, follow_redirects=True, headers=PROBE_HEADERS)
            if response.status_code in {405, 501}:
                request_method = "GET"
                response, request_headers = await fallback_get()
            response_time_ms = int((time.perf_counter() - started) * 1000)
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, httpx.NetworkError):
            try:
                request_method = "GET"
                response, request_headers = await fallback_get()
                response_time_ms = int((time.perf_counter() - started) * 1000)
            except httpx.TooManyRedirects as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _make_error_observation(url, "too_many_redirects", str(exc), elapsed_ms)
            except httpx.TimeoutException as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _make_error_observation(url, "timeout", str(exc), elapsed_ms)
            except httpx.ConnectError as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                text = str(exc).lower()
                error_type = "tls_error" if any(marker in text for marker in ["ssl", "tls", "certificate", "cert"]) else "connect_error"
                return _make_error_observation(url, error_type, str(exc), elapsed_ms)
            except httpx.InvalidURL as exc:
                return _make_error_observation(url, "invalid_url", str(exc), None)
            except httpx.HTTPError as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _make_error_observation(url, "http_error", str(exc), elapsed_ms)
            except Exception as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _make_error_observation(url, "probe_error", str(exc), elapsed_ms)
        except httpx.TooManyRedirects as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return _make_error_observation(url, "too_many_redirects", str(exc), elapsed_ms)
        except httpx.TimeoutException as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return _make_error_observation(url, "timeout", str(exc), elapsed_ms)
        except httpx.ConnectError as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            text = str(exc).lower()
            error_type = "tls_error" if any(marker in text for marker in ["ssl", "tls", "certificate", "cert"]) else "connect_error"
            return _make_error_observation(url, error_type, str(exc), elapsed_ms)
        except httpx.InvalidURL as exc:
            return _make_error_observation(url, "invalid_url", str(exc), None)
        except httpx.HTTPError as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return _make_error_observation(url, "http_error", str(exc), elapsed_ms)
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            return _make_error_observation(url, "probe_error", str(exc), elapsed_ms)

    body = _safe_text(response)
    headers = dict(response.headers)
    title = extract_title(body)
    redirect_meta = _redirect_metadata(url, response)
    blocked, challenged, block_reasons = is_blocked_or_challenged(response.status_code, headers, body)
    tech, is_cdn, waf_name = _tech_hints(response, body)
    content_type = _header_value(headers, "content-type")
    server = _header_value(headers, "server")
    final_url = redirect_meta["final_url"]
    final = urlparse(final_url)
    original = urlparse(url)

    return {
        "module_name": MODULE_NAME,
        "input_host": original.netloc,
        "original_url": url,
        "url": url,
        "final_url": final_url,
        "scheme": final.scheme or original.scheme,
        "original_scheme": original.scheme,
        "final_host": final.netloc,
        "status": _observation_status(response.status_code, blocked, challenged),
        "status_code": response.status_code,
        "title": title,
        "content_type": content_type,
        "content_length": _content_length(response, body),
        "body_hash": body_hash(body),
        "response_time_ms": response_time_ms,
        "redirect_chain": redirect_meta["redirect_chain"],
        "redirect_count": redirect_meta["redirect_count"],
        "cross_domain_redirect": redirect_meta["cross_domain_redirect"],
        "http_to_https_upgrade": redirect_meta["http_to_https_upgrade"],
        "https_to_http_downgrade": redirect_meta["https_to_http_downgrade"],
        "redirect_loop": redirect_meta["redirect_loop"],
        "too_many_redirects": redirect_meta["too_many_redirects"],
        "server": server,
        "tech": tech,
        "is_cdn": is_cdn,
        "is_waf": is_cdn or blocked or challenged,
        "waf_name": waf_name,
        "blocked": blocked,
        "challenged": challenged,
        "blocked_or_challenge_indicators": block_reasons,
        "tls_error": False,
        "probe_error": "",
        "probe_error_detail": "",
        "page_type": _classify_page(final_url or url, body),
        "request_summary": summarize_request(method=request_method, url=url, headers=request_headers),
        "response_summary": _response_summary(response, body, response_time_ms),
    }


def _is_alive_observation(observation: dict) -> bool:
    status_code = observation.get("status_code")
    return isinstance(status_code, int) and 100 <= status_code < 600 and not observation.get("probe_error")


def _prefer_observation(current: dict | None, candidate: dict) -> dict:
    if not current:
        return candidate
    current_original = current.get("original_url", "")
    candidate_original = candidate.get("original_url", "")
    if candidate_original.startswith("https://") and current_original.startswith("http://"):
        return candidate
    if candidate.get("status_code") == 200 and current.get("status_code") != 200:
        return candidate
    if candidate.get("status") == "recon" and current.get("status") != "recon":
        return candidate
    return current


def _new_telemetry(total_hosts: int, total_urls: int) -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "total_hosts_input": total_hosts,
        "total_urls_probed": total_urls,
        "alive_count": 0,
        "dead_count": 0,
        "https_success_count": 0,
        "http_success_count": 0,
        "redirect_count": 0,
        "blocked_or_challenge_count": 0,
        "timeout_count": 0,
        "tls_error_count": 0,
        "average_response_time_ms": 0,
        "status_code_distribution": {},
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _update_telemetry(telemetry: dict, observations: list[dict], alive_count: int) -> dict:
    status_counter = Counter()
    response_times = []
    timeout_count = 0
    tls_error_count = 0
    redirects = 0
    blocked_count = 0
    https_success = 0
    http_success = 0

    for observation in observations:
        status_code = observation.get("status_code")
        if status_code is not None:
            status_counter[str(status_code)] += 1
        if observation.get("probe_error") == "timeout":
            timeout_count += 1
        if observation.get("tls_error"):
            tls_error_count += 1
        if observation.get("redirect_count", 0):
            redirects += 1
        if observation.get("blocked") or observation.get("challenged"):
            blocked_count += 1
        elapsed = observation.get("response_time_ms")
        if isinstance(elapsed, int):
            response_times.append(elapsed)
        if _is_alive_observation(observation):
            if observation.get("scheme") == "https":
                https_success += 1
            elif observation.get("scheme") == "http":
                http_success += 1

    telemetry["alive_count"] = alive_count
    telemetry["dead_count"] = max(0, telemetry["total_hosts_input"] - alive_count)
    telemetry["https_success_count"] = https_success
    telemetry["http_success_count"] = http_success
    telemetry["redirect_count"] = redirects
    telemetry["blocked_or_challenge_count"] = blocked_count
    telemetry["timeout_count"] = timeout_count
    telemetry["tls_error_count"] = tls_error_count
    telemetry["average_response_time_ms"] = int(sum(response_times) / len(response_times)) if response_times else 0
    telemetry["status_code_distribution"] = dict(status_counter)
    telemetry["module_noise_score"] = round(min(1.0, blocked_count / max(1, telemetry["total_urls_probed"])), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _valid_subdomain(value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or any(char.isspace() for char in value):
        return False
    parsed = urlparse(value if "://" in value else f"http://{value}")
    host = parsed.hostname or ""
    return bool(host and re.match(r"^[A-Za-z0-9.-]+$", host))


def _urls_for_subdomain(subdomain: str) -> list[str]:
    if subdomain.startswith(("http://", "https://")):
        parsed = urlparse(subdomain)
        host = parsed.netloc or parsed.path
    else:
        host = subdomain
    return [f"https://{host}", f"http://{host}"]


async def check_alive(domain: str, subdomains: list[str], callback=None) -> list[dict]:
    if callback:
        await callback("alive", "running", f"Probing {len(subdomains)} subdomains...")

    valid_subdomains = [sub.strip() for sub in subdomains if _valid_subdomain(sub)]
    invalid_subdomains = [str(sub) for sub in subdomains if not _valid_subdomain(sub)]

    semaphore = asyncio.Semaphore(CONCURRENCY)
    urls = []
    for subdomain in valid_subdomains:
        urls.extend(_urls_for_subdomain(subdomain))

    telemetry = _new_telemetry(len(subdomains), len(urls))
    log.info(f"[alive] Probing {len(urls)} URLs ({len(subdomains)} subdomains)...")

    observations: list[dict] = []
    async with get_client(
        verify=False,
        limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=20),
        headers=PROBE_HEADERS,
    ) as client:
        tasks = [_probe_url(client, url, domain, semaphore) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict):
            observations.append(result)
        elif isinstance(result, Exception):
            observations.append(_make_error_observation("", "probe_error", str(result), None))

    for invalid in invalid_subdomains:
        observations.append(_make_error_observation(invalid, "invalid_host", "Input host was invalid", None))

    seen: dict[str, dict] = {}
    host_observations: dict[str, list[dict]] = {}
    for observation in observations:
        original = observation.get("original_url") or observation.get("url") or ""
        parsed = urlparse(original if "://" in original else f"http://{original}")
        subdomain = parsed.netloc or parsed.path
        if not _is_alive_observation(observation):
            host_observations.setdefault(subdomain, []).append(observation)
            continue
        host_observations.setdefault(subdomain, []).append(observation)
        seen[subdomain] = _prefer_observation(seen.get(subdomain), observation)

    alive = []
    for subdomain, info in seen.items():
        host_obs = host_observations.get(subdomain, [])
        host_entry = {
            "subdomain": subdomain,
            "input_host": subdomain,
            "url": info["original_url"],
            "final_url": info["final_url"],
            "scheme": info["scheme"],
            "status": info["status_code"],
            "status_code": info["status_code"],
            "title": info["title"],
            "content_type": info["content_type"],
            "content_length": info["content_length"],
            "body_hash": info["body_hash"],
            "response_time": info["response_time_ms"],
            "response_time_ms": info["response_time_ms"],
            "redirect_chain": info["redirect_chain"],
            "redirect_count": info.get("redirect_count", 0),
            "final_host": info["final_host"],
            "cross_domain_redirect": info["cross_domain_redirect"],
            "http_to_https_upgrade": info["http_to_https_upgrade"],
            "https_to_http_downgrade": info["https_to_http_downgrade"],
            "redirect_loop": info["redirect_loop"],
            "too_many_redirects": info["too_many_redirects"],
            "server": info["server"],
            "tech": info.get("tech", []),
            "is_cdn": info.get("is_cdn", False),
            "is_waf": info.get("is_waf", False),
            "waf_name": info.get("waf_name", ""),
            "blocked": info.get("blocked", False),
            "challenged": info.get("challenged", False),
            "blocked_or_challenge_indicators": info.get("blocked_or_challenge_indicators", []),
            "tls_error": info.get("tls_error", False),
            "probe_error": info.get("probe_error", ""),
            "page_type": info.get("page_type", ""),
            "request_summary": info.get("request_summary", {}),
            "response_summary": info.get("response_summary", {}),
            "http_observations": host_obs,
            "alive_status": info.get("status", "recon"),
            "ports": [],
            "endpoints": [],
            "vulns": [],
        }
        alive.append(host_entry)

    telemetry = _update_telemetry(telemetry, observations, len(alive))
    for host in alive:
        host["alive_telemetry"] = telemetry

    log.info(f"[alive] Found {len(alive)} alive hosts out of {len(subdomains)} subdomains")

    if callback:
        await callback("alive", "done", f"Found {len(alive)} alive hosts")

    return alive

