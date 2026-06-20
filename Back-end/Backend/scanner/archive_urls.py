from __future__ import annotations

import asyncio
import time
from urllib.parse import parse_qs, unquote_plus, urlparse

import httpx

from .utils import check_tool, get_tool_path, log
from .scanner_types import utc_now


MODULE_NAME = "archive_cdx"
MAX_ARCHIVE_URLS = 800
UNSAFE_ARCHIVE_MARKERS = (
    " union ",
    " union+",
    "union all select",
    "information_schema",
    "xp_cmdshell",
    "<script",
    "%3cscript",
    "../",
    "..%2f",
    "etc/passwd",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    "drop table",
    " or 1=1",
    " and 1=1",
)


def _new_telemetry() -> dict:
    return {
        "module_name": MODULE_NAME,
        "started_at": utc_now(),
        "completed_at": "",
        "source": "",
        "tool_used": "",
        "archive_urls_seen": 0,
        "archive_urls_in_scope": 0,
        "parameters_extracted": 0,
        "skipped_unsafe_urls": 0,
        "errors_count": 0,
        "timeout_count": 0,
    }


def _finish_telemetry(telemetry: dict, started: float) -> dict:
    telemetry["duration_seconds"] = round(max(0.001, time.monotonic() - started), 3)
    telemetry["completed_at"] = utc_now()
    return telemetry


def _host_key(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or parsed.netloc or "").lower().lstrip("www.")
    except Exception:
        return ""


def _same_origin(url: str, allowed_host: str) -> bool:
    host = _host_key(url)
    return bool(host and allowed_host and host == allowed_host)


def _clean_archive_url(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return parsed._replace(fragment="").geturl()


def _unsafe_archive_url_reason(url: str) -> str:
    decoded = unquote_plus(str(url or "")).lower()
    for marker in UNSAFE_ARCHIVE_MARKERS:
        if marker in decoded:
            return f"historical_attack_payload_marker:{marker.strip()}"
    return ""


async def _run_gau(host: str, telemetry: dict) -> list[str]:
    cmd = [get_tool_path("gau"), host, "--threads", "5"]
    telemetry["source"] = "gau"
    telemetry["tool_used"] = "gau"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        return [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]
    except asyncio.TimeoutError:
        telemetry["timeout_count"] += 1
    except Exception as exc:
        telemetry["errors_count"] += 1
        log.debug(f"[archive_cdx] gau failed for {host}: {exc}")
    return []


async def _run_wayback_cdx(host: str, telemetry: dict) -> list[str]:
    telemetry["source"] = "wayback_cdx"
    telemetry["tool_used"] = "internal_cdx"
    params = {
        "url": f"{host}/*",
        "collapse": "urlkey",
        "output": "text",
        "fl": "original",
        "limit": str(MAX_ARCHIVE_URLS),
    }
    for attempt in range(2):
        try:
            timeout = httpx.Timeout(45.0, connect=10.0)
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                response = await client.get("https://web.archive.org/cdx/search/cdx", params=params)
            if response.status_code != 200:
                telemetry["errors_count"] += 1
                telemetry["last_error"] = f"wayback_cdx_http_{response.status_code}"
                if response.status_code in {429, 500, 502, 503, 504} and attempt == 0:
                    await asyncio.sleep(1.5)
                    continue
                return []
            telemetry["last_error"] = ""
            return [line.strip() for line in response.text.splitlines() if line.strip()]
        except httpx.TimeoutException:
            telemetry["timeout_count"] += 1
            telemetry["last_error"] = "wayback_cdx_timeout"
        except httpx.RequestError:
            telemetry["errors_count"] += 1
            telemetry["last_error"] = "wayback_cdx_request_error"
        if attempt == 0:
            await asyncio.sleep(1.0)
    return []


async def run_archive_url_collection(alive_hosts: list[dict], callback=None) -> list[dict]:
    if not alive_hosts:
        return []

    if callback:
        await callback("archive_cdx", "running", "Collecting archived in-scope URLs")

    semaphore = asyncio.Semaphore(2)

    async def _collect_for_host(host: dict) -> None:
        started = time.monotonic()
        telemetry = _new_telemetry()
        base_url = host.get("url") or host.get("final_url") or host.get("subdomain") or ""
        allowed_host = _host_key(base_url)
        if not allowed_host:
            host["archive_urls"] = []
            host["archive_telemetry"] = _finish_telemetry(telemetry, started)
            return

        async with semaphore:
            raw_urls = await _run_gau(allowed_host, telemetry) if check_tool("gau") else []
            if not raw_urls:
                raw_urls = await _run_wayback_cdx(allowed_host, telemetry)

        telemetry["archive_urls_seen"] = len(raw_urls)
        in_scope: list[str] = []
        seen = set()
        for item in raw_urls:
            clean = _clean_archive_url(item)
            if not clean or clean in seen or not _same_origin(clean, allowed_host):
                continue
            unsafe_reason = _unsafe_archive_url_reason(clean)
            if unsafe_reason:
                telemetry["skipped_unsafe_urls"] += 1
                continue
            seen.add(clean)
            in_scope.append(clean)
            if len(in_scope) >= MAX_ARCHIVE_URLS:
                break

        telemetry["archive_urls_in_scope"] = len(in_scope)
        telemetry["parameters_extracted"] = len({
            key
            for url in in_scope
            for key in parse_qs(urlparse(url).query, keep_blank_values=True)
            if key
        })
        host["archive_urls"] = sorted(in_scope)
        host["extracted_urls"] = sorted(set(host.get("extracted_urls", [])) | set(in_scope))
        host["endpoints"] = sorted(set(host.get("endpoints", [])) | set(in_scope))
        host["archive_telemetry"] = _finish_telemetry(telemetry, started)

    await asyncio.gather(*(_collect_for_host(host) for host in alive_hosts), return_exceptions=True)

    total = sum(len(host.get("archive_urls", [])) for host in alive_hosts)
    log.info(f"[archive_cdx] Complete. Collected {total} in-scope archived URL(s).")
    if callback:
        await callback("archive_cdx", "done", f"Collected {total} archived in-scope URL(s)")
    return alive_hosts
