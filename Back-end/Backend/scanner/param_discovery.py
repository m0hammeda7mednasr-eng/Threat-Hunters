from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from .proxy_manager import get_client
from .utils import check_tool, log


MODULE_NAME = "param_discovery"
PARAM_WORDLIST = [
    "id", "page", "search", "q", "query", "url", "uri", "file", "path", "dir",
    "cat", "category", "name", "user", "username", "email", "token", "key",
    "api", "api_key", "apikey", "auth", "access_token", "secret", "password",
    "callback", "jsonp", "redirect", "return", "next", "ref", "referrer",
    "lang", "language", "locale", "format", "output", "type", "action",
    "method", "view", "template", "theme", "module", "func", "function",
    "cmd", "command", "exec", "execute", "data", "content", "body", "text",
    "msg", "message", "code", "hash", "debug", "test", "sort", "order",
    "limit", "offset", "start", "end", "from", "to", "date", "time",
    "year", "month", "day", "filter", "include", "exclude", "target",
    "source", "dest", "destination", "host", "port", "ip", "address",
    "proxy", "server", "service", "endpoint", "base", "base_url",
    "admin", "mode", "config", "settings", "option", "value", "param",
    "report", "log", "info", "status", "state", "version", "v",
    "tab", "section", "step", "stage", "role", "group", "scope",
    "grant_type", "response_type", "client_id", "redirect_uri", "site",
    "shop", "store", "product", "item", "order", "invoice", "ticket",
    "issue", "project", "webhook", "event", "notification", "session",
    "cookie", "image", "attachment", "upload", "download", "export",
    "import", "backup", "restore", "cache", "size", "sort_by",
]

STATIC_PARAM_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".css", ".woff", ".woff2", ".ttf",
    ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".mp4",
)


def _limits(scan_config: dict | None) -> dict:
    limits = scan_config.get("limits", {}) if isinstance(scan_config, dict) else {}
    return limits if isinstance(limits, dict) else {}


def _max_urls(scan_config: dict | None, profile: str) -> int:
    limits = _limits(scan_config)
    try:
        max_requests = int(limits.get("max_requests") or 0)
    except (TypeError, ValueError):
        max_requests = 0
    default = 60 if profile == "deep" else 20
    if max_requests <= 0:
        return default
    return max(5, min(default, max_requests // max(1, len(PARAM_WORDLIST) // 50)))


def _timeout(scan_config: dict | None) -> float:
    try:
        return float(_limits(scan_config).get("timeout_seconds") or 8)
    except (TypeError, ValueError):
        return 8.0


def _concurrency(scan_config: dict | None) -> int:
    try:
        return max(1, min(20, int(_limits(scan_config).get("concurrency") or 8)))
    except (TypeError, ValueError):
        return 8


def _candidate_urls(alive_hosts: list[dict], max_urls: int) -> list[str]:
    seen = set()
    candidates = []
    for host in alive_hosts:
        for field in ("extracted_urls", "endpoints"):
            for url in host.get(field, []) or []:
                parsed = urlparse(str(url))
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    continue
                if parsed.path.lower().endswith(STATIC_PARAM_EXTENSIONS):
                    continue
                clean = urlunparse(parsed._replace(fragment=""))
                key = clean.rstrip("/")
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(clean)
                if len(candidates) >= max_urls:
                    return candidates
    return candidates


async def _run_arjun(url: str, timeout: float) -> list[str]:
    if not check_tool("arjun"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "arjun", "-u", url, "-oT", "-", "--stable",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max(30.0, timeout * 4))
        found = []
        for line in stdout.decode(errors="replace").splitlines():
            marker = "Parameter found:"
            if marker in line:
                param = line.split(marker, 1)[1].strip().split()[0]
                if param:
                    found.append(param)
        return sorted(set(found))
    except Exception as exc:
        log.debug(f"[param_discovery] arjun failed for {url}: {exc}")
        return []


def _with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    current = parse_qs(parsed.query, keep_blank_values=True)
    merged = {key: values[-1] if values else "" for key, values in current.items()}
    merged.update(params)
    return urlunparse(parsed._replace(query=urlencode(merged, doseq=True)))


async def _probe_batch(
    client: httpx.AsyncClient,
    url: str,
    params_batch: list[str],
    baseline_len: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> list[str]:
    async with semaphore:
        try:
            test_params = {param: "dr4g0n_t3st_xyz" for param in params_batch}
            response = await client.get(_with_params(url, test_params), timeout=timeout)
            if abs(len(response.text) - baseline_len) > 80:
                return params_batch
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            return []
        except Exception as exc:
            log.debug(f"[param_discovery] batch probe error: {exc}")
    return []


async def _discover_for_url(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> list[str]:
    arjun_params = await _run_arjun(url, timeout)
    if arjun_params:
        return arjun_params

    try:
        baseline = await client.get(url, timeout=timeout)
        baseline_len = len(baseline.text)
    except Exception:
        return []

    chunk_size = 50
    batches = [PARAM_WORDLIST[index:index + chunk_size] for index in range(0, len(PARAM_WORDLIST), chunk_size)]
    batch_results = await asyncio.gather(
        *[_probe_batch(client, url, batch, baseline_len, timeout, semaphore) for batch in batches],
        return_exceptions=True,
    )

    suspicious = sorted({param for result in batch_results if isinstance(result, list) for param in result})
    found = []
    for param in suspicious:
        async with semaphore:
            try:
                response = await client.get(_with_params(url, {param: "dr4g0n_t3st_xyz"}), timeout=timeout)
                if abs(len(response.text) - baseline_len) > 80:
                    found.append(param)
            except Exception:
                continue
    return sorted(set(found))


async def run_param_discovery(
    alive_hosts: list[dict],
    *,
    profile: str = "light",
    scan_config: dict | None = None,
    callback=None,
) -> list[dict]:
    candidates = _candidate_urls(alive_hosts, _max_urls(scan_config, profile))
    if not candidates:
        if callback:
            await callback("param_discovery", "done", "No candidate URLs for parameter discovery")
        return alive_hosts

    if callback:
        await callback("param_discovery", "running", f"Probing {len(candidates)} URLs for hidden parameters")
    log.info(f"[param_discovery] Probing {len(candidates)} URLs for hidden parameters...")

    timeout = _timeout(scan_config)
    semaphore = asyncio.Semaphore(_concurrency(scan_config))
    total_params = 0
    async with get_client(
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 Dragon-Recon/2.0"},
        follow_redirects=True,
    ) as client:
        results = await asyncio.gather(
            *[_discover_for_url(client, url, timeout, semaphore) for url in candidates],
            return_exceptions=True,
        )

    for url, result in zip(candidates, results):
        if not isinstance(result, list) or not result:
            continue
        total_params += len(result)
        for host in alive_hosts:
            base_urls = host.get("expanded_urls", [host.get("url", "")])
            if not any(url.startswith(base.rstrip("/") if base else "") for base in base_urls):
                continue
            host.setdefault("discovered_params", [])
            for param in result:
                parameterized_url = _with_params(url, {param: "FUZZ"})
                if parameterized_url not in host.get("extracted_urls", []):
                    host.setdefault("extracted_urls", []).append(parameterized_url)
                if parameterized_url not in host.get("endpoints", []):
                    host.setdefault("endpoints", []).append(parameterized_url)
                host["discovered_params"].append({"url": url, "param": param})
            break

    log.info(f"[param_discovery] Complete. Found {total_params} hidden parameters.")
    if callback:
        await callback("param_discovery", "done", f"Parameter discovery found {total_params} hidden params")
    return alive_hosts
