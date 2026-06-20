from __future__ import annotations

import asyncio
import os
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse

import httpx

from .utils import check_tool, get_tool_path, log


BASE_HEADERS = {"User-Agent": "Mozilla/5.0 Dragon-Recon/2.0"}
GROUPED_NAVIGATION_PARAMS = {"returl"}
GROUPED_NAVIGATION_PATHS = {"/login.asp", "/register.asp"}
STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar",
    ".txt", ".log", ".map",
}


class _EndpointHTMLParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.assets: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_map = {str(k).lower(): str(v or "") for k, v in attrs}
        tag = tag.lower()
        if tag in {"a", "area"} and attrs_map.get("href"):
            self.links.append(attrs_map["href"])
        elif tag in {"script", "iframe"} and attrs_map.get("src"):
            self.links.append(attrs_map["src"])
            if tag == "script":
                self.assets.append(attrs_map["src"])
        elif tag == "link" and attrs_map.get("href"):
            self.assets.append(attrs_map["href"])
        elif tag == "form":
            self._current_form = {
                "action": attrs_map.get("action") or self.base_url,
                "method": (attrs_map.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in {"input", "select", "textarea", "button"} and self._current_form is not None:
            name = attrs_map.get("name") or attrs_map.get("id") or ""
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": attrs_map.get("type") or tag,
                    "value": attrs_map.get("value") or "",
                })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _same_origin_url(candidate: str, base_url: str, origin: str) -> str:
    candidate = str(candidate or "").strip()
    if not candidate or candidate.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return ""
    joined = urljoin(base_url, candidate)
    joined, _fragment = urldefrag(joined)
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != origin.lower():
        return ""
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def _is_static_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _get_form_query_url(action_url: str, inputs: list[dict]) -> str:
    parsed = urlparse(action_url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    existing_names = {name for name, _value in existing}
    added = [
        (field["name"], field.get("value", ""))
        for field in inputs
        if field.get("name") and field["name"] not in existing_names
    ]
    if not added:
        return action_url
    return urlunparse(parsed._replace(query=urlencode([*existing, *added], doseq=True)))


def _canonical_live_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.path.lower() in GROUPED_NAVIGATION_PATHS:
        kept_query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.strip().lower() not in GROUPED_NAVIGATION_PARAMS
        ]
        return urlunparse(parsed._replace(query=urlencode(kept_query, doseq=True), fragment="")).rstrip("?")
    return url


def _form_signature(form: dict) -> tuple:
    action = _canonical_live_url(str(form.get("action") or ""))
    parsed = urlparse(action)
    action_path = (parsed.path or "/").lower().rstrip("/") or "/"
    inputs = tuple(sorted(
        (
            str(field.get("name") or "").strip().lower(),
            str(field.get("type") or field.get("tag") or "text").strip().lower(),
        )
        for field in form.get("inputs", [])
        if field.get("name")
    ))
    return action_path, str(form.get("method") or "GET").upper(), inputs


def _dedupe_forms(forms: list[dict]) -> list[dict]:
    grouped: dict[tuple, dict] = {}
    for form in forms:
        if not isinstance(form, dict):
            continue
        original_action = str(form.get("action") or "")
        canonical_action = _canonical_live_url(original_action)
        normalized = dict(form)
        normalized["action"] = canonical_action
        normalized["method"] = str(normalized.get("method") or "GET").upper()
        key = _form_signature(normalized)
        example = {
            "page_url": form.get("page_url", ""),
            "action": original_action,
        }
        if key not in grouped:
            normalized["examples_count"] = 1
            normalized["examples"] = [example]
            normalized["grouped_action_path"] = urlparse(canonical_action).path or "/"
            grouped[key] = normalized
            continue
        current = grouped[key]
        current["examples_count"] = int(current.get("examples_count") or 1) + 1
        examples = current.setdefault("examples", [])
        if example not in examples and len(examples) < 10:
            examples.append(example)
    return sorted(grouped.values(), key=lambda item: (urlparse(item.get("action", "")).path, item.get("method", "")))


async def _fetch_html(client: httpx.AsyncClient, url: str) -> tuple[str, str]:
    try:
        response = await client.get(url, timeout=12.0, follow_redirects=True)
    except httpx.RequestError as exc:
        log.debug(f"[extraction] built-in crawl fetch failed for {url}: {exc}")
        return "", ""
    content_type = response.headers.get("content-type", "").lower()
    body_head = response.text[:600].lower()
    if response.status_code >= 400 or ("html" not in content_type and "<html" not in body_head):
        return "", ""
    return str(response.url), response.text[:200000]


async def _builtin_same_origin_crawl(start_url: str, profile: str) -> dict:
    parsed_start = urlparse(start_url)
    if parsed_start.scheme not in {"http", "https"} or not parsed_start.netloc:
        return {"urls": [], "js_files": [], "forms": []}

    max_pages = 30 if profile == "deep" else 12
    max_depth = 2 if profile == "deep" else 1
    origin = parsed_start.netloc.lower()
    root_url = urlunparse((parsed_start.scheme.lower(), origin, parsed_start.path or "/", "", parsed_start.query, ""))
    queue: list[tuple[str, int]] = [(root_url, 0)]
    seen_pages: set[str] = set()
    queued_urls: set[str] = {root_url}
    endpoints: set[str] = {root_url}
    js_files: set[str] = set()
    forms: list[dict] = []

    async with httpx.AsyncClient(verify=False, headers=BASE_HEADERS) as client:
        while queue and len(seen_pages) < max_pages:
            page_url, depth = queue.pop(0)
            if page_url in seen_pages or _is_static_url(page_url):
                continue
            seen_pages.add(page_url)

            final_url, body = await _fetch_html(client, page_url)
            if not body:
                continue
            if final_url:
                endpoints.add(final_url)

            parser = _EndpointHTMLParser(final_url or page_url)
            try:
                parser.feed(body)
            except Exception as exc:
                log.debug(f"[extraction] HTML parse issue for {page_url}: {exc}")

            discovered: list[str] = []
            for raw_url in [*parser.links, *parser.assets]:
                normalized = _same_origin_url(raw_url, final_url or page_url, origin)
                if not normalized:
                    continue
                if _is_static_url(normalized):
                    if urlparse(normalized).path.lower().endswith(".js"):
                        js_files.add(normalized)
                    continue
                endpoints.add(normalized)
                discovered.append(normalized)

            for form in parser.forms:
                action = _same_origin_url(form.get("action", ""), final_url or page_url, origin)
                if not action:
                    continue
                canonical_action = _canonical_live_url(action)
                method = str(form.get("method") or "GET").upper()
                form_record = {
                    "page_url": final_url or page_url,
                    "action": canonical_action,
                    "method": method,
                    "inputs": form.get("inputs", []),
                    "examples_count": 1,
                    "examples": [{"page_url": final_url or page_url, "action": action}],
                }
                forms.append(form_record)
                endpoints.add(canonical_action)
                if method == "GET":
                    endpoints.add(_get_form_query_url(canonical_action, form_record["inputs"]))

            if depth < max_depth:
                for next_url in discovered:
                    if next_url not in seen_pages and next_url not in queued_urls:
                        queued_urls.add(next_url)
                        queue.append((next_url, depth + 1))

    return {
        "urls": sorted(endpoints),
        "js_files": sorted(js_files),
        "forms": forms[:50],
    }


async def _run_katana(url: str, profile: str) -> list[str]:
    cmd = [
        get_tool_path("katana"),
        "-u", url,
        "-nc",
    ]
    if profile == "deep":
        cmd.extend(["-d", "3", "-c", "20"])
    else:
        cmd.extend(["-d", "2", "-c", "10"])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode(errors="replace").strip()
        return [line.strip() for line in output.splitlines() if line.strip().startswith("http")]
    except Exception as e:
        log.error(f"[extraction] katana error for {url}: {e}")
        return []


async def _run_gau(url: str) -> list[str]:
    cmd = [
        get_tool_path("gau"),
        url,
        "--threads", "5",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        output = stdout.decode(errors="replace").strip()
        return [line.strip() for line in output.splitlines() if line.strip()]
    except Exception as e:
        log.error(f"[extraction] gau error for {url}: {e}")
        return []


async def _run_archive_cdx(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return []

        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{host}/*",
            "collapse": "urlkey",
            "output": "text",
            "fl": "original",
            "limit": "2000",
        }

        async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
            resp = await client.get(cdx_url, params=params)
            if resp.status_code == 200:
                return [line.strip() for line in resp.text.splitlines() if line.strip() and line.startswith("http")]
            return []
    except Exception:
        return []


async def run_extraction(alive_hosts: list[dict], profile: str = "light", callback=None) -> list[dict]:
    has_katana = check_tool("katana")
    historical_urls_enabled = str(os.environ.get("RECONTOOL_ENABLE_HISTORICAL_URLS", "")).strip().lower() in {
        "1", "true", "yes", "on",
    }
    has_gau = check_tool("gau") if historical_urls_enabled else False

    if not has_katana and not has_gau:
        log.info("[extraction] External tools unavailable; using built-in same-origin crawler.")
        if callback:
            await callback("extraction", "running", "External tools unavailable; using built-in same-origin crawler.")
    if not historical_urls_enabled:
        log.info("[extraction] Historical URL sources disabled for V1 default scan modes.")

    if callback:
        await callback("extraction", "running", f"Running web extraction on {len(alive_hosts)} hosts...")

    semaphore = asyncio.Semaphore(3)

    async def _extract_one(host_info: dict) -> None:
        async with semaphore:
            urls_to_scan = host_info.get("expanded_urls", [host_info.get("url")])
            all_urls = set()
            all_forms: list[dict] = []

            for base_url in urls_to_scan:
                if not base_url:
                    continue
                url = base_url.rstrip("/") or base_url

                builtin_result = await _builtin_same_origin_crawl(url, profile)
                all_urls.update(builtin_result.get("urls", []))
                all_forms.extend(builtin_result.get("forms", []))

                tasks = []
                if has_katana:
                    tasks.append(_run_katana(url, profile))
                if has_gau:
                    tasks.append(_run_gau(url))
                if historical_urls_enabled:
                    tasks.append(_run_archive_cdx(url))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, list):
                        all_urls.update(res)

            js_files = set()
            extracted_urls = set()

            origin_url = next((item for item in urls_to_scan if item), host_info.get("url", ""))
            origin = urlparse(origin_url).netloc.lower()
            for u in all_urls:
                if not isinstance(u, str) or not u.startswith("http"):
                    continue
                normalized = _same_origin_url(u, origin_url, origin)
                if not normalized:
                    continue
                normalized = _canonical_live_url(normalized)
                parsed = urlparse(normalized)
                if parsed.path.lower().endswith(".js"):
                    js_files.add(normalized)
                elif _is_static_url(normalized):
                    continue
                else:
                    extracted_urls.add(normalized)

            host_info["extracted_urls"] = sorted(extracted_urls)
            host_info["endpoints"] = sorted(set(host_info.get("endpoints", [])) | extracted_urls)
            host_info["js_files"] = sorted(js_files)
            host_info["forms"] = _dedupe_forms(all_forms)
            host_info["historical_urls_enabled"] = historical_urls_enabled

            total_found = len(host_info["extracted_urls"]) + len(host_info["js_files"])
            if total_found > 0:
                log.info(
                    f"[extraction] {host_info.get('subdomain', host_info.get('url', 'host'))} "
                    f"-> discovered {total_found} URLs ({len(js_files)} JS files), "
                    f"{len(host_info['forms'])} unique forms from {len(all_forms)} observations"
                )

    tasks = [_extract_one(h) for h in alive_hosts]
    await asyncio.gather(*tasks, return_exceptions=True)

    total_urls = sum(len(h.get("extracted_urls", [])) + len(h.get("js_files", [])) for h in alive_hosts)
    total_forms = sum(len(h.get("forms", [])) for h in alive_hosts)
    log.info(f"[extraction] Complete. Found {total_urls} items and {total_forms} forms total.")

    if callback:
        await callback("extraction", "done", f"Discovered {total_urls} URLs/JS files and {total_forms} forms across {len(alive_hosts)} hosts")

    return alive_hosts

