from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse, urlunparse

import httpx

from .findings import Finding, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import extract_title, is_blocked_or_challenged, response_fingerprint
from .scanner_types import EvidenceItem
from .utils import log


MODULE_NAME = "sensitive_files"
BASE_HEADERS = {"User-Agent": "Mozilla/5.0 Dragon-Recon/2.0"}
RANGE_HEADERS = {"Range": "bytes=0-8191"}
MAX_TEXT_BYTES = 8192

SENSITIVE_REGEX = re.compile(
    r"/(admin|config|backup|logs|uploads|tmp|var|wp-content|vendor|node_modules|\.git|\.svn)|"
    r"\.log$|\.sql$|\.env$|\.conf$|\.bak$|\.old$|\.backup$|\.swp$|\.txt$|\.json$|\.xml$|"
    r"\.yaml$|\.yml$|\.ini$|\.pem$|\.key$|\.cer$|\.crt$|\.pfx$|\.zip$|\.tar$|\.gz$|"
    r"\.7z$|\.rar$|\.tgz$|\.db$|\.sqlite$|\.sqlite3$|\.map$|\.rdp$|\.ppk$|\.sh$|\.bat$|"
    r"\.ps1$|\.php\.bak$|config$|settings$|secrets$|credentials$|password$|api_key$|database$|"
    r"dump$|\.htpasswd$|wp-config\.php$|web\.config$|package-lock\.json$|composer\.lock$",
    re.IGNORECASE,
)

STATIC_EXTS = {
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".ttf",
    ".eot",
}

ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}
BACKUP_EXTS = {".bak", ".old", ".backup", ".swp"}
DATABASE_EXTS = {".sql", ".db", ".sqlite", ".sqlite3"}
CONFIG_EXTS = {".conf", ".config", ".ini", ".yaml", ".yml", ".json", ".xml"}
SOURCE_MAP_EXTS = {".map"}
LOG_EXTS = {".log", ".txt"}

REFERENCE_URLS = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
]

SECRET_PATTERNS = [
    re.compile(
        r"(?im)^\s*([A-Z0-9_.-]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE[_-]?KEY|"
        r"CLIENT[_-]?SECRET|ACCESS[_-]?KEY|DATABASE_URL|DB_PASSWORD|AUTHORIZATION|COOKIE)[A-Z0-9_.-]*)"
        r"\s*(=|:|=>)\s*([^\s#;,]{4,})"
    ),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
]

ENV_KEY_RE = re.compile(
    r"(?im)^\s*[A-Z0-9_.-]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|DATABASE_URL|"
    r"DB_PASSWORD|APP_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)[A-Z0-9_.-]*\s*=\s*[^\s#]{4,}"
)
GIT_CONFIG_RE = re.compile(r"(?is)\[(core|remote\s+\"[^\"]+\"|branch\s+\"[^\"]+\")\].{0,120}")
SOURCE_MAP_RE = re.compile(r'"version"\s*:\s*\d+.*"sources"\s*:\s*\[.*"mappings"\s*:', re.IGNORECASE | re.DOTALL)
SQL_DUMP_RE = re.compile(
    r"(?is)(CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL dump|PostgreSQL database dump|SQLite format 3)"
)
LOG_RE = re.compile(r"(?im)^\s*(\[[^\]]+\]|\d{4}-\d{2}-\d{2}|ERROR|WARN|INFO|Traceback\b)")
CONFIG_RE = re.compile(
    r"(?im)^\s*(\[[a-z0-9_. -]+\]|[a-z0-9_.-]*(host|user|database|password|secret|token|key)"
    r"[a-z0-9_.-]*\s*[=:]\s*.+)"
)

GENERIC_ERROR_MARKERS = [
    "404 not found",
    "not found",
    "page not found",
    "the requested url was not found",
    "resource not found",
    "error 404",
    "server error",
    "an error occurred",
]
LOGIN_MARKERS = ["type=\"password\"", "name=\"password\"", "login", "sign in", "signin"]


def _header_value(headers: dict, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _path_for(url: str) -> str:
    return urlparse(url).path.lower()


def _extension_for(url: str) -> str:
    path = _path_for(url)
    for ext in [*ARCHIVE_EXTS, *BACKUP_EXTS, *DATABASE_EXTS, *SOURCE_MAP_EXTS, *CONFIG_EXTS, *LOG_EXTS]:
        if path.endswith(ext):
            return ext
    return ""


def _is_static_asset(url: str) -> bool:
    path = _path_for(url)
    return any(path.endswith(ext) for ext in STATIC_EXTS)


def _looks_sensitive_path(url: str) -> bool:
    return bool(SENSITIVE_REGEX.search(urlparse(url).path.lower()))


def _decode_text(response: httpx.Response) -> str:
    content = response.content[:MAX_TEXT_BYTES]
    if b"\x00" in content[:200]:
        return ""
    try:
        return content.decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _is_html(headers: dict, text: str) -> bool:
    content_type = _header_value(headers, "content-type").lower()
    lowered = (text or "")[:600].lower()
    return "text/html" in content_type or "<html" in lowered or "<!doctype html" in lowered


def _redact_sensitive_text(text: str) -> str:
    redacted = text or ""
    for pattern in SECRET_PATTERNS:
        def repl(match: re.Match) -> str:
            if len(match.groups()) >= 3:
                return f"{match.group(1)}{match.group(2)}<redacted>"
            return "<redacted-token>"

        redacted = pattern.sub(repl, redacted)
    redacted = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", redacted)
    redacted = re.sub(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+", r"\1: <redacted>", redacted)
    return redacted


def _snippet(text: str, *, marker: re.Pattern | None = None) -> str:
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    selected: list[str] = []
    if marker:
        for line in lines:
            if marker.search(line):
                selected.append(line)
            if len(selected) >= 4:
                break
    if not selected:
        selected = lines[:4]
    return _redact_sensitive_text("\n".join(selected))[:600]


def _binary_signature(body: bytes) -> str:
    if body.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if body.startswith(b"\x1f\x8b"):
        return "gzip"
    if body.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if body.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if body.startswith(b"SQLite format 3"):
        return "sqlite"
    return ""


def _is_archive_response(url: str, response: httpx.Response) -> tuple[bool, str]:
    content_type = _header_value(dict(response.headers), "content-type").lower()
    disposition = _header_value(dict(response.headers), "content-disposition").lower()
    signature = _binary_signature(response.content[:32])
    path = _path_for(url)
    archive_ext = any(path.endswith(ext) for ext in ARCHIVE_EXTS | BACKUP_EXTS)
    archive_type = any(token in content_type for token in ["zip", "gzip", "x-tar", "x-7z", "rar", "octet-stream"])
    downloadable = "attachment" in disposition
    if signature:
        return True, f"binary signature: {signature}"
    if archive_ext and (archive_type or downloadable):
        return True, f"content-type/download header: {content_type or disposition}"
    return False, ""


def _looks_like_login_page(text: str) -> bool:
    lower = (text or "")[:12000].lower()
    return any(marker in lower for marker in LOGIN_MARKERS) and "<form" in lower


def _is_robots_txt(url: str) -> bool:
    return _path_for(url).rstrip("/") == "/robots.txt"


def _has_strong_sensitive_content(text: str) -> bool:
    return bool(
        ENV_KEY_RE.search(text or "")
        or GIT_CONFIG_RE.search(text or "")
        or SQL_DUMP_RE.search(text or "")
        or CONFIG_RE.search(text or "")
        or any(pattern.search(text or "") for pattern in SECRET_PATTERNS)
    )


def _is_application_route(url: str) -> bool:
    path = _path_for(url).rstrip("/") or "/"
    if _extension_for(url):
        return False
    app_prefixes = ("/account/", "/search", "/profile/", "/checkout", "/cart", "/login", "/register")
    app_suffixes = ("/login", "/resetpassword", "/forgotpassword", "/register")
    return path.startswith(app_prefixes) or path.endswith(app_suffixes)


def _looks_like_generic_error(status_code: int, headers: dict, text: str) -> bool:
    if not _is_html(headers, text):
        return False
    lower = (text or "")[:12000].lower()
    title = extract_title(text).lower()
    return any(marker in lower or marker in title for marker in GENERIC_ERROR_MARKERS)


def _soft_404_probe_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/__recontool_soft_404_probe__.txt", "", "", ""))


async def _soft_404_baseline(client: httpx.AsyncClient, url: str, cache: dict[str, dict]) -> dict:
    parsed = urlparse(url)
    cache_key = f"{parsed.scheme}://{parsed.netloc}"
    if cache_key in cache:
        return cache[cache_key]

    probe_url = _soft_404_probe_url(url)
    try:
        response = await client.get(probe_url, headers=RANGE_HEADERS, timeout=5.0, follow_redirects=False)
        text = _decode_text(response)
        baseline = response_fingerprint(response.status_code, dict(response.headers), text)
    except httpx.RequestError:
        baseline = {}

    cache[cache_key] = baseline
    return baseline


def _is_soft_404(response: httpx.Response, text: str, baseline: dict) -> bool:
    headers = dict(response.headers)
    if response.status_code != 200:
        return False
    if _looks_like_generic_error(response.status_code, headers, text):
        return True
    if not baseline or baseline.get("status_code") not in {200, 404}:
        return False

    current = response_fingerprint(response.status_code, headers, text)
    if baseline.get("status_code") == 200 and current.get("body_hash") == baseline.get("body_hash"):
        return True
    if baseline.get("status_code") == 200 and current.get("title") and current.get("title") == baseline.get("title"):
        length_delta = abs(int(current.get("body_length") or 0) - int(baseline.get("body_length") or 0))
        return length_delta < 80
    return False


def _request_summary(url: str) -> dict:
    return summarize_request(method="GET", url=url, headers={**BASE_HEADERS, **RANGE_HEADERS})


def _response_summary(response: httpx.Response, text: str, *, binary: bool = False) -> dict:
    snippet = "<binary content>" if binary else _redact_sensitive_text(text[:500])
    body = response.content[:512] if binary else text
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=body,
        snippet=snippet,
    )


def _make_finding(
    *,
    url: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    response: httpx.Response,
    body_text: str = "",
    reason: str = "",
    binary: bool = False,
) -> dict:
    name = vuln_type.replace("_", " ").title()
    evidence_items = [
        EvidenceItem(
            type="text",
            value=evidence_text,
            location="response",
            comparison=reason,
        )
    ]
    reproduction_steps = [
        f"Send a GET request to {url} with redirects disabled.",
        "Review the response status, content type, and safe evidence snippet recorded in this finding.",
        "Do not download or process the full file unless you own or are authorized to test the target.",
    ]
    if status == "confirmed":
        reproduction_steps.append("Confirm that the response body or file signature matches the recorded sensitive-file evidence.")

    remediation = (
        "Remove the file from the web root, restrict direct access with server rules, and rotate any exposed secrets "
        "or credentials that may have been present."
    )

    return Finding(
        id=vuln_type,
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=url,
        method="GET",
        category="exposure",
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=evidence_items,
        request_summary=_request_summary(url),
        response_summary=_response_summary(response, body_text, binary=binary),
        remediation=remediation,
        references=REFERENCE_URLS,
        name=name,
        description=evidence_text,
        matched_at=url,
        raw={
            "classification_reason": reason,
            "content_type": _header_value(dict(response.headers), "content-type"),
            "content_length": _header_value(dict(response.headers), "content-length"),
        },
    ).to_dict()


def _classify_confirmed(url: str, response: httpx.Response, text: str) -> dict | None:
    body = response.content[:MAX_TEXT_BYTES]
    path = _path_for(url)
    headers = dict(response.headers)

    if (path.endswith(".env") or "/.env" in path) and ENV_KEY_RE.search(text):
        return _make_finding(
            url=url,
            vuln_type="exposed_env_file",
            status="confirmed",
            severity="high",
            confidence=0.95,
            evidence_text=f"Environment-style key/value secrets are visible:\n{_snippet(text, marker=ENV_KEY_RE)}",
            response=response,
            body_text=text,
            reason="env_key_signatures",
        )

    if "/.git/" in path and GIT_CONFIG_RE.search(text):
        return _make_finding(
            url=url,
            vuln_type="exposed_git_metadata",
            status="confirmed",
            severity="high",
            confidence=0.92,
            evidence_text=f"Git metadata content is accessible:\n{_snippet(text, marker=GIT_CONFIG_RE)}",
            response=response,
            body_text=text,
            reason="git_config_signature",
        )

    archive, archive_reason = _is_archive_response(url, response)
    if archive:
        return _make_finding(
            url=url,
            vuln_type="exposed_backup_file",
            status="confirmed",
            severity="high",
            confidence=0.88,
            evidence_text=f"Downloadable backup/archive evidence observed ({archive_reason}).",
            response=response,
            body_text="",
            reason=archive_reason,
            binary=True,
        )

    if path.endswith(tuple(DATABASE_EXTS)) and (SQL_DUMP_RE.search(text) or _binary_signature(body) == "sqlite"):
        return _make_finding(
            url=url,
            vuln_type="exposed_database_dump",
            status="confirmed",
            severity="high",
            confidence=0.9,
            evidence_text=f"Database dump indicators are present:\n{_snippet(text, marker=SQL_DUMP_RE)}",
            response=response,
            body_text=text,
            reason="database_dump_signature",
        )

    if path.endswith(tuple(SOURCE_MAP_EXTS)):
        source_map = False
        if SOURCE_MAP_RE.search(text):
            source_map = True
        else:
            try:
                parsed = json.loads(text)
                source_map = all(key in parsed for key in ("version", "sources", "mappings"))
            except (json.JSONDecodeError, TypeError):
                source_map = False
        if source_map:
            return _make_finding(
                url=url,
                vuln_type="exposed_source_map",
                status="confirmed",
                severity="medium",
                confidence=0.86,
                evidence_text=f"Source map JSON is accessible:\n{_snippet(text)}",
                response=response,
                body_text=text,
                reason="source_map_json_signature",
            )

    if path.endswith(tuple(LOG_EXTS)) and LOG_RE.search(text):
        has_secret = any(pattern.search(text) for pattern in SECRET_PATTERNS)
        return _make_finding(
            url=url,
            vuln_type="exposed_log_file",
            status="confirmed",
            severity="high" if has_secret else "medium",
            confidence=0.84 if has_secret else 0.76,
            evidence_text=f"Log-style content is accessible:\n{_snippet(text, marker=LOG_RE)}",
            response=response,
            body_text=text,
            reason="log_content_signature",
        )

    if (path.endswith(tuple(CONFIG_EXTS)) or "config" in path or "settings" in path) and CONFIG_RE.search(text):
        has_secret = any(pattern.search(text) for pattern in SECRET_PATTERNS)
        return _make_finding(
            url=url,
            vuln_type="exposed_config_file",
            status="confirmed",
            severity="high" if has_secret else "medium",
            confidence=0.88 if has_secret else 0.78,
            evidence_text=f"Configuration-style content is accessible:\n{_snippet(text, marker=CONFIG_RE)}",
            response=response,
            body_text=text,
            reason="config_content_signature",
        )

    return None


def _candidate_type_for(url: str) -> str:
    path = _path_for(url)
    if _is_robots_txt(url):
        return "robots_txt_discovered"
    if _is_application_route(url):
        return "app_route_recon"
    if path.endswith(".env") or "/.env" in path:
        return "exposed_env_file"
    if "/.git/" in path:
        return "exposed_git_metadata"
    if path.endswith(tuple(ARCHIVE_EXTS | BACKUP_EXTS)):
        return "exposed_backup_file"
    if path.endswith(tuple(DATABASE_EXTS)):
        return "exposed_database_dump"
    if path.endswith(tuple(SOURCE_MAP_EXTS)):
        return "exposed_source_map"
    if path.endswith(tuple(LOG_EXTS)):
        return "exposed_log_file"
    if path.endswith(tuple(CONFIG_EXTS)) or "config" in path or "settings" in path:
        return "exposed_config_file"
    if "admin" in path or "login" in path:
        return "exposed_sensitive_endpoint"
    return "sensitive_file_candidate"


def _candidate_finding(url: str, response: httpx.Response, text: str, *, reason: str, status: str = "candidate") -> dict:
    vuln_type = _candidate_type_for(url) if status != "blocked" else "sensitive_file_candidate"
    recon_types = {"robots_txt_discovered", "app_route_recon"}
    if vuln_type == "robots_txt_discovered" and status == "candidate":
        has_secret_material = ENV_KEY_RE.search(text or "") or any(pattern.search(text or "") for pattern in SECRET_PATTERNS)
        if not has_secret_material:
            status = "recon"
    elif vuln_type in recon_types and status == "candidate" and not _has_strong_sensitive_content(text):
        status = "recon"

    if vuln_type == "robots_txt_discovered":
        evidence = (
            f"robots.txt responded with status {response.status_code}; discovered disallowed path metadata, "
            f"not sensitive-file proof. Reason: {reason}."
        )
    elif vuln_type == "app_route_recon":
        evidence = (
            f"Application route responded with status {response.status_code}; no strong sensitive-file proof was present. "
            f"Reason: {reason}."
        )
    else:
        evidence = (
            f"Sensitive-looking path responded with status {response.status_code}, but the response did not contain "
            f"strong sensitive-file proof. Reason: {reason}."
        )
    if text and not _is_html(dict(response.headers), text):
        evidence += f"\nSafe snippet:\n{_snippet(text)}"

    severity = "low"
    confidence = 0.45 if status == "candidate" else 0.25
    if status == "recon":
        severity = "info"
        confidence = 0.35
    if status == "blocked":
        severity = "info"
        confidence = 0.3

    return _make_finding(
        url=url,
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence_text=evidence,
        response=response,
        body_text=text,
        reason=reason,
    )


async def _check_file(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    soft_404_cache: dict[str, dict],
) -> dict | None:
    async with semaphore:
        try:
            response = await client.get(url, headers=RANGE_HEADERS, timeout=5.0, follow_redirects=False)
        except httpx.RequestError:
            return None

    text = _decode_text(response)
    headers = dict(response.headers)
    blocked, challenged, reasons = is_blocked_or_challenged(response.status_code, headers, text)
    if blocked or challenged:
        return _candidate_finding(url, response, text, reason=", ".join(reasons), status="blocked")

    if response.status_code in {404, 410}:
        return None

    if 300 <= response.status_code < 400:
        location = _header_value(headers, "location")
        return _candidate_finding(url, response, text, reason=f"redirected to {location or 'unknown location'}", status="inconclusive")

    if response.status_code in {401, 403}:
        return _candidate_finding(url, response, text, reason="path exists but requires authentication", status="candidate")

    if response.status_code < 200 or response.status_code >= 500:
        return _candidate_finding(url, response, text, reason=f"unexpected status code {response.status_code}", status="inconclusive")

    baseline = await _soft_404_baseline(client, url, soft_404_cache)
    if _is_soft_404(response, text, baseline):
        return None

    confirmed = _classify_confirmed(url, response, text)
    if confirmed:
        return confirmed

    if _looks_like_login_page(text):
        return _candidate_finding(url, response, text, reason="login page observed at sensitive-looking path", status="candidate")

    if _is_html(headers, text) and _looks_like_generic_error(response.status_code, headers, text):
        return None

    if _looks_sensitive_path(url):
        return _candidate_finding(url, response, text, reason="path name is sensitive-looking but content proof is weak", status="candidate")

    return None


def _belongs_to_host(target_url: str, host: dict) -> bool:
    target_host = urlparse(target_url).netloc.lower()
    base_urls = [str(item) for item in host.get("expanded_urls", []) if item] or [str(host.get("url") or "")]
    for base in base_urls:
        if base and target_url.startswith(base):
            return True
        if target_host and urlparse(base).netloc.lower() == target_host:
            return True
    return False


async def run_sensitive_file_hunt(alive_hosts: list[dict], callback=None) -> list[dict]:
    if callback:
        await callback("sensitive_files", "running", "Hunting for exposed sensitive files/backups...")

    potential_urls = set()
    for host in alive_hosts:
        urls = host.get("extracted_urls", []) + host.get("endpoints", [])
        for url in urls:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                continue
            if _is_static_asset(url):
                continue
            if _looks_sensitive_path(url):
                potential_urls.add(url)

    if not potential_urls:
        log.info("[sensitive_files] No potential sensitive URLs found to probe.")
        return alive_hosts

    log.info(f"[sensitive_files] Found {len(potential_urls)} potential sensitive URLs. Probing...")

    semaphore = asyncio.Semaphore(20)
    soft_404_cache: dict[str, dict] = {}
    async with httpx.AsyncClient(verify=False, headers=BASE_HEADERS, follow_redirects=False) as client:
        tasks = [_check_file(client, url, semaphore, soft_404_cache) for url in sorted(potential_urls)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = [item for item in results if isinstance(item, dict)]
    confirmed_count = sum(1 for item in findings if item.get("status") == "confirmed")
    candidate_count = sum(1 for item in findings if item.get("status") == "candidate")
    inconclusive_count = sum(1 for item in findings if item.get("status") == "inconclusive")
    blocked_count = sum(1 for item in findings if item.get("status") == "blocked")

    for finding in findings:
        target_url = finding.get("url", "")
        for host in alive_hosts:
            if _belongs_to_host(target_url, host):
                host["vulns"] = merge_findings(host.get("vulns", []), [finding])
                break

    log.info(
        "[sensitive_files] Complete. "
        f"confirmed={confirmed_count}, candidates={candidate_count}, "
        f"inconclusive={inconclusive_count}, blocked={blocked_count}"
    )
    if callback:
        await callback(
            "sensitive_files",
            "done",
            f"Sensitive-file findings: confirmed={confirmed_count}, candidates={candidate_count}",
        )

    return alive_hosts

