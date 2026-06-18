from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from .findings import Finding, merge_findings
from .http_observer import summarize_request, summarize_response
from .response_analysis import (
    extract_title,
    is_blocked_or_challenged,
    looks_like_directory_listing,
    response_fingerprint,
)
from .scanner_types import EvidenceItem, utc_now
from .utils import get_available_tool, get_tool_path, log


MODULE_NAME = "fuzz"
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconTool/Phase1",
}
RANGE_HEADERS = {"Range": "bytes=0-8191"}
MATCH_STATUS_CODES = "200,201,204,301,302,307,308,401,403,429,503"
MAX_BODY_BYTES = 8192
MAX_PROMOTED_RECON_FINDINGS = 25

_WORDLIST_CANDIDATES_BY_PROFILE = {
    "light": [
        "common.txt",
        "directory-list-2.3-small.txt",
    ],
    "deep": [
        "directory-list-2.3-medium.txt",
        "directory-list-2.3-small.txt",
        "common.txt",
    ],
}

REFERENCES = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
]

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(/(admin|administrator|debug|internal|private|backup|backups|config|configs|server-status|"
    r"phpinfo|swagger|openapi(?:\.json)?|graphql|actuator|metrics|console|\.git|\.svn)\b|"
    r"\.(env|bak|backup|old|zip|tar|gz|tgz|7z|rar|sql|db|sqlite|sqlite3|log|map|ini|conf|yml|yaml)$)"
)
ADMIN_PANEL_RE = re.compile(
    r"(?is)(phpmyadmin|jenkins|grafana|kibana|tomcat\s+manager|jboss|webmin|adminer|wp-login\.php|wordpress)"
)
GENERIC_ERROR_MARKERS = [
    "404 not found",
    "page not found",
    "not found",
    "resource not found",
    "the requested url was not found",
    "server error",
    "an error occurred",
]
LOGIN_MARKERS = ["type=\"password\"", "name=\"password\"", "login", "sign in", "signin"]
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".bak", ".backup"}
CONFIG_EXTS = {".env", ".ini", ".conf", ".yml", ".yaml", ".json", ".xml", ".php"}
LOG_EXTS = {".log", ".txt"}
DATABASE_EXTS = {".sql", ".db", ".sqlite", ".sqlite3"}
STATIC_EXTS = {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".eot"}

ENV_RE = re.compile(
    r"(?im)^\s*[A-Z0-9_.-]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|DATABASE_URL|"
    r"DB_PASSWORD|APP_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)[A-Z0-9_.-]*\s*=\s*[^\s#]{4,}"
)
CONFIG_RE = re.compile(
    r"(?im)^\s*(\[[a-z0-9_. -]+\]|[a-z0-9_.-]*(host|user|database|password|secret|token|key)"
    r"[a-z0-9_.-]*\s*[=:]\s*.+)"
)
LOG_RE = re.compile(r"(?im)^\s*(\[[^\]]+\]|\d{4}-\d{2}-\d{2}|ERROR|WARN|INFO|Traceback\b)")
SQL_RE = re.compile(r"(?is)(CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL dump|PostgreSQL database dump|SQLite format 3)")
SOURCE_MAP_RE = re.compile(r'"version"\s*:\s*\d+.*"sources"\s*:\s*\[.*"mappings"\s*:', re.IGNORECASE | re.DOTALL)
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|authorization|cookie)\s*[:=]\s*[\"']?[^\"'\s,;]{6,}"
)


@dataclass(slots=True)
class FuzzResult:
    path: str
    source_tool: str = "unknown"
    status_code: int | None = None
    content_length: int | None = None
    words: int | None = None
    lines: int | None = None
    redirect_location: str = ""
    content_type: str = ""

    def absolute_url(self, base_url: str) -> str:
        if self.path.startswith(("http://", "https://")):
            return self.path
        return urljoin(f"{base_url.rstrip('/')}/", self.path.lstrip("/"))


def _wordlist_candidates(profile: str = "light") -> list[str]:
    profile_key = str(profile or "light").lower()
    return _WORDLIST_CANDIDATES_BY_PROFILE.get(profile_key, _WORDLIST_CANDIDATES_BY_PROFILE["light"])


def _get_wordlist(profile: str = "light") -> str | None:
    wordlist_dir = os.path.join(os.path.dirname(__file__), "wordlists")
    for name in _wordlist_candidates(profile):
        path = os.path.join(wordlist_dir, name)
        if os.path.exists(path):
            return path
    return None


def _count_wordlist_entries(wordlist: str | None) -> int:
    if not wordlist or not os.path.exists(wordlist):
        return 0
    count = 0
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    count += 1
    except OSError:
        return 0
    return count


def _max_wordlist_entries(scan_config: dict | None) -> int | None:
    if not isinstance(scan_config, dict):
        return None
    limits = scan_config.get("limits") if isinstance(scan_config.get("limits"), dict) else {}
    try:
        value = int(limits.get("max_requests", 0))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _make_capped_wordlist(wordlist: str, max_entries: int | None) -> tuple[str, int, str | None]:
    original_count = _count_wordlist_entries(wordlist)
    if not max_entries or original_count <= max_entries:
        return wordlist, original_count, None

    temp_file = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        prefix="scanner-fuzz-",
        suffix=".txt",
        delete=False,
    )
    temp_path = temp_file.name
    written = 0
    try:
        with temp_file:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    candidate = line.strip()
                    if not candidate or candidate.startswith("#"):
                        continue
                    temp_file.write(candidate + "\n")
                    written += 1
                    if written >= max_entries:
                        break
    except OSError:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        return wordlist, original_count, None

    if written == 0:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        return wordlist, original_count, None

    log.info(f"[fuzz] Capped wordlist to {written} entries from {original_count} using scan limits.")
    return temp_path, written, temp_path


def _wordlist_dirs() -> list[str]:
    dirs = [
        os.path.join(os.path.dirname(__file__), "wordlists"),
        os.getenv("SCANNER_WORDLIST_DIR", ""),
        r"D:\recon\wordlists",
    ]
    return [path for path in dirs if path and os.path.isdir(path)]


def _host_labels(alive_hosts: list[dict]) -> list[str]:
    labels = []
    for host in alive_hosts[:3]:
        for value in (host.get("domain"), host.get("subdomain"), host.get("input_host"), host.get("url")):
            parsed = urlparse(str(value or "") if "://" in str(value or "") else f"http://{value}")
            hostname = (parsed.hostname or str(value or "")).strip().lower()
            if not hostname:
                continue
            labels.append(hostname)
            if hostname.startswith("www."):
                labels.append(hostname[4:])
            parts = hostname.split(".")
            if len(parts) >= 2:
                labels.append(".".join(parts[-2:]))
            if len(parts) >= 3:
                labels.append(parts[-3])
    seen = set()
    return [label for label in labels if label and not (label in seen or seen.add(label))]


def _custom_wordlists(alive_hosts: list[dict]) -> list[str]:
    paths = []
    for directory in _wordlist_dirs():
        for label in _host_labels(alive_hosts):
            candidate = os.path.join(directory, f"custom_{label}.txt")
            if os.path.exists(candidate):
                paths.append(candidate)
    seen = set()
    return [path for path in paths if not (path in seen or seen.add(path))]


def _make_combined_capped_wordlist(wordlists: list[str], max_entries: int | None) -> tuple[str, int, str | None]:
    existing = [path for path in wordlists if path and os.path.exists(path)]
    if not existing:
        return "", 0, None
    if len(existing) == 1:
        return _make_capped_wordlist(existing[0], max_entries)

    cap = max_entries or sum(_count_wordlist_entries(path) for path in existing)
    temp_file = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        prefix="scanner-fuzz-combined-",
        suffix=".txt",
        delete=False,
    )
    temp_path = temp_file.name
    seen = set()
    written = 0
    try:
        with temp_file:
            for path in existing:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    for line in handle:
                        candidate = line.strip()
                        if not candidate or candidate.startswith("#") or candidate in seen:
                            continue
                        seen.add(candidate)
                        temp_file.write(candidate + "\n")
                        written += 1
                        if written >= cap:
                            break
                if written >= cap:
                    break
    except OSError:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        return _make_capped_wordlist(existing[-1], max_entries)

    if written == 0:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        return _make_capped_wordlist(existing[-1], max_entries)

    log.info(f"[fuzz] Built combined wordlist with {written} entries from {len(existing)} sources.")
    return temp_path, written, temp_path


def _safe_int(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _header_value(headers: dict, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _normalize_path(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("/"):
        return value
    return f"/{value}"


def _parse_ffuf_json_payload(payload: str, base_url: str) -> list[FuzzResult]:
    payload = (payload or "").strip()
    if not payload:
        return []

    decoded_items = []
    try:
        decoded = json.loads(payload)
        decoded_items = decoded.get("results", decoded if isinstance(decoded, list) else [])
    except json.JSONDecodeError:
        decoded_items = []
        for line in payload.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                if isinstance(item.get("results"), list):
                    decoded_items.extend(item["results"])
                else:
                    decoded_items.append(item)

    results: list[FuzzResult] = []
    for item in decoded_items:
        if not isinstance(item, dict):
            continue
        input_value = item.get("input") or {}
        fuzz_value = ""
        if isinstance(input_value, dict):
            fuzz_value = input_value.get("FUZZ") or next(iter(input_value.values()), "")
        path = item.get("url") or item.get("path") or item.get("resultfile") or fuzz_value
        path = _normalize_path(str(path).replace(base_url.rstrip("/"), "", 1) if str(path).startswith(base_url) else path)
        if not path:
            continue
        results.append(FuzzResult(
            path=path,
            source_tool="ffuf",
            status_code=_safe_int(item.get("status")),
            content_length=_safe_int(item.get("length") or item.get("size")),
            words=_safe_int(item.get("words")),
            lines=_safe_int(item.get("lines")),
            redirect_location=str(item.get("redirectlocation") or item.get("redirect_location") or ""),
            content_type=str(item.get("content-type") or item.get("content_type") or ""),
        ))
    return results


def _parse_gobuster_json_payload(payload: str, base_url: str) -> list[FuzzResult]:
    payload = (payload or "").strip()
    if not payload or not payload.startswith(("{", "[")):
        return []
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        return []

    items = []
    if isinstance(decoded, dict):
        for key in ("results", "found", "data"):
            if isinstance(decoded.get(key), list):
                items = decoded[key]
                break
    elif isinstance(decoded, list):
        items = decoded

    results: list[FuzzResult] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        path = item.get("path") or item.get("url") or item.get("result")
        path = _normalize_path(str(path).replace(base_url.rstrip("/"), "", 1) if str(path).startswith(base_url) else path)
        if not path:
            continue
        results.append(FuzzResult(
            path=path,
            source_tool="gobuster",
            status_code=_safe_int(item.get("status") or item.get("status_code")),
            content_length=_safe_int(item.get("size") or item.get("length")),
            words=_safe_int(item.get("words")),
            lines=_safe_int(item.get("lines")),
            redirect_location=str(item.get("redirect") or item.get("redirect_location") or ""),
            content_type=str(item.get("content_type") or item.get("content-type") or ""),
        ))
    return results


def _parse_text_output(output: str, source_tool: str) -> list[FuzzResult]:
    results: list[FuzzResult] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "::")):
            continue

        ffuf_match = re.search(
            r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+),"
            r"\s*Words:\s*(?P<words>\d+),\s*Lines:\s*(?P<lines>\d+)",
            line,
        )
        if ffuf_match:
            results.append(FuzzResult(
                path=_normalize_path(ffuf_match.group("path")),
                source_tool=source_tool,
                status_code=_safe_int(ffuf_match.group("status")),
                content_length=_safe_int(ffuf_match.group("size")),
                words=_safe_int(ffuf_match.group("words")),
                lines=_safe_int(ffuf_match.group("lines")),
            ))
            continue

        gobuster_match = re.search(
            r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\](?:\s+\[-->\s*(?P<redirect>[^\]]+)\])?",
            line,
        )
        if gobuster_match:
            results.append(FuzzResult(
                path=_normalize_path(gobuster_match.group("path")),
                source_tool=source_tool,
                status_code=_safe_int(gobuster_match.group("status")),
                content_length=_safe_int(gobuster_match.group("size")),
                redirect_location=str(gobuster_match.group("redirect") or ""),
            ))
            continue

        simple_match = re.match(r"^(?P<path>/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)", line)
        if simple_match:
            results.append(FuzzResult(path=simple_match.group("path"), source_tool=source_tool))
    return results


def _dedupe_results(results: list[FuzzResult], base_url: str) -> list[FuzzResult]:
    seen = set()
    unique = []
    for result in results:
        url = result.absolute_url(base_url).rstrip("/")
        if url in seen:
            continue
        seen.add(url)
        unique.append(result)
    return unique


async def _run_ffuf(url: str, wordlist: str, threads: str, delay: str | None) -> list[FuzzResult]:
    fd, output_path = tempfile.mkstemp(prefix="recon_ffuf_", suffix=".json")
    os.close(fd)
    cmd = [
        get_tool_path("ffuf"),
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-mc", MATCH_STATUS_CODES,
        "-t", threads,
        "-ac",
        "-of", "json",
        "-o", output_path,
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-H", f"User-Agent: {BASE_HEADERS['User-Agent']}",
        "-timeout", "10",
    ]
    if delay:
        cmd.extend(["-p", delay])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        stdout_text = stdout.decode(errors="replace").strip()
        file_text = ""
        try:
            with open(output_path, "r", encoding="utf-8", errors="ignore") as handle:
                file_text = handle.read()
        except OSError:
            file_text = ""

        results = _parse_ffuf_json_payload(file_text, url) or _parse_ffuf_json_payload(stdout_text, url)
        if not results:
            results = _parse_text_output(stdout_text, "ffuf")
        return _dedupe_results(results, url)

    except asyncio.TimeoutError:
        log.warning(f"[fuzz] ffuf timed out for {url}")
        return []
    except Exception as exc:
        log.error(f"[fuzz] ffuf error for {url}: {exc}")
        return []
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


async def _run_gobuster(url: str, wordlist: str, threads: str, delay: str | None) -> list[FuzzResult]:
    cmd = [
        get_tool_path("gobuster"), "dir",
        "-u", url,
        "-w", wordlist,
        "-s", MATCH_STATUS_CODES,
        "-t", threads,
        "-H", "X-Forwarded-For: 127.0.0.1",
        "-a", BASE_HEADERS["User-Agent"],
        "-q",
        "--no-error",
        "--timeout", "10s",
    ]
    if delay:
        cmd.extend(["--delay", f"{int(float(delay) * 1000)}ms"])
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode(errors="replace").strip()
        results = _parse_gobuster_json_payload(output, url) or _parse_text_output(output, "gobuster")
        return _dedupe_results(results, url)

    except asyncio.TimeoutError:
        log.warning(f"[fuzz] gobuster timed out for {url}")
        return []
    except Exception as exc:
        log.error(f"[fuzz] gobuster error for {url}: {exc}")
        return []


def _decode_body(response: httpx.Response) -> str:
    content = response.content[:MAX_BODY_BYTES]
    if b"\x00" in content[:200]:
        return ""
    try:
        return content.decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _is_html(headers: dict, body: str) -> bool:
    content_type = _header_value(headers, "content-type").lower()
    lower = (body or "")[:600].lower()
    return "text/html" in content_type or "<html" in lower or "<!doctype html" in lower


def _redact(text: str) -> str:
    text = text or ""
    text = SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    text = re.sub(r"(?i)\b(cookie|set-cookie|authorization|sessionid)\s*[:=]\s*[^\s,;]+", r"\1=<redacted>", text)
    return text


def _snippet(body: str, marker: re.Pattern | None = None) -> str:
    if not body:
        return ""
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    selected: list[str] = []
    if marker:
        for line in lines:
            if marker.search(line):
                selected.append(line)
            if len(selected) >= 4:
                break
    if not selected:
        selected = lines[:4]
    return _redact("\n".join(selected))[:600]


def _binary_signature(content: bytes) -> str:
    if content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if content.startswith(b"\x1f\x8b"):
        return "gzip"
    if content.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if content.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if content.startswith(b"SQLite format 3"):
        return "sqlite"
    return ""


def _path_ext(url: str) -> str:
    path = urlparse(url).path.lower()
    _, ext = os.path.splitext(path)
    return ext


def _is_archive_response(url: str, response: httpx.Response) -> tuple[bool, str]:
    headers = dict(response.headers)
    content_type = _header_value(headers, "content-type").lower()
    disposition = _header_value(headers, "content-disposition").lower()
    signature = _binary_signature(response.content[:64])
    archive_path = _path_ext(url) in ARCHIVE_EXTS
    archive_type = any(token in content_type for token in ["zip", "gzip", "x-tar", "x-7z", "rar", "octet-stream"])
    if signature:
        return True, f"binary signature: {signature}"
    if archive_path and (archive_type or "attachment" in disposition):
        return True, f"content-type/download header: {content_type or disposition}"
    return False, ""


def _looks_generic_error(status_code: int | None, headers: dict, body: str) -> bool:
    if not _is_html(headers, body):
        return False
    lower = (body or "")[:12000].lower()
    title = extract_title(body).lower()
    return any(marker in lower or marker in title for marker in GENERIC_ERROR_MARKERS)


def _looks_login_page(body: str) -> bool:
    lower = (body or "")[:12000].lower()
    return "<form" in lower and any(marker in lower for marker in LOGIN_MARKERS)


def _is_sensitive_path(url: str) -> bool:
    return bool(SENSITIVE_PATH_RE.search(urlparse(url).path))


def _baseline_probe_urls(base_url: str) -> list[str]:
    parsed = urlparse(base_url)
    root = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    return [
        f"{root}/__recontool_fuzz_baseline_404_a__",
        f"{root}/__recontool_fuzz_baseline_404_b__",
    ]


async def _soft_404_baselines(client: httpx.AsyncClient, base_url: str, telemetry: dict) -> list[dict]:
    baselines = []
    for probe_url in _baseline_probe_urls(base_url):
        telemetry["verification_requests"] += 1
        try:
            response = await client.get(probe_url, headers=RANGE_HEADERS, timeout=5.0, follow_redirects=False)
        except httpx.RequestError:
            continue
        body = _decode_body(response)
        _record_status(telemetry, response.status_code, dict(response.headers), body)
        baselines.append(response_fingerprint(response.status_code, dict(response.headers), body))
    return baselines


def _is_soft_404(response: httpx.Response, body: str, baselines: list[dict]) -> bool:
    if response.status_code != 200:
        return False
    if _looks_generic_error(response.status_code, dict(response.headers), body):
        return True
    current = response_fingerprint(response.status_code, dict(response.headers), body)
    for baseline in baselines:
        if baseline.get("status_code") != 200:
            continue
        if current.get("body_hash") and current.get("body_hash") == baseline.get("body_hash"):
            return True
        if current.get("title") and current.get("title") == baseline.get("title"):
            length_delta = abs(int(current.get("body_length") or 0) - int(baseline.get("body_length") or 0))
            if length_delta < 80:
                return True
    return False


def _response_summary(response: httpx.Response, body: str, *, binary: bool = False) -> dict:
    snippet = "<binary content>" if binary else _snippet(body)
    response_body = response.content[:512] if binary else body
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response_body,
        snippet=snippet,
    )


def _request_summary(url: str) -> dict:
    return summarize_request(method="GET", url=url, headers={**BASE_HEADERS, **RANGE_HEADERS})


def _remediation(vuln_type: str) -> str:
    if vuln_type == "directory_listing":
        return "Disable directory indexing and remove files that should not be web-accessible."
    if vuln_type in {"exposed_backup_file", "exposed_config_file", "exposed_log_file", "exposed_database_dump", "exposed_source_map"}:
        return "Remove the exposed file from the web root, restrict access, and rotate any exposed credentials."
    if vuln_type == "default_admin_panel":
        return "Restrict the admin panel, require strong authentication, and remove default or unused admin interfaces."
    if vuln_type in {"sensitive_endpoint_candidate", "forbidden_interesting_endpoint"}:
        return "Review the endpoint and confirm server-side authentication and authorization are enforced."
    if vuln_type == "fuzz_blocked":
        return "Tune the authorized scan profile or test in a lab to understand which requests trigger defensive controls."
    return "Review the discovered endpoint and ensure it is intentionally exposed."


def _make_finding(
    *,
    url: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    response: httpx.Response,
    body: str,
    source_tool: str,
    category: str = "",
    raw: dict | None = None,
    binary: bool = False,
) -> dict:
    return Finding(
        id=vuln_type,
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=url,
        method="GET",
        category=category or ("recon" if status == "recon" else "exposure"),
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="text",
                value=evidence_text,
                location="response",
                comparison=(raw or {}).get("classification_reason", ""),
            )
        ],
        request_summary=_request_summary(url),
        response_summary=_response_summary(response, body, binary=binary),
        remediation=_remediation(vuln_type),
        references=REFERENCES,
        name=vuln_type.replace("_", " ").title(),
        description=evidence_text,
        matched_at=url,
        raw={
            "source_tool": source_tool,
            "status_code": response.status_code,
            "content_length": _header_value(dict(response.headers), "content-length"),
            "content_type": _header_value(dict(response.headers), "content-type"),
            **(raw or {}),
        },
    ).to_dict()


def _classify_confirmed_content(url: str, response: httpx.Response, body: str, source_tool: str) -> dict | None:
    headers = dict(response.headers)
    path = urlparse(url).path.lower()

    if looks_like_directory_listing(response.status_code, body):
        return _make_finding(
            url=url,
            vuln_type="directory_listing",
            status="confirmed",
            severity="medium",
            confidence=0.9,
            evidence_text=f"Directory listing markers are present: {_snippet(body)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "directory_listing_markers"},
        )

    archive, archive_reason = _is_archive_response(url, response)
    if archive:
        return _make_finding(
            url=url,
            vuln_type="exposed_backup_file",
            status="confirmed",
            severity="high",
            confidence=0.88,
            evidence_text=f"Backup/archive file appears accessible ({archive_reason}).",
            response=response,
            body="",
            source_tool=source_tool,
            raw={"classification_reason": archive_reason},
            binary=True,
        )

    if path.endswith(".map"):
        source_map = bool(SOURCE_MAP_RE.search(body))
        if not source_map:
            try:
                parsed = json.loads(body)
                source_map = isinstance(parsed, dict) and all(key in parsed for key in ("version", "sources", "mappings"))
            except (json.JSONDecodeError, TypeError):
                source_map = False
        if source_map:
            return _make_finding(
                url=url,
                vuln_type="exposed_source_map",
                status="confirmed",
                severity="medium",
                confidence=0.86,
                evidence_text=f"Valid source-map JSON is accessible: {_snippet(body)}",
                response=response,
                body=body,
                source_tool=source_tool,
                raw={"classification_reason": "source_map_json_signature"},
            )

    if (path.endswith(".env") or "/.env" in path) and ENV_RE.search(body):
        return _make_finding(
            url=url,
            vuln_type="exposed_config_file",
            status="confirmed",
            severity="high",
            confidence=0.92,
            evidence_text=f"Environment/config keys are visible: {_snippet(body, ENV_RE)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "env_key_signatures"},
        )

    if _path_ext(url) in DATABASE_EXTS and (SQL_RE.search(body) or _binary_signature(response.content[:64]) == "sqlite"):
        return _make_finding(
            url=url,
            vuln_type="exposed_database_dump",
            status="confirmed",
            severity="high",
            confidence=0.9,
            evidence_text=f"Database dump indicators are present: {_snippet(body, SQL_RE)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "database_dump_signature"},
        )

    if _path_ext(url) in LOG_EXTS and LOG_RE.search(body):
        return _make_finding(
            url=url,
            vuln_type="exposed_log_file",
            status="confirmed",
            severity="high" if SECRET_RE.search(body) else "medium",
            confidence=0.84,
            evidence_text=f"Log-style content is accessible: {_snippet(body, LOG_RE)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "log_content_signature"},
        )

    if (_path_ext(url) in CONFIG_EXTS or "config" in path) and CONFIG_RE.search(body):
        return _make_finding(
            url=url,
            vuln_type="exposed_config_file",
            status="confirmed",
            severity="high" if SECRET_RE.search(body) else "medium",
            confidence=0.84,
            evidence_text=f"Configuration-style content is accessible: {_snippet(body, CONFIG_RE)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "config_content_signature"},
        )

    if ADMIN_PANEL_RE.search(body):
        return _make_finding(
            url=url,
            vuln_type="default_admin_panel",
            status="confirmed",
            severity="medium",
            confidence=0.78,
            evidence_text=f"Known admin panel markers are present: {_snippet(body, ADMIN_PANEL_RE)}",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "known_admin_panel_marker"},
        )

    return None


def _candidate_vuln_type(url: str, status_code: int | None) -> str:
    path = urlparse(url).path.lower()
    if status_code == 403 and _is_sensitive_path(url):
        return "forbidden_interesting_endpoint"
    if path.endswith(tuple(ARCHIVE_EXTS)):
        return "exposed_backup_file"
    if path.endswith(tuple(DATABASE_EXTS)):
        return "exposed_database_dump"
    if path.endswith(".map"):
        return "exposed_source_map"
    if path.endswith(tuple(LOG_EXTS)):
        return "exposed_log_file"
    if path.endswith(tuple(CONFIG_EXTS)) or "config" in path or ".env" in path:
        return "exposed_config_file"
    return "sensitive_endpoint_candidate"


def _classify_fuzz_response(
    *,
    url: str,
    response: httpx.Response,
    body: str,
    baselines: list[dict],
    source_tool: str,
) -> dict | None:
    headers = dict(response.headers)
    status_code = response.status_code
    blocked, challenged, reasons = is_blocked_or_challenged(status_code, headers, body)

    if challenged or status_code in {429, 503}:
        return _make_finding(
            url=url,
            vuln_type="fuzz_blocked",
            status="blocked",
            severity="info",
            confidence=0.3,
            evidence_text=f"Fuzz response appears blocked or challenged: {', '.join(reasons) or status_code}.",
            response=response,
            body=body,
            source_tool=source_tool,
            category="detection-testing",
            raw={"classification_reason": "blocked_or_challenged", "indicators": reasons},
        )

    if status_code in {404, 410}:
        return None

    if _is_soft_404(response, body, baselines):
        return None

    if status_code == 403 and _is_sensitive_path(url):
        return _make_finding(
            url=url,
            vuln_type="forbidden_interesting_endpoint",
            status="candidate",
            severity="low",
            confidence=0.5,
            evidence_text="Sensitive-looking endpoint exists but is forbidden; no content exposure was proven.",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "interesting_forbidden_endpoint"},
        )

    if 300 <= status_code < 400:
        return _make_finding(
            url=url,
            vuln_type="fuzz_inconclusive",
            status="inconclusive",
            severity="info",
            confidence=0.25,
            evidence_text=f"Fuzzed endpoint redirected to {_header_value(headers, 'location') or 'an unknown location'}.",
            response=response,
            body=body,
            source_tool=source_tool,
            category="recon",
            raw={"classification_reason": "redirect_without_content_proof"},
        )

    confirmed = _classify_confirmed_content(url, response, body, source_tool)
    if confirmed:
        return confirmed

    if _looks_login_page(body) and _is_sensitive_path(url):
        return _make_finding(
            url=url,
            vuln_type="sensitive_endpoint_candidate",
            status="candidate",
            severity="low",
            confidence=0.45,
            evidence_text="Sensitive-looking endpoint returned a login page; no vulnerability was confirmed.",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "login_page_at_sensitive_path"},
        )

    if _is_html(headers, body) and _looks_generic_error(status_code, headers, body):
        if _is_sensitive_path(url):
            return _make_finding(
                url=url,
                vuln_type="fuzz_inconclusive",
                status="inconclusive",
                severity="info",
                confidence=0.2,
                evidence_text="Sensitive-looking endpoint returned a generic error page; no exposure was proven.",
                response=response,
                body=body,
                source_tool=source_tool,
                category="recon",
                raw={"classification_reason": "generic_error_page"},
            )
        return None

    if _is_sensitive_path(url):
        vuln_type = _candidate_vuln_type(url, status_code)
        return _make_finding(
            url=url,
            vuln_type=vuln_type,
            status="candidate",
            severity="low",
            confidence=0.45,
            evidence_text="Sensitive-looking path responded, but strong sensitive content proof was not found.",
            response=response,
            body=body,
            source_tool=source_tool,
            raw={"classification_reason": "sensitive_path_without_content_proof"},
        )

    if _path_ext(url) in STATIC_EXTS:
        severity = "info"
        confidence = 0.15
    else:
        severity = "info"
        confidence = 0.22

    return _make_finding(
        url=url,
        vuln_type="endpoint_discovered",
        status="recon",
        severity=severity,
        confidence=confidence,
        evidence_text=f"Endpoint responded with status {status_code}; this is recon, not a confirmed vulnerability.",
        response=response,
        body=body,
        source_tool=source_tool,
        category="recon",
        raw={"classification_reason": "normal_endpoint_discovery"},
    )


def _new_telemetry(tool: str, wordlist_count: int) -> dict:
    return {
        "module_name": MODULE_NAME,
        "source_tool": tool,
        "started_at": utc_now(),
        "completed_at": "",
        "wordlist_entries": wordlist_count,
        "estimated_fuzz_requests": 0,
        "verification_requests": 0,
        "total_fuzz_requests": 0,
        "request_rate_per_second": 0.0,
        "status_codes": {},
        "403_count": 0,
        "429_count": 0,
        "503_count": 0,
        "blocked_or_challenge_indicators": 0,
        "module_noise_score": 0.0,
        "module_detection_impact": "not_calibrated",
    }


def _record_status(telemetry: dict, status_code: int | None, headers: dict, body: str) -> None:
    if status_code is None:
        return
    counter = Counter(telemetry.get("status_codes", {}))
    counter[str(status_code)] += 1
    telemetry["status_codes"] = dict(counter)
    if status_code == 403:
        telemetry["403_count"] += 1
    if status_code == 429:
        telemetry["429_count"] += 1
    if status_code == 503:
        telemetry["503_count"] += 1
    blocked, challenged, _ = is_blocked_or_challenged(status_code, headers, body)
    if blocked or challenged:
        telemetry["blocked_or_challenge_indicators"] += 1


def _finish_telemetry(telemetry: dict, started: float) -> dict:
    elapsed = max(0.001, time.monotonic() - started)
    total = int(telemetry.get("estimated_fuzz_requests", 0)) + int(telemetry.get("verification_requests", 0))
    telemetry["total_fuzz_requests"] = total
    telemetry["request_rate_per_second"] = round(total / elapsed, 2)
    blocked = int(telemetry.get("blocked_or_challenge_indicators", 0))
    telemetry["module_noise_score"] = round(min(1.0, blocked / max(1, total)), 4)
    telemetry["completed_at"] = utc_now()
    return telemetry


async def _verify_results(
    *,
    base_url: str,
    results: list[FuzzResult],
    client: httpx.AsyncClient,
    telemetry: dict,
) -> tuple[list[str], list[dict]]:
    endpoints: set[str] = set()
    findings: list[dict] = []
    baselines = await _soft_404_baselines(client, base_url, telemetry)

    for result in results:
        target_url = result.absolute_url(base_url)
        telemetry["verification_requests"] += 1
        try:
            response = await client.get(target_url, headers=RANGE_HEADERS, timeout=8.0, follow_redirects=False)
        except httpx.RequestError:
            continue

        body = _decode_body(response)
        _record_status(telemetry, response.status_code, dict(response.headers), body)
        finding = _classify_fuzz_response(
            url=target_url,
            response=response,
            body=body,
            baselines=baselines,
            source_tool=result.source_tool,
        )
        if not finding:
            continue
        endpoints.add(target_url)
        findings.append(finding)

    return sorted(endpoints), findings


async def fuzz_endpoints(alive_hosts: list[dict], profile: str = "light", callback=None, scan_config: dict | None = None) -> list[dict]:
    if not alive_hosts:
        return []

    tool = get_available_tool("fuzz")

    if not tool:
        log.warning("[fuzz] No fuzzing tools available (ffuf, gobuster). Skipping.")
        if callback:
            await callback("fuzz", "warning", "No fuzzing tools installed. Skipping.")
        return alive_hosts

    wordlist = _get_wordlist(profile)
    if not wordlist:
        log.warning("[fuzz] No wordlist found. Skipping. Download wordlists by running install_tools.ps1")
        if callback:
            await callback("fuzz", "warning", "No wordlist file found. Skipping.")
        return alive_hosts

    threads = "50" if profile == "deep" else "20"
    delay = "0.5" if profile == "deep" else None

    custom_wordlists = _custom_wordlists(alive_hosts) if profile == "deep" else []
    if custom_wordlists:
        log.info(f"[fuzz] Found {len(custom_wordlists)} custom wordlist(s): {', '.join(custom_wordlists[:3])}")

    wordlist, wordlist_count, capped_wordlist = _make_combined_capped_wordlist(
        [*custom_wordlists, wordlist],
        _max_wordlist_entries(scan_config),
    )
    log.info(f"[fuzz] Using wordlist: {wordlist}")

    async def fuzzer(url: str) -> list[FuzzResult]:
        if tool == "ffuf":
            return await _run_ffuf(url, wordlist, threads, delay)
        return await _run_gobuster(url, wordlist, threads, delay)

    log.info(f"[fuzz] Using {tool} on {len(alive_hosts)} hosts")

    if callback:
        await callback("fuzz", "running", f"Fuzzing {len(alive_hosts)} hosts with {tool}...")

    semaphore = asyncio.Semaphore(3)

    async def _fuzz_one(host_info: dict):
        async with semaphore:
            started = time.monotonic()
            telemetry = _new_telemetry(tool, wordlist_count)
            urls_to_scan = [url for url in host_info.get("expanded_urls", [host_info.get("url")]) if url]
            all_endpoints: set[str] = set()
            all_findings: list[dict] = []

            async with httpx.AsyncClient(verify=False, headers=BASE_HEADERS, follow_redirects=False) as client:
                for base_url in urls_to_scan:
                    url = base_url.rstrip("/")
                    telemetry["estimated_fuzz_requests"] += wordlist_count
                    results = await fuzzer(url)
                    for result in results:
                        if result.status_code is not None:
                            _record_status(telemetry, result.status_code, {}, "")
                    endpoints, findings = await _verify_results(
                        base_url=url,
                        results=results,
                        client=client,
                        telemetry=telemetry,
                    )
                    all_endpoints.update(endpoints)
                    all_findings.extend(findings)

            host_info["endpoints"] = sorted(all_endpoints)
            host_info["fuzz_findings"] = _dedupe_findings(all_findings)
            host_info["fuzz_telemetry"] = _finish_telemetry(telemetry, started)

            promoted = [
                finding for finding in host_info["fuzz_findings"]
                if finding.get("status") != "recon"
            ]
            recon_promoted = [
                finding for finding in host_info["fuzz_findings"]
                if finding.get("status") == "recon"
            ][:MAX_PROMOTED_RECON_FINDINGS]
            if promoted or recon_promoted:
                host_info["vulns"] = merge_findings(host_info.get("vulns", []), [*promoted, *recon_promoted])

            if host_info["endpoints"]:
                log.info(f"[fuzz] {host_info.get('subdomain', host_info.get('url', 'host'))} -> discovered {len(host_info['endpoints'])} endpoints")

    tasks = [_fuzz_one(host) for host in alive_hosts]
    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if capped_wordlist:
            try:
                os.unlink(capped_wordlist)
            except OSError:
                pass

    total_eps = sum(len(host.get("endpoints", [])) for host in alive_hosts)
    total_findings = sum(len(host.get("fuzz_findings", [])) for host in alive_hosts)
    log.info(f"[fuzz] Complete. Found {total_eps} endpoints and {total_findings} normalized fuzz findings total.")

    if callback:
        await callback("fuzz", "done", f"Discovered {total_eps} endpoints across {len(alive_hosts)} hosts")

    return alive_hosts


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("module_name"),
            finding.get("id"),
            finding.get("url"),
            finding.get("status"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique

