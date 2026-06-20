from __future__ import annotations

import asyncio
import json
import math
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .findings import Finding
from .http_observer import summarize_request, summarize_response
from .scanner_types import EvidenceItem
from .utils import log


MODULE_NAME = "js_checks"
BASE_HEADERS = {"User-Agent": "Mozilla/5.0 Dragon-Recon/2.0"}
MAX_JS_BYTES = 1_500_000
MAX_ENDPOINT_FINDINGS_PER_FILE = 60

REFERENCES = [
    "https://owasp.org/www-project-web-security-testing-guide/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
]

PLACEHOLDER_MARKERS = {
    "your_api_key",
    "your-api-key",
    "api_key_here",
    "apikeyhere",
    "changeme",
    "change_me",
    "example",
    "dummy",
    "placeholder",
    "not-a-real",
    "fake",
    "localhost",
    "127.0.0.1",
    "test",
    "xxxx",
}

PUBLIC_CLIENT_KEY_NAMES = {
    "google_analytics",
    "gtag",
    "ga_measurement_id",
    "firebase_api_key",
    "recaptcha_site_key",
    "sentry_dsn",
}

SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<key>\b(?:password|passwd|pwd|db_password|database_password|client_secret|secret_key|
    private_key)\b)
    \s*[:=]\s*
    (?P<quote>["'])?
    (?P<value>[^"'\s,;]{6,})
    (?P=quote)?
    """
)

GENERIC_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<key>\b(?:api[_-]?key|apikey|secret|token|access[_-]?key|auth[_-]?token)\b)
    \s*[:=]\s*
    (?P<quote>["'])?
    (?P<value>[A-Za-z0-9._~+/=-]{18,96})
    (?P=quote)?
    """
)

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
SOURCE_MAP_REF_RE = re.compile(r"sourceMappingURL\s*=\s*(?P<ref>[^\s'\"`]+)", re.IGNORECASE)

ENDPOINT_STRING_RE = re.compile(
    r"""(?x)
    (?P<quote>["'`])
    (?P<value>
        https?://[^"'`\s<>{}\\]+
        |
        /(?:api|admin|debug|internal|backup|config|private|graphql|swagger|openapi|v[0-9]|auth|users|assets)
        [^"'`\s<>{}\\]*
    )
    (?P=quote)
    """
)

SENSITIVE_ENDPOINT_RE = re.compile(
    r"(?i)(/(admin|debug|internal|backup|config|private|graphql|swagger|openapi(?:\.json)?|actuator|metrics|console)\b|/\.env\b|/\.git\b)"
)

STATIC_ENDPOINT_EXTS = {
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
    ".map",
}

INTERESTING_MARKERS = [
    "process.env",
    "window.__config__",
    "__app_config__",
    "firebaseconfig",
    "debug:",
    "swagger",
    "openapi",
]


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern
    vuln_type: str
    status: str
    severity: str
    confidence: float
    secret_group: str = "value"
    require_context: bool = False


SECRET_RULES = [
    SecretRule(
        "Stripe Live Secret Key",
        re.compile(r"\b(?P<value>sk_live_[0-9A-Za-z]{24,})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.9,
    ),
    SecretRule(
        "Stripe Restricted Secret Key",
        re.compile(r"\b(?P<value>rk_live_[0-9A-Za-z]{24,})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.88,
    ),
    SecretRule(
        "GitHub Token",
        re.compile(r"\b(?P<value>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.88,
    ),
    SecretRule(
        "Slack Token",
        re.compile(r"\b(?P<value>xox[baprs]-[0-9A-Za-z-]{20,})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.88,
    ),
    SecretRule(
        "Slack Webhook",
        re.compile(r"\b(?P<value>https://hooks\.slack\.com/services/[A-Za-z0-9_/+-]{30,})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.9,
    ),
    SecretRule(
        "SendGrid API Key",
        re.compile(r"\b(?P<value>SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{24,})\b"),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.88,
    ),
    SecretRule(
        "Twilio API Key",
        re.compile(r"\b(?P<value>SK[0-9a-fA-F]{32})\b"),
        "exposed_js_secret",
        "candidate",
        "medium",
        0.65,
        require_context=True,
    ),
    SecretRule(
        "AWS Access Key ID",
        re.compile(r"\b(?P<value>(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
        "js_secret_candidate",
        "candidate",
        "medium",
        0.62,
    ),
    SecretRule(
        "AWS Secret Access Key",
        re.compile(r"""(?ix)(?:aws.{0,30}secret|aws_secret_access_key)\W+(?P<value>[A-Za-z0-9/+]{40})"""),
        "exposed_js_secret",
        "confirmed",
        "high",
        0.9,
    ),
    SecretRule(
        "Google API Key",
        re.compile(r"\b(?P<value>AIza[0-9A-Za-z_-]{35})\b"),
        "js_secret_candidate",
        "candidate",
        "medium",
        0.6,
    ),
    SecretRule(
        "Firebase Realtime Database URL",
        re.compile(r"\b(?P<value>https://[A-Za-z0-9-]+\.firebaseio\.com)\b"),
        "javascript_recon",
        "recon",
        "info",
        0.25,
    ),
]


def _header_value(headers: dict, name: str) -> str:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _decode_js(response: httpx.Response) -> str:
    content = response.content[:MAX_JS_BYTES]
    try:
        return content.decode(response.encoding or "utf-8", errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _line_number(content: str, position: int) -> int:
    return content.count("\n", 0, max(0, position)) + 1


def _context_window(content: str, start: int, end: int, size: int = 90) -> str:
    return content[max(0, start - size): min(len(content), end + size)]


def _line_context(content: str, position: int) -> str:
    line_start = content.rfind("\n", 0, max(0, position)) + 1
    line_end = content.find("\n", max(0, position))
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]


def _is_placeholder(value: str, context: str = "") -> bool:
    text = f"{value} {context}".lower()
    if any(marker in text for marker in PLACEHOLDER_MARKERS):
        return True
    stripped = re.sub(r"[^A-Za-z0-9]", "", value or "").lower()
    if not stripped:
        return True
    if len(set(stripped)) <= 3 and len(stripped) >= 8:
        return True
    return False


def _is_comment_or_example_context(context: str) -> bool:
    lower = (context or "").lower()
    stripped = lower.strip()
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return True
    return any(marker in lower for marker in ["example", "sample", "dummy", "placeholder", "todo"])


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_high_entropy(value: str) -> bool:
    if len(value or "") < 18:
        return False
    has_alpha = bool(re.search(r"[A-Za-z]", value))
    has_digit = bool(re.search(r"\d", value))
    return has_alpha and has_digit and _entropy(value) >= 3.45


def _mask_secret(value: str) -> str:
    value = value or ""
    if not value:
        return ""
    if PRIVATE_KEY_RE.search(value):
        return "<redacted-private-key>"
    if JWT_RE.fullmatch(value):
        parts = value.split(".")
        return ".".join(_mask_secret(part) for part in parts)
    if len(value) <= 8:
        return "*" * len(value)
    prefix = value[: min(8, max(3, len(value) // 5))]
    suffix = value[-4:]
    return f"{prefix}{'*' * 12}{suffix}"


def _redact_text(text: str) -> str:
    redacted = text or ""
    redacted = re.sub(
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----",
        "<redacted-private-key>",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    for rule in SECRET_RULES:
        redacted = rule.pattern.sub(lambda m: _mask_secret(m.groupdict().get("value") or m.group(0)), redacted)
    redacted = JWT_RE.sub(lambda m: _mask_secret(m.group(0)), redacted)

    def redact_assignment(match: re.Match) -> str:
        key = match.group("key")
        return f"{key}=********"

    redacted = SECRET_ASSIGNMENT_RE.sub(redact_assignment, redacted)
    redacted = GENERIC_SECRET_RE.sub(redact_assignment, redacted)
    redacted = re.sub(
        r"(?i)\b(?:YOUR|EXAMPLE|DUMMY|PLACEHOLDER|CHANGE[_-]?ME)[A-Z0-9_.-]{6,}\b",
        "<redacted-placeholder>",
        redacted,
    )
    redacted = re.sub(r"\b[a-fA-F0-9]{32,64}\b", "<redacted-hash-like-value>", redacted)
    redacted = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", redacted)
    redacted = re.sub(r"(?i)\b(authorization|cookie|set-cookie|sessionid)\s*[:=]\s*[^\s,;]+", r"\1=<redacted>", redacted)
    return redacted


def _safe_snippet(content: str, start: int, end: int) -> str:
    return _redact_text(_context_window(content, start, end)).replace("\r", " ")[:600]


def _request_summary(url: str) -> dict:
    return summarize_request(method="GET", url=url, headers=BASE_HEADERS)


def _response_summary(response: httpx.Response, content: str, start: int = 0, end: int = 0) -> dict:
    snippet = _safe_snippet(content, start, end) if content else ""
    return summarize_response(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=snippet,
        snippet=snippet,
    )


def _remediation_for(vuln_type: str) -> str:
    if vuln_type == "exposed_private_key":
        return "Remove the private key from client-side code, revoke it immediately, and issue a new key pair."
    if vuln_type in {"hardcoded_credential", "exposed_js_secret", "js_secret_candidate"}:
        return "Remove the secret from JavaScript, rotate the credential, and move privileged operations server-side."
    if vuln_type in {"exposed_source_map", "source_map_candidate"}:
        return "Do not publish production source maps unless intentionally public; restrict access or remove the sourceMappingURL reference."
    if vuln_type in {"js_endpoint_discovered", "sensitive_js_endpoint_candidate"}:
        return "Review the endpoint exposure and make sure authorization, authentication, and rate limits are enforced server-side."
    return "Review the JavaScript evidence and remove or protect sensitive client-exposed data."


def _make_finding(
    *,
    url: str,
    name: str,
    vuln_type: str,
    status: str,
    severity: str,
    confidence: float,
    evidence_text: str,
    response: httpx.Response,
    content: str,
    match_text: str = "",
    start: int = 0,
    end: int = 0,
    category: str = "",
    request_url: str = "",
    raw: dict | None = None,
) -> dict:
    redacted_match = _mask_secret(match_text) if match_text else ""
    if match_text and redacted_match not in evidence_text:
        evidence_text = f"{evidence_text} Redacted match: {redacted_match}."

    finding = Finding(
        id=vuln_type,
        scanner_name=MODULE_NAME,
        module_name=MODULE_NAME,
        url=url,
        method="GET",
        category=category or ("exposure" if vuln_type not in {"js_endpoint_discovered", "javascript_recon"} else "recon"),
        vuln_type=vuln_type,
        status=status,
        severity=severity,
        confidence=confidence,
        evidence=evidence_text,
        evidence_items=[
            EvidenceItem(
                type="text",
                value=evidence_text,
                location=f"line:{_line_number(content, start)}" if content else "response",
                comparison=(raw or {}).get("reason", ""),
            )
        ],
        request_summary=_request_summary(request_url or url),
        response_summary=_response_summary(response, content, start, end),
        remediation=_remediation_for(vuln_type),
        references=REFERENCES,
        name=name,
        description=evidence_text,
        matched_at=url,
        raw=raw or {},
    ).to_dict()

    if redacted_match:
        finding["match"] = redacted_match
    finding["source_url"] = request_url or url
    return finding


def _detect_private_keys(url: str, response: httpx.Response, content: str) -> list[dict]:
    findings = []
    for match in PRIVATE_KEY_RE.finditer(content):
        context = _context_window(content, match.start(), match.end())
        line_context = _line_context(content, match.start())
        if _is_comment_or_example_context(line_context):
            continue
        findings.append(_make_finding(
            url=url,
            name="Exposed Private Key",
            vuln_type="exposed_private_key",
            status="confirmed",
            severity="critical",
            confidence=0.96,
            evidence_text=f"Private-key block marker is present in client-side JavaScript near line {_line_number(content, match.start())}.",
            response=response,
            content=content,
            match_text=match.group(0),
            start=match.start(),
            end=match.end(),
            raw={"rule": "private_key_marker", "reason": "private_key_block_marker"},
        ))
    return findings


def _detect_hardcoded_credentials(url: str, response: httpx.Response, content: str) -> list[dict]:
    findings = []
    for match in SECRET_ASSIGNMENT_RE.finditer(content):
        key = match.group("key")
        value = match.group("value").strip("\"'")
        line_context = _line_context(content, match.start())
        if _is_placeholder(value, line_context) or _is_comment_or_example_context(line_context):
            continue
        findings.append(_make_finding(
            url=url,
            name="Hardcoded Credential",
            vuln_type="hardcoded_credential",
            status="confirmed",
            severity="high",
            confidence=0.88,
            evidence_text=(
                f"Credential-like assignment '{key}' is present in client-side JavaScript near line "
                f"{_line_number(content, match.start())}."
            ),
            response=response,
            content=content,
            match_text=value,
            start=match.start(),
            end=match.end(),
            raw={"rule": "credential_assignment", "key": key, "reason": "hardcoded_credential_assignment"},
        ))
    return findings


def _detect_provider_and_generic_secrets(url: str, response: httpx.Response, content: str) -> list[dict]:
    findings = []
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(content):
            value = match.groupdict().get(rule.secret_group) or match.group(0)
            context = _context_window(content, match.start(), match.end())
            line_context = _line_context(content, match.start())
            if _is_placeholder(value, line_context) or _is_comment_or_example_context(line_context):
                continue
            if rule.require_context and rule.name.split()[0].lower() not in context.lower():
                continue
            findings.append(_make_finding(
                url=url,
                name=rule.name,
                vuln_type=rule.vuln_type,
                status=rule.status,
                severity=rule.severity,
                confidence=rule.confidence,
                evidence_text=(
                    f"{rule.name} pattern found in JavaScript near line {_line_number(content, match.start())}. "
                    "The value is redacted for safety."
                ),
                response=response,
                content=content,
                match_text=value,
                start=match.start(),
                end=match.end(),
                raw={"rule": rule.name, "reason": "provider_specific_pattern"},
            ))

    for match in JWT_RE.finditer(content):
        value = match.group(0)
        line_context = _line_context(content, match.start())
        if _is_placeholder(value, line_context) or _is_comment_or_example_context(line_context):
            continue
        findings.append(_make_finding(
            url=url,
            name="JWT Token Candidate",
            vuln_type="js_secret_candidate",
            status="candidate",
            severity="high",
            confidence=0.68,
            evidence_text=f"JWT-like token found in JavaScript near line {_line_number(content, match.start())}.",
            response=response,
            content=content,
            match_text=value,
            start=match.start(),
            end=match.end(),
            raw={"rule": "jwt", "reason": "jwt_shape_without_server_validation"},
        ))

    for match in GENERIC_SECRET_RE.finditer(content):
        key = match.group("key")
        value = match.group("value").strip("\"'")
        line_context = _line_context(content, match.start())
        key_lower = key.lower().replace("-", "_")
        if key_lower in PUBLIC_CLIENT_KEY_NAMES:
            continue
        if _is_placeholder(value, line_context) or _is_comment_or_example_context(line_context):
            continue
        if not _looks_high_entropy(value):
            continue
        findings.append(_make_finding(
            url=url,
            name="JavaScript Secret Candidate",
            vuln_type="js_secret_candidate",
            status="candidate",
            severity="low",
            confidence=0.52,
            evidence_text=(
                f"High-entropy value assigned to '{key}' in JavaScript near line "
                f"{_line_number(content, match.start())}. Provider validation was not performed."
            ),
            response=response,
            content=content,
            match_text=value,
            start=match.start(),
            end=match.end(),
            raw={"rule": "generic_high_entropy_assignment", "key": key, "reason": "generic_secret_candidate"},
        ))
    return findings


def _is_endpoint(value: str) -> bool:
    parsed = urlparse(value)
    path = parsed.path or value
    lower = path.lower().split("?", 1)[0]
    if not path or len(path) <= 1:
        return False
    if any(lower.endswith(ext) for ext in STATIC_ENDPOINT_EXTS):
        return False
    if "{{" in value or "${" in value:
        return False
    return value.startswith("/") or parsed.scheme in {"http", "https"}


def _endpoint_severity(value: str) -> str:
    lower = value.lower()
    if any(marker in lower for marker in ["/debug", "/internal", "/backup", "/config", "/openapi", "/swagger"]):
        return "medium"
    if any(marker in lower for marker in ["/admin", "/private", "/graphql", "/actuator", "/metrics"]):
        return "low"
    return "info"


def _extract_endpoints(url: str, response: httpx.Response, content: str) -> tuple[list[dict], list[dict]]:
    endpoint_records = []
    findings = []
    seen = set()
    for match in ENDPOINT_STRING_RE.finditer(content):
        value = match.group("value")
        if not _is_endpoint(value):
            continue
        resolved = urljoin(url, value) if value.startswith("/") else value
        key = resolved.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        endpoint_records.append({"url": resolved, "source": url, "line": _line_number(content, match.start())})
        if len(findings) >= MAX_ENDPOINT_FINDINGS_PER_FILE:
            continue

        sensitive = bool(SENSITIVE_ENDPOINT_RE.search(urlparse(resolved).path))
        vuln_type = "sensitive_js_endpoint_candidate" if sensitive else "js_endpoint_discovered"
        status = "candidate" if sensitive else "recon"
        severity = _endpoint_severity(resolved) if sensitive else "info"
        confidence = 0.48 if sensitive else 0.2
        name = "Sensitive JavaScript Endpoint Candidate" if sensitive else "JavaScript Endpoint Discovered"
        findings.append(_make_finding(
            url=resolved,
            name=name,
            vuln_type=vuln_type,
            status=status,
            severity=severity,
            confidence=confidence,
            evidence_text=(
                f"Endpoint string found in {url} near line {_line_number(content, match.start())}. "
                f"Endpoint: {resolved}"
            ),
            response=response,
            content=content,
            match_text=resolved if sensitive else "",
            start=match.start(),
            end=match.end(),
            category="recon" if not sensitive else "exposure",
            request_url=url,
            raw={"reason": "endpoint_extracted_from_javascript", "endpoint": resolved},
        ))
    return endpoint_records, findings


def _source_map_url(js_url: str, reference: str) -> str:
    if reference.startswith("data:"):
        return reference
    return urljoin(js_url, reference.strip())


def _valid_source_map(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(parsed, dict) and all(key in parsed for key in ("version", "sources", "mappings"))


async def _check_source_maps(url: str, response: httpx.Response, content: str, client: httpx.AsyncClient) -> list[dict]:
    findings = []
    for match in SOURCE_MAP_REF_RE.finditer(content):
        reference = match.group("ref").strip()
        map_url = _source_map_url(url, reference)
        if map_url.startswith("data:"):
            findings.append(_make_finding(
                url=url,
                name="Inline Source Map Reference",
                vuln_type="source_map_candidate",
                status="candidate",
                severity="low",
                confidence=0.45,
                evidence_text=f"Inline source map reference found in JavaScript near line {_line_number(content, match.start())}.",
                response=response,
                content=content,
                start=match.start(),
                end=match.end(),
                raw={"reason": "inline_source_map_reference"},
            ))
            continue

        try:
            map_response = await client.get(map_url, timeout=8.0, follow_redirects=True)
            map_text = _decode_js(map_response)
        except httpx.RequestError as exc:
            findings.append(_make_finding(
                url=map_url,
                name="Source Map Candidate",
                vuln_type="source_map_candidate",
                status="candidate",
                severity="low",
                confidence=0.4,
                evidence_text=f"Source map reference found in {url}, but the map was not proven accessible: {type(exc).__name__}.",
                response=response,
                content=content,
                start=match.start(),
                end=match.end(),
                request_url=url,
                raw={"reason": "source_map_reference_not_fetched", "source_map_url": map_url},
            ))
            continue

        if map_response.status_code == 200 and _valid_source_map(map_text):
            findings.append(_make_finding(
                url=map_url,
                name="Exposed Source Map",
                vuln_type="exposed_source_map",
                status="confirmed",
                severity="medium",
                confidence=0.86,
                evidence_text=f"Source map reference from {url} is accessible and has valid source-map JSON keys.",
                response=map_response,
                content=map_text,
                start=0,
                end=min(len(map_text), 120),
                raw={"reason": "valid_source_map_json", "source_javascript": url},
            ))
        else:
            findings.append(_make_finding(
                url=map_url,
                name="Source Map Candidate",
                vuln_type="source_map_candidate",
                status="candidate",
                severity="low",
                confidence=0.42,
                evidence_text=(
                    f"Source map reference found in {url}, but the fetched response was not valid source-map JSON "
                    f"(status {map_response.status_code})."
                ),
                response=map_response,
                content=map_text,
                start=0,
                end=min(len(map_text), 120),
                raw={"reason": "source_map_reference_unconfirmed", "source_javascript": url},
            ))
    return findings


def _interesting_js_finding(url: str, response: httpx.Response, content: str) -> dict | None:
    lower = content[:50000].lower()
    markers = [marker for marker in INTERESTING_MARKERS if marker in lower]
    if not markers:
        return None
    marker = markers[0]
    index = lower.find(marker)
    return _make_finding(
        url=url,
        name="Interesting JavaScript File",
        vuln_type="javascript_recon",
        status="recon",
        severity="info",
        confidence=0.2,
        evidence_text=f"JavaScript contains application/configuration marker '{marker}'.",
        response=response,
        content=content,
        start=max(0, index),
        end=max(0, index + len(marker)),
        category="recon",
        raw={"reason": "interesting_javascript_marker", "marker": marker},
    )


async def _download_and_scan(url: str, client: httpx.AsyncClient) -> dict:
    result = {"findings": [], "secrets": [], "endpoints": []}
    try:
        response = await client.get(url, timeout=10.0, follow_redirects=True)
    except Exception as exc:
        log.debug(f"[js_checks] Failed to fetch {url}: {exc}")
        return result

    if response.status_code != 200:
        return result

    content_type = _header_value(dict(response.headers), "content-type").lower()
    content = _decode_js(response)
    if "html" in content_type and "<html" in content[:500].lower():
        return result

    findings = []
    findings.extend(_detect_private_keys(url, response, content))
    findings.extend(_detect_hardcoded_credentials(url, response, content))
    findings.extend(_detect_provider_and_generic_secrets(url, response, content))

    endpoints, endpoint_findings = _extract_endpoints(url, response, content)
    findings.extend(endpoint_findings)
    result["endpoints"].extend(endpoints)

    findings.extend(await _check_source_maps(url, response, content, client))

    interesting = _interesting_js_finding(url, response, content)
    if interesting:
        findings.append(interesting)

    result["findings"] = _dedupe_findings(findings)
    result["secrets"] = [
        finding for finding in result["findings"]
        if finding.get("vuln_type") in {
            "exposed_js_secret",
            "js_secret_candidate",
            "hardcoded_credential",
            "exposed_private_key",
        }
    ]
    return result


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("id"),
            finding.get("url"),
            finding.get("status"),
            finding.get("match") or finding.get("raw", {}).get("endpoint") or "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


async def run_js_checks(domain: str, alive_hosts: list, profile: str) -> dict:
    log.info(f"[{domain}] [JS Checks] Starting JavaScript analysis...")

    js_urls = []
    for host in alive_hosts:
        js_urls.extend(host.get("js_files", []))

    js_urls = sorted({url for url in js_urls if isinstance(url, str) and url.startswith(("http://", "https://"))})

    if not js_urls:
        log.info(f"[{domain}] [JS Checks] No JS files found to scan.")
        return {"secrets": [], "findings": [], "endpoints": []}

    log.info(f"[{domain}] [JS Checks] Downloading and scanning {len(js_urls)} JS files...")

    all_findings = []
    all_secrets = []
    all_endpoints = []
    async with httpx.AsyncClient(verify=False, headers=BASE_HEADERS) as client:
        sem = asyncio.Semaphore(20 if profile == "deep" else 10)

        async def bounded_scan(js_url):
            async with sem:
                return await _download_and_scan(js_url, client)

        results = await asyncio.gather(*(bounded_scan(url) for url in js_urls))

    for item in results:
        all_findings.extend(item.get("findings", []))
        all_secrets.extend(item.get("secrets", []))
        all_endpoints.extend(item.get("endpoints", []))

    unique_findings = _dedupe_findings(all_findings)
    unique_secrets = _dedupe_findings(all_secrets)
    unique_endpoints = []
    seen_endpoints = set()
    for endpoint in all_endpoints:
        key = (endpoint.get("url"), endpoint.get("source"))
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)
        unique_endpoints.append(endpoint)

    log.info(
        f"[{domain}] [JS Checks] Findings: {len(unique_findings)} total, "
        f"{len(unique_secrets)} secret-related, {len(unique_endpoints)} endpoints."
    )
    return {
        "secrets": unique_secrets,
        "findings": unique_findings,
        "endpoints": unique_endpoints,
    }

