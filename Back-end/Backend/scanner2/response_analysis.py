from __future__ import annotations

import re
from urllib.parse import urlparse

from .scanner_types import body_hash


BLOCK_STATUS_CODES = {403, 429, 503}
CHALLENGE_MARKERS = [
    "cf-challenge",
    "cloudflare ray id",
    "checking your browser",
    "please enable cookies",
    "access denied",
    "request blocked",
    "bot detection",
]
CAPTCHA_CHALLENGE_RE = re.compile(
    r"(?is)("
    r"g-recaptcha|h-captcha|cf-turnstile|data-sitekey|"
    r"name\s*=\s*['\"](?:captcha|g-recaptcha-response|h-captcha-response)['\"]|"
    r"id\s*=\s*['\"]captcha['\"]|captcha[_-]token|captcha challenge|"
    r"solve\s+(?:the\s+)?captcha|enter\s+(?:the\s+)?captcha"
    r")"
)

DIRECTORY_LISTING_MARKERS = [
    "<title>index of /",
    "directory listing for",
    "parent directory</a>",
    "<h1>index of /",
]


def response_fingerprint(status_code: int | None, headers: dict | None, body: str | bytes | None) -> dict:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
    return {
        "status_code": status_code,
        "body_hash": body_hash(text),
        "body_length": len(text),
        "content_type": (headers or {}).get("content-type") or (headers or {}).get("Content-Type") or "",
        "title": extract_title(text),
    }


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def is_blocked_or_challenged(status_code: int | None, headers: dict | None, body: str | bytes | None) -> tuple[bool, bool, list[str]]:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or "")
    lower_body = text[:20000].lower()
    lower_headers = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    combined = f"{lower_headers}\n{lower_body}"
    reasons: list[str] = []

    blocked = status_code in BLOCK_STATUS_CODES
    if blocked:
        reasons.append(f"status_code:{status_code}")

    challenged = False
    for marker in CHALLENGE_MARKERS:
        if marker in combined:
            challenged = True
            reasons.append(f"challenge_marker:{marker}")

    if CAPTCHA_CHALLENGE_RE.search(text[:20000]) or CAPTCHA_CHALLENGE_RE.search(lower_headers):
        challenged = True
        reasons.append("challenge_marker:captcha")

    return blocked, challenged, reasons


def has_meaningful_diff(
    baseline: dict,
    observed: dict,
    *,
    min_length_delta: int = 80,
) -> bool:
    if not baseline or not observed:
        return False
    if baseline.get("status_code") != observed.get("status_code"):
        return True
    if baseline.get("title") and observed.get("title") and baseline["title"] != observed["title"]:
        return True
    return abs(int(baseline.get("body_length") or 0) - int(observed.get("body_length") or 0)) >= min_length_delta


def reflects_payload(body: str, payload: str) -> bool:
    return bool(payload and body and payload in body)


def reflection_context(body: str, payload: str) -> str:
    if not reflects_payload(body, payload):
        return ""
    index = body.find(payload)
    before = body[max(0, index - 80):index].lower()
    after = body[index + len(payload):index + len(payload) + 80].lower()
    window = before + payload.lower() + after
    if "<script" in before or "</script" in after:
        return "script"
    if re.search(r"<[^>]+(?:href|src|on\w+)\s*=\s*['\"]?[^>]*$", before):
        return "html_attribute"
    if "<" in before and ">" in after:
        return "html_body"
    return "text"


def is_external_redirect(location: str, original_url: str, allowed_host: str = "") -> bool:
    if not location:
        return False
    parsed_location = urlparse(location)
    original_host = allowed_host or urlparse(original_url).netloc
    if location.startswith("//"):
        return True
    if not parsed_location.netloc:
        return False
    return parsed_location.netloc.lower() != original_host.lower()


def looks_like_directory_listing(status_code: int | None, body: str) -> bool:
    if status_code != 200:
        return False
    lower_body = (body or "")[:20000].lower()
    return any(marker in lower_body for marker in DIRECTORY_LISTING_MARKERS)

