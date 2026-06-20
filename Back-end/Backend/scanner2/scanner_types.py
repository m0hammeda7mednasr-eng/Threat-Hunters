from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


FINDING_STATUSES = {
    "recon",
    "candidate",
    "confirmed",
    "inconclusive",
    "blocked",
}

SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
    "unknown",
}

REDACTED_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, confidence))


def default_confidence(status: str, severity: str = "info") -> float:
    status = (status or "candidate").lower()
    severity = (severity or "info").lower()
    if status == "confirmed":
        return 0.9 if severity in {"critical", "high", "medium"} else 0.8
    if status == "candidate":
        return 0.55 if severity in {"critical", "high", "medium"} else 0.45
    if status == "blocked":
        return 0.3
    if status == "inconclusive":
        return 0.2
    return 0.1


def normalize_status(status: str | None, *, severity: str = "info", confirmed: bool = False) -> str:
    if confirmed:
        return "confirmed"
    status_value = (status or "").lower().strip()
    if status_value in FINDING_STATUSES:
        return status_value
    severity_value = (severity or "info").lower().strip()
    return "candidate" if severity_value in {"critical", "high", "medium"} else "recon"


def normalize_severity(severity: str | None) -> str:
    severity_value = (severity or "info").lower().strip()
    return severity_value if severity_value in SEVERITIES else "unknown"


def redact_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in (headers or {}).items():
        key_text = str(key)
        if key_text.lower() in REDACTED_HEADER_NAMES:
            clean[key_text] = "<redacted>"
        else:
            clean[key_text] = str(value)[:300]
    return clean


def body_hash(body: bytes | str | None) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return hashlib.sha256(body).hexdigest()


@dataclass(slots=True)
class EvidenceItem:
    type: str
    value: str
    location: str = ""
    comparison: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class RequestSummary:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ResponseSummary:
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_hash: str = ""
    snippet: str = ""
    elapsed_ms: int | None = None
    content_type: str = ""
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def request_summary(
    *,
    method: str = "GET",
    url: str = "",
    headers: dict[str, Any] | None = None,
    body: bytes | str | None = None,
) -> dict[str, Any]:
    return RequestSummary(
        method=(method or "GET").upper(),
        url=url,
        headers=redact_headers(headers),
        body_hash=body_hash(body),
    ).to_dict()


def response_summary(
    *,
    status_code: int | None = None,
    headers: dict[str, Any] | None = None,
    body: bytes | str | None = None,
    elapsed_ms: int | None = None,
    snippet: str = "",
) -> dict[str, Any]:
    header_map = redact_headers(headers)
    content_type = header_map.get("content-type", header_map.get("Content-Type", ""))
    if not snippet and isinstance(body, str):
        snippet = body[:500]
    return ResponseSummary(
        status_code=status_code,
        headers=header_map,
        body_hash=body_hash(body),
        snippet=snippet[:500],
        elapsed_ms=elapsed_ms,
        content_type=content_type,
    ).to_dict()


