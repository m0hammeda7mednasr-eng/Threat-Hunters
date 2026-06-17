from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .scanner_types import request_summary, response_summary, utc_now


PRIVATE_KEY_RE = re.compile(
    r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(['\"]?\b(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|access[_-]?key|"
    r"token|auth[_-]?token|password|passwd|pwd|secret|sessionid)\b['\"]?\s*[:=]\s*['\"]?)[^'\"\s,;}]+"
)


def redact_text(value: Any, *, limit: int | None = None) -> str:
    text = "" if value is None else str(value)
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = JWT_RE.sub("<redacted-jwt>", text)
    text = BEARER_RE.sub("Bearer <redacted>", text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: match.group(1) + "<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    if limit is not None:
        return text[:limit]
    return text


def _redact_body(body: bytes | str | None) -> bytes | str | None:
    if isinstance(body, str):
        return redact_text(body)
    return body


@dataclass(slots=True)
class ModuleTelemetry:
    module_name: str
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    request_count: int = 0
    unique_payload_count: int = 0
    payloads: set[str] = field(default_factory=set)
    status_codes: Counter = field(default_factory=Counter)
    blocked_count: int = 0
    challenge_count: int = 0
    errors: list[str] = field(default_factory=list)

    def record_request(self, payload: str = "") -> None:
        self.request_count += 1
        if payload:
            self.payloads.add(payload)
            self.unique_payload_count = len(self.payloads)

    def record_response(self, status_code: int | None, *, blocked: bool = False, challenged: bool = False) -> None:
        if status_code is not None:
            self.status_codes[str(status_code)] += 1
        if blocked:
            self.blocked_count += 1
        if challenged:
            self.challenge_count += 1

    def record_error(self, error: str) -> None:
        if error:
            self.errors.append(error[:300])

    def finish(self) -> None:
        self.completed_at = utc_now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "request_count": self.request_count,
            "unique_payload_count": self.unique_payload_count,
            "status_codes": dict(self.status_codes),
            "blocked_count": self.blocked_count,
            "challenge_count": self.challenge_count,
            "errors": self.errors,
        }


class ScanTelemetry:
    def __init__(self) -> None:
        self.modules: dict[str, ModuleTelemetry] = {}

    def module(self, module_name: str) -> ModuleTelemetry:
        if module_name not in self.modules:
            self.modules[module_name] = ModuleTelemetry(module_name=module_name)
        return self.modules[module_name]

    def finish_module(self, module_name: str) -> None:
        self.module(module_name).finish()

    def to_dict(self) -> dict[str, Any]:
        modules = {name: telemetry.to_dict() for name, telemetry in self.modules.items()}
        total_requests = sum(item["request_count"] for item in modules.values())
        blocked_requests = sum(item["blocked_count"] for item in modules.values())
        challenge_events = sum(item["challenge_count"] for item in modules.values())
        return {
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "challenge_events": challenge_events,
            "modules": modules,
        }


def summarize_request(
    *,
    method: str = "GET",
    url: str = "",
    headers: dict[str, Any] | None = None,
    body: bytes | str | None = None,
) -> dict[str, Any]:
    return request_summary(method=method, url=url, headers=headers, body=body)


def summarize_response(
    *,
    status_code: int | None = None,
    headers: dict[str, Any] | None = None,
    body: bytes | str | None = None,
    elapsed_ms: int | None = None,
    snippet: str = "",
) -> dict[str, Any]:
    redacted_body = _redact_body(body)
    redacted_snippet = redact_text(snippet, limit=500) if snippet else ""
    return response_summary(
        status_code=status_code,
        headers=headers,
        body=redacted_body,
        elapsed_ms=elapsed_ms,
        snippet=redacted_snippet,
    )


def summarize_httpx_response(response: Any, *, elapsed_ms: int | None = None, snippet_chars: int = 500) -> dict[str, Any]:
    text = ""
    try:
        text = response.text[:snippet_chars]
    except Exception:
        text = ""
    return summarize_response(
        status_code=getattr(response, "status_code", None),
        headers=dict(getattr(response, "headers", {}) or {}),
        body=text,
        elapsed_ms=elapsed_ms,
        snippet=text,
    )

