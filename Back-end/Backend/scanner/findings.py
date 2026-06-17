from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .scanner_types import (
    FINDING_STATUSES,
    EvidenceItem,
    clamp_confidence,
    default_confidence,
    normalize_severity,
    normalize_status,
    utc_now,
)


VALID_CATEGORIES = {
    "confirmed vuln",
    "probable vuln",
    "security observation",
}

VULN_TYPE_TO_CATEGORY = {
    "xss": "injection",
    "sqli": "injection",
    "sql_injection": "injection",
    "command_injection": "injection",
    "ssrf": "server-side request forgery",
    "open_redirect": "redirect",
    "idor": "authorization",
    "sensitive_file": "exposure",
    "js_secret": "exposure",
    "cors": "misconfiguration",
    "security_header": "misconfiguration",
    "subdomain_takeover": "takeover",
    "directory_listing": "exposure",
    "default_admin_panel": "exposure",
    "known_cve": "known vulnerability",
    "websocket_cswsh": "websocket",
}

DEFAULT_REMEDIATION = {
    "xss": "Encode untrusted output in the correct HTML/JavaScript context and validate input server-side.",
    "sqli": "Use parameterized queries, avoid string-built SQL, and validate input type/length server-side.",
    "sql_injection": "Use parameterized queries, avoid string-built SQL, and validate input type/length server-side.",
    "open_redirect": "Allow only relative redirects or validate destinations against an explicit allowlist.",
    "sensitive_file": "Remove the exposed file, rotate any leaked secrets, and block access with server rules.",
    "js_secret": "Revoke and rotate the exposed secret, then move privileged credentials server-side.",
    "cors": "Restrict allowed origins and avoid combining wildcard/reflected origins with credentials.",
    "security_header": "Set the missing or weak security header according to OWASP guidance.",
    "subdomain_takeover": "Remove dangling DNS records or reclaim and configure the referenced third-party resource.",
    "directory_listing": "Disable directory indexing and remove files that should not be web-accessible.",
}

HTTP_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
}


def _looks_like_security_header(parameter: str) -> bool:
    normalized = str(parameter or "").strip().lower()
    return normalized in HTTP_SECURITY_HEADERS or (
        normalized.startswith(("x-", "cross-origin-")) and "options" in normalized
    )


def _legacy_category_from_status(status: str, severity: str) -> str:
    if status == "confirmed":
        return "confirmed vuln"
    if status == "candidate" and severity in {"critical", "high", "medium"}:
        return "probable vuln"
    return "security observation"


def _status_from_legacy(vuln_category: str, severity: str) -> str:
    text = (vuln_category or "").lower()
    if "confirmed" in text:
        return "confirmed"
    if "probable" in text or severity in {"critical", "high", "medium"}:
        return "candidate"
    return "recon"


def _infer_vuln_type(finding_id: str, name: str = "") -> str:
    text = f"{finding_id} {name}".lower()
    checks = [
        ("sql", "sqli"),
        ("xss", "xss"),
        ("redirect", "open_redirect"),
        ("cors", "cors"),
        ("header", "security_header"),
        ("secret", "js_secret"),
        ("sensitive", "sensitive_file"),
        ("takeover", "subdomain_takeover"),
        ("directory", "directory_listing"),
        ("lfi", "lfi"),
        ("crlf", "crlf"),
        ("websocket", "websocket_cswsh"),
    ]
    for marker, vuln_type in checks:
        if marker in text:
            return vuln_type
    return "unknown"


def _default_reproduction(method: str, url: str, parameter: str, payload: str, evidence: str) -> list[str]:
    if parameter and _looks_like_security_header(parameter):
        steps = [f"Send a {method or 'GET'} request to {url or 'the affected endpoint'} and inspect the response headers."]
        if evidence:
            steps.append("Compare the observed headers with the evidence and response summary in this finding.")
        return steps

    steps = [f"Send a {method or 'GET'} request to {url or 'the affected endpoint'}."]
    if parameter:
        steps.append(f"Set parameter '{parameter}' to the documented test value.")
    if payload:
        steps.append("Use the payload recorded in payload_used exactly as shown.")
    if evidence:
        steps.append("Compare the response with the evidence and response summary in this finding.")
    return steps


def _coerce_evidence_items(value: Any, fallback_text: str = "") -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, EvidenceItem):
                items.append(item)
            elif isinstance(item, dict):
                items.append(EvidenceItem(
                    type=str(item.get("type", "text")),
                    value=str(item.get("value", "")),
                    location=str(item.get("location", "")),
                    comparison=str(item.get("comparison", "")),
                ))
            elif item:
                items.append(EvidenceItem(type="text", value=str(item)))
    elif isinstance(value, dict):
        items.append(EvidenceItem(
            type=str(value.get("type", "text")),
            value=str(value.get("value", "")),
            location=str(value.get("location", "")),
            comparison=str(value.get("comparison", "")),
        ))

    if not items and fallback_text:
        items.append(EvidenceItem(type="text", value=str(fallback_text), location="scanner_output"))
    return items


@dataclass(slots=True)
class Finding:
    id: str
    scanner_name: str
    url: str
    parameter: str = ""
    severity: str = "info"
    evidence: str = ""
    output_path: str = ""
    vuln_category: str = "security observation"
    name: str = ""
    description: str = ""
    matched_at: str = ""
    payload: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    scan_id: str = ""
    target: str = ""
    method: str = "GET"
    category: str = ""
    vuln_type: str = ""
    status: str = ""
    confidence: float = 0.0
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    payload_used: str = ""
    request_summary: dict[str, Any] = field(default_factory=dict)
    response_summary: dict[str, Any] = field(default_factory=dict)
    reproduction_steps: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    module_name: str = ""
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.id = str(self.id or "unknown-finding").strip()
        self.scanner_name = str(self.scanner_name or self.module_name or "unknown").strip()
        self.module_name = str(self.module_name or self.scanner_name).strip()
        self.url = str(self.url or self.matched_at or "").strip()
        self.matched_at = str(self.matched_at or self.url).strip()
        self.parameter = str(self.parameter or "").strip()
        self.method = str(self.method or "GET").upper().strip()
        self.severity = normalize_severity(self.severity)
        self.name = str(self.name or self.id.replace("-", " ").title()).strip()
        self.description = str(self.description or self.evidence or "").strip()
        self.vuln_type = str(self.vuln_type or _infer_vuln_type(self.id, self.name)).strip()
        self.category = str(self.category or VULN_TYPE_TO_CATEGORY.get(self.vuln_type, "observation")).strip()

        legacy_status = _status_from_legacy(self.vuln_category, self.severity)
        self.status = normalize_status(self.status or legacy_status, severity=self.severity)
        if self.status not in FINDING_STATUSES:
            self.status = "candidate"

        self.confidence = clamp_confidence(self.confidence or default_confidence(self.status, self.severity))
        self.payload_used = str(self.payload_used or self.payload or "").strip()
        self.evidence_items = _coerce_evidence_items(self.evidence_items, self.evidence)
        self.evidence = str(self.evidence or (self.evidence_items[0].value if self.evidence_items else "")).strip()
        self.vuln_category = _legacy_category_from_status(self.status, self.severity)

        if not self.reproduction_steps:
            self.reproduction_steps = _default_reproduction(
                self.method,
                self.url,
                self.parameter,
                self.payload_used,
                self.evidence,
            )
        if not self.remediation:
            self.remediation = DEFAULT_REMEDIATION.get(self.vuln_type, "Review the evidence and apply the relevant secure configuration or code fix.")

    @property
    def dedupe_key(self) -> tuple[str, str, str, str]:
        return finding_key(self)

    def to_dict(self) -> dict[str, Any]:
        strict = {
            "id": self.id,
            "scan_id": self.scan_id,
            "target": self.target,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "category": self.category,
            "vuln_type": self.vuln_type,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": [item.to_dict() for item in self.evidence_items],
            "payload_used": self.payload_used,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "references": self.references,
            "module_name": self.module_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

        strict.update({
            "scanner_name": self.scanner_name,
            "scanner": self.scanner_name,
            "vuln_category": self.vuln_category,
            "name": self.name,
            "description": self.description,
            "matched_at": self.matched_at,
            "matched": self.matched_at,
            "type": self.name,
            "payload": self.payload_used,
            "output_path": self.output_path,
            "raw": self.raw,
        })
        return strict


def severity_to_category(severity: str, *, confirmed: bool = False) -> str:
    severity = (severity or "info").lower()
    if confirmed and severity not in {"info", "unknown"}:
        return "confirmed vuln"
    if severity in {"critical", "high", "medium"}:
        return "probable vuln"
    return "security observation"


def finding_key(finding: Finding | dict[str, Any]) -> tuple[str, str, str, str]:
    if isinstance(finding, Finding):
        scanner_name = finding.module_name or finding.scanner_name
        finding_id = finding.id
        matched_at = finding.matched_at or finding.url
        parameter = finding.parameter
    else:
        scanner_name = finding.get("module_name") or finding.get("scanner_name") or finding.get("scanner") or "unknown"
        finding_id = finding.get("id") or finding.get("template-id") or finding.get("type") or "unknown-finding"
        matched_at = (
            finding.get("matched_at")
            or finding.get("matched")
            or finding.get("url")
            or finding.get("matched-at")
            or ""
        )
        parameter = finding.get("parameter") or finding.get("param") or ""

    return (
        str(scanner_name).lower().strip(),
        str(finding_id).lower().strip(),
        str(matched_at).lower().strip().rstrip("/"),
        str(parameter).lower().strip(),
    )


def normalize_finding(
    raw: Finding | dict[str, Any],
    *,
    scanner_name: str = "unknown",
    vuln_category: str | None = None,
) -> dict[str, Any]:
    if isinstance(raw, Finding):
        return raw.to_dict()

    evidence_value = raw.get("evidence") or raw.get("details") or raw.get("description") or ""
    evidence_items = _coerce_evidence_items(raw.get("evidence"), str(evidence_value) if not isinstance(evidence_value, list) else "")
    evidence_text = evidence_items[0].value if evidence_items else str(evidence_value)
    severity = raw.get("severity", "info")
    status = raw.get("status")
    if not status:
        status = _status_from_legacy(raw.get("vuln_category") or vuln_category or "", normalize_severity(severity))

    url = raw.get("url") or raw.get("matched_at") or raw.get("matched") or raw.get("matched-at") or ""

    return Finding(
        id=raw.get("id") or raw.get("template-id") or raw.get("type") or "unknown-finding",
        scanner_name=raw.get("scanner_name") or raw.get("scanner") or raw.get("module_name") or scanner_name,
        url=url,
        parameter=raw.get("parameter") or raw.get("param") or "",
        severity=severity,
        evidence=evidence_text,
        output_path=raw.get("output_path") or "",
        vuln_category=vuln_category or raw.get("vuln_category") or severity_to_category(severity),
        name=raw.get("name") or raw.get("type") or "",
        description=raw.get("description") or evidence_text,
        matched_at=raw.get("matched_at") or raw.get("matched") or raw.get("matched-at") or url,
        payload=raw.get("payload") or raw.get("payload_used") or "",
        raw=raw.get("raw") or {},
        scan_id=raw.get("scan_id") or "",
        target=raw.get("target") or "",
        method=raw.get("method") or "GET",
        category=raw.get("category") or "",
        vuln_type=raw.get("vuln_type") or "",
        status=status,
        confidence=raw.get("confidence") or 0.0,
        evidence_items=evidence_items,
        payload_used=raw.get("payload_used") or raw.get("payload") or "",
        request_summary=raw.get("request_summary") or {},
        response_summary=raw.get("response_summary") or {},
        reproduction_steps=raw.get("reproduction_steps") or [],
        remediation=raw.get("remediation") or "",
        references=raw.get("references") or [],
        module_name=raw.get("module_name") or raw.get("scanner_name") or raw.get("scanner") or scanner_name,
        created_at=raw.get("created_at") or utc_now(),
        updated_at=raw.get("updated_at") or utc_now(),
    ).to_dict()


def dedupe_findings(findings: Iterable[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in findings:
        if not item:
            continue
        normalized = normalize_finding(item)
        key = finding_key(normalized)
        if key not in merged:
            merged[key] = normalized
            continue

        existing = merged[key]
        if existing.get("confidence", 0) < normalized.get("confidence", 0):
            existing["confidence"] = normalized["confidence"]
        if existing.get("status") != "confirmed" and normalized.get("status") == "confirmed":
            existing["status"] = "confirmed"
            existing["vuln_category"] = "confirmed vuln"
        for field_name in ("evidence", "reproduction_steps", "references"):
            if not existing.get(field_name) and normalized.get(field_name):
                existing[field_name] = normalized[field_name]
        for field_name in ("output_path", "payload_used", "payload", "remediation"):
            if not existing.get(field_name) and normalized.get(field_name):
                existing[field_name] = normalized[field_name]

    return list(merged.values())


def merge_findings(
    existing: Iterable[Finding | dict[str, Any]] | Finding | dict[str, Any] | None,
    incoming: Iterable[Finding | dict[str, Any]] | Finding | dict[str, Any] | None,
) -> list[dict[str, Any]]:
    def _items(value):
        if value is None:
            return []
        if isinstance(value, (Finding, dict)):
            return [value]
        return list(value)

    return dedupe_findings([*_items(existing), *_items(incoming)])


