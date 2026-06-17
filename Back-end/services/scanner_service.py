from datetime import datetime
from urllib.parse import urlparse
import re
import socket
import ssl

import requests


SECURITY_HEADERS = {
    "content-security-policy": {
        "severity": "High",
        "title": "Missing Content Security Policy",
        "recommendation": "Add a strict Content-Security-Policy header to reduce XSS and injection impact.",
    },
    "strict-transport-security": {
        "severity": "High",
        "title": "Missing HSTS",
        "recommendation": "Add Strict-Transport-Security for HTTPS sites to enforce encrypted connections.",
    },
    "x-frame-options": {
        "severity": "Medium",
        "title": "Missing clickjacking protection",
        "recommendation": "Add X-Frame-Options or frame-ancestors in CSP.",
    },
    "x-content-type-options": {
        "severity": "Medium",
        "title": "Missing MIME sniffing protection",
        "recommendation": "Add X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "severity": "Low",
        "title": "Missing Referrer Policy",
        "recommendation": "Add Referrer-Policy to limit sensitive URL leakage.",
    },
    "permissions-policy": {
        "severity": "Low",
        "title": "Missing Permissions Policy",
        "recommendation": "Add Permissions-Policy to reduce browser feature exposure.",
    },
}

SEVERITY_POINTS = {
    "Critical": 28,
    "High": 18,
    "Medium": 10,
    "Low": 4,
}


def _normalize_url(raw_target):
    value = str(raw_target or "").strip()
    if not value:
        raise ValueError("Website URL is required")

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not _is_valid_hostname(parsed.hostname):
        raise ValueError("Enter a valid website URL, for example https://example.com")

    return value


def _is_valid_hostname(hostname):
    host = str(hostname or "").lower()
    if host == "localhost":
        return True

    parts = host.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return all(0 <= int(part) <= 255 for part in parts)

    return "." in host and ".." not in host and all(parts) and len(parts[-1]) >= 2


def _risk_label(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _certificate_summary(parsed):
    if parsed.scheme != "https":
        return None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as secure_sock:
                cert = secure_sock.getpeercert()
    except Exception:
        return {
            "valid": False,
            "issuer": "Unknown",
            "expires": None,
        }

    issuer = ", ".join("=".join(pair) for group in cert.get("issuer", []) for pair in group)
    return {
        "valid": True,
        "issuer": issuer or "Unknown",
        "expires": cert.get("notAfter"),
    }


def _make_finding(code, severity, title, description, recommendation):
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
    }


def _make_check(name, status, details, evidence=None):
    return {
        "name": name,
        "status": status,
        "details": details,
        "evidence": evidence or "",
    }


def _header_snapshot(headers):
    interesting_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "cache-control",
        "set-cookie",
        "server",
        "x-powered-by",
    ]

    return {
        header: headers.get(header, "Missing")
        for header in interesting_headers
    }


def _response_text(response):
    content_type = response.headers.get("content-type", "").lower()
    if "text/html" not in content_type and "application/xhtml" not in content_type:
        return ""

    try:
        return response.text[:250000]
    except Exception:
        return ""


def _analyze_body(text, final_url):
    findings = []
    checks = []

    if not text:
        checks.append(_make_check("HTML body analysis", "Skipped", "The response is not HTML or the body could not be decoded."))
        return findings, checks

    lower_text = text.lower()
    parsed = urlparse(final_url)

    form_count = len(re.findall(r"<form\b", lower_text))
    password_fields = len(re.findall(r'type=["\']?password', lower_text))
    hidden_csrf = re.search(r'name=["\']?(csrf|csrf_token|_token|authenticity_token)', lower_text)
    checks.append(_make_check(
        "Form inventory",
        "Review" if form_count else "Passed",
        f"Detected {form_count} form(s) and {password_fields} password field(s).",
    ))

    if form_count and not hidden_csrf:
        findings.append(_make_finding(
            "csrf-token-not-detected",
            "Medium",
            "CSRF token not detected in forms",
            "The HTML contains forms, but no common CSRF token field name was detected in the page source.",
            "Add anti-CSRF tokens to state-changing forms and verify them server-side.",
        ))

    if parsed.scheme == "https" and re.search(r'(src|href)=["\']http://', lower_text):
        findings.append(_make_finding(
            "mixed-content-reference",
            "Medium",
            "Possible mixed content reference",
            "The HTTPS page references one or more HTTP resources in src/href attributes.",
            "Serve all scripts, images, styles, and links over HTTPS.",
        ))

    if re.search(r'(api[_-]?key|secret|token|password)\s*[:=]', lower_text):
        findings.append(_make_finding(
            "possible-secret-pattern",
            "High",
            "Possible secret-like string in page source",
            "The scanner found token/secret/password style patterns in the HTML response.",
            "Review the rendered source and remove credentials, tokens, or sensitive configuration from client output.",
        ))

    checks.append(_make_check(
        "Client-side exposure review",
        "Review",
        "Checked HTML for mixed content, common secret patterns, and basic form hygiene.",
    ))
    return findings, checks


def _check_cookie_flags(headers):
    findings = []
    checks = []
    cookies = headers.get("set-cookie")

    if not cookies:
        checks.append(_make_check("Cookie security", "Passed", "No Set-Cookie header was returned on the scanned response."))
        return findings, checks

    cookie_text = cookies.lower()
    checks.append(_make_check("Cookie security", "Review", "Set-Cookie header detected; checking common security flags."))

    if "secure" not in cookie_text:
        findings.append(_make_finding(
            "cookie-missing-secure",
            "Medium",
            "Cookie missing Secure flag",
            "At least one cookie appears to be set without the Secure flag.",
            "Add Secure to cookies so browsers only send them over HTTPS.",
        ))
    if "httponly" not in cookie_text:
        findings.append(_make_finding(
            "cookie-missing-httponly",
            "Medium",
            "Cookie missing HttpOnly flag",
            "At least one cookie appears to be set without HttpOnly.",
            "Add HttpOnly to session cookies to reduce script-based theft impact.",
        ))
    if "samesite" not in cookie_text:
        findings.append(_make_finding(
            "cookie-missing-samesite",
            "Low",
            "Cookie missing SameSite attribute",
            "At least one cookie appears to be set without SameSite.",
            "Add SameSite=Lax or SameSite=Strict where appropriate.",
        ))

    return findings, checks


def _safe_endpoint_check(session, parsed, path, label):
    base = f"{parsed.scheme}://{parsed.netloc}"
    url = f"{base}{path}"

    try:
        response = session.get(url, timeout=6, allow_redirects=False, headers={"User-Agent": "ThreatHuntersScanner/1.0"})
    except requests.RequestException as exc:
        return _make_check(label, "Skipped", f"Could not request {path}: {exc}")

    status = response.status_code
    if status in {200, 401, 403}:
        return _make_check(label, "Review", f"{path} returned HTTP {status}.", url)
    if status in {301, 302, 307, 308}:
        return _make_check(label, "Info", f"{path} redirected with HTTP {status}.", response.headers.get("location", url))
    return _make_check(label, "Passed", f"{path} returned HTTP {status}.", url)


def _endpoint_checks(session, final_url):
    parsed = urlparse(final_url)
    endpoints = [
        ("/robots.txt", "robots.txt"),
        ("/sitemap.xml", "sitemap.xml"),
        ("/.well-known/security.txt", "security.txt"),
        ("/admin", "Admin surface"),
        ("/login", "Login surface"),
    ]
    return [_safe_endpoint_check(session, parsed, path, label) for path, label in endpoints]


def start_scan(data):
    payload = data or {}
    target = _normalize_url(payload.get("target") or payload.get("url"))
    scan_mode = str(payload.get("scan_mode") or payload.get("mode") or "quick").lower()
    parsed = urlparse(target)
    started_at = datetime.utcnow()

    findings = []

    session = requests.Session()

    try:
        response = session.get(
            target,
            timeout=12 if scan_mode == "quick" else 18,
            allow_redirects=True,
            headers={"User-Agent": "ThreatHuntersScanner/1.0"},
        )
    except requests.RequestException as exc:
        raise ValueError(f"Could not reach target: {exc}") from exc

    headers = {key.lower(): value for key, value in response.headers.items()}
    checks = [
        _make_check("Target reachability", "Passed", f"Target returned HTTP {response.status_code}.", response.url),
        _make_check("Redirect handling", "Info", f"{len(response.history)} redirect(s) followed."),
    ]

    if parsed.scheme != "https":
        findings.append(_make_finding(
            "plain-http",
            "High",
            "Site is not using HTTPS",
            "The target was scanned over plain HTTP, which exposes traffic to interception.",
            "Redirect all traffic to HTTPS and enable HSTS.",
        ))
    else:
        checks.append(_make_check("HTTPS transport", "Passed", "The submitted target uses HTTPS."))

    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_make_finding(
                f"missing-{header}",
                meta["severity"],
                meta["title"],
                f"The {header} response header was not present.",
                meta["recommendation"],
            ))
        else:
            checks.append(_make_check(meta["title"], "Passed", f"{header} is present.", headers.get(header)))

    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        findings.append(_make_finding(
            "technology-disclosure",
            "Low",
            "Technology header disclosure",
            f"The response exposes X-Powered-By: {powered_by}.",
            "Remove technology disclosure headers from production responses.",
        ))
    if server_header:
        checks.append(_make_check("Server fingerprint", "Review", "Server header is visible.", server_header))

    if response.status_code >= 500:
        findings.append(_make_finding(
            "server-error",
            "Medium",
            "Server returned an error",
            f"The target returned HTTP {response.status_code}.",
            "Review server logs and avoid exposing unstable endpoints.",
        ))

    cookie_findings, cookie_checks = _check_cookie_flags(headers)
    body_findings, body_checks = _analyze_body(_response_text(response), response.url)
    findings.extend(cookie_findings)
    findings.extend(body_findings)
    checks.extend(cookie_checks)
    checks.extend(body_checks)

    endpoint_checks = _endpoint_checks(session, response.url) if scan_mode == "deep" else [
        _safe_endpoint_check(session, urlparse(response.url), "/.well-known/security.txt", "security.txt"),
        _safe_endpoint_check(session, urlparse(response.url), "/robots.txt", "robots.txt"),
    ]

    for check in endpoint_checks:
        if check["name"] == "Admin surface" and check["status"] == "Review":
            findings.append(_make_finding(
                "admin-surface-detected",
                "Low",
                "Administrative surface may be exposed",
                f"The {check['name']} check returned a reachable response: {check['details']}",
                "Confirm administrative paths require authentication, rate limiting, and monitoring.",
            ))
        checks.append(check)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity_counts[finding["severity"]] += 1

    risk_score = min(
        100,
        sum(SEVERITY_POINTS[finding["severity"]] for finding in findings),
    )
    risk = _risk_label(risk_score)
    completed_at = datetime.utcnow()

    report_id = f"RPT-{completed_at.strftime('%Y%m%d%H%M%S')}"
    duration = max((completed_at - started_at).total_seconds(), 0.1)

    return {
        "id": report_id,
        "reference": report_id.replace("RPT-", "TH-"),
        "target": target,
        "url": response.url,
        "status": "Completed",
        "scan_mode": scan_mode,
        "http_status": response.status_code,
        "server": server_header or "Not disclosed",
        "content_type": response.headers.get("content-type", "Unknown"),
        "content_length": response.headers.get("content-length", str(len(response.content or b""))),
        "tls": _certificate_summary(urlparse(response.url)),
        "headers": _header_snapshot(headers),
        "risk": risk,
        "risk_label": f"{risk} Risk",
        "risk_score": risk_score,
        "score": f"{risk_score}/100",
        "duration": f"{duration:.1f}s",
        "date": completed_at.strftime("%Y-%m-%d"),
        "time": completed_at.strftime("%H:%M"),
        "created_at": completed_at.isoformat() + "Z",
        "findings": findings,
        "checks": checks,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "headers_checked": list(SECURITY_HEADERS.keys()),
            "redirects": len(response.history),
            "checks_run": len(checks),
            "passed_checks": len([check for check in checks if check["status"] == "Passed"]),
            "review_checks": len([check for check in checks if check["status"] == "Review"]),
        },
        "recommendations": list(dict.fromkeys(finding["recommendation"] for finding in findings))[:10],
    }
