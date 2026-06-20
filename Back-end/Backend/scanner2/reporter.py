import re
from jinja2 import Environment

SNIPPET_LIMIT = 300

TEMPLATE = """\
**Scan Date:** {{ scan_time | default('N/A') }}
**Profile:** {{ profile | default('N/A') }}

| Metric | Value |
|--------|-------|
| Subdomains Found | {{ summary.subdomains_found | default(0) }} |
| Alive Hosts | {{ summary.alive_hosts | default(0) }} |
| Open Services | {{ summary.open_services | default(0) }} |
| Endpoints Found | {{ summary.endpoints_found | default(0) }} |
| Total Normalized Findings | {{ summary.total_findings | default(0) }} |
| Nuclei Findings | {{ summary.nuclei_findings_count | default(summary.nuclei_findings | default(0)) }} |
| Nuclei Raw Findings | {{ summary.nuclei_raw_findings_count | default(0) }} |
| Nuclei Profile Used | {{ summary.nuclei_template_profile | default('N/A') or 'N/A' }} |
| Nuclei Safety Gate | {{ summary.nuclei_profile_safety_gate | default('N/A') or 'N/A' }} |
| Nuclei Target Type | {{ summary.nuclei_target_type | default('N/A') or 'N/A' }} |
| Correlated ReconTool/Nuclei Findings | {{ summary.correlated_findings_count | default(summary.correlated_findings | default(0)) }} |
| Legacy Vulns Entries | {{ summary.legacy_vulns_count | default(0) }} |
| JS Secrets | {{ summary.secrets_found | default(0) }} |
| Confirmed App Vulnerabilities | {{ summary.confirmed_app_vulns | default(0) }} |
| Confirmed Header/Config Findings | {{ summary.security_header_findings | default(0) }} |
| Candidate Findings | {{ summary.candidate_findings | default(summary.candidate_issues | default(0)) }} |
| Strong App Candidates | {{ summary.strong_app_candidates | default(summary.strong_candidate_findings | default(0)) }} |
| Weak App Candidates / Needs Triage | {{ summary.weak_app_candidates | default(summary.weak_candidate_findings | default(0)) }} |
| Recon Items | {{ summary.recon_items | default(summary.informational_findings | default(0)) }} |
| Inconclusive Tests | {{ summary.inconclusive_tests | default(0) }} |
| Blocked Tests | {{ summary.blocked_tests | default(0) }} |

| Section | Count | Notes |
|---------|-------|-------|
| Core Findings | {{ (summary.confirmed_app_vulns | default(0)) + (summary.strong_app_candidates | default(0)) + (summary.weak_app_candidates | default(0)) }} | ReconTool app findings only; excludes Nuclei and headers. |
| Nuclei Support Findings | {{ summary.nuclei_findings_count | default(summary.nuclei_findings | default(0)) }} | Optional Deep-mode evidence, reported separately. |
| Nuclei Raw Matches | {{ summary.nuclei_raw_findings_count | default(0) }} | Parser input count before report grouping/dedupe. |
| Correlated Findings | {{ summary.correlated_findings_count | default(summary.correlated_findings | default(0)) }} | Same route/category or same host-level issue; support only. |
| Security Headers | {{ summary.security_header_findings | default(0) }} | Header/config checks are not counted as app-vuln proof. |
| Recon Observations | {{ summary.recon_items | default(summary.informational_findings | default(0)) }} | Technology, exposure, and supporting observations. |
| Profile Safety Gate | {{ summary.nuclei_profile_safety_gate | default('N/A') or 'N/A' }} | Effective profile: {{ summary.nuclei_template_profile | default('N/A') or 'N/A' }}; target type: {{ summary.nuclei_target_type | default('N/A') or 'N/A' }}. |

- Public online testing is intentionally safe and non-destructive.
- Nuclei support does not promote findings to confirmed app vulnerabilities by itself.
- Confirmed app-vuln proof requires stronger evidence than route, reflection, or host-level support alone.
- Results are reference/smoke evidence for authorized targets, not exhaustive coverage.

{% if confirmed_cards %}
{% for finding in confirmed_cards %}
- **Evidence ID:** `{{ finding.evidence_id }}`
- **Source:** {{ finding.module_name }}{% if finding.source_tool %} / {{ finding.source_tool }}{% endif %}{% if finding.template_id %} / `{{ finding.template_id }}`{% endif %}
- **Matched URL:** `{{ finding.url or 'N/A' }}`
- **Status:** {{ finding.status }} / confidence {{ finding.confidence_text }}
- **Parameter:** `{{ finding.parameter or 'N/A' }}`
- **Evidence Summary:** {{ finding.evidence_summary }}
- **Safe Reproduction:** {{ finding.reproduction_summary }}
- **Remediation:** {{ finding.remediation }}
{% endfor %}
{% else %}
*No confirmed app vulnerabilities recorded.*
{% endif %}

{% if strong_candidate_cards %}
{% for finding in strong_candidate_cards %}
- **[{{ finding.severity | upper }}] {{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}`{% if finding.parameter %} parameter `{{ finding.parameter }}`{% endif %}; confidence {{ finding.confidence_text }}{% if finding.examples_count > 1 %}; grouped examples: {{ finding.examples_count }}{% endif %}
  - {{ finding.evidence_summary }}
{% endfor %}
{% else %}
*No strong app candidates recorded.*
{% endif %}

{% if weak_candidate_cards %}
{% for finding in weak_candidate_cards %}
- **[{{ finding.severity | upper }}] {{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}`{% if finding.parameter %} parameter `{{ finding.parameter }}`{% endif %}; confidence {{ finding.confidence_text }}{% if finding.examples_count > 1 %}; grouped examples: {{ finding.examples_count }}{% endif %}
  - {{ finding.evidence_summary }}
{% endfor %}
{% else %}
*No weak app candidates recorded.*
{% endif %}

{% if security_header_cards %}
{% for finding in security_header_cards %}
- **[{{ finding.severity | upper }}] {{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}`; status {{ finding.status }}; confidence {{ finding.confidence_text }}
  - {{ finding.evidence_summary }}
{% endfor %}
{% else %}
*No security-header findings recorded.*
{% endif %}

- **Recon items:** {{ recon_cards | length }}
- **Blocked tests:** {{ blocked_cards | length }}
- **Inconclusive tests:** {{ inconclusive_cards | length }}

{% if recon_cards %}
{% for finding in recon_cards[:20] %}
- **{{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}`
  - **Source:** {{ finding.module_name }}{% if finding.source_tool %} / {{ finding.source_tool }}{% endif %}{% if finding.template_id %} / `{{ finding.template_id }}`{% endif %}; status {{ finding.status }}; severity {{ finding.severity }}; confidence {{ finding.confidence_text }}
  - **Evidence Summary:** {{ finding.evidence_summary }}
{% endfor %}
{% endif %}

{% if blocked_cards %}
{% for finding in blocked_cards %}
- **{{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}` - {{ finding.evidence_summary }}
{% endfor %}
{% endif %}

{% if inconclusive_cards %}
{% for finding in inconclusive_cards %}
- **{{ finding.title }}** `{{ finding.evidence_id }}` at `{{ finding.url or 'N/A' }}` - {{ finding.evidence_summary }}
{% endfor %}
{% endif %}

{% if telemetry_lines %}
{% for line in telemetry_lines %}
- {{ line }}
{% endfor %}
{% else %}
*No useful module telemetry recorded.*
{% endif %}

{% set hosts = stages.alive_probing.data | default([]) %}
{% if hosts %}
{% for host in hosts %}
- **Status:** {{ host.status | default('N/A') }}
- **Tech Stack:** {{ host.tech | join(', ') if host.tech else 'Not detected' }}
- **WAF:** {{ host.waf_name if host.is_waf else 'None detected' }}
- **Open Ports:** {{ host.ports | join(', ') if host.ports else 'N/A' }}
{% endfor %}
{% else %}
*No alive hosts recorded.*
{% endif %}

{% if nuclei_cards %}
{% for finding in nuclei_cards %}
- **[{{ finding.severity | upper }}] {{ finding.title }}** `{{ finding.evidence_id }}`{% if finding.template_id %} / `{{ finding.template_id }}`{% endif %}
  - Matched URL: `{{ finding.url or 'N/A' }}`
  - Evidence Summary: {{ finding.evidence_summary }}
{% endfor %}
{% else %}
*No Nuclei findings recorded.*
{% endif %}

{% set secrets = stages.js_secrets.data | default([]) %}
{% if secrets %}
{% for secret in secrets %}
- **{{ secret.type | default('Unknown') }}** at `{{ secret.url | default('N/A') }}`
  - Match: `{{ secret.match[:120] if secret.match else 'N/A' }}`
{% endfor %}
{% else %}
*No secrets found.*
{% endif %}

{% set s3 = stages.s3_buckets.data | default([]) %}
{% if s3 %}
{% for bucket in s3 %}
- `{{ bucket.name | default('N/A') }}` - **{{ bucket.status | default('N/A') }}** {% if bucket.listable %}PUBLICLY LISTABLE{% endif %}
{% endfor %}
{% else %}
*No exposed S3 buckets found.*
{% endif %}

---
*Report generated by ReconTool Dragon Engine*
"""

REDACTION_PATTERNS = [
    re.compile(r"(?is)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END .*?PRIVATE KEY(?: BLOCK)?-----"),
    re.compile(r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|password|passwd|pwd|secret|sessionid)\s*[:=]\s*['\"]?[^'\"\s,;]+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
]


def _redact_text(value: object, limit: int = SNIPPET_LIMIT) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = REDACTION_PATTERNS[0].sub("<redacted-private-key>", text)
    text = REDACTION_PATTERNS[2].sub("Bearer <redacted>", text)
    text = REDACTION_PATTERNS[3].sub("<redacted-jwt>", text)
    text = REDACTION_PATTERNS[1].sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<redacted-email>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _first_evidence_text(finding: dict) -> str:
    evidence = finding.get("evidence") or finding.get("evidence_items") or ""
    if isinstance(evidence, list) and evidence:
        first = evidence[0]
        if isinstance(first, dict):
            return str(first.get("value") or "")
        return str(first)
    if isinstance(evidence, dict):
        return str(evidence.get("value") or "")
    return str(evidence or "")


def _candidate_strength(finding: dict) -> str:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    strength = str(finding.get("candidate_strength") or raw.get("candidate_strength") or "").lower()
    if strength in {"strong", "weak"}:
        return strength
    try:
        confidence = float(finding.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    return "strong" if confidence >= 0.6 else "weak"


def _compact_finding(finding: dict) -> dict:
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    confidence = finding.get("confidence") or 0
    try:
        confidence_text = f"{float(confidence):.2f}"
    except (TypeError, ValueError):
        confidence_text = "0.00"
    evidence_summary = (
        finding.get("evidence_summary")
        or raw.get("ai_ready_evidence_summary")
        or _first_evidence_text(finding)
        or finding.get("description")
        or (finding.get("response_summary", {}) or {}).get("snippet")
        or "No concise evidence summary available."
    )
    reproduction = " ".join(finding.get("reproduction_steps") or []) or "See normalized evidence."
    return {
        "evidence_id": finding.get("evidence_id") or raw.get("evidence_id") or finding.get("id", ""),
        "title": finding.get("name") or finding.get("id") or "Finding",
        "status": finding.get("status", ""),
        "severity": finding.get("severity", "info"),
        "confidence_text": confidence_text,
        "url": finding.get("url") or finding.get("matched_at") or "",
        "parameter": finding.get("parameter") or "",
        "module_name": finding.get("module_name") or finding.get("scanner_name") or "",
        "source_tool": finding.get("source_tool") or raw.get("source_tool") or finding.get("scanner_name") or "",
        "template_id": raw.get("template-id") or raw.get("template_id") or finding.get("template-id") or "",
        "examples_count": int(finding.get("examples_count") or raw.get("examples_count") or 1),
        "evidence_summary": _redact_text(evidence_summary),
        "reproduction_summary": _redact_text(reproduction),
        "remediation": _redact_text(finding.get("remediation") or "Review and remediate according to the finding type."),
        "candidate_strength": _candidate_strength(finding),
    }


def _telemetry_line(module_name: str, telemetry) -> str:
    if not isinstance(telemetry, dict):
        return f"**{module_name}:** present"
    numeric_keys = (
        "requests", "requests_sent", "urls_tested", "targets_tested", "forms_tested",
        "payloads_sent", "findings_count", "candidates_count", "confirmed_count",
        "blocked_count", "inconclusive_count", "errors_count", "timeout_count",
        "duration", "duration_seconds", "elapsed_ms", "module_noise_score",
    )
    parts = []
    for key in numeric_keys:
        value = telemetry.get(key)
        if value not in ("", None):
            parts.append(f"{key}={value}")
    if "samples" in telemetry and isinstance(telemetry["samples"], list):
        parts.append(f"samples={len(telemetry['samples'])}")
    return f"**{module_name}:** " + (", ".join(parts) if parts else "present")


def _render_context(report_data: dict) -> dict:
    candidates = report_data.get("candidates", [])
    strong_candidates = report_data.get("strong_candidates")
    weak_candidates = report_data.get("weak_candidates")
    if strong_candidates is None and weak_candidates is None:
        strong_candidates = [finding for finding in candidates if _candidate_strength(finding) == "strong"]
        weak_candidates = [finding for finding in candidates if _candidate_strength(finding) != "strong"]

    telemetry = report_data.get("telemetry", {})
    return {
        "domain": report_data.get("domain", "Unknown"),
        "scan_time": report_data.get("scan_time", "N/A"),
        "profile": report_data.get("profile", "N/A"),
        "summary": report_data.get("summary", {}),
        "stages": report_data.get("stages", {}),
        "confirmed_cards": [_compact_finding(item) for item in report_data.get("confirmed_app_vulns", report_data.get("findings", []))],
        "strong_candidate_cards": [_compact_finding(item) for item in report_data.get("strong_app_candidates", (strong_candidates or []))],
        "weak_candidate_cards": [_compact_finding(item) for item in report_data.get("weak_app_candidates", (weak_candidates or []))],
        "security_header_cards": [_compact_finding(item) for item in report_data.get("security_headers", [])],
        "recon_cards": [_compact_finding(item) for item in report_data.get("recon", [])],
        "inconclusive_cards": [_compact_finding(item) for item in report_data.get("inconclusive", [])],
        "blocked_cards": [_compact_finding(item) for item in report_data.get("blocked_tests", [])],
        "nuclei_cards": [_compact_finding(item) for item in report_data.get("nuclei_findings", report_data.get("stages", {}).get("vulnerability_scanning", {}).get("nuclei_findings", []))],
        "telemetry_lines": [_telemetry_line(name, value) for name, value in telemetry.items()] if isinstance(telemetry, dict) else [],
    }


def generate_markdown_report(report_data: dict, output_path: str):
    try:
        env = Environment()
        template = env.from_string(TEMPLATE)
        context = _render_context(report_data)
        md_content = template.render(**context)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
    except Exception as e:
        from .utils import log
        log.error(f"[reporter] Failed to generate markdown: {e}")


def generate_html_report(report_data: dict, output_path: str):
    try:
        import markdown as md_lib
        env = Environment()
        template = env.from_string(TEMPLATE)
        context = _render_context(report_data)
        md_content = template.render(**context)
        html_body = md_lib.markdown(md_content, extensions=["tables", "fenced_code"])
        domain = report_data.get("domain", "Unknown")

        full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dragon Report: {domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.7; max-width: 1100px; margin: 0 auto; padding: 30px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #e74c3c; border-bottom: 2px solid #e74c3c; padding-bottom: 8px; }}
        h2 {{ color: #58a6ff; border-bottom: 1px solid #21262d; padding-bottom: 4px; margin-top: 40px; }}
        h3 {{ color: #ffa657; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #161b22; color: #58a6ff; padding: 10px 14px; text-align: left; border: 1px solid #30363d; }}
        td {{ padding: 8px 14px; border: 1px solid #30363d; }}
        tr:nth-child(even) {{ background: #161b22; }}
        code {{ background: #161b22; color: #79c0ff; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; }}
        hr {{ border: 0; border-top: 1px solid #21262d; margin: 30px 0; }}
        em {{ color: #8b949e; }}
        strong {{ color: #f0f6fc; }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)
    except Exception as e:
        from .utils import log
        log.error(f"[reporter] Failed to generate html: {e}")
