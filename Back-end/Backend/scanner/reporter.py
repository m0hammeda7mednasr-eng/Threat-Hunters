import re
import subprocess
from pathlib import Path
from html import escape
from jinja2 import Environment

SNIPPET_LIMIT = 300

TEMPLATE = """\
**Scan Date:** {{ scan_time | default('N/A') }}
**Profile:** {{ profile | default('N/A') }}
{% if report_owner.display_name or report_owner.email %}
**Prepared For:** {{ report_owner.display_name or report_owner.email }}{% if report_owner.email and report_owner.display_name and report_owner.email != report_owner.display_name %} <{{ report_owner.email }}>{% endif %}
{% endif %}
{% if scan_provenance.scan_id %}
**Scan ID:** `{{ scan_provenance.scan_id }}`
{% endif %}

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

- The assessment used controlled, non-destructive techniques suitable for externally exposed web applications.
- Automated findings are weighted by evidence strength, exploit confidence, and business-facing exposure.
- Confirmed application risk requires reproducible evidence; candidate findings are retained for analyst validation.
- The report treats the target as a standard production-style web application with normal business-facing risk context.

{% if report_sections %}
## Executive Summary

{{ report_sections.executive_summary | default('Executive summary unavailable.') }}

{% if report_sections.key_risks %}
### Key Risks
{% for risk in report_sections.key_risks %}
- {{ risk }}
{% endfor %}
{% endif %}

{% if report_sections.recommendations %}
### Strategic Recommendations
{% for recommendation in report_sections.recommendations %}
- {{ recommendation }}
{% endfor %}
{% endif %}

{% if report_sections.limitations %}
### Report Notes
- {{ report_sections.limitations }}
{% endif %}

### Scan Execution Proof
- **Scan ID:** `{{ scan_provenance.scan_id | default('N/A') }}`
- **Report ID:** `{{ scan_provenance.report_id | default('N/A') }}`
- **Target:** `{{ scan_provenance.target | default(domain) }}`
- **Profile:** {{ profile | default('N/A') }}
- **Scan Time:** {{ scan_provenance.scan_time | default(scan_time) }}
{% if report_owner.display_name or report_owner.email %}
- **Prepared For:** {{ report_owner.display_name or report_owner.email }}{% if report_owner.email and report_owner.display_name and report_owner.email != report_owner.display_name %} <{{ report_owner.email }}>{% endif %}
{% endif %}

{% set proof = report_sections.generation_proof | default({}) %}
### Report Section Generation Proof
- **Generated By:** {{ proof.generated_by | default('local_report_section_builder') }}
- **Model:** `{{ proof.model | default('N/A') }}`
- **Generated At:** {{ proof.generated_at | default('N/A') }}
- **Evidence Fingerprint:** `{{ proof.evidence_fingerprint_sha256 | default('N/A') }}`
- **Narrative Fingerprint:** `{{ proof.narrative_fingerprint_sha256 | default('N/A') }}`
{% endif %}

{% if known_vulnerability_summary %}
## Known Vulnerability Intelligence

| Source | Count |
|--------|-------|
| Startup NVD/CISA context | {{ known_vulnerability_summary.startup_count | default(0) }} |
| Targeted technology matches | {{ known_vulnerability_summary.targeted_count | default(0) }} |

{% if known_vulnerability_summary.keywords %}
- **Detected technology keywords:** {{ known_vulnerability_summary.keywords | join(', ') }}
{% endif %}

{% if targeted_known_vulnerabilities %}
{% for vuln in targeted_known_vulnerabilities[:10] %}
- **{{ vuln.id }}**{% if vuln.matched_keyword %} for {{ vuln.matched_keyword }}{% endif %} - severity {{ vuln.severity | default('Unknown') }}, score {{ vuln.score | default(0) }}{% if vuln.kev %}, CISA KEV{% endif %}
  - {{ vuln.description | default('No description available.') }}
{% endfor %}
{% else %}
- No targeted NVD matches were found for detected technologies.
{% endif %}

{% if known_vulnerability_summary.errors %}
{% for error in known_vulnerability_summary.errors[:3] %}
- Lookup note: {{ error }}
{% endfor %}
{% endif %}
{% endif %}

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

SAMPLE_REPORT_TEMPLATE = """\
<h2>Summary for the Reader</h2>
<blockquote>
<p><strong>In plain language:</strong> {{ report_sections.reader_summary | default(reader_summary, true) }}</p>
<p><strong>Bottom line:</strong> {{ report_sections.bottom_line | default(bottom_line, true) }}</p>
</blockquote>

<h2>1. Executive Summary</h2>
<p>{{ report_sections.executive_summary | default('Executive summary unavailable.') }}</p>

<div class="table-grid">
<div>
<h3>Scan Metrics</h3>
<table>
<thead><tr><th>Metric</th><th>Value</th></tr></thead>
<tbody>
{% for row in scan_metrics %}
<tr><td>{{ row.label | e }}</td><td>{{ row.value | e }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>
<div>
<h3>Triage Breakdown</h3>
<table>
<thead><tr><th>Category</th><th>Value</th></tr></thead>
<tbody>
{% for row in triage_metrics %}
<tr><td>{{ row.label | e }}</td><td>{{ row.value | e }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>
</div>

<h3>Section Overview</h3>
<table>
<thead><tr><th>Section</th><th>Count</th><th>Notes</th></tr></thead>
<tbody>
{% for row in section_overview %}
<tr><td>{{ row.section | e }}</td><td>{{ row.count | e }}</td><td>{{ row.notes | e }}</td></tr>
{% endfor %}
</tbody>
</table>

<p class="report-note">Automated findings are weighted by evidence strength. Candidate findings remain validation items until a human analyst confirms exploitability.</p>

<h2>2. Confirmed Application Vulnerabilities</h2>
{% if confirmed_cards %}
{% for finding in confirmed_cards %}
<div class="finding-card">
<div class="finding-card-header">
<span class="severity severity-{{ finding.severity | lower }}">{{ finding.severity | upper }}</span>
<div>
<h3 class="finding-title">{{ finding.title | e }}</h3>
<p class="finding-meta"><code>{{ finding.evidence_id | e }}</code> · Source: {{ finding.module_name | e }}{% if finding.source_tool %} / {{ finding.source_tool | e }}{% endif %} · Status: {{ finding.status | e }} · Confidence: {{ finding.confidence_text | e }}</p>
</div>
</div>
<p class="finding-url"><span class="finding-label">Location</span> {{ finding.url or 'N/A' }}{% if finding.parameter %} <span class="finding-chip">parameter {{ finding.parameter | e }}</span>{% endif %}</p>
<p class="finding-detail"><span class="finding-label">Evidence</span> {{ finding.evidence_summary | e }}</p>
<p class="finding-detail"><span class="finding-label">Remediation</span> {{ finding.remediation | e }}</p>
{% if finding.guidance %}
<div class="finding-guidance">
{% if finding.guidance.explanation %}<p><span class="finding-label">Explanation</span> {{ finding.guidance.explanation | e }}</p>{% endif %}
{% if finding.guidance.impact %}<p><span class="finding-label">Impact</span> {{ finding.guidance.impact | e }}</p>{% endif %}
{% if finding.guidance.fix %}<p><span class="finding-label">Fix</span> {{ finding.guidance.fix | e }}</p>{% endif %}
{% if finding.guidance.validation %}<p><span class="finding-label">Verify</span> {{ finding.guidance.validation | e }}</p>{% endif %}
</div>
{% endif %}
</div>
{% endfor %}
{% else %}
<p>No confirmed application vulnerabilities recorded.</p>
{% endif %}

<h2>3. Candidate Findings (Needs Triage)</h2>
{% set candidate_cards = strong_candidate_cards + weak_candidate_cards %}
{% if candidate_cards %}
{% for finding in candidate_cards[:24] %}
<div class="finding-card finding-card-candidate">
<div class="finding-card-header">
<span class="severity severity-{{ finding.severity | lower }}">{{ finding.severity | upper }}</span>
<div>
<h3 class="finding-title">{{ finding.title | e }}</h3>
<p class="finding-meta"><code>{{ finding.evidence_id | e }}</code> · Source: {{ finding.module_name | e }}{% if finding.source_tool %} / {{ finding.source_tool | e }}{% endif %} · Confidence: {{ finding.confidence_text | e }}{% if finding.examples_count > 1 %} · Grouped examples: {{ finding.examples_count }}{% endif %}</p>
</div>
</div>
<p class="finding-url"><span class="finding-label">Location</span> {{ finding.url or 'N/A' }}{% if finding.parameter %} <span class="finding-chip">parameter {{ finding.parameter | e }}</span>{% endif %}</p>
<p class="finding-detail"><span class="finding-label">Why triage</span> {{ finding.evidence_summary | e }}</p>
<p class="finding-detail"><span class="finding-label">Next step</span> {{ finding.remediation | e }}</p>
{% if finding.guidance %}
<div class="finding-guidance">
{% if finding.guidance.explanation %}<p><span class="finding-label">Explanation</span> {{ finding.guidance.explanation | e }}</p>{% endif %}
{% if finding.guidance.impact %}<p><span class="finding-label">Impact</span> {{ finding.guidance.impact | e }}</p>{% endif %}
{% if finding.guidance.fix %}<p><span class="finding-label">Fix</span> {{ finding.guidance.fix | e }}</p>{% endif %}
{% if finding.guidance.validation %}<p><span class="finding-label">Verify</span> {{ finding.guidance.validation | e }}</p>{% endif %}
</div>
{% endif %}
</div>
{% endfor %}
{% else %}
<p>No candidate application findings recorded.</p>
{% endif %}

<h2>4. Security Header &amp; Configuration Findings</h2>
{% if security_header_cards %}
{% for finding in security_header_cards[:20] %}
<div class="finding-card finding-card-config">
<div class="finding-card-header">
<span class="severity severity-{{ finding.severity | lower }}">{{ finding.severity | upper }}</span>
<div>
<h3 class="finding-title">{{ finding.title | e }}</h3>
<p class="finding-meta"><code>{{ finding.evidence_id | e }}</code> · Source: {{ finding.module_name | e }}{% if finding.source_tool %} / {{ finding.source_tool | e }}{% endif %} · Status: {{ finding.status | e }} · Confidence: {{ finding.confidence_text | e }}</p>
</div>
</div>
<p class="finding-url"><span class="finding-label">Location</span> {{ finding.url or domain }}</p>
<p class="finding-detail"><span class="finding-label">Configuration issue</span> {{ finding.evidence_summary | e }}</p>
<p class="finding-detail"><span class="finding-label">Remediation</span> {{ finding.remediation | e }}</p>
{% if finding.guidance %}
<div class="finding-guidance">
{% if finding.guidance.explanation %}<p><span class="finding-label">Explanation</span> {{ finding.guidance.explanation | e }}</p>{% endif %}
{% if finding.guidance.impact %}<p><span class="finding-label">Impact</span> {{ finding.guidance.impact | e }}</p>{% endif %}
{% if finding.guidance.fix %}<p><span class="finding-label">Fix</span> {{ finding.guidance.fix | e }}</p>{% endif %}
{% if finding.guidance.validation %}<p><span class="finding-label">Verify</span> {{ finding.guidance.validation | e }}</p>{% endif %}
</div>
{% endif %}
</div>
{% endfor %}
{% else %}
<p>No security header or configuration findings recorded.</p>
{% endif %}

<h2>5. Recon Observations &amp; Discovered Forms</h2>
<p>Recon items: {{ recon_cards | length }} | Blocked tests: {{ blocked_cards | length }} | Inconclusive tests: {{ inconclusive_cards | length }}</p>
{% if recon_cards %}
<table>
<thead><tr><th>ID</th><th>Type</th><th>Location</th><th>Detail</th></tr></thead>
<tbody>
{% for finding in recon_cards[:24] %}
<tr><td>{{ finding.evidence_id | e }}</td><td>{{ finding.title | e }}</td><td>{{ finding.url or domain }}</td><td>{{ finding.evidence_summary | e }}</td></tr>
{% endfor %}
</tbody>
</table>
{% else %}
<p>No recon observations recorded.</p>
{% endif %}

{% if blocked_cards %}
<h3>Blocked Tests</h3>
<table>
<thead><tr><th>ID</th><th>Path</th><th>Reason</th></tr></thead>
<tbody>
{% for finding in blocked_cards[:12] %}
<tr><td>{{ finding.evidence_id | e }}</td><td>{{ finding.url or 'N/A' }}</td><td>{{ finding.evidence_summary | e }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}

{% if inconclusive_cards %}
<h3>Inconclusive Tests</h3>
<table>
<thead><tr><th>ID</th><th>Path</th><th>Reason</th></tr></thead>
<tbody>
{% for finding in inconclusive_cards[:12] %}
<tr><td>{{ finding.evidence_id | e }}</td><td>{{ finding.url or 'N/A' }}</td><td>{{ finding.evidence_summary | e }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>6. Target Profile &amp; Module Telemetry</h2>
<div class="table-grid">
<div>
<h3>Host Profile</h3>
<table>
<tbody>
{% for row in host_profile %}
<tr><th>{{ row.label | e }}</th><td>{{ row.value | e }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>
<div>
<h3>Module Timing &amp; Telemetry</h3>
<table>
<thead><tr><th>Module</th><th>Metric</th></tr></thead>
<tbody>
{% for row in module_telemetry %}
<tr><td>{{ row.module | e }}</td><td>{{ row.metric | e }}</td></tr>
{% endfor %}
</tbody>
</table>
</div>
</div>

<h2>7. Supplementary Scans</h2>
<table>
<thead><tr><th>Area</th><th>Result</th></tr></thead>
<tbody>
<tr><td>Nuclei Findings</td><td>{{ nuclei_summary | e }}</td></tr>
<tr><td>JS Secrets</td><td>{{ js_secret_summary | e }}</td></tr>
<tr><td>S3 Buckets</td><td>{{ s3_summary | e }}</td></tr>
<tr><td>Known Vulnerability Intelligence</td><td>{{ known_vulnerability_text | e }}</td></tr>
</tbody>
</table>
{% if targeted_known_vulnerabilities %}
<table>
<thead><tr><th>CVE</th><th>Matched Tech</th><th>Severity</th><th>Summary</th></tr></thead>
<tbody>
{% for vuln in targeted_known_vulnerabilities[:8] %}
<tr><td>{{ vuln.id | e }}</td><td>{{ vuln.matched_keyword | default('N/A') | e }}</td><td>{{ vuln.severity | default('Unknown') | e }} {{ vuln.score | default(0) }}</td><td>{{ vuln.description | default('No description available.') | e }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>8. Recommendations</h2>
{% if report_sections.recommendations %}
{% for recommendation in report_sections.recommendations %}
<p><strong>Priority {{ loop.index }}:</strong> {{ recommendation | e }}</p>
{% endfor %}
{% elif recommendations %}
{% for recommendation in recommendations %}
<p><strong>Priority {{ loop.index }}:</strong> {{ recommendation | e }}</p>
{% endfor %}
{% else %}
<p>No recommendations were attached to this scan.</p>
{% endif %}

<footer>
Report generated by Threat Hunters Scanner Engine - Source scan: {{ profile | e }} {{ domain | e }} {{ scan_id | e }} - AI narrative: {{ ai_narrative_label | e }}
</footer>
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
    if isinstance(confidence, str) and confidence.strip():
        confidence_text = confidence.strip()
    else:
        try:
            confidence_text = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_text = "unknown"
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
        "title": finding.get("title") or finding.get("name") or finding.get("id") or "Finding",
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


def _finding_guidance_lookup(report_sections: dict) -> dict:
    guidance_items = report_sections.get("finding_guidance") if isinstance(report_sections, dict) else []
    if not isinstance(guidance_items, list):
        return {}
    lookup = {}
    for item in guidance_items:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("evidence_id") or "").strip()
        if not evidence_id:
            continue
        lookup[evidence_id] = {
            "explanation": _redact_text(item.get("explanation"), 900),
            "impact": _redact_text(item.get("impact"), 700),
            "fix": _redact_text(item.get("fix"), 900),
            "validation": _redact_text(item.get("validation"), 700),
        }
    return lookup


def _attach_finding_guidance(cards: list[dict], guidance_lookup: dict) -> list[dict]:
    for card in cards:
        if not isinstance(card, dict):
            continue
        guidance = guidance_lookup.get(str(card.get("evidence_id") or "").strip())
        if guidance:
            card["guidance"] = guidance
        elif card.get("evidence_summary") or card.get("remediation"):
            card["guidance"] = {
                "explanation": _redact_text(
                    f"{card.get('title') or 'This finding'} was recorded from scanner evidence at the affected location. {card.get('evidence_summary') or ''}",
                    900,
                ),
                "impact": _redact_text(
                    "This issue can increase the likelihood of abuse against the affected endpoint or weaken the target's defensive posture if left unresolved.",
                    700,
                ),
                "fix": _redact_text(card.get("remediation") or "Apply the appropriate control for the vulnerability class and retest the affected request.", 900),
                "validation": _redact_text(
                    "After remediation, re-run the scan and manually repeat the affected request to confirm the original evidence no longer appears.",
                    700,
                ),
            }
    return cards


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


def _value_text(value, default: str = "N/A") -> str:
    if value in (None, ""):
        return default
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else default
    return str(value)


def _format_scan_time(value) -> str:
    text = str(value or "").strip()
    if not text:
        return "N/A"
    try:
        from datetime import datetime, timezone
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return text


def _reader_summary(report_data: dict, summary: dict) -> tuple[str, str]:
    domain = report_data.get("domain") or report_data.get("target") or "the target"
    confirmed_app = int(summary.get("confirmed_app_vulns") or 0)
    confirmed_headers = int(summary.get("security_header_findings") or 0)
    candidates = int(summary.get("candidate_findings") or summary.get("candidate_issues") or 0)
    if confirmed_app:
        first = (
            f"We ran an automated, non-damaging security scan of {domain}. "
            f"The scanner recorded {confirmed_app} confirmed application vulnerability record(s), "
            f"{confirmed_headers} confirmed header/configuration finding(s), and {candidates} candidate item(s) that need triage."
        )
        bottom = "Fix confirmed vulnerabilities first, then close header/configuration gaps and manually validate the candidate findings."
    else:
        first = (
            f"We ran an automated, non-damaging security scan of {domain}. "
            f"No confirmed application vulnerability was recorded, but the scanner found {confirmed_headers} header/configuration finding(s) "
            f"and {candidates} candidate item(s) that should be reviewed."
        )
        bottom = "No confirmed application break-in path is shown by this scan. Apply the recommended fixes, validate candidate findings, and re-scan."
    return first, bottom


def _module_telemetry_rows(telemetry: dict) -> list[dict]:
    modules = telemetry.get("modules", {}) if isinstance(telemetry, dict) else {}
    if not isinstance(modules, dict) or not modules:
        return [{"module": "N/A", "metric": "No useful module telemetry recorded."}]
    rows = []
    for module_name, data in modules.items():
        if not isinstance(data, dict):
            rows.append({"module": module_name, "metric": _value_text(data, "present")})
            continue
        pieces = []
        duration = data.get("duration_seconds")
        if duration not in (None, ""):
            try:
                pieces.append(f"{float(duration):.1f}s")
            except (TypeError, ValueError):
                pieces.append(str(duration))
        for key in ("urls_tested", "forms_tested", "payloads_sent", "candidates_count", "confirmed_count", "blocked_count", "inconclusive_count", "timeout_count", "errors_count"):
            value = data.get(key)
            if value not in (None, ""):
                pieces.append(f"{key.replace('_', ' ')}: {value}")
        rows.append({"module": module_name, "metric": ", ".join(pieces) if pieces else _value_text(data.get("status"), "present")})
    return rows


def _host_profile_rows(report_data: dict) -> list[dict]:
    hosts = (((report_data.get("stages") or {}).get("alive_probing") or {}).get("data") or [])
    first_host = hosts[0] if hosts and isinstance(hosts[0], dict) else {}
    tech = first_host.get("tech") or []
    ports = first_host.get("ports") or []
    return [
        {"label": "Status", "value": _value_text(first_host.get("status") or report_data.get("http_status"))},
        {"label": "Tech Stack", "value": _value_text(tech, "Not detected")},
        {"label": "WAF", "value": first_host.get("waf_name") if first_host.get("is_waf") else "None detected"},
        {"label": "Open Ports", "value": _value_text(ports)},
    ]


def _render_context(report_data: dict) -> dict:
    candidates = report_data.get("candidates", [])
    strong_candidates = report_data.get("strong_candidates")
    weak_candidates = report_data.get("weak_candidates")
    if strong_candidates is None and weak_candidates is None:
        strong_candidates = [finding for finding in candidates if _candidate_strength(finding) == "strong"]
        weak_candidates = [finding for finding in candidates if _candidate_strength(finding) != "strong"]

    telemetry = report_data.get("telemetry", {})
    summary = report_data.get("summary", {}) if isinstance(report_data.get("summary"), dict) else {}
    report_sections = report_data.get("report_sections", {})
    report_sections = report_sections if isinstance(report_sections, dict) else {}
    guidance_lookup = _finding_guidance_lookup(report_sections)
    known_summary = report_data.get("known_vulnerability_summary", {})
    known_summary = known_summary if isinstance(known_summary, dict) else {}
    targeted_known = ((report_data.get("known_vulnerabilities") or {}).get("targeted") or {}).get("items", [])
    reader_summary, bottom_line = _reader_summary(report_data, summary)
    scan_metrics = [
        {"label": "Subdomains Found", "value": summary.get("subdomains_found", 0)},
        {"label": "Alive Hosts", "value": summary.get("alive_hosts", 0)},
        {"label": "Open Services", "value": summary.get("open_services", 0)},
        {"label": "Endpoints Found", "value": summary.get("endpoints_found", 0)},
        {"label": "Total Normalized Findings", "value": summary.get("total_findings", 0)},
        {"label": "Nuclei Findings", "value": summary.get("nuclei_findings_count", summary.get("nuclei_findings", 0))},
        {"label": "Legacy Vulns Entries", "value": summary.get("legacy_vulns_count", 0)},
        {"label": "JS Secrets", "value": summary.get("secrets_found", 0)},
        {"label": "Confirmed App Vulnerabilities", "value": summary.get("confirmed_app_vulns", 0)},
        {"label": "Confirmed Header/Config Findings", "value": summary.get("security_header_findings", 0)},
    ]
    triage_metrics = [
        {"label": "Candidate Findings", "value": summary.get("candidate_findings", summary.get("candidate_issues", 0))},
        {"label": "Strong App Candidates", "value": summary.get("strong_app_candidates", 0)},
        {"label": "Weak / Needs Triage", "value": summary.get("weak_app_candidates", summary.get("weak_candidate_findings", 0))},
        {"label": "Recon Items", "value": summary.get("recon_items", summary.get("informational_findings", 0))},
        {"label": "Inconclusive Tests", "value": summary.get("inconclusive_tests", 0)},
        {"label": "Blocked Tests", "value": summary.get("blocked_tests", 0)},
        {"label": "Nuclei Profile", "value": summary.get("nuclei_template_profile") or "N/A"},
        {"label": "Nuclei Safety Gate", "value": summary.get("nuclei_profile_safety_gate") or "N/A"},
        {"label": "Correlated Findings", "value": summary.get("correlated_findings_count", summary.get("correlated_findings", 0))},
    ]
    section_overview = [
        {"section": "Core Findings", "count": int(summary.get("confirmed_app_vulns") or 0) + int(summary.get("strong_app_candidates") or 0) + int(summary.get("weak_app_candidates") or 0), "notes": "Threat Hunters app findings only; excludes Nuclei and headers."},
        {"section": "Nuclei Support Findings", "count": summary.get("nuclei_findings_count", summary.get("nuclei_findings", 0)), "notes": "Optional deep-mode evidence, reported separately."},
        {"section": "Correlated Findings", "count": summary.get("correlated_findings_count", summary.get("correlated_findings", 0)), "notes": "Same route/category or host-level issue; support only."},
        {"section": "Security Headers", "count": summary.get("security_header_findings", 0), "notes": "Header/config checks are not counted as app-vulnerability proof."},
        {"section": "Recon Observations", "count": summary.get("recon_items", summary.get("informational_findings", 0)), "notes": "Technology, exposure, and supporting observations."},
        {"section": "Profile Safety Gate", "count": summary.get("nuclei_profile_safety_gate") or "N/A", "notes": f"Effective profile: {summary.get('nuclei_template_profile') or 'N/A'}; target type: {summary.get('nuclei_target_type') or 'N/A'}."},
    ]
    if known_summary.get("enabled") is False:
        known_vulnerability_text = "AI_search disabled for this scan."
    elif targeted_known:
        known_vulnerability_text = f"{len(targeted_known)} targeted NVD/CISA match(es) for detected technologies."
    else:
        known_vulnerability_text = "No targeted NVD/CISA matches were found for detected technologies."
    proof = report_sections.get("generation_proof", {}) if isinstance(report_sections.get("generation_proof"), dict) else {}
    generated_by = str(proof.get("generated_by") or "")
    model = report_sections.get("model") or proof.get("model") or ""
    ai_narrative_label = "DeepSeek Pro" if "DeepSeek" in generated_by else "Threat Hunters local fallback"
    if model:
        ai_narrative_label = f"{ai_narrative_label} ({model})"
    confirmed_cards = _attach_finding_guidance(
        [_compact_finding(item) for item in report_data.get("confirmed_app_vulns", report_data.get("findings", []))],
        guidance_lookup,
    )
    strong_candidate_cards = _attach_finding_guidance(
        [_compact_finding(item) for item in report_data.get("strong_app_candidates", (strong_candidates or []))],
        guidance_lookup,
    )
    weak_candidate_cards = _attach_finding_guidance(
        [_compact_finding(item) for item in report_data.get("weak_app_candidates", (weak_candidates or []))],
        guidance_lookup,
    )
    security_header_cards = _attach_finding_guidance(
        [_compact_finding(item) for item in report_data.get("security_headers", [])],
        guidance_lookup,
    )

    return {
        "domain": report_data.get("domain", "Unknown"),
        "scan_time": report_data.get("scan_time", "N/A"),
        "scan_id": report_data.get("scan_id", "N/A"),
        "profile": report_data.get("profile", "N/A"),
        "report_owner": report_data.get("report_owner", {}),
        "scan_provenance": {
            "scan_id": report_data.get("scan_id"),
            "report_id": report_data.get("report_id"),
            "target": report_data.get("target") or report_data.get("domain"),
            "scan_time": report_data.get("scan_time"),
        },
        "summary": summary,
        "stages": report_data.get("stages", {}),
        "confirmed_cards": confirmed_cards,
        "strong_candidate_cards": strong_candidate_cards,
        "weak_candidate_cards": weak_candidate_cards,
        "security_header_cards": security_header_cards,
        "recon_cards": [_compact_finding(item) for item in report_data.get("recon", [])],
        "inconclusive_cards": [_compact_finding(item) for item in report_data.get("inconclusive", [])],
        "blocked_cards": [_compact_finding(item) for item in report_data.get("blocked_tests", [])],
        "nuclei_cards": [_compact_finding(item) for item in report_data.get("nuclei_findings", report_data.get("stages", {}).get("vulnerability_scanning", {}).get("nuclei_findings", []))],
        "telemetry_lines": [_telemetry_line(name, value) for name, value in telemetry.items()] if isinstance(telemetry, dict) else [],
        "report_sections": report_sections,
        "reader_summary": reader_summary,
        "bottom_line": bottom_line,
        "scan_metrics": scan_metrics,
        "triage_metrics": triage_metrics,
        "section_overview": section_overview,
        "host_profile": _host_profile_rows(report_data),
        "module_telemetry": _module_telemetry_rows(telemetry),
        "recommendations": report_data.get("recommendations", []),
        "known_vulnerability_summary": known_summary,
        "targeted_known_vulnerabilities": targeted_known,
        "known_vulnerability_text": known_vulnerability_text,
        "nuclei_summary": f"{summary.get('nuclei_findings_count', summary.get('nuclei_findings', 0))} Nuclei finding(s) recorded.",
        "js_secret_summary": "No secrets found." if int(summary.get("secrets_found") or 0) == 0 else f"{summary.get('secrets_found')} possible secret(s) found.",
        "s3_summary": "No exposed S3 buckets found." if not (((report_data.get("stages") or {}).get("s3_buckets") or {}).get("data") or []) else "S3 bucket observations recorded.",
        "ai_narrative_label": ai_narrative_label,
    }


def _render_markdown(report_data: dict) -> str:
    env = Environment()
    template = env.from_string(SAMPLE_REPORT_TEMPLATE)
    context = _render_context(report_data)
    return template.render(**context)


def _render_html_document(report_data: dict) -> str:
    import markdown as md_lib
    md_content = _render_markdown(report_data)
    html_body = md_lib.markdown(md_content, extensions=["tables", "fenced_code"])
    domain = escape(str(report_data.get("domain", "Unknown")))
    scan_time = escape(_format_scan_time(report_data.get("scan_time")))
    profile = escape(str(report_data.get("profile") or report_data.get("scan_mode") or "N/A"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Scan Report - {domain}</title>
    <style>
        * {{ box-sizing: border-box; }}
        html {{ background: #ffffff; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.43; max-width: 980px; margin: 0 auto; padding: 62px 0 54px; background: #ffffff; color: #243142; font-size: 12.8px; }}
        .report-header {{ background: #174b9b; color: #ffffff; border-radius: 7px; padding: 22px 26px 21px; margin-bottom: 30px; }}
        .report-header h1 {{ margin: 0 0 10px; color: #ffffff; font-size: 25px; line-height: 1.12; border: 0; padding: 0; }}
        .report-header p {{ margin: 5px 0 0; color: #dce9fb; font-size: 12.5px; }}
        .report-header strong {{ color: #ffffff; }}
        main {{ background: #ffffff; }}
        h2 {{ color: #0d4493; border-bottom: 2px solid #1753a5; padding-bottom: 7px; margin: 28px 0 12px; font-size: 20px; line-height: 1.2; page-break-after: avoid; }}
        h3 {{ color: #26384f; margin: 22px 0 9px; font-size: 15px; page-break-after: avoid; }}
        p {{ margin: 8px 0; }}
        blockquote {{ margin: 0 0 28px; padding: 12px 16px 11px; border: 1px solid #bdcddd; border-left: 4px solid #27aeea; border-radius: 5px; background: #eef5ff; color: #243142; }}
        blockquote p {{ margin: 6px 0; }}
        .table-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; align-items: start; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0 18px; page-break-inside: auto; }}
        th {{ background: #edf3f8; color: #1d2c3d; font-weight: 700; }}
        th, td {{ padding: 8px 10px; border: 1px solid #c4ced8; text-align: left; vertical-align: top; }}
        tr:nth-child(even) td {{ background: #f8fafc; }}
        code {{ background: #eef2f7; color: #1d2c3d; padding: 1px 5px; border-radius: 3px; font-family: Consolas, monospace; font-size: 12px; }}
        strong {{ color: #1f2a37; }}
        .finding-line {{ margin: 10px 0 13px; break-inside: avoid; }}
        .finding-line p {{ margin: 3px 0; }}
        .finding-card {{ margin: 16px 0 20px; padding: 16px 18px 17px; border: 1px solid #cbd7e4; border-left: 5px solid #1753a5; border-radius: 7px; background: #ffffff; box-shadow: 0 1px 0 rgba(15, 23, 42, 0.04); break-inside: avoid; page-break-inside: avoid; }}
        .finding-card-candidate {{ border-left-color: #b45309; }}
        .finding-card-config {{ border-left-color: #2563eb; }}
        .finding-card-header {{ display: flex; gap: 12px; align-items: flex-start; margin-bottom: 11px; }}
        .finding-title {{ margin: 0 0 5px; color: #172033; font-size: 18px; line-height: 1.25; }}
        .finding-meta {{ margin: 0; color: #536173; font-size: 14px; line-height: 1.45; }}
        .finding-url {{ margin: 10px 0 10px; padding: 10px 12px; border-radius: 5px; background: #f3f7fb; color: #1d2c3d; font-size: 15px; line-height: 1.48; overflow-wrap: anywhere; }}
        .finding-detail {{ margin: 9px 0 0; color: #26384f; font-size: 15.2px; line-height: 1.55; }}
        .finding-guidance {{ margin-top: 12px; padding: 11px 12px; border-radius: 6px; background: #f8fbff; border: 1px solid #d8e4f2; }}
        .finding-guidance p {{ margin: 7px 0; color: #203047; font-size: 15.1px; line-height: 1.55; }}
        .finding-label {{ display: inline-block; margin-right: 8px; color: #0d4493; font-weight: 800; text-transform: uppercase; font-size: 12px; letter-spacing: 0.04em; }}
        .finding-chip {{ display: inline-block; margin-left: 8px; padding: 3px 8px; border-radius: 999px; background: #e7eef8; color: #23344d; font-size: 12.6px; font-weight: 700; }}
        .severity {{ display: inline-block; min-width: 52px; padding: 4px 8px; border-radius: 4px; color: #ffffff; background: #6b7280; font-size: 11.5px; font-weight: 800; text-align: center; letter-spacing: 0.02em; flex: 0 0 auto; }}
        .severity-critical {{ background: #7f1d1d; }}
        .severity-high {{ background: #b91c1c; }}
        .severity-medium {{ background: #b45309; }}
        .severity-low {{ background: #2563eb; }}
        .severity-info {{ background: #64748b; }}
        .report-note {{ color: #36465a; font-size: 12px; }}
        footer {{ margin-top: 28px; padding-top: 12px; border-top: 1px solid #c4ced8; color: #475569; font-size: 11px; }}
        @media print {{ body {{ padding: 0; max-width: none; }} .table-grid {{ grid-template-columns: 1fr 1fr; }} }}
        @page {{ size: A4; margin: 15mm; }}
    </style>
</head>
<body>
<section class="report-header">
  <h1>Web Application Security Scan Report</h1>
  <p>Target: <strong>{domain}</strong></p>
  <p>Scan Date: {scan_time} | Profile: <strong>{profile}</strong> | Engine: Threat Hunters Scanner Engine</p>
</section>
<main>
{html_body}
</main>
</body>
</html>"""


def generate_markdown_report(report_data: dict, output_path: str):
    try:
        md_content = _render_markdown(report_data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
    except Exception as e:
        from .utils import log
        log.error(f"[reporter] Failed to generate markdown: {e}")


def generate_html_report(report_data: dict, output_path: str):
    try:
        full_html = _render_html_document(report_data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)
    except Exception as e:
        from .utils import log
        log.error(f"[reporter] Failed to generate html: {e}")


def _browser_candidates() -> list[str]:
    import os

    candidates = [
        os.getenv("REPORT_PDF_BROWSER", ""),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    return [candidate for candidate in candidates if candidate and Path(candidate).exists()]


def _generate_browser_pdf_report(report_data: dict, output_path: str) -> bool:
    browsers = _browser_candidates()
    if not browsers:
        return False
    html_path = str(Path(output_path).with_suffix(".print.html"))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_render_html_document(report_data))
    html_url = Path(html_path).resolve().as_uri()
    for browser in browsers:
        command = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-pdf-header-footer",
            f"--print-to-pdf={output_path}",
            html_url,
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
            if result.returncode == 0 and Path(output_path).exists() and Path(output_path).stat().st_size > 1000:
                return True
        except Exception:
            continue
    return False


def _pdf_clean(value) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "-",
        "\u2022": "-",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", "replace").decode("latin-1")


def _pdf_escape(value) -> str:
    return _pdf_clean(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_wrap(value, max_chars: int) -> list[str]:
    words = _pdf_clean(value).split()
    lines = []
    current = []
    current_len = 0
    for word in words:
        extra = len(word) + (1 if current else 0)
        if current and current_len + extra > max_chars:
            lines.append(" ".join(current))
            current = [word]
            current_len = len(word)
        else:
            current.append(word)
            current_len += extra
    if current:
        lines.append(" ".join(current))
    return lines or [""]


class _NativePdfReport:
    page_width = 595
    page_height = 842
    margin = 44

    def __init__(self):
        self.pages = []
        self.commands = []
        self.y = self.page_height - self.margin
        self.page_no = 0
        self._new_page()

    def _new_page(self):
        if self.commands:
            self.pages.append(self.commands)
        self.page_no += 1
        self.commands = []
        self.y = self.page_height - self.margin
        self.rect(0, 0, self.page_width, self.page_height, (0.98, 0.99, 1.0))
        self.text("Threat Hunters Security Report", self.margin, 24, 8, "F2", (0.35, 0.4, 0.5))
        self.text(f"Page {self.page_no}", self.page_width - self.margin - 30, 24, 8, "F1", (0.35, 0.4, 0.5))

    def finish(self):
        if self.commands:
            self.pages.append(self.commands)
            self.commands = []
        return self._build_pdf()

    def ensure(self, height: float):
        if self.y - height < self.margin + 30:
            self._new_page()

    def color(self, rgb):
        return f"{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f}"

    def rect(self, x, y, w, h, fill, stroke=None):
        self.commands.append("q")
        self.commands.append(f"{self.color(fill)} rg")
        if stroke:
            self.commands.append(f"{self.color(stroke)} RG 1 w")
            self.commands.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re B")
        else:
            self.commands.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")
        self.commands.append("Q")

    def text(self, value, x, y, size=10, font="F1", color=(0.08, 0.1, 0.16)):
        self.commands.append("q")
        self.commands.append(f"{self.color(color)} rg")
        self.commands.append(f"BT /{font} {size:.2f} Tf {x:.2f} {y:.2f} Td ({_pdf_escape(value)}) Tj ET")
        self.commands.append("Q")

    def wrapped(self, value, x, width, size=10, font="F1", leading=None, color=(0.08, 0.1, 0.16), prefix=""):
        leading = leading or size + 4
        max_chars = max(18, int(width / (size * 0.5)))
        lines = _pdf_wrap(value, max_chars)
        for index, line in enumerate(lines):
            self.ensure(leading + 4)
            label = f"{prefix}{line}" if index == 0 else f"{' ' * len(prefix)}{line}"
            self.text(label, x, self.y, size, font, color)
            self.y -= leading
        return self.y

    def section(self, title):
        self.ensure(46)
        self.y -= 10
        self.text(title, self.margin, self.y, 15, "F2", (0.1, 0.27, 0.55))
        self.y -= 8
        self.rect(self.margin, self.y, self.page_width - self.margin * 2, 1.2, (0.72, 0.79, 0.9))
        self.y -= 20

    def metric(self, x, y, w, label, value):
        value = _pdf_clean(value)
        value_size = 15 if len(value) <= 9 else 12 if len(value) <= 16 else 10
        self.rect(x, y, w, 54, (1, 1, 1), (0.82, 0.86, 0.92))
        self.text(label, x + 10, y + 34, 8, "F2", (0.42, 0.47, 0.56))
        self.text(value[:24], x + 10, y + 14, value_size, "F2", (0.05, 0.09, 0.18))

    def _build_pdf(self) -> bytes:
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [] /Count 0 >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        ]
        page_refs = []
        for page in self.pages:
            content = "\n".join(page).encode("latin-1", "replace")
            content_obj = len(objects) + 2
            page_obj = len(objects) + 1
            page_refs.append(page_obj)
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.page_width} {self.page_height}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_obj} 0 R >>".encode("latin-1")
            )
            objects.append(f"<< /Length {len(content)} >>\nstream\n".encode("latin-1") + content + b"\nendstream")
        objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{ref} 0 R' for ref in page_refs)}] /Count {len(page_refs)} >>".encode("latin-1")

        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{index} 0 obj\n".encode("latin-1"))
            output.extend(obj)
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("latin-1"))
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
        output.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("latin-1")
        )
        return bytes(output)


def _generate_native_pdf_report(report_data: dict, output_path: str) -> bool:
    summary = report_data.get("summary", {}) if isinstance(report_data.get("summary"), dict) else {}
    sections = report_data.get("report_sections", {})
    sections = sections if isinstance(sections, dict) else {}
    proof = sections.get("generation_proof", {}) if isinstance(sections.get("generation_proof"), dict) else {}
    findings = report_data.get("confirmed_app_vulns") or report_data.get("findings") or []
    known_items = ((report_data.get("known_vulnerabilities") or {}).get("targeted") or {}).get("items") or []
    recommendations = sections.get("recommendations") or report_data.get("recommendations") or []
    key_risks = sections.get("key_risks") or []
    risk_label = report_data.get("risk_label") or summary.get("risk_label") or "Risk Pending"
    risk_score = report_data.get("risk_score") or summary.get("risk_score") or 0
    target = report_data.get("target") or report_data.get("domain") or "Unknown target"

    pdf = _NativePdfReport()
    pdf.rect(0, 642, pdf.page_width, 200, (0.05, 0.08, 0.14))
    pdf.text("THREAT HUNTERS SECURITY ASSESSMENT", pdf.margin, 778, 9, "F2", (0.5, 0.78, 1.0))
    pdf.wrapped(target, pdf.margin, 500, 24, "F2", 30, (1, 1, 1))
    pdf.wrapped("Report sections, known-vulnerability intelligence, scanner evidence, and remediation priorities.", pdf.margin, 480, 11, "F1", 15, (0.78, 0.84, 0.92))
    metric_y = 654
    metric_w = 95
    for index, (label, value) in enumerate([
        ("Risk", risk_label),
        ("Score", f"{risk_score}/100"),
        ("Findings", summary.get("total_findings", 0)),
        ("Confirmed", summary.get("confirmed_findings", summary.get("confirmed_app_vulns", 0))),
        ("Writer", "DeepSeek" if "DeepSeek" in str((sections.get("generation_proof") or {}).get("generated_by") or "") else {"local_template_writer": "local", "external_writer": "external"}.get(str(sections.get("provider") or "local"), str(sections.get("provider") or "local")[:18])),
    ]):
        pdf.metric(pdf.margin + index * (metric_w + 8), metric_y, metric_w, label, _pdf_clean(value)[:22])
    pdf.y = 616

    pdf.section("Report Section Proof")
    pdf.wrapped(f"Generated by {proof.get('generated_by') or 'local_report_section_builder'}. Evidence SHA256: {proof.get('evidence_fingerprint_sha256') or 'N/A'}. Narrative SHA256: {proof.get('narrative_fingerprint_sha256') or 'N/A'}.", pdf.margin, 500, 9, "F1", color=(0.18, 0.22, 0.3))

    pdf.section("Executive Summary")
    pdf.wrapped(sections.get("executive_summary") or "Executive summary unavailable.", pdf.margin, 500, 10.5, "F1", 15)

    pdf.section("Key Risks")
    if key_risks:
        for item in key_risks[:6]:
            pdf.wrapped(item, pdf.margin + 12, 488, 10, "F1", 14, prefix="- ")
    else:
        pdf.wrapped("No report-section risk narrative was available for this run.", pdf.margin, 500, 10)

    pdf.section("Strategic Recommendations")
    for index, item in enumerate(recommendations[:8], start=1):
        pdf.wrapped(item, pdf.margin + 14, 486, 10, "F1", 14, prefix=f"{index}. ")
    if not recommendations:
        pdf.wrapped("No recommendations were attached to this scan.", pdf.margin, 500, 10)

    pdf.section("Known Vulnerability Intelligence")
    if known_items:
        for item in known_items[:8]:
            title = f"{item.get('id', 'CVE')} - severity {item.get('severity', 'Unknown')}, score {item.get('score', 0)}"
            pdf.wrapped(title, pdf.margin + 12, 488, 10, "F2", 14, prefix="- ")
            pdf.wrapped(item.get("description") or "No description available.", pdf.margin + 24, 476, 8.8, "F1", 12, color=(0.24, 0.29, 0.38))
    else:
        pdf.wrapped("No targeted NVD matches were found for detected technologies.", pdf.margin, 500, 10)

    pdf.section("Finding Evidence")
    if findings:
        for index, finding in enumerate(findings[:12], start=1):
            if not isinstance(finding, dict):
                continue
            title = finding.get("title") or finding.get("name") or finding.get("id") or "Finding"
            severity = finding.get("severity") or finding.get("status") or "Info"
            location = finding.get("url") or finding.get("endpoint") or finding.get("matched_at") or "location not supplied"
            remediation = finding.get("remediation") or finding.get("recommendation") or "Review evidence and remediate according to severity."
            pdf.wrapped(f"{index}. [{severity}] {title}", pdf.margin, 500, 10, "F2", 14)
            pdf.wrapped(f"Where: {location}. Fix: {remediation}", pdf.margin + 14, 486, 8.8, "F1", 12, color=(0.24, 0.29, 0.38))
    else:
        pdf.wrapped("No confirmed finding records were attached to this report.", pdf.margin, 500, 10)

    with open(output_path, "wb") as handle:
        handle.write(pdf.finish())
    return True


def generate_pdf_report(report_data: dict, output_path: str) -> bool:
    try:
        if _generate_browser_pdf_report(report_data, output_path):
            return True
    except Exception as e:
        from .utils import log
        log.warning(f"[reporter] Browser PDF generation unavailable: {e}")
    try:
        from weasyprint import HTML
        HTML(string=_render_html_document(report_data), base_url=".").write_pdf(output_path)
        return True
    except Exception as e:
        from .utils import log
        log.warning(f"[reporter] WeasyPrint PDF unavailable; using native styled PDF renderer: {e}")
    try:
        return _generate_native_pdf_report(report_data, output_path)
    except Exception as e:
        from .utils import log
        log.error(f"[reporter] Failed to generate native styled pdf: {e}")
        return False
