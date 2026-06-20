from datetime import datetime, timedelta, timezone

import requests

from utils.cwe_mapper import map_cwe


FALLBACK_CVES = [
    {
        "id": "CVE-2026-23734",
        "severity": "Critical",
        "score": 9.8,
        "cwe": "CWE-287",
        "category": "Authentication Bypass",
        "published": "2026-05-20T20:16:36.027",
        "description": "Authentication bypass in a popular wiki platform can expose protected content.",
    },
    {
        "id": "CVE-2026-20253",
        "severity": "Critical",
        "score": 9.8,
        "cwe": "CWE-306",
        "category": "Missing Authentication",
        "published": "2026-06-18T00:00:00.000",
        "description": "An issue in enterprise software can allow unauthorized access to sensitive interfaces.",
    },
    {
        "id": "CVE-2026-54420",
        "severity": "High",
        "score": 8.8,
        "cwe": "CWE-79",
        "category": "Cross-Site Scripting",
        "published": "2026-06-15T00:00:00.000",
        "description": "A plugin issue could let attackers inject script content into management flows.",
    },
    {
        "id": "CVE-2026-48907",
        "severity": "High",
        "score": 8.6,
        "cwe": "CWE-89",
        "category": "SQL Injection",
        "published": "2026-06-16T00:00:00.000",
        "description": "An input validation flaw could permit database access through crafted requests.",
    },
]


def extract_cvss(metrics):
    severity = "Unknown"
    score = 0

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key) or []
        if not entries:
            continue

        metric = entries[0]
        cvss = metric.get("cvssData", {})
        severity = cvss.get("baseSeverity") or metric.get("baseSeverity") or "Unknown"
        score = cvss.get("baseScore", 0) or metric.get("baseScore", 0) or 0
        break

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0

    return severity, score


def parse_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def parse_cwe(cve):
    weaknesses = cve.get("weaknesses", [])
    if not weaknesses:
        return "Unknown"

    descriptions = weaknesses[0].get("description", [])
    if descriptions:
        return descriptions[0].get("value", "Unknown")

    return "Unknown"


def get_latest_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 200,
    }

    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code != 200:
            return FALLBACK_CVES

        data = response.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            severity, score = extract_cvss(cve.get("metrics", {}))
            cwe_id = parse_cwe(cve)

            results.append(
                {
                    "id": cve.get("id"),
                    "severity": severity,
                    "score": score,
                    "cwe": cwe_id,
                    "category": map_cwe(cwe_id),
                    "published": cve.get("published"),
                    "description": parse_description(cve),
                }
            )

        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results[:20] if results else FALLBACK_CVES

    except Exception as e:
        print("NVD ERROR:", e)
        return FALLBACK_CVES
