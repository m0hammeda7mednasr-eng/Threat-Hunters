from __future__ import annotations

from datetime import datetime, timedelta, timezone

from database.db import mongo


def _empty_payload():
    return {
        "total_scans": 0,
        "completed_scans": 0,
        "unique_targets": 0,
        "vulnerable_targets": 0,
        "average_risk_score": 0,
        "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "total_findings": 0,
        "recent_scans": [],
        "monthly_trend": [],
    }


def _normalize_severity(value: str) -> str:
    severity = str(value or "").strip().lower()
    if severity == "critical":
        return "Critical"
    if severity == "high":
        return "High"
    if severity == "medium":
        return "Medium"
    if severity in {"low", "info", "informational", "recon"}:
        return "Low"
    return ""


def _count_severities(findings: list) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        label = _normalize_severity(finding.get("severity") or finding.get("status"))
        if label:
            counts[label] += 1
    return counts


def _scan_documents(limit: int = 500) -> list[dict]:
    if getattr(mongo, "db", None) is None:
        return []

    cursor = (
        mongo.db.scan_reports.find({})
        .sort("created_at", -1)
        .limit(max(1, min(limit, 500)))
    )
    return list(cursor)


def _risk_grade(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Moderate"
    if score > 0:
        return "Low"
    return "Minimal"


def _format_relative_time(value) -> str:
    if value is None:
        return "Recently"

    if hasattr(value, "tzinfo") and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    if not hasattr(value, "isoformat"):
        return "Recently"

    now = datetime.now(timezone.utc)
    delta = now - value
    if delta.days > 0:
        return f"{delta.days} day(s) ago"
    hours = delta.seconds // 3600
    if hours > 0:
        return f"{hours} hour(s) ago"
    minutes = max(delta.seconds // 60, 1)
    return f"{minutes} minute(s) ago"


def aggregate_scan_analytics(limit: int = 500) -> dict:
    scans = _scan_documents(limit)
    if not scans:
        return _empty_payload()

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_findings = 0
    risk_scores: list[int] = []
    targets: set[str] = set()
    vulnerable_targets: set[str] = set()
    completed_scans = 0
    recent_scans: list[dict] = []
    now = datetime.now(timezone.utc)
    last_7_days = 0

    for document in scans:
        findings = document.get("findings") if isinstance(document.get("findings"), list) else []
        counts = _count_severities(findings)
        for key, value in counts.items():
            severity_counts[key] += value
        total_findings += len(findings)

        target = str(document.get("target") or document.get("url") or "").strip()
        if target:
            targets.add(target)
            if counts["Critical"] or counts["High"]:
                vulnerable_targets.add(target)

        risk_score = document.get("risk_score")
        if isinstance(risk_score, (int, float)):
            risk_scores.append(max(0, min(100, int(round(float(risk_score))))))

        status = str(document.get("scan_status") or "completed").strip().lower()
        if status in {"completed", "done", "success"}:
            completed_scans += 1

        created_at = document.get("created_at")
        if hasattr(created_at, "tzinfo"):
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if created_at >= now - timedelta(days=7):
                last_7_days += 1

        recent_scans.append(
            {
                "report_id": document.get("report_id") or document.get("scan_id"),
                "target": target or "Unknown target",
                "risk_label": document.get("risk_label") or "No Risk",
                "risk_score": int(document.get("risk_score") or 0),
                "findings_count": len(findings),
                "critical_count": counts["Critical"],
                "high_count": counts["High"],
                "scan_status": document.get("scan_status") or "completed",
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else None,
            }
        )

    monthly_buckets: dict[str, int] = {}
    for document in scans:
        created_at = document.get("created_at")
        if not hasattr(created_at, "strftime"):
            continue
        label = created_at.strftime("%b")
        findings = document.get("findings") if isinstance(document.get("findings"), list) else []
        monthly_buckets[label] = monthly_buckets.get(label, 0) + len(findings)

    monthly_trend = [
        {"label": label, "value": monthly_buckets[label]}
        for label in sorted(monthly_buckets.keys(), key=lambda item: datetime.strptime(item, "%b"))
    ][-6:]

    average_risk_score = round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0

    return {
        "total_scans": len(scans),
        "completed_scans": completed_scans,
        "unique_targets": len(targets),
        "vulnerable_targets": len(vulnerable_targets),
        "average_risk_score": average_risk_score,
        "risk_grade": _risk_grade(average_risk_score),
        "severity_counts": severity_counts,
        "total_findings": total_findings,
        "recent_scans": recent_scans[:25],
        "scans_last_7_days": last_7_days,
        "monthly_trend": monthly_trend,
    }


def build_dashboard_stats() -> list[dict]:
    analytics = aggregate_scan_analytics()
    if analytics["total_scans"] == 0:
        return [
            {"label": "Overall Risk Score", "value": "0/100", "subtitle": "No scans recorded yet"},
            {"label": "Active Vulnerabilities", "value": "0", "subtitle": "Run scans to populate findings"},
            {"label": "Vulnerable Assets", "value": "0 of 0", "subtitle": "No scanned targets yet"},
            {"label": "Total Scans", "value": "0", "subtitle": "Waiting for the first scan"},
        ]

    severity = analytics["severity_counts"]
    return [
        {
            "label": "Overall Risk Score",
            "value": f"{analytics['average_risk_score']}/100",
            "subtitle": f"{analytics['risk_grade']} risk across completed scans",
        },
        {
            "label": "Active Vulnerabilities",
            "value": str(analytics["total_findings"]),
            "subtitle": f"Critical: {severity['Critical']} · High: {severity['High']}",
        },
        {
            "label": "Vulnerable Assets",
            "value": f"{analytics['vulnerable_targets']} of {analytics['unique_targets']}",
            "subtitle": "Targets with critical or high findings",
        },
        {
            "label": "Total Scans",
            "value": str(analytics["total_scans"]),
            "subtitle": f"{analytics['scans_last_7_days']} in the last 7 days",
        },
    ]


def build_security_metrics() -> list[dict]:
    analytics = aggregate_scan_analytics()
    severity = analytics["severity_counts"]
    total_scans = analytics["total_scans"]
    completed = analytics["completed_scans"]
    success_rate = round((completed / total_scans) * 100) if total_scans else 0
    avg_per_scan = round(analytics["total_findings"] / total_scans, 1) if total_scans else 0

    return [
        {"label": "Critical", "value": severity["Critical"], "subtitle": "Confirmed critical findings"},
        {"label": "High", "value": severity["High"], "subtitle": "High severity findings"},
        {"label": "Medium", "value": severity["Medium"], "subtitle": "Medium severity findings"},
        {"label": "Low", "value": severity["Low"], "subtitle": "Low and informational findings"},
        {"label": "Total Scans", "value": total_scans, "subtitle": f"{analytics['scans_last_7_days']} in the last 7 days"},
        {"label": "Success Rate", "value": f"{success_rate}%", "subtitle": "Completed scan rate"},
        {"label": "Total Vulnerabilities", "value": analytics["total_findings"], "subtitle": "Across all stored scans"},
        {"label": "Avg. per Scan", "value": str(avg_per_scan), "subtitle": "Findings per completed scan"},
    ]


def build_recent_activities() -> list[dict]:
    analytics = aggregate_scan_analytics()
    activities = []

    for scan in analytics["recent_scans"][:6]:
        created_at = scan.get("created_at")
        timestamp = None
        if created_at:
            try:
                timestamp = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
            except ValueError:
                timestamp = None

        activities.append(
            {
                "title": f"Scan completed for {scan['target']}",
                "detail": (
                    f"{scan['risk_label']} · {scan['findings_count']} finding(s) · "
                    f"{scan['critical_count']} critical · {scan['high_count']} high"
                ),
                "time": _format_relative_time(timestamp),
            }
        )

    if not activities:
        return [{"title": "No scan activity yet", "detail": "Completed scans will appear here automatically.", "time": "Now"}]

    return activities


def serialize_scan_as_admin_report(document: dict) -> dict:
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []
    severity = _count_severities(findings)
    created_at = document.get("created_at") or datetime.utcnow()
    report_id = document.get("report_id") or document.get("scan_id") or str(document.get("_id", ""))

    return {
        "id": report_id,
        "title": document.get("target") or document.get("url") or "Scan Report",
        "subtitle": f"{document.get('risk_label') or 'No Risk'} · {len(findings)} finding(s)",
        "date": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
        "size": "Live scan report",
        "type": "Scan",
        "status": document.get("scan_status") or "completed",
        "scanCount": 1,
        "vulnerabilities": len(findings),
        "critical": severity["Critical"],
        "high": severity["High"],
        "medium": severity["Medium"],
        "low": severity["Low"],
        "score": int(document.get("risk_score") or 0),
        "downloads": 0,
        "findings": [
            str(finding.get("title") or finding.get("name") or finding.get("vuln_type") or "Finding")
            for finding in findings[:8]
            if isinstance(finding, dict)
        ],
        "target": document.get("target") or document.get("url") or "",
        "report_id": report_id,
    }


def list_admin_scan_reports(limit: int = 25) -> list[dict]:
    scans = _scan_documents(limit)
    return [serialize_scan_as_admin_report(document) for document in scans[:limit]]
