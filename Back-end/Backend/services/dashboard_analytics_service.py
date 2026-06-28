from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Lock

from database.db import mongo

SCAN_REPORTS_LIST_PROJECTION = {
    "_id": 1,
    "report_id": 1,
    "scan_id": 1,
    "target": 1,
    "url": 1,
    "risk_score": 1,
    "risk_label": 1,
    "scan_status": 1,
    "created_at": 1,
    "summary": 1,
    "findings": {"$slice": 3},
}

ANALYTICS_CACHE_TTL_SECONDS = 30
_analytics_cache_lock = Lock()
_analytics_cache = {"expires_at": None, "payload": None}
_admin_reports_cache = {"expires_at": None, "payload": None, "limit": None}


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
        "scans_last_7_days": 0,
    }


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


def _summary_severity_counts(summary: dict | None) -> dict[str, int]:
    payload = summary if isinstance(summary, dict) else {}
    severity = payload.get("severity_counts") if isinstance(payload.get("severity_counts"), dict) else {}
    return {
        "Critical": int(severity.get("Critical", 0) or 0),
        "High": int(severity.get("High", 0) or 0),
        "Medium": int(severity.get("Medium", 0) or 0),
        "Low": int(severity.get("Low", 0) or 0) + int(severity.get("Info", 0) or 0),
    }


def _summary_total_findings(summary: dict | None) -> int:
    payload = summary if isinstance(summary, dict) else {}
    return int(payload.get("total_findings", 0) or 0)


def _scan_reports_cursor(limit: int = 25):
    safe_limit = max(1, min(int(limit or 25), 100))
    cursor = mongo.db.scan_reports.find({}, SCAN_REPORTS_LIST_PROJECTION)
    if hasattr(cursor, "allow_disk_use"):
        cursor = cursor.allow_disk_use(True)
    return cursor.sort("created_at", -1).limit(safe_limit)


def _recent_scan_documents(limit: int = 25) -> list[dict]:
    if getattr(mongo, "db", None) is None:
        return []
    return list(_scan_reports_cursor(limit))


def _aggregate_totals() -> dict:
    if getattr(mongo, "db", None) is None:
        return {}

    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    pipeline = [
        {
            "$project": {
                "target": {"$ifNull": ["$target", "$url"]},
                "risk_score": {"$ifNull": ["$risk_score", 0]},
                "scan_status": {"$toLower": {"$ifNull": ["$scan_status", "completed"]}},
                "created_at": "$created_at",
                "total_findings": {"$ifNull": ["$summary.total_findings", 0]},
                "critical": {"$ifNull": ["$summary.severity_counts.Critical", 0]},
                "high": {"$ifNull": ["$summary.severity_counts.High", 0]},
                "medium": {"$ifNull": ["$summary.severity_counts.Medium", 0]},
                "low": {
                    "$add": [
                        {"$ifNull": ["$summary.severity_counts.Low", 0]},
                        {"$ifNull": ["$summary.severity_counts.Info", 0]},
                    ]
                },
            }
        },
        {
            "$group": {
                "_id": None,
                "total_scans": {"$sum": 1},
                "completed_scans": {
                    "$sum": {
                        "$cond": [
                            {"$in": ["$scan_status", ["completed", "done", "success"]]},
                            1,
                            0,
                        ]
                    }
                },
                "total_findings": {"$sum": "$total_findings"},
                "critical": {"$sum": "$critical"},
                "high": {"$sum": "$high"},
                "medium": {"$sum": "$medium"},
                "low": {"$sum": "$low"},
                "risk_score_sum": {"$sum": "$risk_score"},
                "targets": {"$addToSet": "$target"},
                "vulnerable_targets_raw": {
                    "$addToSet": {
                        "$cond": [
                            {"$gt": [{"$add": ["$critical", "$high"]}, 0]},
                            "$target",
                            None,
                        ]
                    }
                },
                "scans_last_7_days": {
                    "$sum": {
                        "$cond": [
                            {"$gte": ["$created_at", seven_days_ago]},
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]

    result = list(mongo.db.scan_reports.aggregate(pipeline, allowDiskUse=True))
    return result[0] if result else {}


def _cache_is_fresh(entry: dict, *, limit: int | None = None) -> bool:
    expires_at = entry.get("expires_at")
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        return False
    if limit is not None and entry.get("limit") != limit:
        return False
    return entry.get("payload") is not None


def aggregate_scan_analytics(limit: int = 25) -> dict:
    if _cache_is_fresh(_analytics_cache):
        return _analytics_cache["payload"]

    with _analytics_cache_lock:
        if _cache_is_fresh(_analytics_cache):
            return _analytics_cache["payload"]

        totals = _aggregate_totals()
        if not totals:
            payload = _empty_payload()
        else:
            recent_documents = _recent_scan_documents(limit)
            recent_scans = []
            monthly_buckets: dict[str, int] = {}

            for document in recent_documents:
                summary = document.get("summary")
                counts = _summary_severity_counts(summary)
                findings_count = _summary_total_findings(summary)
                target = str(document.get("target") or document.get("url") or "").strip() or "Unknown target"
                created_at = document.get("created_at")

                if hasattr(created_at, "strftime"):
                    label = created_at.strftime("%b")
                    monthly_buckets[label] = monthly_buckets.get(label, 0) + findings_count

                recent_scans.append(
                    {
                        "report_id": document.get("report_id") or document.get("scan_id"),
                        "target": target,
                        "risk_label": document.get("risk_label") or "No Risk",
                        "risk_score": int(document.get("risk_score") or 0),
                        "findings_count": findings_count,
                        "critical_count": counts["Critical"],
                        "high_count": counts["High"],
                        "scan_status": document.get("scan_status") or "completed",
                        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else None,
                    }
                )

            monthly_trend = [
                {"label": label, "value": monthly_buckets[label]}
                for label in sorted(monthly_buckets.keys(), key=lambda item: datetime.strptime(item, "%b"))
            ][-6:]

            total_scans = int(totals.get("total_scans", 0) or 0)
            average_risk_score = round((totals.get("risk_score_sum", 0) or 0) / total_scans) if total_scans else 0
            all_targets = [target for target in totals.get("targets", []) if target]
            vulnerable_targets = [target for target in totals.get("vulnerable_targets_raw", []) if target]

            payload = {
                "total_scans": total_scans,
                "completed_scans": int(totals.get("completed_scans", 0) or 0),
                "unique_targets": len(set(all_targets)),
                "vulnerable_targets": len(set(vulnerable_targets)),
                "average_risk_score": average_risk_score,
                "risk_grade": _risk_grade(average_risk_score),
                "severity_counts": {
                    "Critical": int(totals.get("critical", 0) or 0),
                    "High": int(totals.get("high", 0) or 0),
                    "Medium": int(totals.get("medium", 0) or 0),
                    "Low": int(totals.get("low", 0) or 0),
                },
                "total_findings": int(totals.get("total_findings", 0) or 0),
                "recent_scans": recent_scans[:25],
                "monthly_trend": monthly_trend,
                "scans_last_7_days": int(totals.get("scans_last_7_days", 0) or 0),
            }

        _analytics_cache["payload"] = payload
        _analytics_cache["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=ANALYTICS_CACHE_TTL_SECONDS)
        return payload


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
            "subtitle": f"Critical: {severity['Critical']} | High: {severity['High']}",
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
                    f"{scan['risk_label']} | {scan['findings_count']} finding(s) | "
                    f"{scan['critical_count']} critical | {scan['high_count']} high"
                ),
                "time": _format_relative_time(timestamp),
            }
        )

    if not activities:
        return [{"title": "No scan activity yet", "detail": "Completed scans will appear here automatically.", "time": "Now"}]

    return activities


def serialize_scan_as_admin_report(document: dict) -> dict:
    summary = document.get("summary")
    severity = _summary_severity_counts(summary)
    findings_count = _summary_total_findings(summary)
    created_at = document.get("created_at") or datetime.utcnow()
    report_id = document.get("report_id") or document.get("scan_id") or str(document.get("_id", ""))
    findings = document.get("findings") if isinstance(document.get("findings"), list) else []

    finding_titles = [
        str(finding.get("title") or finding.get("name") or finding.get("vuln_type") or "Finding")
        for finding in findings[:3]
        if isinstance(finding, dict)
    ]
    if not finding_titles:
        finding_titles = [
            f"{severity['Critical']} critical finding(s)",
            f"{severity['High']} high severity finding(s)",
            f"{findings_count} total finding(s)",
        ]

    return {
        "id": report_id,
        "title": document.get("target") or document.get("url") or "Scan Report",
        "subtitle": f"{document.get('risk_label') or 'No Risk'} | {findings_count} finding(s)",
        "date": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
        "size": "Live scan report",
        "type": "Scan",
        "status": document.get("scan_status") or "completed",
        "scanCount": 1,
        "vulnerabilities": findings_count,
        "critical": severity["Critical"],
        "high": severity["High"],
        "medium": severity["Medium"],
        "low": severity["Low"],
        "score": int(document.get("risk_score") or 0),
        "downloads": 0,
        "findings": finding_titles,
        "target": document.get("target") or document.get("url") or "",
        "report_id": report_id,
    }


def list_admin_scan_reports(limit: int = 25) -> list[dict]:
    safe_limit = max(1, min(int(limit or 25), 100))
    if _cache_is_fresh(_admin_reports_cache, limit=safe_limit):
        return _admin_reports_cache["payload"]

    scans = _recent_scan_documents(safe_limit)
    payload = [serialize_scan_as_admin_report(document) for document in scans]
    _admin_reports_cache["payload"] = payload
    _admin_reports_cache["limit"] = safe_limit
    _admin_reports_cache["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=ANALYTICS_CACHE_TTL_SECONDS)
    return payload
