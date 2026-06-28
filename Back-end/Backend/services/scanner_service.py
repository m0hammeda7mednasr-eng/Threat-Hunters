from __future__ import annotations

from datetime import datetime, timezone

from database.db import mongo
from scanner.runner import run_scan

MAX_LIST_FINDINGS = 40
MAX_LIST_CHECKS = 20
MAX_LIST_RECOMMENDATIONS = 8
MAX_LIST_DISCOVERED_URLS = 25
MAX_LIST_VALIDATION_RESULTS = 15
MAX_LIST_HEADERS = 12


def _normalize_scan_mode(value: str | None) -> str:
    mode = str(value or "light").strip().lower()
    if mode in {"quick", "light", "fast"}:
        return "light"
    if mode == "deep":
        return "deep"
    return "light"


def _derive_risk_score(report: dict) -> int:
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    score = 0

    severity_weights = {
        "critical": 30,
        "high": 18,
        "medium": 10,
        "low": 4,
        "info": 1,
        "informational": 1,
        "recon": 1,
        "candidate": 6,
        "blocked": 0,
        "inconclusive": 2,
    }

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or finding.get("status") or "").strip().lower()
        score += severity_weights.get(severity, 2)

    score += int(summary.get("confirmed_findings") or summary.get("confirmed_vulns") or 0) * 25
    score += int(summary.get("candidate_findings") or summary.get("candidate_issues") or 0) * 6
    score += int(summary.get("blocked_tests") or 0) * 1
    score += int(summary.get("inconclusive_tests") or 0) * 1

    return max(0, min(100, int(round(score))))


def _risk_label_from_score(score: int) -> str:
    if score >= 80:
        return "Critical Risk"
    if score >= 50:
        return "High Risk"
    if score >= 20:
        return "Moderate Risk"
    if score > 0:
        return "Low Risk"
    return "No Risk"


def _report_owner_from_user(current_user: dict | None) -> dict:
    if not isinstance(current_user, dict):
        return {}
    display_name = (
        current_user.get("name")
        or current_user.get("full_name")
        or current_user.get("username")
        or current_user.get("email")
        or ""
    )
    return {
        "display_name": str(display_name or "").strip(),
        "email": str(current_user.get("email") or "").strip(),
        "user_id": str(current_user.get("_id") or current_user.get("id") or "").strip(),
    }


def _enrich_scan_result(result: dict, requested_mode: str) -> dict:
    if not isinstance(result, dict):
        return result

    report = result.get("report") if isinstance(result.get("report"), dict) else {}
    normalized_mode = _normalize_scan_mode(result.get("profile") or requested_mode)

    raw_score = result.get("risk_score")
    if not isinstance(raw_score, (int, float)):
        raw_score = report.get("risk_score")
    if not isinstance(raw_score, (int, float)):
        raw_score = _derive_risk_score(report)

    risk_score = max(0, min(100, int(round(float(raw_score)))))
    risk_label = result.get("risk_label") or report.get("risk_label") or _risk_label_from_score(risk_score)
    score_text = result.get("score") or report.get("score") or f"{risk_score}/100"
    scan_coverage = result.get("scan_coverage")
    if not isinstance(scan_coverage, (int, float)):
        scan_coverage = report.get("scan_coverage")
    scan_confidence = result.get("scan_confidence")
    if not isinstance(scan_confidence, (int, float)):
        scan_confidence = report.get("scan_confidence")

    enriched_report = {
        **report,
        "scan_mode": normalized_mode,
        "profile": normalized_mode,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "score": score_text,
        "scan_coverage": scan_coverage,
        "scan_confidence": scan_confidence,
    }

    scan_time = str(enriched_report.get("scan_time") or datetime.now(timezone.utc).isoformat())
    date_part, _, time_part = scan_time.partition("T")
    time_text = time_part[:5] if time_part else ""
    client_report = {
        "id": result.get("report_id") or enriched_report.get("scan_id") or result.get("scan_id") or "RPT-LIVE",
        "reference": result.get("scan_id") or result.get("report_id") or "LIVE",
        "report_id": result.get("report_id"),
        "scan_id": result.get("scan_id") or enriched_report.get("scan_id"),
        "date": date_part,
        "time": time_text,
        "target": enriched_report.get("target") or result.get("target") or result.get("domain"),
        "url": enriched_report.get("url") or result.get("target"),
        "final_url": enriched_report.get("final_url") or enriched_report.get("url") or result.get("target"),
        "scan_status": enriched_report.get("scan_status") or enriched_report.get("summary", {}).get("scan_status") or "completed",
        "scan_mode": normalized_mode,
        "profile": normalized_mode,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "score": score_text,
        "scan_coverage": scan_coverage,
        "scan_confidence": scan_confidence,
        "summary": enriched_report.get("summary", {}),
        "findings": enriched_report.get("findings", []),
        "confirmed_findings": enriched_report.get("confirmed_findings", []),
        "candidate_findings": enriched_report.get("candidate_findings", []),
        "security_headers": enriched_report.get("security_headers", []),
        "checks": enriched_report.get("checks", []),
        "headers": enriched_report.get("headers", {}),
        "tool_availability": enriched_report.get("tool_availability", []),
        "recommendations": enriched_report.get("recommendations", []),
        "report_sections": enriched_report.get("report_sections", {}),
        "deepseek_prompt_package": enriched_report.get("deepseek_prompt_package", {}),
        "known_vulnerability_summary": enriched_report.get("known_vulnerability_summary", {}),
        "known_vulnerabilities": enriched_report.get("known_vulnerabilities", {}),
        "report_owner": enriched_report.get("report_owner", {}),
        "discovered_urls": enriched_report.get("discovered_urls", []),
        "parameter_inventory": enriched_report.get("parameter_inventory", []),
        "form_inventory": enriched_report.get("form_inventory", []),
        "active_validation_results": enriched_report.get("active_validation_results", []),
        "active_validation_summary": enriched_report.get("active_validation_summary", {}),
        "http_status": enriched_report.get("http_status"),
        "server": enriched_report.get("server"),
        "content_type": enriched_report.get("content_type"),
        "content_length": enriched_report.get("content_length"),
        "duration": enriched_report.get("duration") or "0.0s",
        "report_files": result.get("report_files", {}),
    }

    return {
        **result,
        **client_report,
        "scan_mode": normalized_mode,
        "profile": normalized_mode,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "score": score_text,
        "scan_coverage": scan_coverage,
        "scan_confidence": scan_confidence,
        "report": enriched_report,
    }


def _store_scan_result(result: dict, current_user: dict | None = None) -> None:
    if not current_user or not isinstance(result, dict):
        return
    if getattr(mongo, "db", None) is None:
        return

    report_id = result.get("report_id") or result.get("id") or result.get("scan_id")
    if not report_id:
        return

    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    document = {
        "report_id": report_id,
        "scan_id": result.get("scan_id"),
        "user_id": current_user.get("_id"),
        "target": result.get("target"),
        "url": result.get("url"),
        "risk_score": result.get("risk_score"),
        "risk_label": result.get("risk_label"),
        "scan_status": result.get("scan_status"),
        "scan_mode": result.get("scan_mode"),
        "scan_coverage": result.get("scan_coverage"),
        "scan_confidence": result.get("scan_confidence"),
        "summary": result.get("summary", {}),
        "findings": findings,
        "checks": result.get("checks", []),
        "headers": result.get("headers", {}),
        "security_headers": result.get("security_headers", []),
        "tool_availability": result.get("tool_availability", []),
        "recommendations": result.get("recommendations", []),
        "report_sections": result.get("report_sections", {}),
        "deepseek_prompt_package": result.get("deepseek_prompt_package", {}),
        "known_vulnerability_summary": result.get("known_vulnerability_summary", {}),
        "known_vulnerabilities": result.get("known_vulnerabilities", {}),
        "scan_coverage": result.get("scan_coverage"),
        "scan_confidence": result.get("scan_confidence"),
        "report_owner": result.get("report_owner", {}),
        "discovered_urls": result.get("discovered_urls", []),
        "parameter_inventory": result.get("parameter_inventory", []),
        "form_inventory": result.get("form_inventory", []),
        "active_validation_results": result.get("active_validation_results", []),
        "active_validation_summary": result.get("active_validation_summary", {}),
        "report": result.get("report", {}),
        "report_files": result.get("report_files", {}),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }

    mongo.db.scan_reports.update_one(
        {"report_id": report_id, "user_id": current_user.get("_id")},
        {"$set": document},
        upsert=True,
    )
    mongo.db.users.update_one(
        {"_id": current_user.get("_id")},
        {"$inc": {"scans": 1, "vulnerabilities": len(findings)}},
    )


def _trim_items(items, limit: int):
    if not isinstance(items, list):
        return []
    return items[:limit]


def _build_nested_report_preview(document: dict, report: dict) -> dict:
    known_vulnerabilities = report.get("known_vulnerabilities")
    if not isinstance(known_vulnerabilities, dict):
        known_vulnerabilities = document.get("known_vulnerabilities", {})

    return {
        "target": report.get("target") or document.get("target"),
        "url": report.get("url") or document.get("url"),
        "final_url": report.get("final_url") or document.get("url"),
        "scan_time": report.get("scan_time"),
        "scan_status": report.get("scan_status") or document.get("scan_status"),
        "scan_mode": report.get("scan_mode") or document.get("scan_mode"),
        "profile": report.get("profile") or document.get("scan_mode"),
        "risk_score": report.get("risk_score") or document.get("risk_score"),
        "risk_label": report.get("risk_label") or document.get("risk_label"),
        "score": report.get("score") or f"{int(document.get('risk_score') or 0)}/100",
        "scan_coverage": report.get("scan_coverage", document.get("scan_coverage")),
        "scan_confidence": report.get("scan_confidence", document.get("scan_confidence")),
        "summary": document.get("summary", {}),
        "report_sections": report.get("report_sections", document.get("report_sections", {})),
        "security_headers": _trim_items(
            report.get("security_headers", document.get("security_headers", [])),
            MAX_LIST_HEADERS,
        ),
        "known_vulnerability_summary": report.get(
            "known_vulnerability_summary",
            document.get("known_vulnerability_summary", {}),
        ),
        "known_vulnerabilities": known_vulnerabilities if isinstance(known_vulnerabilities, dict) else {},
        "report_owner": report.get("report_owner", document.get("report_owner", {})),
        "recommendations": _trim_items(
            report.get("recommendations", document.get("recommendations", [])),
            MAX_LIST_RECOMMENDATIONS,
        ),
        "duration": report.get("duration") or "0.0s",
        "http_status": report.get("http_status"),
        "server": report.get("server"),
        "content_type": report.get("content_type"),
        "content_length": report.get("content_length"),
    }


def _serialize_stored_scan(document: dict) -> dict:
    created_at = document.get("created_at")
    if hasattr(created_at, "isoformat"):
        created_at = created_at.isoformat()
    report = document.get("report") if isinstance(document.get("report"), dict) else {}
    findings = _trim_items(document.get("findings", []), MAX_LIST_FINDINGS)
    checks = _trim_items(document.get("checks", []), MAX_LIST_CHECKS)
    recommendations = _trim_items(
        document.get("recommendations", []),
        MAX_LIST_RECOMMENDATIONS,
    )
    security_headers = _trim_items(
        report.get("security_headers", document.get("security_headers", [])),
        MAX_LIST_HEADERS,
    )
    nested_preview = _build_nested_report_preview(document, report)
    return {
        "id": document.get("report_id") or document.get("scan_id"),
        "report_id": document.get("report_id"),
        "scan_id": document.get("scan_id"),
        "target": document.get("target"),
        "url": document.get("url"),
        "risk_score": document.get("risk_score", 0),
        "risk_label": document.get("risk_label", "No Risk"),
        "scan_status": document.get("scan_status", "completed"),
        "scan_mode": document.get("scan_mode", "light"),
        "profile": document.get("scan_mode", "light"),
        "score": f"{int(document.get('risk_score') or 0)}/100",
        "scan_coverage": report.get("scan_coverage", document.get("scan_coverage")),
        "scan_confidence": report.get("scan_confidence", document.get("scan_confidence")),
        "summary": document.get("summary", {}),
        "findings": findings,
        "checks": checks,
        "headers": document.get("headers", {}),
        "tool_availability": document.get("tool_availability", []),
        "recommendations": recommendations,
        "security_headers": security_headers,
        "report_sections": report.get("report_sections", document.get("report_sections", {})),
        "deepseek_prompt_package": report.get("deepseek_prompt_package", document.get("deepseek_prompt_package", {})),
        "known_vulnerability_summary": report.get("known_vulnerability_summary", document.get("known_vulnerability_summary", {})),
        "known_vulnerabilities": report.get("known_vulnerabilities", document.get("known_vulnerabilities", {})),
        "report_owner": report.get("report_owner", document.get("report_owner", {})),
        "report_files": document.get("report_files", report.get("report_files", {})),
        "discovered_urls": _trim_items(document.get("discovered_urls", []), MAX_LIST_DISCOVERED_URLS),
        "parameter_inventory": _trim_items(document.get("parameter_inventory", []), MAX_LIST_DISCOVERED_URLS),
        "form_inventory": _trim_items(document.get("form_inventory", []), MAX_LIST_DISCOVERED_URLS),
        "active_validation_results": _trim_items(
            document.get("active_validation_results", []),
            MAX_LIST_VALIDATION_RESULTS,
        ),
        "active_validation_summary": document.get("active_validation_summary", {}),
        "date": str(created_at or "")[:10],
        "time": str(created_at or "")[11:16],
        "duration": report.get("duration") or "0.0s",
        "http_status": report.get("http_status"),
        "server": report.get("server"),
        "content_type": report.get("content_type"),
        "content_length": report.get("content_length"),
        "report": nested_preview,
    }


def list_scan_reports(current_user: dict, limit: int = 12) -> list[dict]:
    if not current_user or getattr(mongo, "db", None) is None:
        return []

    projection = {
        "report_id": 1,
        "scan_id": 1,
        "user_id": 1,
        "target": 1,
        "url": 1,
        "risk_score": 1,
        "risk_label": 1,
        "scan_status": 1,
        "scan_mode": 1,
        "scan_coverage": 1,
        "scan_confidence": 1,
        "summary": 1,
        "findings": {"$slice": MAX_LIST_FINDINGS},
        "checks": {"$slice": MAX_LIST_CHECKS},
        "headers": 1,
        "security_headers": {"$slice": MAX_LIST_HEADERS},
        "tool_availability": 1,
        "recommendations": {"$slice": MAX_LIST_RECOMMENDATIONS},
        "report_sections": 1,
        "deepseek_prompt_package": 1,
        "known_vulnerability_summary": 1,
        "known_vulnerabilities": 1,
        "report_owner": 1,
        "discovered_urls": {"$slice": MAX_LIST_DISCOVERED_URLS},
        "parameter_inventory": {"$slice": MAX_LIST_DISCOVERED_URLS},
        "form_inventory": {"$slice": MAX_LIST_DISCOVERED_URLS},
        "active_validation_results": {"$slice": MAX_LIST_VALIDATION_RESULTS},
        "active_validation_summary": 1,
        "report_files": 1,
        "created_at": 1,
        "report.scan_time": 1,
        "report.scan_status": 1,
        "report.scan_mode": 1,
        "report.profile": 1,
        "report.risk_score": 1,
        "report.risk_label": 1,
        "report.score": 1,
        "report.scan_coverage": 1,
        "report.scan_confidence": 1,
        "report.target": 1,
        "report.url": 1,
        "report.final_url": 1,
        "report.duration": 1,
        "report.http_status": 1,
        "report.server": 1,
        "report.content_type": 1,
        "report.content_length": 1,
        "report.report_sections": 1,
        "report.security_headers": {"$slice": MAX_LIST_HEADERS},
        "report.known_vulnerability_summary": 1,
        "report.known_vulnerabilities": 1,
        "report.report_owner": 1,
        "report.recommendations": {"$slice": MAX_LIST_RECOMMENDATIONS},
    }

    cursor = (
        mongo.db.scan_reports
        .find({"user_id": current_user.get("_id")}, projection)
        .sort("created_at", -1)
        .limit(max(1, min(int(limit or 12), 50)))
    )
    return [_serialize_stored_scan(document) for document in cursor]


def start_scan(data, current_user: dict | None = None):

    target = data.get(
        "target"
    )

    if not target:

        raise ValueError(
            "Target is required"
        )

    scan_mode = _normalize_scan_mode(data.get("scan_mode", "light"))

    cookie_header = data.get(
        "cookie_header"
    )

    enable_nuclei = data.get(
        "enable_nuclei"
    )
    if enable_nuclei is None:
        enable_nuclei = scan_mode == "deep"

    nuclei_profile = data.get(
        "nuclei_profile",
        "public-safe-v1"
    )

    ai_search = data.get(
        "ai_search",
        True
    )

    modules = data.get(
        "modules"
    )
    confirm_permission = data.get(
        "confirm_permission"
    )
    if confirm_permission is None:
        confirm_permission = True

    result = run_scan(

        target=target,

        scan_mode=scan_mode,

        cookie_header=cookie_header,

        enable_nuclei=enable_nuclei,

        confirm_permission=confirm_permission,

        nuclei_profile=nuclei_profile,

        ai_search=ai_search,

        modules=modules,

        report_owner=_report_owner_from_user(current_user)

    )

    enriched = _enrich_scan_result(result, scan_mode)
    _store_scan_result(enriched, current_user=current_user)
    return enriched
