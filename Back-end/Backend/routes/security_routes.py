from flask import Blueprint, jsonify
from services.awareness_service import get_awareness_content
from services.nvd_service import get_latest_cves
from services.cisa_service import get_exploited_vulnerabilities
from services.news_service import get_security_news

security_bp = Blueprint("security", __name__)

@security_bp.route("/latest-cves", methods=["GET"])
def latest_cves():
    return jsonify(get_latest_cves())

@security_bp.route("/critical-cves", methods=["GET"])
def critical_cves():
    latest = get_latest_cves()
    critical = []

    for cve in latest:
        severity = str(cve.get("severity", "")).lower()
        try:
            score = float(cve.get("score", 0) or 0)
        except (TypeError, ValueError):
            score = 0

        if severity in {"critical", "high"} or score >= 8.0:
            critical.append(cve)

    return jsonify(critical[:10] if critical else latest[:5])

@security_bp.route("/kev", methods=["GET"])
def kev():
    return jsonify(
        get_exploited_vulnerabilities()
    )

@security_bp.route("/news", methods=["GET"])
def security_news():

    return jsonify(
        get_security_news()
    )

@security_bp.route("/awareness", methods=["GET"])
def awareness_content():
    return jsonify(get_awareness_content())
