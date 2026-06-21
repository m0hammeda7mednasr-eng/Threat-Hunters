from flask import Blueprint, jsonify
from services.awareness_service import get_awareness_content
from services.nvd_service import get_latest_cves
from services.cisa_service import get_exploited_vulnerabilities
from services.news_service import get_security_news
from services.cache_service import get_cached_data
from database.db import mongo

security_bp = Blueprint("security", __name__)

@security_bp.route("/latest-cves", methods=["GET"])
def latest_cves():
    data = get_cached_data(
        "latest_cves",
        get_latest_cves,
        cache_hours=6
    )

    return jsonify(data)

@security_bp.route("/critical-cves", methods=["GET"])
def critical_cves():
    latest = get_cached_data(
    "latest_cves",
    get_latest_cves,
    cache_hours=6
        )
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
    data = get_cached_data(
        "kev_catalog",
        get_exploited_vulnerabilities,
        cache_hours=6
    )
    return jsonify(data)

@security_bp.route("/news", methods=["GET"])
def security_news():
    data = get_cached_data(
        "security_news",
        get_security_news,
        cache_hours=1)

    return jsonify(data)

@security_bp.route("/awareness", methods=["GET"])
def awareness_content():
    return jsonify(get_awareness_content())

@security_bp.route("/cache/clear", methods=["POST"])
def clear_cache():

    mongo.db.security_cache.delete_many({})

    return jsonify({
        "message": "Cache cleared successfully"
    })
