from flask import Blueprint, jsonify
from database.db import mongo
from services.awareness_service import get_awareness_content as get_default_awareness_content
from services.nvd_service import get_latest_cves
from services.cisa_service import get_exploited_vulnerabilities
from services.news_service import get_security_news
from services.cache_service import get_cached_data
from database.db import mongo

security_bp = Blueprint("security", __name__)


def _normalize_awareness_item(item, kind):
    if isinstance(item, str):
        if kind == "download":
            return {
                "title": item,
                "description": "Downloadable security resource.",
                "fileMeta": "PDF | generated instantly",
            }

        return {
            "title": item,
            "type": "Guide",
            "description": "Security awareness resource.",
            "url": "",
        }

    return item


def _normalize_awareness_content(content):
    next_content = dict(content or {})
    next_content["resources"] = [
        _normalize_awareness_item(item, "resource") for item in (next_content.get("resources") or [])
    ]
    next_content["downloads"] = [
        _normalize_awareness_item(item, "download") for item in (next_content.get("downloads") or [])
    ]
    return next_content


def _is_legacy_awareness_content(content):
    resources = content.get("resources") or []
    downloads = content.get("downloads") or []
    return (
        content.get("title") == "Security Awareness Training & Resources"
        or not downloads
        or any(isinstance(item, str) for item in resources)
    )

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
    content = _normalize_awareness_content(get_default_awareness_content())
    stored = mongo.db.web_content.find_one({"page": "awareness"}, {"_id": 0, "page": 0}) or {}

    stored_awareness = {
        key: value for key, value in stored.items() if key in {"title", "description", "owasp", "resources", "downloads"}
    }

    if _is_legacy_awareness_content(stored_awareness):
        return jsonify(content)

    if "resources" in stored_awareness:
        stored_awareness["resources"] = [_normalize_awareness_item(item, "resource") for item in stored_awareness["resources"]]
    if "downloads" in stored_awareness:
        stored_awareness["downloads"] = [_normalize_awareness_item(item, "download") for item in stored_awareness["downloads"]]

    return jsonify({**content, **stored_awareness})

@security_bp.route("/cache/clear", methods=["POST"])
def clear_cache():

    mongo.db.security_cache.delete_many({})

    return jsonify({
        "message": "Cache cleared successfully"
    })
