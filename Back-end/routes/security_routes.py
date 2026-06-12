from flask import Blueprint, jsonify
from services.nvd_service import get_latest_cves
from services.cisa_service import get_exploited_vulnerabilities
from services.news_service import get_security_news

security_bp = Blueprint("security", __name__)

@security_bp.route("/latest-cves", methods=["GET"])
def latest_cves():
    return jsonify(get_latest_cves())

@security_bp.route("/critical-cves", methods=["GET"])
def critical_cves():
    return jsonify(get_latest_cves())

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