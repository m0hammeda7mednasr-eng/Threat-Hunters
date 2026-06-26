from flask import Blueprint, jsonify

from middleware.auth_middleware import token_required
from services.dashboard_analytics_service import (
    build_dashboard_stats,
    build_recent_activities,
    build_security_metrics,
)


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
@token_required
def stats():
    return jsonify(build_dashboard_stats()), 200


@dashboard_bp.route("/dashboard/activities", methods=["GET"])
@token_required
def activities():
    return jsonify(build_recent_activities()), 200


@dashboard_bp.route("/dashboard/security-metrics", methods=["GET"])
@token_required
def security_metrics():
    return jsonify(build_security_metrics()), 200
