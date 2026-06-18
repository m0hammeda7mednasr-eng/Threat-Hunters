from flask import Blueprint, jsonify, request

from middleware.auth_middleware import get_current_user_optional, token_required
from services.scanner_service import list_scan_reports, start_scan


scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scanner/scan", methods=["POST"])
def scan():
    try:
        current_user = get_current_user_optional()
        return jsonify(start_scan(request.json or {}, current_user=current_user)), 200
    except ValueError as exc:
        return jsonify({"message": str(exc)}), 400
    except Exception as exc:
        return jsonify({
            "message": "Scan failed",
            "error": str(exc),
        }), 500


@scanner_bp.route("/scanner/reports", methods=["GET"])
@token_required
def reports():
    try:
        limit = request.args.get("limit", 12)
        return jsonify({"items": list_scan_reports(request.current_user, limit=limit)}), 200
    except Exception as exc:
        return jsonify({
            "message": "Could not load scan reports",
            "error": str(exc),
        }), 500
