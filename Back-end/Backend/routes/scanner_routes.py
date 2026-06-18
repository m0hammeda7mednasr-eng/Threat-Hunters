from flask import Blueprint, jsonify, request

from services.scanner_service import start_scan


scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scanner/scan", methods=["POST"])
def scan():
    try:
        return jsonify(start_scan(request.json or {})), 200
    except ValueError as exc:
        return jsonify({"message": str(exc)}), 400
    except Exception as exc:
        return jsonify({
            "message": "Scan failed",
            "error": str(exc),
        }), 500
