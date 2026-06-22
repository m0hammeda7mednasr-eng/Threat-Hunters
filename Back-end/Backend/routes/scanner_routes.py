from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from middleware.auth_middleware import get_current_user_optional, token_required
from services.scanner_service import list_scan_reports, start_scan
from scanner.runner import ALLOWED_REPORT_SUFFIXES, REPORTS_DIR, get_report
from database.db import mongo


scanner_bp = Blueprint("scanner", __name__)


def _stored_report_file(document: dict | None, requested_fmt: str):
    if not isinstance(document, dict):
        return None

    report = document.get("report") if isinstance(document.get("report"), dict) else {}
    report_files = document.get("report_files") or report.get("report_files") or {}
    if not isinstance(report_files, dict):
        return None

    requested_fmt = str(requested_fmt or "html").strip().lower()
    candidates = [requested_fmt] if requested_fmt == "pdf" else [requested_fmt, "html", "md", "json"]
    reports_root = REPORTS_DIR.resolve()

    for fmt in dict.fromkeys(candidates):
        raw_path = report_files.get(fmt)
        if not raw_path:
            continue
        path = Path(str(raw_path)).expanduser().resolve()
        if path.suffix.lower() not in ALLOWED_REPORT_SUFFIXES:
            continue
        if reports_root not in path.parents:
            continue
        if path.exists():
            return {
                "path": str(path),
                "report_id": path.stem,
                "format": path.suffix.lstrip("."),
            }
    return None


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


@scanner_bp.route("/scanner/reports/<report_id>/download/<fmt>", methods=["GET"])
@token_required
def download_report(report_id, fmt):
    try:
        owned_report = None
        if getattr(mongo, "db", None) is not None:
            owned_report = mongo.db.scan_reports.find_one({
                "report_id": report_id,
                "user_id": request.current_user.get("_id"),
            })
            if not owned_report:
                return jsonify({"message": "Report file not found. Run a fresh scan so this account owns a generated backend report."}), 404
        report_info = _stored_report_file(owned_report, fmt)
        if not report_info:
            report_info = get_report(report_id, fmt)
        return send_file(
            report_info["path"],
            as_attachment=False,
            download_name=f"{report_info['report_id']}.{report_info['format']}",
        )
    except FileNotFoundError:
        return jsonify({"message": "Report file not found on disk. Run the scan again to create a new backend report file."}), 404
    except Exception as exc:
        return jsonify({
            "message": "Could not load report file",
            "error": str(exc),
        }), 400
