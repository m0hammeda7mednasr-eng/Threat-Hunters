from flask import Blueprint, request, jsonify

from services.scanner_service import (
    start_scan
)

scanner_bp = Blueprint(
    "scanner",
    __name__
)


@scanner_bp.route(
    "/scanner/scan",
    methods=["POST"]
)
def scan():

    try:

        result = start_scan(
            request.json
        )

        return jsonify(
            result
        ), 200

    except Exception as e:

        return jsonify({

            "message":
            "Scan failed",

            "error":
            str(e)

        }), 500