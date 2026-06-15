from flask import Blueprint, request

from services.breach_service import (
    check_password_breach
)

breach_bp = Blueprint(
    "breach",
    __name__
)


@breach_bp.route(
    "/security/check-password",
    methods=["POST"]
)
def check_password():

    return check_password_breach(
        request.json
    )