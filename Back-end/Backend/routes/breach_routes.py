from flask import Blueprint, request

from services.breach_service import (
    check_password_breach,
    check_email_breach
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

@breach_bp.route(
    "/security/check-email",
    methods=["POST"]
)
def check_email():

    return check_email_breach(
        request.json
    )