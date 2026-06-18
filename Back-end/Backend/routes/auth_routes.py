from flask import Blueprint, request

from services.auth_service import (
    forgot_password,
    login_user,
    register_user,
    resend_verification_otp,
    request_password_reset,
    reset_password,
    verify_email,
)


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    return register_user(request.json)


@auth_bp.route("/login", methods=["POST"])
def login():
    return login_user(request.json)


@auth_bp.route("/verify-email", methods=["POST"])
def verify():
    return verify_email(request.json)


@auth_bp.route("/verify-email/resend", methods=["POST"])
def resend_verify():
    return resend_verification_otp(request.json)


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_legacy():
    return forgot_password(request.json)


@auth_bp.route("/reset-password", methods=["POST"])
def reset_legacy():
    return reset_password(request.json)


@auth_bp.route("/password/forgot", methods=["POST"])
def forgot_password_route():
    return request_password_reset(request.json)


@auth_bp.route("/password/reset", methods=["POST"])
def confirm_password_reset():
    return reset_password(request.json)
