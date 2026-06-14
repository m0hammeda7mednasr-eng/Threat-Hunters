from flask import Blueprint, request

from services.auth_service import (
    register_user,
    login_user,
    verify_email,
    forgot_password,
    reset_password
)

auth_bp = Blueprint(
    "auth",
    __name__
)


@auth_bp.route("/register", methods=["POST"])
def register():

    return register_user(
        request.json
    )


@auth_bp.route("/login", methods=["POST"])
def login():

    return login_user(
        request.json
    )


@auth_bp.route("/verify-email", methods=["POST"])
def verify():

    return verify_email(
        request.json
    )
@auth_bp.route("/forgot-password", methods=["POST"])
def forgot():

    return forgot_password(
        request.json
    )

@auth_bp.route("/reset-password", methods=["POST"])
def reset():

    return reset_password(
        request.json
    )