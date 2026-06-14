from flask import Blueprint, jsonify, request
from middleware.auth_middleware import token_required

user_bp = Blueprint("user", __name__)

@user_bp.route("/dashboard", methods=["GET"])
@token_required
def dashboard():
    current_user = request.current_user
    return jsonify({
        "user": {
            "id": str(current_user["_id"]),
            "firstName": current_user.get("first_name"),
            "lastName": current_user.get("last_name"),
            "email": current_user.get("email"),
            "createdAt": str(current_user.get("created_at")),
            "lastLogin": current_user.get("last_login").isoformat() if current_user.get("last_login") else None
        }
    })
