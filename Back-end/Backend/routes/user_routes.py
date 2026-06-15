from flask import Blueprint, jsonify, request
from middleware.auth_middleware import token_required
from database.db import mongo
from utils.password_utils import check_password, hash_password, validate_password

user_bp = Blueprint("user", __name__)


def serialize_profile(user):
    return {
        "id": str(user["_id"]),
        "firstName": user.get("first_name", ""),
        "lastName": user.get("last_name", ""),
        "email": user.get("email", ""),
        "role": user.get("role", "user"),
        "phone": user.get("phone", ""),
        "bio": user.get("bio", ""),
        "createdAt": str(user.get("created_at", "")),
        "lastLogin": user.get("last_login").isoformat() if user.get("last_login") else None
    }


@user_bp.route("/dashboard", methods=["GET"])
@token_required
def dashboard():
    current_user = request.current_user
    return jsonify({
        "user": serialize_profile(current_user)
    })


@user_bp.route("/user/profile", methods=["GET"])
@token_required
def get_profile():
    return jsonify(serialize_profile(request.current_user)), 200


@user_bp.route("/user/profile", methods=["PUT"])
@token_required
def update_profile():
    data = request.json or {}
    updates = {}

    if "firstName" in data:
        updates["first_name"] = data.get("firstName", "").strip()

    if "lastName" in data:
        updates["last_name"] = data.get("lastName", "").strip()

    if "phone" in data:
        updates["phone"] = str(data.get("phone", "")).strip()

    if "bio" in data:
        updates["bio"] = str(data.get("bio", "")).strip()

    if updates:
        mongo.db.users.update_one(
            {"_id": request.current_user["_id"]},
            {"$set": updates}
        )

    user = mongo.db.users.find_one({"_id": request.current_user["_id"]})
    return jsonify(serialize_profile(user)), 200


@user_bp.route("/user/password", methods=["PUT"])
@token_required
def update_password():
    data = request.json or {}
    current_password = data.get("currentPassword", "")
    new_password = data.get("newPassword", "")

    if not current_password or not new_password:
        return jsonify({"message": "Current and new password are required"}), 400

    if not check_password(request.current_user["password"], current_password):
        return jsonify({"message": "Current password is incorrect"}), 400

    password_error = validate_password(new_password)
    if password_error:
        return jsonify({"message": password_error}), 400

    mongo.db.users.update_one(
        {"_id": request.current_user["_id"]},
        {"$set": {"password": hash_password(new_password)}}
    )

    return jsonify({"message": "Password updated successfully"}), 200
