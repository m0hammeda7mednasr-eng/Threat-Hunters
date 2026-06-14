from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, jsonify, request

from database.db import mongo
from middleware.auth_middleware import token_required


admin_bp = Blueprint("admin", __name__)


def is_admin(user):
    return user and user.get("role") == "admin"


def parse_object_id(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def serialize_user(user):
    first_name = user.get("first_name") or user.get("firstName") or ""
    last_name = user.get("last_name") or user.get("lastName") or ""
    email = user.get("email", "")
    full_name = f"{first_name} {last_name}".strip() or email
    created_at = user.get("created_at") or user.get("createdAt")

    return {
        "id": str(user["_id"]),
        "firstName": first_name,
        "lastName": last_name,
        "name": full_name,
        "email": email,
        "role": user.get("role", "user"),
        "status": "disabled" if user.get("disabled") else "active",
        "plan": user.get("plan", "Free"),
        "scans": user.get("scans", 0),
        "vulnerabilities": user.get("vulnerabilities", 0),
        "phone": user.get("phone", ""),
        "bio": user.get("bio", ""),
        "joined": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or ""),
    }


def require_admin():
    current_user = request.current_user
    if not is_admin(current_user):
        return None, (jsonify({"message": "Admin access required"}), 403)
    return current_user, None


@admin_bp.route("/admin/users", methods=["GET"])
@token_required
def list_users():
    _, error = require_admin()
    if error:
        return error

    page = max(int(request.args.get("page", 1)), 1)
    limit = max(min(int(request.args.get("limit", 10)), 100), 1)
    query = {}
    total = mongo.db.users.count_documents(query)
    cursor = mongo.db.users.find(query).sort("created_at", -1).skip((page - 1) * limit).limit(limit)

    return jsonify({
        "items": [serialize_user(user) for user in cursor],
        "page": page,
        "limit": limit,
        "total": total,
    }), 200


@admin_bp.route("/admin/users/<user_id>", methods=["GET"])
@token_required
def get_user(user_id):
    _, error = require_admin()
    if error:
        return error

    object_id = parse_object_id(user_id)
    if not object_id:
        return jsonify({"message": "User not found"}), 404

    user = mongo.db.users.find_one({"_id": object_id})
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify(serialize_user(user)), 200


@admin_bp.route("/admin/users/<user_id>", methods=["PUT"])
@token_required
def update_user(user_id):
    current_user, error = require_admin()
    if error:
        return error

    object_id = parse_object_id(user_id)
    if not object_id:
        return jsonify({"message": "User not found"}), 404

    payload = request.json or {}
    updates = {"updated_at": datetime.utcnow()}

    if payload.get("role") in ["user", "analyst", "manager", "admin"]:
        updates["role"] = payload["role"]

    if payload.get("status") in ["active", "disabled"]:
        updates["disabled"] = payload["status"] == "disabled"

    for field in ["phone", "bio", "plan"]:
        if field in payload:
            updates[field] = str(payload[field]).strip()

    result = mongo.db.users.update_one({"_id": object_id}, {"$set": updates})
    if result.matched_count == 0:
        return jsonify({"message": "User not found"}), 404

    user = mongo.db.users.find_one({"_id": object_id})
    return jsonify(serialize_user(user)), 200


@admin_bp.route("/admin/users/<user_id>", methods=["DELETE"])
@token_required
def delete_user(user_id):
    current_user, error = require_admin()
    if error:
        return error

    object_id = parse_object_id(user_id)
    if not object_id:
        return jsonify({"message": "User not found"}), 404

    if str(current_user["_id"]) == str(object_id):
        return jsonify({"message": "You cannot delete your own admin account"}), 400

    result = mongo.db.users.delete_one({"_id": object_id})
    if result.deleted_count == 0:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"message": "User deleted successfully"}), 200
