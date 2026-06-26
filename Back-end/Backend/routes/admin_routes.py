from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, jsonify, request

from database.db import mongo
from services.dashboard_analytics_service import aggregate_scan_analytics, list_admin_scan_reports
from middleware.auth_middleware import token_required
from utils.password_utils import hash_password, validate_password
from utils.validators import validate_email_format


admin_bp = Blueprint("admin", __name__)

DEFAULT_ADMIN_SETTINGS = {
    "general": {
        "siteName": "Threat Hunters",
        "siteDescription": "Smart AI-Powered Web Vulnerability Scanner",
        "language": "English",
        "timezone": "UTC+02:00 Cairo",
    },
    "notifications": {
        "emailAlerts": True,
        "criticalOnly": True,
        "weeklyReports": True,
        "productUpdates": False,
        "digestFrequency": "Daily digest",
    },
    "security": {
        "requireTwoFactor": True,
        "loginAlerts": True,
        "sessionTimeout": "30 minutes",
        "passwordRotation": "Every 90 days",
    },
    "email": {
        "senderName": "Threat Hunters",
        "senderAddress": "alerts@threathunters.ai",
        "replyTo": "support@threathunters.ai",
        "footerNote": "AI-powered vulnerability scanning to protect your web applications.",
    },
}

DEFAULT_ADMIN_TEAM = [
    {
        "id": "team-super-admin",
        "initials": "MN",
        "name": "Mohamed Nasr",
        "email": "admin@threathunters.com",
        "status": "active",
        "time": "Online now",
        "role": "Super Admin",
        "badges": ["Full Access", "User Management", "System Config"],
    },
    {
        "id": "team-security-lead",
        "initials": "SA",
        "name": "Sarah Ahmed",
        "email": "sarah@threathunters.com",
        "status": "active",
        "time": "2 hours ago",
        "role": "Admin",
        "badges": ["Scan Management", "Reports", "User Support"],
    },
]

DEFAULT_ADMIN_PRICING = {
    "plans": [
        {
            "id": "plan-free",
            "name": "Free",
            "price": "$0",
            "description": "Perfect for trying out our service",
            "subscribers": 456,
            "badge": "",
            "tone": "is-free",
            "features": [
                {"label": "Basic vulnerability scanning", "included": True},
                {"label": "1 active project", "included": True},
                {"label": "Email notifications", "included": True},
                {"label": "Advanced reporting", "included": False},
                {"label": "Priority support", "included": False},
            ],
        },
        {
            "id": "plan-professional",
            "name": "Professional",
            "price": "$49",
            "description": "For professionals and small teams",
            "subscribers": 234,
            "badge": "Most Popular",
            "tone": "is-professional",
            "features": [
                {"label": "Advanced vulnerability scanning", "included": True},
                {"label": "10 active projects", "included": True},
                {"label": "Detailed PDF reports", "included": True},
                {"label": "Priority email support", "included": True},
                {"label": "Team collaboration tools", "included": False},
            ],
        },
        {
            "id": "plan-enterprise",
            "name": "Enterprise",
            "price": "$199",
            "description": "For large teams and organizations",
            "subscribers": 123,
            "badge": "",
            "tone": "is-enterprise",
            "features": [
                {"label": "Unlimited vulnerability scans", "included": True},
                {"label": "Unlimited active projects", "included": True},
                {"label": "Custom reports and exports", "included": True},
                {"label": "Dedicated success manager", "included": True},
                {"label": "SSO and advanced access control", "included": True},
            ],
        },
    ],
    "transactions": [
        {"id": "txn-1", "customer": "Mohamed Ahmed", "plan": "Professional", "amount": "$49", "date": "2026-06-11T09:20:00Z", "status": "completed"},
        {"id": "txn-2", "customer": "Sarah Ali", "plan": "Enterprise", "amount": "$199", "date": "2026-06-10T14:10:00Z", "status": "completed"},
        {"id": "txn-3", "customer": "Hassan Omar", "plan": "Professional", "amount": "$49", "date": "2026-06-09T16:45:00Z", "status": "completed"},
    ],
}


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


def merge_nested(defaults, payload):
    result = {**defaults}
    for key, value in (payload or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_nested(result[key], value)
        else:
            result[key] = value
    return result


def initials_for(name):
    initials = "".join(part[0] for part in str(name or "").split() if part).upper()
    return (initials or "NA")[:2]


def non_negative_int(value, default=0):
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return default


def parse_non_negative_int(value, label):
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return None, f"{label} must be zero or a positive number"

    if parsed < 0:
        return None, f"{label} must be zero or a positive number"

    return parsed, None


def get_admin_singleton(key, default_value):
    collection = getattr(mongo.db, "admin_config", None)
    if collection is None:
        return default_value

    record = collection.find_one({"key": key})
    if not record:
        return default_value
    return record.get("value", default_value)


def save_admin_singleton(key, value):
    collection = getattr(mongo.db, "admin_config", None)
    if collection is None:
        return value

    try:
        collection.update_one(
            {"key": key},
            {"$set": {"key": key, "value": value, "updated_at": datetime.utcnow()}},
            upsert=True,
        )
    except TypeError:
        result = collection.update_one(
            {"key": key},
            {"$set": {"key": key, "value": value, "updated_at": datetime.utcnow()}},
        )
        if getattr(result, "matched_count", 0) == 0 and hasattr(collection, "insert_one"):
            collection.insert_one({"key": key, "value": value, "updated_at": datetime.utcnow()})
    return value


def blog_comment_count():
    total = 0
    for blog in mongo.db.blogs.find({}):
        if blog.get("comments_count") is not None:
            total += int(blog.get("comments_count") or 0)
            continue

        comments = blog.get("comments") or []
        for comment in comments:
            total += 1 + len(comment.get("replies", []) or [])
    return total


def total_vulnerability_count():
    analytics = aggregate_scan_analytics()
    return int(analytics.get("total_findings") or 0)


def security_metrics_payload():
    analytics = aggregate_scan_analytics()
    severity = analytics.get("severity_counts") or {}
    return [
        {"label": "Critical", "value": severity.get("Critical", 0), "subtitle": "Confirmed critical findings"},
        {"label": "High", "value": severity.get("High", 0), "subtitle": "High severity findings"},
        {"label": "Medium", "value": severity.get("Medium", 0), "subtitle": "Medium severity findings"},
        {"label": "Low", "value": severity.get("Low", 0), "subtitle": "Low and informational findings"},
    ]


def pricing_stats(pricing):
    plans = pricing.get("plans", [])
    transactions = pricing.get("transactions", [])
    active_subscriptions = sum(int(plan.get("subscribers", 0) or 0) for plan in plans)
    monthly_revenue = 0
    for plan in plans:
        price = "".join(ch for ch in str(plan.get("price", "0")) if ch.isdigit() or ch == ".")
        monthly_revenue += float(price or 0) * int(plan.get("subscribers", 0) or 0)
    churn_rate = "0.0" if not active_subscriptions else f"{max(1.2, min(4.5, 100 / active_subscriptions)):.1f}"
    return {
        "totalRevenue": f"${monthly_revenue:,.0f}",
        "activeSubscriptions": active_subscriptions,
        "mrr": f"${monthly_revenue:,.0f}",
        "churnRate": f"{churn_rate}%",
        "completedTransactions": len([item for item in transactions if item.get("status") == "completed"]),
    }


def serialize_admin_report(report):
    report_id = report.get("id") or str(report.get("_id", ""))
    date_value = report.get("date") or report.get("created_at") or datetime.utcnow()
    return {
        "id": report_id,
        "title": report.get("title", "Admin Security Snapshot"),
        "subtitle": report.get("subtitle", "Generated from backend data"),
        "date": date_value.isoformat() if hasattr(date_value, "isoformat") else str(date_value),
        "size": report.get("size", "1.8 MB"),
        "type": report.get("type", "PDF"),
        "status": report.get("status", "ready"),
        "scanCount": report.get("scanCount", 0),
        "vulnerabilities": report.get("vulnerabilities", 0),
        "critical": report.get("critical", 0),
        "score": report.get("score", 0),
        "downloads": report.get("downloads", 0),
        "findings": report.get("findings", []),
    }


def build_admin_report(payload=None):
    payload = payload or {}
    total_users = mongo.db.users.count_documents({})
    total_posts = mongo.db.blogs.count_documents({})
    total_likes = sum(blog.get("likes", 0) for blog in mongo.db.blogs.find({}))
    comments = blog_comment_count()
    vulnerabilities = total_vulnerability_count()
    critical = security_metrics_payload()[0]["value"]
    scan_count = sum(int(user.get("scans", 0) or 0) for user in mongo.db.users.find({}))
    score = max(50, min(98, 100 - critical * 3 - round(vulnerabilities / 12)))
    title = str(payload.get("title") or "Admin Security Snapshot").strip() or "Admin Security Snapshot"

    return {
        "id": f"report-{ObjectId()}",
        "title": title,
        "subtitle": str(payload.get("subtitle") or "Generated from current users, blog, reports, and security metrics").strip(),
        "date": datetime.utcnow(),
        "size": f"{1.6 + min(vulnerabilities, 120) / 100:.1f} MB",
        "type": "PDF",
        "status": "ready",
        "scanCount": scan_count,
        "vulnerabilities": vulnerabilities,
        "critical": critical,
        "score": score,
        "downloads": 0,
        "findings": [
            f"{total_users} account(s) under admin management.",
            f"{total_posts} blog post(s), {total_likes} like(s), and {comments} comment/reply item(s).",
            f"{critical} critical signal(s) need immediate review.",
            "Use admin user controls to disable risky accounts and content moderation to hide unsafe posts.",
        ],
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


@admin_bp.route("/admin/users", methods=["POST"])
@token_required
def create_user():
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    first_name = str(payload.get("firstName") or payload.get("first_name") or "").strip()
    last_name = str(payload.get("lastName") or payload.get("last_name") or "").strip()
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "Temp@12345")

    if not first_name or not last_name or not email:
        return jsonify({"message": "First name, last name, and email are required"}), 400

    if not validate_email_format(email):
        return jsonify({"message": "Enter a valid email address"}), 400

    password_error = validate_password(password)
    if password_error:
        return jsonify({"message": password_error}), 400

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"message": "Email already exists"}), 409

    scans, scans_error = parse_non_negative_int(payload.get("scans", 0), "Scans")
    vulnerabilities, vulnerabilities_error = parse_non_negative_int(payload.get("vulnerabilities", 0), "Vulnerabilities")
    if scans_error or vulnerabilities_error:
        return jsonify({"message": scans_error or vulnerabilities_error}), 400

    now = datetime.utcnow()
    user = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": hash_password(password),
        "role": payload.get("role") if payload.get("role") in ["user", "analyst", "manager", "admin"] else "user",
        "disabled": payload.get("status") == "disabled",
        "plan": str(payload.get("plan") or "Free").strip(),
        "phone": str(payload.get("phone") or "").strip(),
        "bio": str(payload.get("bio") or "").strip(),
        "scans": scans,
        "vulnerabilities": vulnerabilities,
        "is_verified": True,
        "created_at": now,
        "updated_at": now,
        "failed_attempts": 0,
        "lock_until": None,
    }

    result = mongo.db.users.insert_one(user)
    user["_id"] = result.inserted_id
    return jsonify(serialize_user(user)), 201


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

    if "firstName" in payload or "first_name" in payload:
        first_name = str(payload.get("firstName") or payload.get("first_name") or "").strip()
        if first_name:
            updates["first_name"] = first_name

    if "lastName" in payload or "last_name" in payload:
        last_name = str(payload.get("lastName") or payload.get("last_name") or "").strip()
        if last_name:
            updates["last_name"] = last_name

    if "email" in payload:
        email = str(payload.get("email") or "").strip().lower()
        if not validate_email_format(email):
            return jsonify({"message": "Enter a valid email address"}), 400
        duplicate = mongo.db.users.find_one({"email": email, "_id": {"$ne": object_id}})
        if duplicate:
            return jsonify({"message": "Email already exists"}), 409
        updates["email"] = email

    if payload.get("role") in ["user", "analyst", "manager", "admin"]:
        updates["role"] = payload["role"]

    if payload.get("status") in ["active", "disabled"]:
        updates["disabled"] = payload["status"] == "disabled"

    for field in ["phone", "bio", "plan"]:
        if field in payload:
            updates[field] = str(payload[field]).strip()

    for numeric_field in ["scans", "vulnerabilities"]:
        if numeric_field in payload:
            label = "Scans" if numeric_field == "scans" else "Vulnerabilities"
            parsed_value, error_message = parse_non_negative_int(payload[numeric_field], label)
            if error_message:
                return jsonify({"message": error_message}), 400
            updates[numeric_field] = parsed_value

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


@admin_bp.route("/admin/settings", methods=["GET"])
@token_required
def get_admin_settings():
    _, error = require_admin()
    if error:
        return error

    settings = merge_nested(DEFAULT_ADMIN_SETTINGS, get_admin_singleton("settings", {}))
    return jsonify(settings), 200


@admin_bp.route("/admin/settings", methods=["PUT"])
@token_required
def update_admin_settings():
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    current_settings = merge_nested(DEFAULT_ADMIN_SETTINGS, get_admin_singleton("settings", {}))
    next_settings = merge_nested(current_settings, payload)
    save_admin_singleton("settings", next_settings)
    return jsonify(next_settings), 200


@admin_bp.route("/admin/team", methods=["GET"])
@token_required
def get_admin_team():
    _, error = require_admin()
    if error:
        return error

    team = get_admin_singleton("team", DEFAULT_ADMIN_TEAM)
    return jsonify({"items": team}), 200


@admin_bp.route("/admin/team", methods=["POST"])
@token_required
def add_admin_team_member():
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    name = str(payload.get("name") or "New Admin").strip()
    email = str(payload.get("email") or "").strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"message": "Enter a valid admin email address"}), 400

    team = list(get_admin_singleton("team", DEFAULT_ADMIN_TEAM))
    if any(str(member.get("email", "")).lower() == email for member in team):
        return jsonify({"message": "Admin team email already exists"}), 409

    member = {
        "id": f"team-{ObjectId()}",
        "initials": initials_for(name),
        "name": name,
        "email": email,
        "status": payload.get("status", "pending"),
        "time": payload.get("time", "Invite pending"),
        "role": payload.get("role", "Admin"),
        "badges": payload.get("badges") if isinstance(payload.get("badges"), list) else ["Reports", "User Support"],
    }
    team.append(member)
    save_admin_singleton("team", team)
    return jsonify(member), 201


@admin_bp.route("/admin/team/<member_id>", methods=["PUT"])
@token_required
def update_admin_team_member(member_id):
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    team = list(get_admin_singleton("team", DEFAULT_ADMIN_TEAM))
    for member in team:
        if member.get("id") == member_id:
            if "email" in payload:
                next_email = str(payload.get("email") or "").strip().lower()
                if "@" not in next_email or "." not in next_email.split("@")[-1]:
                    return jsonify({"message": "Enter a valid admin email address"}), 400
                if any(
                    item.get("id") != member_id and str(item.get("email", "")).lower() == next_email
                    for item in team
                ):
                    return jsonify({"message": "Admin team email already exists"}), 409

            for field in ["name", "email", "role", "status", "time"]:
                if field in payload:
                    member[field] = str(payload[field]).strip() or member.get(field, "")
            if isinstance(payload.get("badges"), list):
                member["badges"] = payload["badges"]
            member["initials"] = initials_for(member.get("name"))
            save_admin_singleton("team", team)
            return jsonify(member), 200

    return jsonify({"message": "Team member not found"}), 404


@admin_bp.route("/admin/team/<member_id>", methods=["DELETE"])
@token_required
def delete_admin_team_member(member_id):
    _, error = require_admin()
    if error:
        return error

    team = list(get_admin_singleton("team", DEFAULT_ADMIN_TEAM))
    next_team = [member for member in team if member.get("id") != member_id]
    if len(next_team) == len(team):
        return jsonify({"message": "Team member not found"}), 404

    save_admin_singleton("team", next_team)
    return jsonify({"message": "Team member removed"}), 200


@admin_bp.route("/admin/pricing", methods=["GET"])
@token_required
def get_admin_pricing():
    _, error = require_admin()
    if error:
        return error

    pricing = merge_nested(DEFAULT_ADMIN_PRICING, get_admin_singleton("pricing", {}))
    return jsonify({**pricing, "stats": pricing_stats(pricing)}), 200


@admin_bp.route("/admin/pricing", methods=["PUT"])
@token_required
def update_admin_pricing():
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    pricing = merge_nested(DEFAULT_ADMIN_PRICING, payload)
    save_admin_singleton("pricing", pricing)
    return jsonify({**pricing, "stats": pricing_stats(pricing)}), 200


@admin_bp.route("/admin/pricing/plans", methods=["POST"])
@token_required
def add_admin_pricing_plan():
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    pricing = merge_nested(DEFAULT_ADMIN_PRICING, get_admin_singleton("pricing", {}))
    subscribers, subscribers_error = parse_non_negative_int(payload.get("subscribers", 0), "Subscribers")
    if subscribers_error:
        return jsonify({"message": subscribers_error}), 400

    plan = {
        "id": f"plan-{ObjectId()}",
        "name": str(payload.get("name") or "New Plan").strip(),
        "price": str(payload.get("price") or "$99").strip(),
        "description": str(payload.get("description") or "Custom security plan").strip(),
        "subscribers": subscribers,
        "badge": str(payload.get("badge") or "").strip(),
        "tone": payload.get("tone", "is-professional"),
        "features": payload.get("features") if isinstance(payload.get("features"), list) else [
            {"label": "Security scanning", "included": True},
            {"label": "PDF reports", "included": True},
            {"label": "Priority support", "included": False},
        ],
    }
    pricing["plans"] = list(pricing.get("plans", [])) + [plan]
    save_admin_singleton("pricing", pricing)
    return jsonify(plan), 201


@admin_bp.route("/admin/pricing/plans/<plan_id>", methods=["PUT"])
@token_required
def update_admin_pricing_plan(plan_id):
    _, error = require_admin()
    if error:
        return error

    payload = request.json or {}
    pricing = merge_nested(DEFAULT_ADMIN_PRICING, get_admin_singleton("pricing", {}))
    for plan in pricing.get("plans", []):
        if plan.get("id") == plan_id:
            for field in ["name", "price", "description", "badge", "tone"]:
                if field in payload:
                    plan[field] = str(payload[field]).strip()
            if "subscribers" in payload:
                subscribers, subscribers_error = parse_non_negative_int(payload.get("subscribers"), "Subscribers")
                if subscribers_error:
                    return jsonify({"message": subscribers_error}), 400
                plan["subscribers"] = subscribers
            if isinstance(payload.get("features"), list):
                plan["features"] = payload["features"]
            save_admin_singleton("pricing", pricing)
            return jsonify(plan), 200

    return jsonify({"message": "Pricing plan not found"}), 404


@admin_bp.route("/admin/pricing/plans/<plan_id>", methods=["DELETE"])
@token_required
def delete_admin_pricing_plan(plan_id):
    _, error = require_admin()
    if error:
        return error

    pricing = merge_nested(DEFAULT_ADMIN_PRICING, get_admin_singleton("pricing", {}))
    plans = pricing.get("plans", [])
    next_plans = [plan for plan in plans if plan.get("id") != plan_id]
    if len(next_plans) == len(plans):
        return jsonify({"message": "Pricing plan not found"}), 404

    pricing["plans"] = next_plans
    save_admin_singleton("pricing", pricing)
    return jsonify({"message": "Pricing plan deleted"}), 200


@admin_bp.route("/admin/reports", methods=["GET"])
@token_required
def list_admin_reports():
    _, error = require_admin()
    if error:
        return error

    reports = list_admin_scan_reports(25)
    return jsonify({"items": reports}), 200


@admin_bp.route("/admin/reports", methods=["POST"])
@token_required
def create_admin_report():
    _, error = require_admin()
    if error:
        return error

    report = build_admin_report(request.json or {})
    collection = getattr(mongo.db, "admin_reports", None)
    if collection is not None:
        collection.insert_one(report)
    return jsonify(serialize_admin_report(report)), 201


@admin_bp.route("/admin/reports/<report_id>/download", methods=["POST"])
@token_required
def record_admin_report_download(report_id):
    _, error = require_admin()
    if error:
        return error

    collection = getattr(mongo.db, "admin_reports", None)
    if collection is None:
        return jsonify({"message": "Report not found"}), 404

    report = collection.find_one({"id": report_id})
    if not report:
        return jsonify({"message": "Report not found"}), 404

    collection.update_one({"id": report_id}, {"$inc": {"downloads": 1}})
    report["downloads"] = int(report.get("downloads", 0) or 0) + 1
    return jsonify(serialize_admin_report(report)), 200
