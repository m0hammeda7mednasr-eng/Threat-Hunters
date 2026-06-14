from flask import Blueprint, jsonify

from database.db import mongo
from middleware.auth_middleware import token_required


dashboard_bp = Blueprint("dashboard", __name__)


def count_blog_comments():
    total = 0
    for blog in mongo.db.blogs.find({}, {"comments_count": 1}):
        total += blog.get("comments_count", 0)
    return total


@dashboard_bp.route("/dashboard/stats", methods=["GET"])
@token_required
def stats():
    total_users = mongo.db.users.count_documents({})
    total_blogs = mongo.db.blogs.count_documents({})
    total_likes = sum(blog.get("likes", 0) for blog in mongo.db.blogs.find({}, {"likes": 1}))

    return jsonify([
        {"label": "Total Users", "value": str(total_users), "subtitle": "Registered accounts"},
        {"label": "Published Posts", "value": str(total_blogs), "subtitle": "Blog articles in the system"},
        {"label": "Blog Likes", "value": str(total_likes), "subtitle": "Across published articles"},
        {"label": "Comments", "value": str(count_blog_comments()), "subtitle": "Reader discussions"},
    ]), 200


@dashboard_bp.route("/dashboard/activities", methods=["GET"])
@token_required
def activities():
    latest_blogs = mongo.db.blogs.find({}, {"title": 1, "status": 1}).sort("updatedAt", -1).limit(3)
    payload = [
        {
            "title": "Blog updated",
            "detail": f"{blog.get('title', 'Untitled')} is {blog.get('status', 'published')}",
        }
        for blog in latest_blogs
    ]

    if not payload:
        payload = [{"title": "Workspace ready", "detail": "No recent content changes yet"}]

    return jsonify(payload), 200


@dashboard_bp.route("/dashboard/security-metrics", methods=["GET"])
@token_required
def security_metrics():
    return jsonify([
        {"label": "Critical", "value": 12},
        {"label": "High", "value": 27},
        {"label": "Medium", "value": 41},
        {"label": "Low", "value": 88},
    ]), 200
