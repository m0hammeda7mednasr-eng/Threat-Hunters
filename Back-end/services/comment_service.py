from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from flask import jsonify

from database.db import mongo


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_object_id(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def _is_admin(user):
    return bool(user and user.get("role") == "admin")


def _can_manage_comment(comment, current_user):
    if not current_user:
        return False

    return (
        comment.get("user_id") == str(current_user.get("_id"))
        or _is_admin(current_user)
    )


def create_comment(blog_id, user_id, username, data):
    payload = data or {}
    content = str(payload.get("content", "")).strip()
    parent_comment_id = payload.get("parentCommentId")

    if not content:
        return jsonify({"message": "Comment content is required"}), 400

    blog_object_id = _parse_object_id(blog_id)
    if not blog_object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    blog = mongo.db.blogs.find_one({"_id": blog_object_id})
    if not blog:
        return jsonify({"message": "Blog not found"}), 404

    comment = {
        "blog_id": blog_id,
        "user_id": str(user_id),
        "author_name": username,
        "content": content,
        "parent_comment_id": parent_comment_id,
        "createdAt": _utcnow(),
    }

    result = mongo.db.comments.insert_one(comment)
    mongo.db.blogs.update_one({"_id": blog_object_id}, {"$inc": {"comments_count": 1}})

    return jsonify({
        "message": "Comment added successfully",
        "comment_id": str(result.inserted_id),
    }), 201


def reply_comment(blog_id, parent_comment_id, user_id, username, data):
    payload = data or {}
    content = str(payload.get("content", "")).strip()

    if not content:
        return jsonify({"message": "Reply content is required"}), 400

    blog_object_id = _parse_object_id(blog_id)
    parent_object_id = _parse_object_id(parent_comment_id)
    if not blog_object_id or not parent_object_id:
        return jsonify({"message": "Invalid comment id"}), 400

    parent = mongo.db.comments.find_one({
        "_id": parent_object_id,
        "blog_id": blog_id,
    })
    if not parent:
        return jsonify({"message": "Parent comment not found"}), 404

    reply = {
        "blog_id": blog_id,
        "user_id": str(user_id),
        "author_name": username,
        "content": content,
        "parent_comment_id": parent_comment_id,
        "createdAt": _utcnow(),
    }

    result = mongo.db.comments.insert_one(reply)
    mongo.db.blogs.update_one({"_id": blog_object_id}, {"$inc": {"comments_count": 1}})

    return jsonify({
        "message": "Reply added successfully",
        "comment_id": str(result.inserted_id),
    }), 201


def get_comments(blog_id):
    blog_object_id = _parse_object_id(blog_id)
    if not blog_object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    comments = []
    replies_map = {}

    cursor = mongo.db.comments.find({"blog_id": blog_id}).sort("createdAt", -1)

    for comment in cursor:
        comment_id = str(comment["_id"])
        serialized = {
            "id": comment_id,
            "author": comment["author_name"],
            "content": comment["content"],
            "createdAt": comment["createdAt"],
            "replies": [],
        }

        parent_comment_id = comment.get("parent_comment_id")
        if parent_comment_id:
            replies_map.setdefault(str(parent_comment_id), []).append(serialized)
        else:
            comments.append(serialized)

    for comment in comments:
        comment["replies"] = replies_map.get(comment["id"], [])

    return jsonify(comments), 200


def update_comment(comment_id, current_user, data):
    object_id = _parse_object_id(comment_id)
    if not object_id:
        return jsonify({"message": "Invalid comment id"}), 400

    comment = mongo.db.comments.find_one({"_id": object_id})
    if not comment:
        return jsonify({"message": "Comment not found"}), 404

    if not _can_manage_comment(comment, current_user):
        return jsonify({"message": "Unauthorized"}), 403

    content = str((data or {}).get("content", "")).strip()
    if not content:
        return jsonify({"message": "Comment content is required"}), 400

    mongo.db.comments.update_one(
        {"_id": object_id},
        {"$set": {"content": content, "updatedAt": _utcnow()}},
    )

    return jsonify({"message": "Comment updated successfully"}), 200


def delete_comment(comment_id, current_user):
    object_id = _parse_object_id(comment_id)
    if not object_id:
        return jsonify({"message": "Invalid comment id"}), 400

    comment = mongo.db.comments.find_one({"_id": object_id})
    if not comment:
        return jsonify({"message": "Comment not found"}), 404

    if not _can_manage_comment(comment, current_user):
        return jsonify({"message": "Unauthorized"}), 403

    mongo.db.comments.delete_one({"_id": object_id})
    mongo.db.blogs.update_one(
        {"_id": _parse_object_id(comment["blog_id"])},
        {"$inc": {"comments_count": -1}},
    )

    return jsonify({"message": "Comment deleted successfully"}), 200
