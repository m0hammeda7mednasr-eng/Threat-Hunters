from flask import jsonify
from datetime import datetime
from database.db import mongo
from bson import ObjectId


def create_comment(blog_id, user_id, username, data):

    content = data.get("content", "").strip()
    parent_comment_id = data.get("parentCommentId")

    if not content:
        return jsonify({
            "message": "Comment content is required"
        }), 400

    blog = mongo.db.blogs.find_one({
        "_id": ObjectId(blog_id)
    })

    if not blog:
        return jsonify({
            "message": "Blog not found"
        }), 404

    comment = {
        "blog_id": blog_id,
        "user_id": str(user_id),
        "author_name": username,
        "content": content,
        "parent_comment_id": parent_comment_id,
        "createdAt": datetime.utcnow()
    }

    result = mongo.db.comments.insert_one(comment)

    mongo.db.blogs.update_one(
        {"_id": ObjectId(blog_id)},
        {"$inc": {"comments_count": 1}}
    )

    return jsonify({
        "message": "Comment added successfully",
        "comment_id": str(result.inserted_id)
    }), 201


def reply_comment(blog_id, parent_comment_id, user_id, username, data):

    content = data.get("content", "").strip()

    if not content:
        return jsonify({
            "message": "Reply content is required"
        }), 400

    parent = mongo.db.comments.find_one({
        "_id": ObjectId(parent_comment_id),
        "blog_id": blog_id
    })

    if not parent:
        return jsonify({
            "message": "Parent comment not found"
        }), 404

    reply = {
        "blog_id": blog_id,
        "user_id": str(user_id),
        "author_name": username,
        "content": content,
        "parent_comment_id": parent_comment_id,
        "createdAt": datetime.utcnow()
    }

    result = mongo.db.comments.insert_one(reply)

    mongo.db.blogs.update_one(
        {"_id": ObjectId(blog_id)},
        {"$inc": {"comments_count": 1}}
    )

    return jsonify({
        "message": "Reply added successfully",
        "comment_id": str(result.inserted_id)
    }), 201


def get_comments(blog_id):

    comments = []
    replies_map = {}

    cursor = mongo.db.comments.find({
        "blog_id": blog_id
    }).sort("createdAt", -1)

    for comment in cursor:
        comment_id = str(comment["_id"])
        serialized = {
            "id": comment_id,
            "author": comment["author_name"],
            "content": comment["content"],
            "createdAt": comment["createdAt"],
            "replies": []
        }

        parent_comment_id = comment.get("parent_comment_id")

        if parent_comment_id:
            replies_map.setdefault(str(parent_comment_id), []).append(serialized)
        else:
            comments.append(serialized)

    for comment in comments:
        comment["replies"] = replies_map.get(comment["id"], [])

    return jsonify(comments), 200
