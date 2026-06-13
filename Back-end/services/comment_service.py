from flask import jsonify
from datetime import datetime
from database.db import mongo
from bson import ObjectId


def create_comment(blog_id, user_id, username, data):

    content = data.get("content", "").strip()

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


def get_comments(blog_id):

    comments = []

    cursor = mongo.db.comments.find({
        "blog_id": blog_id
    }).sort("createdAt", -1)

    for comment in cursor:

        comments.append({
            "id": str(comment["_id"]),
            "author": comment["author_name"],
            "content": comment["content"],
            "createdAt": comment["createdAt"]
        })

    return jsonify(comments), 200