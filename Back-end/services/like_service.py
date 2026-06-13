from flask import jsonify
from datetime import datetime
from database.db import mongo
from bson import ObjectId


def toggle_like(blog_id, user_id):

    blog = mongo.db.blogs.find_one({
        "_id": ObjectId(blog_id)
    })

    if not blog:
        return jsonify({
            "message": "Blog not found"
        }), 404

    existing_like = mongo.db.likes.find_one({
        "blog_id": blog_id,
        "user_id": str(user_id)
    })

    # Unlike
    if existing_like:

        mongo.db.likes.delete_one({
            "_id": existing_like["_id"]
        })

        mongo.db.blogs.update_one(
            {"_id": ObjectId(blog_id)},
            {"$inc": {"likes": -1}}
        )

        return jsonify({
            "message": "Like removed",
            "liked": False
        }), 200

    # Like
    mongo.db.likes.insert_one({
        "blog_id": blog_id,
        "user_id": str(user_id),
        "createdAt": datetime.utcnow()
    })

    mongo.db.blogs.update_one(
        {"_id": ObjectId(blog_id)},
        {"$inc": {"likes": 1}}
    )

    return jsonify({
        "message": "Blog liked",
        "liked": True
    }), 200