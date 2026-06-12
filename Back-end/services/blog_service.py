from flask import jsonify
from datetime import datetime
from database.db import mongo


def create_blog(data):
    title = data.get("title")
    content = data.get("content")
    category = data.get("category")

    if not title or not content:
        return jsonify({"message": "Title and content are required"}), 400

    mongo.db.blogs.insert_one({
        "title": title.strip(),
        "content": content.strip(),
        "category": category if category else "General",
        "author": "Admin",
        "views": 0,
        "createdAt": datetime.utcnow()
    })

    return jsonify({
        "message": "Blog created successfully"
    }), 201

def get_blogs():
    blogs = []

    for blog in mongo.db.blogs.find():
        blogs.append({
            "id": str(blog["_id"]),
            "title": blog["title"],
            "content": blog["content"],
            "category": blog["category"],
            "author": blog["author"],
            "views": blog["views"]
        })

    return jsonify(blogs), 200