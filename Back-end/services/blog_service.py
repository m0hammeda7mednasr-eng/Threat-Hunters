from flask import jsonify
from datetime import datetime
from database.db import mongo
import re


def generate_slug(title):
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug)
    return slug


def create_blog(data):

    title = data.get("title", "").strip()
    content = data.get("content", "").strip()
    category = data.get("category", "General").strip()

    if not title:
        return jsonify({"message": "Title is required"}), 400

    if not content:
        return jsonify({"message": "Content is required"}), 400

    slug = generate_slug(title)

    # منع تكرار نفس الـ slug
    existing_blog = mongo.db.blogs.find_one({
        "slug": slug
    })

    if existing_blog:
        return jsonify({
            "message": "Blog with similar title already exists"
        }), 400

    blog = {
        "title": title,
        "slug": slug,
        "content": content,
        "category": category,

        # Future Ready
        "author": "Admin",
        "status": "published",
        "tags": [],

        # Statistics
        "views": 0,
        "likes": 0,
        "comments_count": 0,

        # Dates
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }

    result = mongo.db.blogs.insert_one(blog)

    return jsonify({
        "message": "Blog created successfully",
        "blog_id": str(result.inserted_id),
        "slug": slug
    }), 201


def get_blogs():

    blogs = []

    cursor = mongo.db.blogs.find().sort(
        "createdAt",
        -1
    )

    for blog in cursor:

        blogs.append({
            "id": str(blog["_id"]),
            "title": blog.get("title"),
            "slug": blog.get("slug"),
            "category": blog.get("category"),
            "author": blog.get("author"),
            "views": blog.get("views", 0),
            "likes": blog.get("likes", 0),
            "comments_count": blog.get("comments_count", 0),
            "createdAt": blog.get("createdAt")
        })

    return jsonify(blogs), 200


def get_blog_by_id(blog_id):

    from bson import ObjectId

    try:

        blog = mongo.db.blogs.find_one({
            "_id": ObjectId(blog_id)
        })

        if not blog:
            return jsonify({
                "message": "Blog not found"
            }), 404

        # زيادة المشاهدات تلقائياً
        mongo.db.blogs.update_one(
            {"_id": blog["_id"]},
            {"$inc": {"views": 1}}
        )

        return jsonify({
            "id": str(blog["_id"]),
            "title": blog["title"],
            "slug": blog["slug"],
            "content": blog["content"],
            "category": blog["category"],
            "author": blog["author"],
            "views": blog.get("views", 0) + 1,
            "likes": blog.get("likes", 0),
            "comments_count": blog.get("comments_count", 0),
            "createdAt": blog["createdAt"],
            "updatedAt": blog["updatedAt"]
        }), 200

    except Exception:
        return jsonify({
            "message": "Invalid blog id"
        }), 400