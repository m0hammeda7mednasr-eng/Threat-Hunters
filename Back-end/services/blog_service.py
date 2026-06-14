from flask import jsonify
from datetime import datetime
from database.db import mongo
from bson import ObjectId
import re


def is_admin(user):
    return user and user.get("role") == "admin"


def generate_slug(title):
    slug = title.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'\s+', '-', slug)
    return slug


def create_blog(data, user_id, username):

    title = data.get("title", "").strip()
    content = data.get("content", "").strip()
    category = data.get("category", "General").strip()
    description = data.get("description", "").strip()
    tags = data.get("tags", [])

    if not title:
        return jsonify({
            "message": "Title is required"
        }), 400

    if not content:
        return jsonify({
            "message": "Content is required"
        }), 400

    slug = generate_slug(title)

    existing_blog = mongo.db.blogs.find_one({
        "slug": slug
    })

    if existing_blog:
        return jsonify({
            "message": "Blog with similar title already exists"
        }), 400

    status = data.get("status", "published")
    if status not in ["published", "hidden"]:
        status = "published"

    blog = {
        "title": title,
        "slug": slug,
        "content": content,
        "description": description or content[:180],
        "category": category,

        "author_id": str(user_id),
        "author_name": username,

        "status": status,
        "tags": tags if isinstance(tags, list) else [],

        "views": 0,
        "likes": 0,
        "shares": 0,
        "comments_count": 0,

        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }

    result = mongo.db.blogs.insert_one(blog)

    return jsonify({
        "message": "Blog created successfully",
        "blog_id": str(result.inserted_id),
        "slug": slug
    }), 201


def update_blog(blog_id, data, current_user):

    try:

        blog = mongo.db.blogs.find_one({
            "_id": ObjectId(blog_id)
        })

        if not blog:
            return jsonify({
                "message": "Blog not found"
            }), 404

        if not current_user:
            return jsonify({
                "message": "Unauthorized"
            }), 401

        updates = {}

        if data.get("title"):
            updates["title"] = data["title"].strip()
            updates["slug"] = generate_slug(data["title"])

        if data.get("content"):
            updates["content"] = data["content"].strip()

        if data.get("description"):
            updates["description"] = data["description"].strip()

        if data.get("category"):
            updates["category"] = data["category"].strip()

        if isinstance(data.get("tags"), list):
            updates["tags"] = data["tags"]

        if data.get("badge"):
            updates["badge"] = data["badge"].strip()

        if data.get("status") in ["published", "hidden"]:
            updates["status"] = data["status"]

        updates["updatedAt"] = datetime.utcnow()

        mongo.db.blogs.update_one(
            {"_id": ObjectId(blog_id)},
            {"$set": updates}
        )

        return jsonify({
            "message": "Blog updated successfully"
        }), 200

    except Exception as e:
        print("UPDATE BLOG ERROR:", e)
        return jsonify({
            "message": "Failed to update blog"
        }), 500


def delete_blog(blog_id, current_user):

    try:
        if not current_user:
            return jsonify({
                "message": "Unauthorized"
            }), 401

        result = mongo.db.blogs.delete_one({
            "_id": ObjectId(blog_id)
        })

        if result.deleted_count == 0:
            return jsonify({
                "message": "Blog not found"
            }), 404

        mongo.db.comments.delete_many({
            "blog_id": blog_id
        })

        mongo.db.likes.delete_many({
            "blog_id": blog_id
        })

        return jsonify({
            "message": "Blog deleted successfully"
        }), 200

    except Exception as e:
        print("DELETE BLOG ERROR:", e)
        return jsonify({
            "message": "Failed to delete blog"
        }), 500


def share_blog(blog_id):

    try:
        blog = mongo.db.blogs.find_one({
            "_id": ObjectId(blog_id)
        })

        if not blog:
            return jsonify({
                "message": "Blog not found"
            }), 404

        mongo.db.blogs.update_one(
            {"_id": ObjectId(blog_id)},
            {"$inc": {"shares": 1}}
        )

        return jsonify({
            "message": "Blog shared",
            "shared": True
        }), 200

    except Exception as e:
        print("SHARE BLOG ERROR:", e)
        return jsonify({
            "message": "Failed to share blog"
        }), 500


def set_blog_status(blog_id, status, current_user):

    try:
        if not is_admin(current_user):
            return jsonify({
                "message": "Admin access required"
            }), 403

        if status not in ["published", "hidden"]:
            return jsonify({
                "message": "Status must be published or hidden"
            }), 400

        result = mongo.db.blogs.update_one(
            {"_id": ObjectId(blog_id)},
            {"$set": {
                "status": status,
                "updatedAt": datetime.utcnow()
            }}
        )

        if result.matched_count == 0:
            return jsonify({
                "message": "Blog not found"
            }), 404

        return jsonify({
            "message": "Blog status updated",
            "status": status
        }), 200

    except Exception as e:
        print("BLOG STATUS ERROR:", e)
        return jsonify({
            "message": "Failed to update blog status"
        }), 500


def get_blogs(current_user=None, include_hidden=False):

    blogs = []

    query = {}
    if not include_hidden or not is_admin(current_user):
        query["status"] = "published"

    cursor = mongo.db.blogs.find(query).sort(
        "createdAt",
        -1
    )

    for blog in cursor:

        blogs.append({
            "id": str(blog["_id"]),
            "title": blog.get("title"),
            "slug": blog.get("slug"),
            "category": blog.get("category"),
            "description": blog.get("description"),
            "author": blog.get("author_name"),
            "views": blog.get("views", 0),
            "likes": blog.get("likes", 0),
            "shares": blog.get("shares", 0),
            "comments_count": blog.get("comments_count", 0),
            "tags": blog.get("tags", []),
            "status": blog.get("status", "published"),
            "createdAt": blog.get("createdAt"),
            "updatedAt": blog.get("updatedAt")
        })

    return jsonify(blogs), 200


def get_blog_by_id(blog_id, current_user):

    try:

        query = {"_id": ObjectId(blog_id)}
        if not is_admin(current_user):
            query["status"] = "published"

        blog = mongo.db.blogs.find_one(query)

        if not blog:
            return jsonify({
                "message": "Blog not found"
            }), 404

        if current_user:

            existing_view = mongo.db.blog_views.find_one({
                "blog_id": blog_id,
                "user_id": str(current_user["_id"])
            })

            if not existing_view:

                mongo.db.blog_views.insert_one({
                    "blog_id": blog_id,
                    "user_id": str(current_user["_id"]),
                    "viewedAt": datetime.utcnow()
                })

                mongo.db.blogs.update_one(
                    {"_id": blog["_id"]},
                    {"$inc": {"views": 1}}
                )

                blog["views"] = blog.get("views", 0) + 1

        return jsonify({
            "id": str(blog["_id"]),
            "title": blog["title"],
            "slug": blog["slug"],
            "content": blog["content"],
            "description": blog.get("description"),
            "category": blog["category"],
            "author": blog["author_name"],
            "views": blog.get("views", 0),
            "likes": blog.get("likes", 0),
            "shares": blog.get("shares", 0),
            "comments_count": blog.get("comments_count", 0),
            "tags": blog.get("tags", []),
            "status": blog.get("status", "published"),
            "createdAt": blog["createdAt"],
            "updatedAt": blog["updatedAt"]
        }), 200

    except Exception as e:

        print("BLOG ERROR:", e)

        return jsonify({
            "message": "Invalid blog id"
        }), 400
