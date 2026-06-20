from datetime import datetime, timezone
import re

from bson import ObjectId
from bson.errors import InvalidId
from flask import jsonify

from database.db import mongo


VALID_BLOG_STATUSES = {"published", "hidden"}


def _utcnow():
    return datetime.now(timezone.utc)


def is_admin(user):
    return bool(user and user.get("role") == "admin")


def _parse_object_id(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


def _clean_text(value, default=""):
    return str(value or default).strip()


def _clean_tags(value):
    if not isinstance(value, list):
        return []

    return [str(tag).strip() for tag in value if str(tag).strip()]


def _initial_from_name(name):
    for part in str(name or "").strip().split():
        if part:
            return part[0].upper()
    return ""


def generate_slug(title):
    slug = re.sub(r"[^a-z0-9\s-]", "", _clean_text(title).lower())
    slug = re.sub(r"[\s-]+", "-", slug).strip("-")
    return slug or "post"


def _serialize_blog(blog, include_content=False, include_media=False):
    payload = {
        "id": str(blog["_id"]),
        "title": blog.get("title", ""),
        "slug": blog.get("slug", ""),
        "description": blog.get("description", ""),
        "category": blog.get("category", "General"),
        "author": blog.get("author_name", ""),
        "authorInitial": _initial_from_name(blog.get("author_name", "")),
        "views": blog.get("views", 0),
        "likes": blog.get("likes", 0),
        "shares": blog.get("shares", 0),
        "comments_count": blog.get("comments_count", 0),
        "tags": blog.get("tags", []),
        "status": blog.get("status", "published"),
        "createdAt": blog.get("createdAt"),
        "updatedAt": blog.get("updatedAt"),
    }

    if include_content:
        payload["content"] = blog.get("content", "")

    if include_media:
        payload["imageUrl"] = blog.get("imageUrl", "")
        payload["imageName"] = blog.get("imageName", "")

    return payload


def _require_author_or_admin(blog, current_user):
    if not current_user:
        return False

    is_author = blog.get("author_id") == str(current_user.get("_id"))
    return is_author or is_admin(current_user)


def create_blog(data, user_id, username):
    data = data or {}

    title = _clean_text(data.get("title"))
    content = _clean_text(data.get("content"))
    category = _clean_text(data.get("category"), "General") or "General"
    description = _clean_text(data.get("description"))
    tags = _clean_tags(data.get("tags"))
    image_url = _clean_text(data.get("imageUrl"))
    image_name = _clean_text(data.get("imageName"))

    if not title:
        return jsonify({"message": "Title is required"}), 400

    if not content:
        return jsonify({"message": "Content is required"}), 400

    slug = generate_slug(title)
    existing_blog = mongo.db.blogs.find_one({"slug": slug})

    if existing_blog:
        return jsonify({"message": "Blog with similar title already exists"}), 400

    status = data.get("status", "published")
    if status not in VALID_BLOG_STATUSES:
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
        "tags": tags,
        "imageUrl": image_url,
        "imageName": image_name,
        "views": 0,
        "likes": 0,
        "shares": 0,
        "comments_count": 0,
        "createdAt": _utcnow(),
        "updatedAt": _utcnow(),
    }

    result = mongo.db.blogs.insert_one(blog)
    created_blog = {**blog, "_id": result.inserted_id}

    return jsonify({
        "message": "Blog created successfully",
        "blog_id": str(result.inserted_id),
        "id": str(result.inserted_id),
        "slug": slug,
        "blog": _serialize_blog(created_blog, include_content=True, include_media=True),
    }), 201


def update_blog(blog_id, data, current_user):
    object_id = _parse_object_id(blog_id)
    if not object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    blog = mongo.db.blogs.find_one({"_id": object_id})
    if not blog:
        return jsonify({"message": "Blog not found"}), 404

    if not _require_author_or_admin(blog, current_user):
        return jsonify({"message": "Unauthorized"}), 403

    data = data or {}
    updates = {}

    if "title" in data:
        title = _clean_text(data.get("title"))
        if not title:
            return jsonify({"message": "Title is required"}), 400

        new_slug = generate_slug(title)
        duplicate = mongo.db.blogs.find_one({
            "slug": new_slug,
            "_id": {"$ne": object_id},
        })
        if duplicate:
            return jsonify({"message": "Blog with similar title already exists"}), 400

        updates["title"] = title
        updates["slug"] = new_slug

    if "content" in data:
        content = _clean_text(data.get("content"))
        if not content:
            return jsonify({"message": "Content is required"}), 400
        updates["content"] = content

    if "description" in data:
        updates["description"] = _clean_text(data.get("description"))

    if "category" in data:
        category = _clean_text(data.get("category"))
        if not category:
            return jsonify({"message": "Category is required"}), 400
        updates["category"] = category

    if "tags" in data:
        updates["tags"] = _clean_tags(data.get("tags"))

    if "badge" in data:
        updates["badge"] = _clean_text(data.get("badge"))

    if "imageUrl" in data:
        updates["imageUrl"] = _clean_text(data.get("imageUrl"))

    if "imageName" in data:
        updates["imageName"] = _clean_text(data.get("imageName"))

    if data.get("status") in VALID_BLOG_STATUSES:
        updates["status"] = data["status"]

    updates["updatedAt"] = _utcnow()

    mongo.db.blogs.update_one({"_id": object_id}, {"$set": updates})
    updated_blog = mongo.db.blogs.find_one({"_id": object_id}) or {**blog, **updates, "_id": object_id}

    return jsonify({
        "message": "Blog updated successfully",
        "id": blog_id,
        "slug": updated_blog.get("slug", blog.get("slug")),
        "blog": _serialize_blog(updated_blog, include_content=True, include_media=True),
    }), 200


def delete_blog(blog_id, current_user):
    object_id = _parse_object_id(blog_id)
    if not object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    blog = mongo.db.blogs.find_one({"_id": object_id})
    if not blog:
        return jsonify({"message": "Blog not found"}), 404

    if not _require_author_or_admin(blog, current_user):
        return jsonify({"message": "Unauthorized"}), 403

    mongo.db.comments.delete_many({"blog_id": blog_id})
    mongo.db.likes.delete_many({"blog_id": blog_id})
    if hasattr(mongo.db, "blog_views"):
        mongo.db.blog_views.delete_many({"blog_id": blog_id})
    mongo.db.blogs.delete_one({"_id": object_id})

    return jsonify({"message": "Blog deleted successfully"}), 200


def share_blog(blog_id):
    object_id = _parse_object_id(blog_id)
    if not object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    blog = mongo.db.blogs.find_one({"_id": object_id})
    if not blog:
        return jsonify({"message": "Blog not found"}), 404

    mongo.db.blogs.update_one({"_id": object_id}, {"$inc": {"shares": 1}})

    return jsonify({"message": "Blog shared", "shared": True}), 200


def set_blog_status(blog_id, status, current_user):
    object_id = _parse_object_id(blog_id)
    if not object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    if not is_admin(current_user):
        return jsonify({"message": "Admin access required"}), 403

    if status not in VALID_BLOG_STATUSES:
        return jsonify({"message": "Status must be published or hidden"}), 400

    result = mongo.db.blogs.update_one(
        {"_id": object_id},
        {"$set": {"status": status, "updatedAt": _utcnow()}},
    )

    if result.matched_count == 0:
        return jsonify({"message": "Blog not found"}), 404

    return jsonify({"message": "Blog status updated", "status": status}), 200


def get_blogs(current_user=None, include_hidden=False):
    query = {}
    if not include_hidden or not is_admin(current_user):
        query["status"] = "published"

    blogs = []
    cursor = mongo.db.blogs.find(query).sort("createdAt", -1)

    for blog in cursor:
        blogs.append(_serialize_blog(blog))

    return jsonify(blogs), 200


def get_blog_by_id(blog_id, current_user):
    object_id = _parse_object_id(blog_id)
    if not object_id:
        return jsonify({"message": "Invalid blog id"}), 400

    query = {"_id": object_id}
    if not is_admin(current_user):
        query["status"] = "published"

    blog = mongo.db.blogs.find_one(query)
    if not blog:
        return jsonify({"message": "Blog not found"}), 404

    if current_user and hasattr(mongo.db, "blog_views"):
        existing_view = mongo.db.blog_views.find_one({
            "blog_id": blog_id,
            "user_id": str(current_user["_id"]),
        })

        if not existing_view:
            mongo.db.blog_views.insert_one({
                "blog_id": blog_id,
                "user_id": str(current_user["_id"]),
                "viewedAt": _utcnow(),
            })
            mongo.db.blogs.update_one({"_id": object_id}, {"$inc": {"views": 1}})
            blog["views"] = blog.get("views", 0) + 1

    return jsonify(_serialize_blog(blog, include_content=True, include_media=True)), 200
