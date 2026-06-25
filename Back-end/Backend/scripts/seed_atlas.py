from __future__ import annotations

import argparse
import json
import os
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from bson import ObjectId
from dotenv import load_dotenv
from pymongo import MongoClient


PACKAGE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = PACKAGE_DIR.parents[1]
LEGACY_BOOTSTRAP_PATH = ROOT_DIR / "server" / "data" / "mock-db.json"

sys.path.insert(0, str(PACKAGE_DIR))

from utils.password_utils import hash_password  # noqa: E402


def parse_dt(value: str | None):
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except Exception:
        return None


def load_legacy_bootstrap_data():
    return json.loads(LEGACY_BOOTSTRAP_PATH.read_text(encoding="utf-8"))


def password_from_env(env_name: str, email: str) -> str:
    password = os.getenv(env_name, "").strip()
    if not password:
        raise RuntimeError(f"{env_name} must be set before seeding {email}.")
    return password


def make_user_password(email: str) -> str:
    email = (email or "").lower()
    if email == "admin@threathunters.com":
        return password_from_env("ADMIN_SEED_PASSWORD", email)
    if email == "user@threathunters.com":
        return password_from_env("USER_SEED_PASSWORD", email)
    return password_from_env("DEFAULT_SEED_PASSWORD", email)


def build_user(doc: dict) -> dict:
    email = str(doc.get("email", "")).strip().lower()
    created_at = parse_dt(doc.get("createdAt")) or datetime.now(timezone.utc)
    return {
        "_id": ObjectId(),
        "first_name": str(doc.get("firstName", "")).strip(),
        "last_name": str(doc.get("lastName", "")).strip(),
        "email": email,
        "password": hash_password(make_user_password(email)),
        "role": doc.get("role", "user"),
        "is_verified": True,
        "verification_code": None,
        "verification_expires": None,
        "created_at": created_at,
        "failed_attempts": 0,
        "lock_until": None,
        "last_login": None,
        "disabled": False,
        "phone": str(doc.get("phone", "")).strip(),
        "bio": str(doc.get("bio", "")).strip(),
        "settings": deepcopy(doc.get("settings") or {}),
        "plan": doc.get("plan", "Free"),
        "scans": int(doc.get("scans", 0) or 0),
        "vulnerabilities": int(doc.get("vulnerabilities", 0) or 0),
    }


def normalize_blog_title(title: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in title or "")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "post"


def build_blogs(bootstrap_posts: list[dict], user_map: dict[str, ObjectId]) -> tuple[list[dict], list[dict], list[dict]]:
    blogs = []
    comments = []
    likes = []
    blog_views = []

    for post in bootstrap_posts:
        blog_id = ObjectId()
        author_email = str(post.get("authorEmail") or "").strip().lower()
        author_id = str(user_map.get(author_email, next(iter(user_map.values()))))
        created_at = parse_dt(post.get("publishedAt")) or datetime.now(timezone.utc)
        updated_at = parse_dt(post.get("updatedAt")) or created_at
        blog = {
            "_id": blog_id,
            "title": str(post.get("title", "")).strip(),
            "slug": normalize_blog_title(str(post.get("title", "")).strip()),
            "content": str(post.get("content", "")).strip(),
            "description": str(post.get("description", "")).strip(),
            "category": str(post.get("category", "General")).strip() or "General",
            "author_id": author_id,
            "author_name": str(post.get("author", "")).strip() or "Threat Hunters",
            "status": str(post.get("status", "published")).strip(),
            "tags": list(post.get("tags") or []),
            "imageUrl": str(post.get("imageUrl", "")).strip(),
            "imageName": str(post.get("imageName", "")).strip(),
            "badge": str(post.get("badge", "")).strip(),
            "views": int(post.get("views", 0) or 0),
            "likes": int(post.get("likes", 0) or 0),
            "shares": int(post.get("shares", 0) or 0),
            "comments_count": 0,
            "createdAt": created_at,
            "updatedAt": updated_at,
        }

        comment_count = 0
        for item in post.get("comments") or []:
            comment_id = ObjectId()
            comment_email = str(item.get("authorEmail") or "").strip().lower()
            comment_user_id = str(user_map.get(comment_email, author_id))
            comments.append({
                "_id": comment_id,
                "blog_id": str(blog_id),
                "user_id": comment_user_id,
                "author_name": str(item.get("author", "")).strip(),
                "content": str(item.get("text", "")).strip(),
                "parent_comment_id": None,
                "createdAt": parse_dt(item.get("createdAt")) or created_at,
            })
            comment_count += 1

            for reply in item.get("replies") or []:
                reply_email = str(reply.get("authorEmail") or "").strip().lower()
                reply_user_id = str(user_map.get(reply_email, author_id))
                comments.append({
                    "_id": ObjectId(),
                    "blog_id": str(blog_id),
                    "user_id": reply_user_id,
                    "author_name": str(reply.get("author", "")).strip(),
                    "content": str(reply.get("text", "")).strip(),
                    "parent_comment_id": str(comment_id),
                    "createdAt": parse_dt(reply.get("createdAt")) or created_at,
                })
                comment_count += 1

        blog["comments_count"] = int(post.get("comments_count") or comment_count)

        for email in post.get("likedBy") or []:
            user_id = str(user_map.get(str(email).strip().lower(), author_id))
            likes.append({
                "_id": ObjectId(),
                "blog_id": str(blog_id),
                "user_id": user_id,
                "likedAt": created_at,
            })

        for idx in range(min(int(post.get("views", 0) or 0), 5)):
            blog_views.append({
                "_id": ObjectId(),
                "blog_id": str(blog_id),
                "user_id": str(author_id),
                "viewedAt": created_at,
                "seedIndex": idx,
            })

        blogs.append(blog)

    return blogs, comments, likes, blog_views


def main():
    parser = argparse.ArgumentParser(description="Seed Atlas MongoDB from legacy bootstrap data.")
    parser.add_argument("--reset", action="store_true", help="Drop target collections before seeding.")
    args = parser.parse_args()

    load_dotenv(ROOT_DIR / "Back-end" / ".env")
    mongo_uri = os.getenv("MONGO_URI")

    if not mongo_uri:
        raise SystemExit("MONGO_URI is missing from Back-end/.env")

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
    db = client.get_default_database()
    client.admin.command("ping")

    bootstrap = load_legacy_bootstrap_data()
    users = [build_user(user) for user in bootstrap.get("users", [])]
    user_map = {user["email"]: user["_id"] for user in users}

    blogs, comments, likes, blog_views = build_blogs(bootstrap.get("posts", []), user_map)

    if args.reset:
        for collection_name in [
            "users",
            "blogs",
            "comments",
            "likes",
            "blog_views",
            "password_reset_tokens",
            "web_content",
            "admin_config",
            "admin_reports",
        ]:
            db[collection_name].delete_many({})

    blog_seed_exists = db.blogs.count_documents({}) > 0
    seed_blog_data = args.reset or not blog_seed_exists

    if users and (args.reset or db.users.count_documents({}) == 0):
        db.users.insert_many(users)

    if seed_blog_data:
        if blogs:
            db.blogs.insert_many(blogs)
        if comments:
            db.comments.insert_many(comments)
        if likes:
            db.likes.insert_many(likes)
        if blog_views:
            db.blog_views.insert_many(blog_views)
    else:
        print("Blogs already exist; skipping blog seed data to avoid duplicates.")

    for page, payload in (bootstrap.get("webContent") or {}).items():
        record = deepcopy(payload)
        record["page"] = page
        db.web_content.update_one({"page": page}, {"$set": record}, upsert=True)

    db.admin_config.update_one(
        {"key": "settings"},
        {"$set": {"key": "settings", "value": deepcopy(bootstrap.get("adminSettings") or {}), "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
    db.admin_config.update_one(
        {"key": "team"},
        {"$set": {"key": "team", "value": deepcopy(bootstrap.get("adminTeam") or []), "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )
    db.admin_config.update_one(
        {"key": "pricing"},
        {"$set": {"key": "pricing", "value": deepcopy(bootstrap.get("adminPricing") or {}), "updated_at": datetime.now(timezone.utc)}},
        upsert=True,
    )

    if bootstrap.get("adminReports"):
        db.admin_reports.insert_many(deepcopy(bootstrap["adminReports"]))

    print(
        f"Seeded Atlas database '{db.name}' with "
        f"{len(users)} users, {len(blogs)} blogs, {len(comments)} comments, "
        f"{len(likes)} likes, {len(blog_views)} blog views."
    )


if __name__ == "__main__":
    main()
