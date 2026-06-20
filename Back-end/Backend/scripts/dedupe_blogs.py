from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient


ROOT_DIR = Path(__file__).resolve().parents[2]


def _blog_sort_key(blog: dict) -> tuple:
    updated_at = blog.get("updatedAt") or blog.get("createdAt") or datetime.min.replace(tzinfo=timezone.utc)
    return (updated_at, str(blog.get("_id")))


def main() -> int:
    load_dotenv(ROOT_DIR / ".env")
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise SystemExit("MONGO_URI is missing from Back-end/.env")

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=10000)
    db = client.get_default_database()
    client.admin.command("ping")

    blogs = list(db.blogs.find({}))
    by_slug: dict[str, list[dict]] = defaultdict(list)
    for blog in blogs:
        slug = str(blog.get("slug") or "").strip().lower()
        if slug:
            by_slug[slug].append(blog)

    removed = 0
    for slug, items in by_slug.items():
        if len(items) < 2:
            continue

        items_sorted = sorted(items, key=_blog_sort_key, reverse=True)
        keep = items_sorted[0]
        drop_items = items_sorted[1:]
        drop_ids = [item["_id"] for item in drop_items]

        if drop_ids:
            db.comments.delete_many({"blog_id": {"$in": [str(item_id) for item_id in drop_ids]}})
            db.likes.delete_many({"blog_id": {"$in": [str(item_id) for item_id in drop_ids]}})
            if hasattr(db, "blog_views"):
                db.blog_views.delete_many({"blog_id": {"$in": [str(item_id) for item_id in drop_ids]}})
            db.blogs.delete_many({"_id": {"$in": drop_ids}})
            removed += len(drop_ids)

        print(f"Kept slug {slug!r} -> {keep.get('title', '')!r}")

    if removed:
        print(f"Removed {removed} duplicate blog record(s).")
    else:
        print("No duplicate blog slugs found.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
