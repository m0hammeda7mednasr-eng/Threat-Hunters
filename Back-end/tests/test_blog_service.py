import unittest
import sys
from types import SimpleNamespace
from pathlib import Path

from bson import ObjectId
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import services.blog_service as blog_service
from tests.helpers import InMemoryCollection, build_fake_db


class BlogServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.ctx = self.app.app_context()
        self.ctx.push()

        self.blog_id = ObjectId()
        self.blog_doc = {
            "_id": self.blog_id,
            "title": "Zero Trust for Modern Web Apps",
            "slug": "zero-trust-for-modern-web-apps",
            "content": "A deep dive",
            "description": "A deep dive",
            "category": "web-security",
            "author_id": "user-1",
            "author_name": "Ada Lovelace",
            "status": "published",
            "tags": ["Zero Trust"],
            "imageUrl": "",
            "imageName": "",
            "views": 4,
            "likes": 2,
            "shares": 1,
            "comments_count": 3,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z",
        }

        self.fake_db = build_fake_db(
            blogs=InMemoryCollection([self.blog_doc]),
            comments=InMemoryCollection([
                {"_id": ObjectId(), "blog_id": str(self.blog_id), "author_name": "Reader", "content": "Nice", "createdAt": "2026-01-01T00:00:00Z"},
            ]),
            likes=InMemoryCollection([
                {"_id": ObjectId(), "blog_id": str(self.blog_id), "user_id": "user-2"},
            ]),
            blog_views=InMemoryCollection([
                {"_id": ObjectId(), "blog_id": str(self.blog_id), "user_id": "user-3"},
            ]),
        )

        self.original_mongo = blog_service.mongo
        blog_service.mongo = SimpleNamespace(db=self.fake_db)

    def tearDown(self):
        blog_service.mongo = self.original_mongo
        self.ctx.pop()

    def test_create_blog_stores_metadata_and_slug(self):
        response, status = blog_service.create_blog(
            {
                "title": "New Post",
                "content": "Full body",
                "category": "web-security",
                "description": "Summary",
                "tags": ["OWASP", "Zero Trust"],
                "imageUrl": "data:image/png;base64,abc",
                "imageName": "shot.png",
            },
            user_id=ObjectId(),
            username="Ada Lovelace",
        )

        payload = response.get_json()
        self.assertEqual(status, 201)
        self.assertEqual(payload["slug"], "new-post")
        self.assertEqual(payload["blog"]["author"], "Ada Lovelace")
        self.assertEqual(payload["blog"]["authorInitial"], "A")
        self.assertEqual(self.fake_db.blogs.documents[-1]["imageName"], "shot.png")

    def test_update_blog_allows_admin_and_updates_image_fields(self):
        response, status = blog_service.update_blog(
            str(self.blog_id),
            {
                "title": "Updated Title",
                "content": "Updated body",
                "description": "Updated summary",
                "category": "Threat Intelligence",
                "tags": ["CVE"],
                "badge": "Featured",
                "imageUrl": "https://example.com/image.png",
                "imageName": "image.png",
            },
            current_user={"_id": ObjectId(), "role": "admin"},
        )

        payload = response.get_json()
        self.assertEqual(status, 200)
        self.assertEqual(payload["blog"]["title"], "Updated Title")
        self.assertEqual(payload["blog"]["imageUrl"], "https://example.com/image.png")
        self.assertEqual(payload["blog"]["authorInitial"], "A")

    def test_set_blog_status_requires_admin(self):
        response, status = blog_service.set_blog_status(str(self.blog_id), "hidden", {"_id": ObjectId(), "role": "user"})
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["message"], "Admin access required")

    def test_get_blogs_hides_private_posts_from_non_admin(self):
        self.fake_db.blogs.documents.append({
            "_id": ObjectId(),
            "title": "Hidden Draft",
            "slug": "hidden-draft",
            "content": "Hidden",
            "description": "Hidden",
            "category": "web-security",
            "author_name": "Ada Lovelace",
            "status": "hidden",
            "tags": [],
            "imageUrl": "",
            "imageName": "",
            "views": 0,
            "likes": 0,
            "shares": 0,
            "comments_count": 0,
            "createdAt": "2026-01-02T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
        })

        response, status = blog_service.get_blogs(current_user={"_id": ObjectId(), "role": "user"}, include_hidden=True)
        payload = response.get_json()
        self.assertEqual(status, 200)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["title"], "Zero Trust for Modern Web Apps")

    def test_delete_blog_removes_related_records(self):
        response, status = blog_service.delete_blog(str(self.blog_id), {"_id": ObjectId(), "role": "admin"})
        self.assertEqual(status, 200)
        self.assertEqual(response.get_json()["message"], "Blog deleted successfully")
        self.assertEqual(self.fake_db.comments.count_documents({"blog_id": str(self.blog_id)}), 0)
        self.assertEqual(self.fake_db.likes.count_documents({"blog_id": str(self.blog_id)}), 0)
        self.assertEqual(self.fake_db.blog_views.count_documents({"blog_id": str(self.blog_id)}), 0)


if __name__ == "__main__":
    unittest.main()
