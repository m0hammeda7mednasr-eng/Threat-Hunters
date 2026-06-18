import unittest
import sys
from types import SimpleNamespace
from pathlib import Path

from bson import ObjectId
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "Backend"
for path in (BACKEND_ROOT, ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import services.comment_service as comment_service
from tests.helpers import InMemoryCollection, build_fake_db


class CommentServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.ctx = self.app.app_context()
        self.ctx.push()

        self.blog_id = ObjectId()
        self.comment_id = ObjectId()
        self.fake_db = build_fake_db(
            blogs=InMemoryCollection([
                {
                    "_id": self.blog_id,
                    "title": "Post",
                    "status": "published",
                    "comments_count": 0,
                }
            ]),
            comments=InMemoryCollection([
                {
                    "_id": self.comment_id,
                    "blog_id": str(self.blog_id),
                    "user_id": "user-1",
                    "author_name": "Ada Lovelace",
                    "content": "Original",
                    "createdAt": "2026-01-01T00:00:00Z",
                }
            ]),
        )

        self.original_mongo = comment_service.mongo
        comment_service.mongo = SimpleNamespace(db=self.fake_db)

    def tearDown(self):
        comment_service.mongo = self.original_mongo
        self.ctx.pop()

    def test_create_comment_increments_blog_count(self):
        response, status = comment_service.create_comment(
            str(self.blog_id),
            user_id=ObjectId(),
            username="Grace Hopper",
            data={"content": "Great post"},
        )
        payload = response.get_json()
        self.assertEqual(status, 201)
        self.assertEqual(payload["message"], "Comment added successfully")
        self.assertEqual(self.fake_db.blogs.find_one({"_id": self.blog_id})["comments_count"], 1)

    def test_update_comment_allows_admin(self):
        response, status = comment_service.update_comment(
            str(self.comment_id),
            current_user={"_id": ObjectId(), "role": "admin"},
            data={"content": "Updated"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(response.get_json()["message"], "Comment updated successfully")
        self.assertEqual(self.fake_db.comments.find_one({"_id": self.comment_id})["content"], "Updated")

    def test_delete_comment_rejects_non_owner(self):
        response, status = comment_service.delete_comment(
            str(self.comment_id),
            current_user={"_id": ObjectId(), "role": "user"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(response.get_json()["message"], "Unauthorized")

    def test_reply_comment_requires_valid_parent(self):
        response, status = comment_service.reply_comment(
            str(self.blog_id),
            str(ObjectId()),
            user_id=ObjectId(),
            username="Grace Hopper",
            data={"content": "Reply"},
        )
        self.assertEqual(status, 404)
        self.assertEqual(response.get_json()["message"], "Parent comment not found")


if __name__ == "__main__":
    unittest.main()
