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

import routes.admin_routes as admin_routes
from tests.helpers import InMemoryCollection, build_fake_db


class AdminRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.ctx = self.app.app_context()
        self.ctx.push()

        self.user_id = ObjectId()
        self.fake_db = build_fake_db(
            users=InMemoryCollection([
                {
                    "_id": self.user_id,
                    "first_name": "Admin",
                    "last_name": "User",
                    "email": "admin@example.com",
                    "role": "admin",
                    "plan": "Enterprise",
                    "disabled": False,
                    "created_at": "2026-01-01T00:00:00Z",
                },
                {
                    "_id": ObjectId(),
                    "first_name": "Regular",
                    "last_name": "User",
                    "email": "user@example.com",
                    "role": "user",
                    "plan": "Free",
                    "disabled": True,
                    "created_at": "2026-01-02T00:00:00Z",
                },
            ])
        )

        self.original_mongo = admin_routes.mongo
        admin_routes.mongo = SimpleNamespace(db=self.fake_db)

    def tearDown(self):
        admin_routes.mongo = self.original_mongo
        self.ctx.pop()

    def test_list_users_serializes_users_for_admin(self):
        with self.app.test_request_context("/api/admin/users"):
            admin_routes.request.current_user = {"_id": self.user_id, "role": "admin"}
            response, status = admin_routes.list_users.__wrapped__()

        payload = response.get_json()
        self.assertEqual(status, 200)
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["items"][0]["email"], "admin@example.com")
        self.assertEqual(payload["items"][1]["status"], "disabled")

    def test_delete_user_blocks_self_delete(self):
        with self.app.test_request_context(f"/api/admin/users/{self.user_id}"):
            admin_routes.request.current_user = {"_id": self.user_id, "role": "admin"}
            response, status = admin_routes.delete_user.__wrapped__(str(self.user_id))

        self.assertEqual(status, 400)
        self.assertEqual(response.get_json()["message"], "You cannot delete your own admin account")


if __name__ == "__main__":
    unittest.main()
