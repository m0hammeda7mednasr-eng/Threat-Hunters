from dotenv import load_dotenv
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parents[1]

for env_path in (
    BASE_DIR / ".env",
    BASE_DIR.parent / ".env",
    PROJECT_DIR / ".env",
    PROJECT_DIR / ".env.local",
    PROJECT_DIR / ".vercel" / ".env.development.local",
):
    load_dotenv(env_path, override=False)

from flask import Flask, request
from flask_cors import CORS
from pymongo.errors import PyMongoError

from config import Config
from database.db import mongo
from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.blog_routes import blog_bp
from routes.breach_routes import breach_bp
from routes.comment_routes import comment_bp
from routes.content_routes import content_bp
from routes.dashboard_routes import dashboard_bp
from routes.like_routes import like_bp
from routes.scanner_routes import scanner_bp
from routes.security_routes import security_bp
from routes.user_routes import user_bp


app = Flask(__name__)
app.config.from_object(Config)

LOCAL_DEV_ORIGINS = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
}

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": list(LOCAL_DEV_ORIGINS)
        }
    },
    supports_credentials=True,
)


@app.after_request
def add_cors_headers(response):
    request_origin = request.headers.get("Origin")

    if request_origin in LOCAL_DEV_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = request_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return response

mongo.init_app(app)


def ensure_mongo_indexes():
    if getattr(mongo, "db", None) is None:
        return
    try:
        mongo.db.blogs.create_index("slug", unique=True, name="uq_blogs_slug")
        mongo.db.scan_reports.create_index(
            [("created_at", -1)],
            name="idx_scan_reports_created",
        )
        mongo.db.scan_reports.create_index(
            [("user_id", 1), ("created_at", -1)],
            name="idx_scan_reports_user_created",
        )
        mongo.db.scan_reports.create_index(
            [("report_id", 1), ("user_id", 1)],
            unique=True,
            name="uq_scan_reports_report_user",
        )
    except Exception:
        # Let the app continue if the index already exists or the database is unavailable.
        pass


with app.app_context():
    ensure_mongo_indexes()


@app.get("/api/ping")
def ping():
    database_name = ""
    try:
        if getattr(mongo, "db", None) is not None:
            mongo.cx.admin.command("ping")
            database_name = mongo.db.name
        return {
            "ok": True,
            "service": "threat-hunters-backend",
            "database": database_name,
        }, 200
    except PyMongoError:
        return {
            "ok": False,
            "service": "threat-hunters-backend",
            "database": database_name,
            "message": "MongoDB is unavailable",
        }, 503

app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(user_bp, url_prefix="/api")
app.register_blueprint(blog_bp, url_prefix="/api")
app.register_blueprint(security_bp, url_prefix="/api/security")
app.register_blueprint(comment_bp, url_prefix="/api")
app.register_blueprint(like_bp, url_prefix="/api")
app.register_blueprint(dashboard_bp, url_prefix="/api")
app.register_blueprint(content_bp, url_prefix="/api")
app.register_blueprint(admin_bp, url_prefix="/api")
app.register_blueprint(breach_bp, url_prefix="/api")
app.register_blueprint(scanner_bp, url_prefix="/api")

# print("SECRET:", os.getenv("SECRET_KEY"))


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
