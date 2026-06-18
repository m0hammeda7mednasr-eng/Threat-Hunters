from dotenv import load_dotenv
import os

load_dotenv()

from flask import Flask
from flask_cors import CORS

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

CORS(
    app,
    resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
    supports_credentials=True,
)


@app.after_request
def add_cors_headers(response):
    origin = request_origin = None
    try:
        from flask import request

        request_origin = request.headers.get("Origin")
    except Exception:
        request_origin = None

    if request_origin in {"http://localhost:5173", "http://127.0.0.1:5173"}:
        response.headers["Access-Control-Allow-Origin"] = request_origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return response

mongo.init_app(app)

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
    app.run(debug=True)
