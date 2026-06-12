from flask import Blueprint, request
from services.blog_service import create_blog , get_blogs

blog_bp = Blueprint("blog", __name__)

@blog_bp.route("/blogs", methods=["POST"])
def create():
    return create_blog(request.json)
@blog_bp.route("/blogs", methods=["GET"])
def get_all_blogs():
    return get_blogs()