from flask import Blueprint, request

from services.blog_service import (
    create_blog,
    get_blogs,
    get_blog_by_id
)

from middleware.auth_middleware import (
    token_required,
    get_current_user_optional
)

blog_bp = Blueprint("blog", __name__)


@blog_bp.route("/blogs", methods=["POST"])
@token_required
def create():

    current_user = request.current_user

    return create_blog(
        request.json,
        current_user["_id"],
        current_user["first_name"]
    )


@blog_bp.route("/blogs", methods=["GET"])
def get_all_blogs():

    return get_blogs()


@blog_bp.route("/blogs/<blog_id>", methods=["GET"])
def get_blog(blog_id):

    current_user = get_current_user_optional()

    return get_blog_by_id(
        blog_id,
        current_user
    )