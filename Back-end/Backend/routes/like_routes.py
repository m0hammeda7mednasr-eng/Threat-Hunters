from flask import Blueprint, request

from middleware.auth_middleware import token_required

from services.like_service import toggle_like

like_bp = Blueprint(
    "likes",
    __name__
)


@like_bp.route("/blogs/<blog_id>/like",methods=["POST"]
)
@token_required
def like_blog(blog_id):

    current_user = request.current_user

    return toggle_like(
        blog_id,
        current_user["_id"]
    )