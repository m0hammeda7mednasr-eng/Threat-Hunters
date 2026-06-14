from flask import Blueprint, request

from services.blog_service import (
    create_blog,
    get_blogs,
    get_blog_by_id,
    update_blog,
    delete_blog,
    share_blog,
    set_blog_status
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
    current_user = get_current_user_optional()
    include_hidden = request.args.get("include_hidden") == "true"

    return get_blogs(
        current_user,
        include_hidden
    )


@blog_bp.route("/blogs/<blog_id>", methods=["GET"])
def get_blog(blog_id):

    current_user = get_current_user_optional()

    return get_blog_by_id(
        blog_id,
        current_user
    )


@blog_bp.route("/blogs/<blog_id>", methods=["PUT"])
@token_required
def edit_blog(blog_id):
    return update_blog(
        blog_id,
        request.json,
        request.current_user
    )


@blog_bp.route("/blogs/<blog_id>", methods=["DELETE"])
@token_required
def remove_blog(blog_id):
    return delete_blog(
        blog_id,
        request.current_user
    )


@blog_bp.route("/blogs/<blog_id>/status", methods=["PATCH"])
@token_required
def change_blog_status(blog_id):
    data = request.json or {}

    return set_blog_status(
        blog_id,
        data.get("status"),
        request.current_user
    )


@blog_bp.route("/blogs/<blog_id>/share", methods=["POST"])
def share_blog_route(blog_id):
    return share_blog(blog_id)
