from flask import Blueprint, request

from middleware.auth_middleware import token_required

from services.comment_service import (
    create_comment,
    get_comments,
    reply_comment,
    update_comment,
    delete_comment
)

comment_bp = Blueprint(
    "comments",
    __name__
)


@comment_bp.route(
    "/blogs/<blog_id>/comments",
    methods=["POST"]
)
@token_required
def add_comment(blog_id):

    current_user = request.current_user

    return create_comment(
        blog_id,
        current_user["_id"],
        current_user["first_name"],
        request.json
    )


@comment_bp.route("/blogs/<blog_id>/comments",methods=["GET"])
def list_comments(blog_id):

    return get_comments(blog_id)


@comment_bp.route(
    "/blogs/<blog_id>/comments/<comment_id>/replies",
    methods=["POST"]
)
@token_required
def add_reply(blog_id, comment_id):

    current_user = request.current_user

    return reply_comment(
        blog_id,
        comment_id,
        current_user["_id"],
        current_user["first_name"],
        request.json
    )
@comment_bp.route(
    "/comments/<comment_id>",
    methods=["PUT"]
)
@token_required
def edit_comment(comment_id):

    return update_comment(
        comment_id,
        request.current_user,
        request.json
    )


@comment_bp.route(
    "/comments/<comment_id>",
    methods=["DELETE"]
)
@token_required
def remove_comment(comment_id):

    return delete_comment(
        comment_id,
        request.current_user
    )
