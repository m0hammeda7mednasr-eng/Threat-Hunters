from functools import wraps
from flask import request, jsonify
import jwt

from config import Config
from database.db import mongo
from bson.objectid import ObjectId


def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get(
            "Authorization"
        )

        if not auth_header:

            return jsonify({
                "message": "Token missing"
            }), 401

        try:

            if not auth_header.startswith(
                "Bearer "
            ):

                return jsonify({
                    "message": "Invalid authorization format"
                }), 401

            token = auth_header.split(
                " "
            )[1]
            
            payload = jwt.decode(
                token,
                Config.SECRET_KEY,
                algorithms=["HS256"]
            )

            user_id = payload.get(
                "user_id"
            )

            current_user = mongo.db.users.find_one({

                "_id": ObjectId(
                    user_id
                )

            })

            if not current_user:

                return jsonify({
                    "message": "User not found"
                }), 401

            # Attach user to request
            request.current_user = current_user

        except jwt.ExpiredSignatureError:

            return jsonify({
                "message": "Token expired"
            }), 401

        except jwt.InvalidTokenError:

            return jsonify({
                "message": "Invalid token"
            }), 401

        except Exception as e:

            print("AUTH ERROR:", e)

            return jsonify({
                "message": "Authentication failed"
            }), 401

        return f(
            *args,
            **kwargs
        )
    

    return decorated
def get_current_user_optional():

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None

    try:

        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=["HS256"]
        )

        user = mongo.db.users.find_one({
            "_id": ObjectId(payload["user_id"])
        })

        return user

    except Exception:
        return None