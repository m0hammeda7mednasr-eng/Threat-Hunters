from functools import wraps
from flask import request, jsonify
import jwt
from config import Config
from database.db import mongo
from bson.objectid import ObjectId

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"message": "Token missing"}), 401

        try:
            token = token.split(" ")[1]

            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])

            current_user = mongo.db.users.find_one({
                "_id": ObjectId(data["user_id"])
            })

        except Exception as e:
            return jsonify({"message": "Invalid token"}), 401

        # 🔥 هنا الحل
        return f(current_user, *args, **kwargs)

    return decorated