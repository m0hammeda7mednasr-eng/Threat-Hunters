from database.db import mongo
from flask import jsonify
from utils.password_utils import hash_password, check_password
from utils.validators import validate_email
import datetime
import jwt
from config import Config
from utils.password_utils import validate_password



def register_user(data):
    first_name = data.get("firstName")
    last_name = data.get("lastName")  
    email = data.get("email").strip().lower()
    password = data.get("password")

    first_name = first_name.strip()
    last_name = last_name.strip()

    error = validate_password(password)
    if error:
        return jsonify({"message": error}), 400

    if not first_name or not last_name or not email or not password:
        return jsonify({"message": "Missing fields"}), 400

    if not validate_email(email):
        return jsonify({"message": "Invalid email"}), 400

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"message": "Email exists"}), 400

    hashed = hash_password(password)

    mongo.db.users.insert_one({
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": hashed,
        "created_at": datetime.datetime.utcnow(),
        "failed_attempts": 0,
        "lock_until": None
    })

    return jsonify({"message": "User created"}), 201

def login_user(data):
    email = data.get("email").strip().lower()
    password = data.get("password").strip()

    user = mongo.db.users.find_one({"email": email})

    # ❌ لو مفيش user
    if not user:
        return jsonify({"message": "Invalid email or password"}), 401

    # 🔒 لو الحساب متقفل مؤقت
    if user.get("lock_until") and user["lock_until"] > datetime.datetime.utcnow():
        return jsonify({"message": "Account locked. Try again later"}), 403

    # ❌ لو الباسورد غلط
    if not check_password(user["password"], password):
        
        # نزود عدد المحاولات
        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$inc": {"failed_attempts": 1}}
        )

        # نجيب القيمة الجديدة
        updated_user = mongo.db.users.find_one({"_id": user["_id"]})

        # لو وصل 5 محاولات → نعمل lock
        if updated_user.get("failed_attempts", 0) >= 5:
            mongo.db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "lock_until": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
                    }
                }
            )

        return jsonify({"message": "Invalid email or password"}), 401

    # ✅ لو الباسورد صح
    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "last_login": datetime.datetime.utcnow(),
                "failed_attempts": 0,
                "lock_until": None
            }
        }
    )

    # 🎟️ التوكن
    token = jwt.encode({
        "user_id": str(user["_id"]),
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=Config.JWT_EXPIRATION_HOURS)
    }, Config.SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "Login successful",
        "token": token
    }), 200