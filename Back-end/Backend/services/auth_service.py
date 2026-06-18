from database.db import mongo
from flask import jsonify

from utils.password_utils import (
    hash_password,
    check_password,
    validate_password
)

from utils.validators import validate_email_format
from utils.email_service import send_email

import datetime
import jwt
import random
import secrets

from config import Config


def generate_otp():

    return str(
        random.randint(
            100000,
            999999
        )
    )


def register_user(data):

    first_name = data.get(
        "firstName",
        ""
    ).strip()

    last_name = data.get(
        "lastName",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    if not first_name or not last_name or not email or not password:

        return jsonify({
            "message": "Missing fields"
        }), 400

    password_error = validate_password(
        password
    )

    if password_error:

        return jsonify({
            "message": password_error
        }), 400

    if not validate_email_format(email):

        return jsonify({
            "message": "Invalid or undeliverable email"
        }), 400

    existing_user = mongo.db.users.find_one({
        "email": email
    })

    if existing_user:

        return jsonify({
            "message": "Email already exists"
        }), 400

    hashed_password = hash_password(
        password
    )

    otp = generate_otp()

    mongo.db.users.insert_one({

        "first_name": first_name,

        "last_name": last_name,

        "email": email,

        "password": hashed_password,

        "role": "user",

        "is_verified": False,

        "verification_code": otp,

        "verification_expires":
        datetime.datetime.utcnow()
        +
        datetime.timedelta(
            minutes=10
        ),

        "created_at":
        datetime.datetime.utcnow(),

        "failed_attempts": 0,

        "lock_until": None

    })

    send_email(
        email,
        "Threat Hunters Verification Code",
        f"Your verification code is: {otp}"
    )

    return jsonify({

        "message":
        "Verification code sent to your email"

    }), 201


def login_user(data):

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    ).strip()

    if not email or not password:

        return jsonify({
            "message": "Email and password are required"
        }), 400

    user = mongo.db.users.find_one({
        "email": email
    })

    if not user:

        return jsonify({
            "message": "Invalid email or password"
        }), 401

    if user.get("disabled"):

        return jsonify({
            "message": "Account disabled by administrator"
        }), 403
    
    if not user.get(
    "is_verified",
    False
        ):

        return jsonify({
            "message": "Please verify your email first"
        }), 403

    if (
        user.get("lock_until")
        and
        user["lock_until"] > datetime.datetime.utcnow()
    ):

        return jsonify({
            "message": "Account locked. Try again later"
        }), 403

    if not check_password(
        user["password"],
        password
    ):

        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$inc": {"failed_attempts": 1}}
        )

        updated_user = mongo.db.users.find_one({
            "_id": user["_id"]
        })

        if updated_user.get(
            "failed_attempts",
            0
        ) >= 5:

            mongo.db.users.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "lock_until":
                        datetime.datetime.utcnow()
                        +
                        datetime.timedelta(
                            minutes=1
                        )
                    }
                }
            )

        return jsonify({
            "message": "Invalid email or password"
        }), 401

    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "last_login":
                datetime.datetime.utcnow(),

                "failed_attempts": 0,

                "lock_until": None
            }
        }
    )

    token = jwt.encode({

        "user_id": str(
            user["_id"]
        ),

        "role": user.get(
            "role",
            "user"
        ),

        "iat":
        datetime.datetime.utcnow(),

        "exp":
        datetime.datetime.utcnow()
        +
        datetime.timedelta(
            hours=Config.JWT_EXPIRATION_HOURS
        )

    },
        Config.SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({

        "message":
        "Login successful",

        "token":
        token,

        "role":
        user.get(
            "role",
            "user"
        )

    }), 200
def verify_email(data):

    email = data.get(
        "email",
        ""
    ).strip().lower()

    code = data.get(
        "code",
        ""
    ).strip()

    if not email or not code:

        return jsonify({
            "message": "Email and code are required"
        }), 400

    user = mongo.db.users.find_one({
        "email": email
    })

    if not user:

        return jsonify({
            "message": "User not found"
        }), 404

    if user.get(
        "is_verified",
        False
    ):

        return jsonify({
            "message": "Account already verified"
        }), 400

    if (
        user.get("verification_expires")
        and
        user["verification_expires"]
        < datetime.datetime.utcnow()
    ):

        return jsonify({
            "message": "Verification code expired"
        }), 400

    if code != user.get(
        "verification_code"
    ):

        return jsonify({
            "message": "Invalid verification code"
        }), 400

    mongo.db.users.update_one(
        {
            "_id": user["_id"]
        },
        {
            "$set": {
                "is_verified": True
            },
            "$unset": {
                "verification_code": "",
                "verification_expires": ""
            }
        }
    )

    return jsonify({
        "message": "Email verified successfully"
    }), 200


def request_password_reset(data):

    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({
            "message": "Email is required"
        }), 400

    user = mongo.db.users.find_one({
        "email": email
    })

    if not user:
        return jsonify({
            "message": "No account found for that email"
        }), 404

    token = secrets.token_hex(16)
    reset_code = generate_otp()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=20)

    mongo.db.password_reset_tokens.update_one(
        {"email": email},
        {"$set": {
            "email": email,
            "token": token,
            "code": reset_code,
            "expires_at": expires_at
        }},
        upsert=True
    )

    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_code": reset_code,
            "reset_expires": expires_at
        }}
    )

    send_email(
        email,
        "Threat Hunters Password Reset",
        f"Your password reset code is: {reset_code}"
    )

    return jsonify({
        "message": "Password reset OTP prepared",
        "email": email,
        "resetToken": token
    }), 200


def forgot_password(data):
    return request_password_reset(data)


def reset_password(data):

    email = data.get("email", "").strip().lower()
    token = data.get("token", "").strip()
    code = data.get("code", "").strip()
    new_password = data.get("newPassword") or data.get("new_password", "")

    if not email or not new_password or (not token and not code):
        return jsonify({
            "message": "Email, OTP, and new password are required"
        }), 400

    password_error = validate_password(new_password)
    if password_error:
        return jsonify({
            "message": password_error
        }), 400

    reset_record = mongo.db.password_reset_tokens.find_one({
        "email": email,
        "$or": [
            {"token": token},
            {"code": code}
        ]
    })

    user = mongo.db.users.find_one({
        "email": email
    })

    if not user:
        return jsonify({
            "message": "Account not found"
        }), 404

    legacy_code_matches = code and code == user.get("reset_code")
    legacy_valid = (
        legacy_code_matches
        and user.get("reset_expires")
        and user["reset_expires"] >= datetime.datetime.utcnow()
    )

    token_valid = (
        reset_record
        and reset_record.get("expires_at") >= datetime.datetime.utcnow()
    )

    if not token_valid and not legacy_valid:
        return jsonify({
            "message": "Invalid or expired OTP"
        }), 400

    mongo.db.users.update_one(
        {"email": email},
        {
            "$set": {
                "password": hash_password(new_password),
                "failed_attempts": 0,
                "lock_until": None
            },
            "$unset": {
                "reset_code": "",
                "reset_expires": ""
            }
        }
    )

    mongo.db.password_reset_tokens.delete_many({
        "email": email
    })

    return jsonify({
        "message": "Password updated successfully"
    }), 200
