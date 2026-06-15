from flask import jsonify
from haveibeenpwned import HIBP

hibp = HIBP()


def check_password_breach(data):

    password = data.get(
        "password",
        ""
    ).strip()

    if not password:

        return jsonify({
            "message": "Password is required"
        }), 400

    count = hibp.is_password_pwned(
        password
    )

    return jsonify({

        "breached": count > 0,

        "count": count,

        "message":
        f"Password found {count} times in known breaches"
        if count > 0
        else
        "Password not found in known breaches"

    }), 200