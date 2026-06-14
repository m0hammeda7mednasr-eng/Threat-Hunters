import re

import bcrypt


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(hashed, password):
    if isinstance(hashed, str):
        hashed = hashed.encode()

    return bcrypt.checkpw(password.encode(), hashed)


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters"

    if not re.search(r"[A-Z]", password):
        return "Must contain uppercase letter"

    if not re.search(r"[a-z]", password):
        return "Must contain lowercase letter"

    if not re.search(r"[0-9]", password):
        return "Must contain number"

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Must contain special character"

    return None
