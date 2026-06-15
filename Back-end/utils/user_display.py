def get_display_name(user):
    if not user:
        return ""

    first_name = str(user.get("first_name") or user.get("firstName") or "").strip()
    last_name = str(user.get("last_name") or user.get("lastName") or "").strip()
    email = str(user.get("email") or "").strip()

    full_name = f"{first_name} {last_name}".strip()
    return full_name or email
