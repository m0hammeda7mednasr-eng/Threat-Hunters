import hashlib
import html
import math
import re
from urllib.parse import quote

import requests
from flask import jsonify

from config import Config


APP_USER_AGENT = "Threat Hunters Security Tools"
PASSWORD_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


def _normalize_text(value):
    cleaned = html.unescape(str(value or ""))
    cleaned = re.sub(r"<[^>]+>", "", cleaned)
    return cleaned.strip()


def _headers(include_api_key=False):
    headers = {"User-Agent": APP_USER_AGENT}

    if include_api_key:
        api_key = (Config.HIBP_API_KEY or "").strip()
        if not api_key:
            return None
        headers["hibp-api-key"] = api_key

    return headers


def _risk_level_from_count(count):
    if count <= 0:
        return "Safe"
    if count > 10000:
        return "Critical"
    if count > 1000:
        return "High"
    if count > 100:
        return "Medium"
    return "Low"


def _pwned_password_count(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    response = requests.get(
        PASSWORD_RANGE_URL.format(prefix=prefix),
        headers=_headers(),
        timeout=15,
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        try:
            hash_suffix, occurrences = line.split(":")
        except ValueError:
            continue

        if hash_suffix.strip().upper() == suffix:
            return int(occurrences.strip() or 0)

    return 0


def check_password_breach(data):
    payload = data or {}
    password = str(payload.get("password", "")).strip()

    if not password:
        return jsonify({"message": "Password is required"}), 400

    try:
        count = _pwned_password_count(password)
        risk_level = _risk_level_from_count(count)

        return jsonify({
            "breached": count > 0,
            "count": count,
            "risk_level": risk_level,
            "message": (
                f"Password found {count} times in known breaches"
                if count > 0
                else "Password not found in known breaches"
            ),
        }), 200

    except requests.RequestException as exc:
        return jsonify({
            "message": "Failed to check password breaches",
            "error": str(exc),
        }), 502


def check_email_breach(data):
    payload = data or {}
    email = str(payload.get("email", "")).strip().lower()

    if not email:
        return jsonify({"message": "Email is required"}), 400

    headers = _headers(include_api_key=True)
    if not headers:
        return jsonify({
            "message": "HIBP_API_KEY is required for email breach checks",
        }), 503

    url = (
        f"{HIBP_BREACH_URL.format(email=quote(email))}"
        "?truncateResponse=false"
    )

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 404:
            return jsonify({
                "email": email,
                "breached": False,
                "risk_level": "Safe",
                "breach_count": 0,
                "verified_breach_count": 0,
                "stealer_log_count": 0,
                "latest_breach": None,
                "exposed_data": [],
                "summary": {
                    "verified_breaches": 0,
                    "stealer_logs": 0,
                    "latest_breach": None,
                    "risk_level": "Safe",
                },
                "breaches": [],
            }), 200

        response.raise_for_status()
        breaches = response.json() or []

        results = []
        exposed_data = set()
        verified_breach_count = 0
        stealer_log_count = 0

        for breach in breaches:
            normalized = {
                "name": breach.get("Name"),
                "title": breach.get("Title"),
                "domain": breach.get("Domain"),
                "breach_date": breach.get("BreachDate"),
                "added_date": breach.get("AddedDate"),
                "modified_date": breach.get("ModifiedDate"),
                "pwn_count": breach.get("PwnCount", 0),
                "description": _normalize_text(breach.get("Description", "")),
                "logo_path": breach.get("LogoPath"),
                "data_classes": breach.get("DataClasses", []),
                "verified": bool(breach.get("IsVerified")),
                "fabricated": bool(breach.get("IsFabricated")),
                "sensitive": bool(breach.get("IsSensitive")),
                "retired": bool(breach.get("IsRetired")),
                "spam_list": bool(breach.get("IsSpamList")),
                "malware": bool(breach.get("IsMalware")),
                "stealer_log": bool(breach.get("IsStealerLog")),
                "subscription_free": bool(breach.get("IsSubscriptionFree")),
                "attribution": breach.get("Attribution"),
            }

            if normalized["verified"]:
                verified_breach_count += 1
            if normalized["stealer_log"]:
                stealer_log_count += 1
            exposed_data.update(normalized["data_classes"] or [])
            results.append(normalized)

        results.sort(
            key=lambda item: (
                item["breach_date"] or "",
                item["pwn_count"] or 0,
            ),
            reverse=True,
        )

        latest_breach = results[0] if results else None
        breach_count = len(results)
        risk_level = "Low"
        if breach_count >= 1:
            risk_level = "Medium"
        if breach_count >= 5:
            risk_level = "High"
        if breach_count >= 10 or stealer_log_count > 0:
            risk_level = "Critical"

        return jsonify({
            "email": email,
            "breached": breach_count > 0,
            "risk_level": risk_level,
            "breach_count": breach_count,
            "verified_breach_count": verified_breach_count,
            "stealer_log_count": stealer_log_count,
            "latest_breach": latest_breach,
            "exposed_data": sorted(exposed_data),
            "summary": {
                "verified_breaches": verified_breach_count,
                "stealer_logs": stealer_log_count,
                "latest_breach": latest_breach,
                "risk_level": risk_level,
            },
            "breaches": results,
        }), 200

    except requests.RequestException as exc:
        return jsonify({
            "message": "Failed to check email breaches",
            "error": str(exc),
        }), 502


def analyze_password(data):
    payload = data or {}
    password = str(payload.get("password", "")).strip()

    if not password:
        return jsonify({"message": "Password is required"}), 400

    common_words = [
        "password",
        "admin",
        "welcome",
        "football",
        "qwerty",
        "letmein",
        "login",
        "root",
        "user",
        "secret",
        "test",
        "guest",
    ]
    sequential_patterns = [
        "123456",
        "654321",
        "abcdef",
        "fedcba",
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "111111",
        "222222",
        "333333",
        "000000",
    ]

    recommendations = []
    score = 0

    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(char in special_chars for char in password)

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += len(special_chars)

    entropy_bits = round(len(password) * math.log2(charset_size), 2) if charset_size else 0

    if len(password) >= 12:
        score += 20
    else:
        recommendations.append("Use at least 12 characters")

    if has_upper:
        score += 20
    else:
        recommendations.append("Add uppercase letters")

    if has_lower:
        score += 20
    else:
        recommendations.append("Add lowercase letters")

    if has_digit:
        score += 20
    else:
        recommendations.append("Add numbers")

    if has_special:
        score += 20
    else:
        recommendations.append("Add special characters")

    dictionary_word_found = False
    for word in common_words:
        if word in password.lower():
            dictionary_word_found = True
            score -= 20
            recommendations.append(f"Contains common word: {word}")
            break

    sequential_pattern_found = False
    for pattern in sequential_patterns:
        if pattern in password.lower():
            sequential_pattern_found = True
            score -= 15
            recommendations.append(f"Contains predictable pattern: {pattern}")
            break

    breached_count = 0
    breach_error = None
    try:
        breached_count = _pwned_password_count(password)
    except requests.RequestException as exc:
        breach_error = str(exc)

    if breached_count > 0:
        score -= 40
        recommendations.append(
            f"Password appeared {breached_count:,} times in known breaches"
        )

    score = max(0, min(score, 100))

    if score <= 20:
        strength = "Very Weak"
    elif score <= 40:
        strength = "Weak"
    elif score <= 60:
        strength = "Medium"
    elif score <= 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    if entropy_bits >= 100:
        entropy_level = "Very Strong"
    elif entropy_bits >= 80:
        entropy_level = "Strong"
    elif entropy_bits >= 60:
        entropy_level = "Medium"
    elif entropy_bits >= 40:
        entropy_level = "Weak"
    else:
        entropy_level = "Very Weak"

    return jsonify({
        "strength": strength,
        "score": score,
        "breached": breached_count > 0,
        "breach_count": breached_count,
        "breach_error": breach_error,
        "password_length": len(password),
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_numbers": has_digit,
        "has_special_characters": has_special,
        "entropy_bits": entropy_bits,
        "entropy_level": entropy_level,
        "recommendations": recommendations,
        "dictionary_word_found": dictionary_word_found,
        "sequential_pattern_found": sequential_pattern_found,
    }), 200
