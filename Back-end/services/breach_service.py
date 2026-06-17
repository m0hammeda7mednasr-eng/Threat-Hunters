import hashlib
import html
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
    headers = {
        "User-Agent": APP_USER_AGENT,
    }

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


def check_password_breach(data):
    payload = data or {}
    password = str(payload.get("password", "")).strip()

    if not password:
        return jsonify({"message": "Password is required"}), 400

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = requests.get(
            PASSWORD_RANGE_URL.format(prefix=prefix),
            headers=_headers(),
            timeout=15,
        )
        response.raise_for_status()

        count = 0
        for line in response.text.splitlines():
            try:
                hash_suffix, occurrences = line.split(":")
            except ValueError:
                continue

            if hash_suffix.strip().upper() == suffix:
                count = int(occurrences.strip() or 0)
                break

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
