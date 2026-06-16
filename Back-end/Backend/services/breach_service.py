from flask import jsonify
from haveibeenpwned import HIBP
from config import Config
import math

hibp = HIBP(api_key=Config.HIBP_API_KEY)

ALL_BREACHES_CACHE = {}

try:

    all_breaches = hibp.get_all_breaches()

    for breach in all_breaches:

        ALL_BREACHES_CACHE[
            breach.name
        ] = breach

    print(
        f"Loaded {len(ALL_BREACHES_CACHE)} breaches into cache"
    )

except Exception as e:

    print(
        f"Failed to load breach cache: {e}"
    )



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

    risk_level = "Safe"

    if count > 0:
        risk_level = "Low"

    if count > 100:
        risk_level = "Medium"

    if count > 1000:
        risk_level = "High"

    if count > 10000:
        risk_level = "Critical"

    return jsonify({

        "breached": count > 0,

        "count": count,

        "risk_level": risk_level,

        "message":
        f"Password found {count} times in known breaches"
        if count > 0
        else
        "Password not found in known breaches"

    }), 200

def check_email_breach(data):

    email = data.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        return jsonify({
            "message": "Email is required"
        }), 400

    try:

        account_breaches = hibp.get_account_breaches(
            email
        )

        results = []
        seen = set()

        for breach in account_breaches:

            try:

                if breach.name in seen:
                    continue

                seen.add(
                    breach.name
                )

                full_breach = ALL_BREACHES_CACHE.get(
                    breach.name
                )

                if not full_breach:
                    continue

                results.append({

                    "name": full_breach.name,

                    "title": full_breach.title,

                    "domain": full_breach.domain,

                    "breach_date": str(
                        full_breach.breach_date
                    ),

                    "added_date": str(
                        full_breach.added_date
                    ),

                    "modified_date": str(
                        full_breach.modified_date
                    ),

                    "pwn_count":
                    full_breach.pwn_count,

                    "description":
                    full_breach.description,

                    "logo_path":
                    full_breach.logo_path,

                    "data_classes":
                    full_breach.data_classes,

                    "verified":
                    full_breach.is_verified,

                    "fabricated":
                    full_breach.is_fabricated,

                    "sensitive":
                    full_breach.is_sensitive,

                    "retired":
                    full_breach.is_retired,

                    "spam_list":
                    full_breach.is_spam_list,

                    "malware":
                    full_breach.is_malware,

                    "stealer_log":
                    full_breach.is_stealer_log,

                    "subscription_free":
                    full_breach.is_subscription_free,

                    "attribution":
                    full_breach.attribution

                })

            except Exception:
                continue

        results.sort(
            key=lambda x: (
                x["breach_date"]
                if x["breach_date"] != "None"
                else "",
                x["pwn_count"]
            ),
            reverse=True
        )
        latest_breach = None

        if results:

            latest_breach = results[0][
                "breach_date"
            ]

        exposed_data = set()

        for breach in results:

            exposed_data.update(
                breach["data_classes"]
            )

        breach_count = len(
            results
        )

        verified_breach_count = sum(
            1 for breach in results
            if breach["verified"]
        )

        stealer_log_count = sum(
            1 for breach in results
            if breach["stealer_log"]
        )

        risk_level = "Low"

        if breach_count >= 1:
            risk_level = "Medium"

        if breach_count >= 5:
            risk_level = "High"

        if breach_count >= 10:
            risk_level = "Critical"

        if stealer_log_count > 0:
            risk_level = "Critical"

        return jsonify({

            "email": email,

            "breached":
            breach_count > 0,

            "risk_level":
            risk_level,

            "breach_count":
            breach_count,

            "verified_breach_count":
            verified_breach_count,

            "stealer_log_count":
            stealer_log_count,

            "latest_breach":
            latest_breach,

            "exposed_data":
            sorted(
                list(exposed_data)
            ),

            "summary": {

                "verified_breaches":
                verified_breach_count,

                "stealer_logs":
                stealer_log_count,

                "latest_breach":
                latest_breach,

                "risk_level":
                risk_level

            },

            "breaches":
            results

        }), 200

    except Exception as e:

        return jsonify({

            "message":
            "Failed to check email breaches",

            "error":
            str(e)

        }), 500
    
def analyze_password(data):

    password = data.get(
        "password",
        ""
    ).strip()

    if not password:

        return jsonify({
            "message":
            "Password is required"
        }), 400

    score = 0

    recommendations = []
    COMMON_WORDS = [

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
        "guest"

    ]

    SEQUENTIAL_PATTERNS = [

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

        "000000"

    ]

    breached_count = hibp.is_password_pwned(
        password
    )

    has_upper = any(
        c.isupper()
        for c in password
    )

    has_lower = any(
        c.islower()
        for c in password
    )

    has_digit = any(
        c.isdigit()
        for c in password
    )

    special_chars = (
        "!@#$%^&*()_+-=[]{}|;:,.<>?"
    )

    has_special = any(
        c in special_chars
        for c in password
    )
    charset_size = 0

    if has_lower:
        charset_size += 26

    if has_upper:
        charset_size += 26

    if has_digit:
        charset_size += 10

    if has_special:
        charset_size += len(
            special_chars
        )

    entropy_bits = 0

    if charset_size > 0:

        entropy_bits = round(

            len(password)
            * math.log2(charset_size),

            2
        )

    if len(password) >= 12:
        score += 20
    else:
        recommendations.append(
            "Use at least 12 characters"
        )

    if has_upper:
        score += 20
    else:
        recommendations.append(
            "Add uppercase letters"
        )

    if has_lower:
        score += 20
    else:
        recommendations.append(
            "Add lowercase letters"
        )

    if has_digit:
        score += 20
    else:
        recommendations.append(
            "Add numbers"
        )

    if has_special:
        score += 20
    else:
        recommendations.append(
            "Add special characters"
        )
    
    dictionary_word_found = False

    for word in COMMON_WORDS:

        if word in password.lower():

            dictionary_word_found = True

            score -= 20

            recommendations.append(
                f"Contains common word: {word}"
            )

            break
    
    sequential_pattern_found = False

    for pattern in SEQUENTIAL_PATTERNS:

        if pattern in password.lower():

            sequential_pattern_found = True

            score -= 15

            recommendations.append(
                f"Contains predictable pattern: {pattern}"
            )

            break
    
    
    if breached_count > 0:

        score -= 40

        recommendations.append(
            f"Password appeared "
            f"{breached_count:,} times "
            f"in known breaches"
        )

    score = max(
        0,
        min(score, 100)
    )

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

    entropy_level = "Very Weak"

    if entropy_bits >= 40:
        entropy_level = "Weak"

    if entropy_bits >= 60:
        entropy_level = "Medium"

    if entropy_bits >= 80:
        entropy_level = "Strong"

    if entropy_bits >= 100:
        entropy_level = "Very Strong"
    
    return jsonify({

        "strength":
        strength,

        "score":
        score,

        "breached":
        breached_count > 0,

        "breach_count":
        breached_count,

        "password_length":
        len(password),

        "has_uppercase":
        has_upper,

        "has_lowercase":
        has_lower,

        "has_numbers":
        has_digit,

        "has_special_characters":
        has_special,

        "recommendations":
        recommendations,

        "dictionary_word_found":
        dictionary_word_found,

        "sequential_pattern_found":
        sequential_pattern_found,

    }), 200