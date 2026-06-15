from flask import jsonify
from haveibeenpwned import HIBP
from config import Config
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