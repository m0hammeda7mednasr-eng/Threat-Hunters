from flask import Blueprint, jsonify, request

from database.db import mongo
from middleware.auth_middleware import get_current_user_optional, token_required


content_bp = Blueprint("content", __name__)


def _normalize_awareness_item(item, kind):
    if isinstance(item, str):
        if kind == "download":
            return {
                "title": item,
                "description": "Downloadable security resource.",
                "fileMeta": "PDF | generated instantly",
            }

        return {
            "title": item,
            "type": "Guide",
            "description": "Security awareness resource.",
            "url": "",
        }

    return item


def _normalize_awareness_content(content):
    next_content = dict(content or {})
    if "resources" in next_content:
        next_content["resources"] = [_normalize_awareness_item(item, "resource") for item in (next_content.get("resources") or [])]
    if "downloads" in next_content:
        next_content["downloads"] = [_normalize_awareness_item(item, "download") for item in (next_content.get("downloads") or [])]
    return next_content


def _is_legacy_awareness_content(content):
    resources = content.get("resources") or []
    downloads = content.get("downloads") or []
    return (
        content.get("title") == "Security Awareness Training & Resources"
        or not downloads
        or any(isinstance(item, str) for item in resources)
    )

DEFAULT_CONTENT = {
    "home": {
        "title": "Protect Your Digital Assets with Advanced Security Testing",
        "subtitle": "Comprehensive vulnerability scanning and penetration testing platform",
        "description": "Start proactive testing that surfaces misconfigurations, weak endpoints, and risky flows before attackers do.",
        "primaryButton": "Start Free Scan",
        "secondaryButton": "View Live Demo",
        "features": [
            "Automated Security Scanning",
            "Real-time Threat Intelligence",
            "Comprehensive Reports",
            "API Security Testing",
        ],
        "stats": [
            {"value": "100,000+", "label": "Scans Completed"},
            {"value": "500,000+", "label": "Vulnerabilities Found"},
            {"value": "10,000+", "label": "Active Users"},
            {"value": "150+", "label": "Countries Served"},
        ],
        "ctaTitle": "Ready to Secure Your Applications?",
        "ctaDescription": "Start your free security scan today. No credit card required.",
        "ctaButton": "Get Started Free",
    },
    "blog": {
        "title": "Security Insights & Best Practices",
        "description": "Publish and edit the latest threat briefings, commentary, and response guides.",
        "sectionTitle": "Featured Articles",
        "postsToDisplay": "3",
        "categories": [
            "Vulnerability Reports",
            "Security Best Practices",
            "Threat Intelligence",
            "Penetration Testing",
            "Web Application Security",
            "API Security",
        ],
    },
    "awareness": {
        "title": "Security Awareness Training Hub",
        "description": "Curated awareness content, practical defenses, and training resources for teams that want security habits to stick.",
        "owasp": [
            {"rank": "01", "name": "Broken Access Control", "link": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
            {"rank": "02", "name": "Cryptographic Failures", "link": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
            {"rank": "03", "name": "Injection", "link": "https://owasp.org/Top10/A03_2021-Injection/"},
            {"rank": "04", "name": "Insecure Design", "link": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
            {"rank": "05", "name": "Security Misconfiguration", "link": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
        ],
        "resources": [
            {
                "title": "Phishing Response Essentials",
                "type": "Video",
                "url": "https://www.youtube.com/results?search_query=cisa+phishing+awareness",
                "description": "Short video guidance for spotting and reporting suspicious emails.",
            },
            {
                "title": "MFA Rollout Playbook",
                "type": "Guide",
                "url": "https://www.cisa.gov/secure-our-world/turn-mfa",
                "description": "Step-by-step guidance for rolling out multi-factor authentication.",
            },
            {
                "title": "Secure Coding Foundations",
                "type": "Article",
                "url": "https://owasp.org/www-project-top-ten/",
                "description": "Practical coding habits that reduce common web app risk.",
            },
            {
                "title": "Incident Readiness Checklist",
                "type": "PDF",
                "url": "https://www.cisa.gov/stopransomware",
                "description": "A quick checklist for response, evidence, and recovery.",
            },
            {
                "title": "Password Manager Adoption Guide",
                "type": "Video",
                "url": "https://www.youtube.com/results?search_query=secure+password+manager+guide",
                "description": "How to standardize credential storage for teams and individuals.",
            },
        ],
        "downloads": [
            {
                "title": "Security Awareness Checklist",
                "description": "Daily security practices checklist",
                "fileMeta": "PDF | generated instantly",
            },
            {
                "title": "Incident Response Plan Template",
                "description": "Template for handling security incidents",
                "fileMeta": "PDF | generated instantly",
            },
            {
                "title": "Password Manager Comparison",
                "description": "Compare popular password managers",
                "fileMeta": "PDF | generated instantly",
            },
        ],
    },
    "tools": {
        "title": "Give Users More Powerful Security Tools",
        "subtitle": "Expand the utility suite with focused scanners, validators, and quick-win helpers",
        "description": "Control how each tool page positions value, workflows, and future roadmap messaging.",
        "primaryButton": "Open Tool Workbench",
        "secondaryButton": "See Upcoming Tools",
        "features": [
            "Domain intelligence checks",
            "Certificate validation",
            "Header and config audits",
            "Fast incident triage helpers",
        ],
        "stats": [
            {"value": "14", "label": "Tools Available"},
            {"value": "52k+", "label": "Monthly Runs"},
            {"value": "7", "label": "Tools In Progress"},
            {"value": "4.9/5", "label": "Average Rating"},
        ],
        "ctaTitle": "Need a custom security utility next?",
        "ctaDescription": "Use the roadmap section to direct users toward the tools that ship next.",
        "ctaButton": "Request a Tool",
    },
}


def is_admin(user):
    return user and user.get("role") == "admin"


def get_page_content(page):
    record = mongo.db.web_content.find_one({"page": page}, {"_id": 0, "page": 0})
    content = record or DEFAULT_CONTENT.get(page, {})
    if page == "awareness":
        if _is_legacy_awareness_content(content):
            return _normalize_awareness_content(DEFAULT_CONTENT["awareness"])
        return _normalize_awareness_content(content)
    return content


@content_bp.route("/web-content", methods=["GET"])
def get_content():
    return jsonify({page: get_page_content(page) for page in DEFAULT_CONTENT}), 200


@content_bp.route("/web-content/<page>", methods=["PUT"])
@token_required
def update_content(page):
    if page not in DEFAULT_CONTENT:
        return jsonify({"message": "Unknown content page"}), 404

    current_user = request.current_user
    if not is_admin(current_user):
        return jsonify({"message": "Admin access required"}), 403

    payload = request.json or {}
    mongo.db.web_content.update_one(
        {"page": page},
        {"$set": {**payload, "page": page}},
        upsert=True,
    )

    return jsonify(get_page_content(page)), 200
