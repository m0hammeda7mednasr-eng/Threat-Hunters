from flask import Blueprint, jsonify, request

from database.db import mongo
from middleware.auth_middleware import get_current_user_optional, token_required


content_bp = Blueprint("content", __name__)

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
        "title": "Security Awareness Training & Resources",
        "description": "",
        "owasp": [
            {"rank": "01", "name": "Broken Access Control", "link": ""},
            {"rank": "02", "name": "Cryptographic Failures", "link": ""},
            {"rank": "03", "name": "Injection", "link": ""},
            {"rank": "04", "name": "Insecure Design", "link": ""},
            {"rank": "05", "name": "Security Misconfiguration", "link": ""},
        ],
        "resources": [
            "Secure Coding Fundamentals",
            "Penetration Testing Basics",
            "Web Application Security",
            "API Security Best Practices",
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
    return record or DEFAULT_CONTENT.get(page, {})


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
