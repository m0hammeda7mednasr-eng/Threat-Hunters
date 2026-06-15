CWE_MAPPING = {
    "CWE-79": "Cross Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-78": "Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-287": "Authentication Bypass",
    "CWE-269": "Privilege Escalation",
    "CWE-862": "Missing Authorization",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Unsafe Deserialization",
    "CWE-352": "CSRF",
    "CWE-798": "Hardcoded Credentials",
    "CWE-200": "Information Disclosure",
    "CWE-416": "Use After Free",
    "CWE-787": "Buffer Overflow",
    "CWE-125": "Out of Bounds Read"
}


def map_cwe(cwe_id):
    return CWE_MAPPING.get(cwe_id, "Other")