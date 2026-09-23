import re

PATTERNS = {
    "SQL injection": [
        r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|or\s+1\s*=\s*1|'--|;--)",
    ],
    "XSS": [
        r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\()",
    ],
    "Path traversal": [
        r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)",
    ],
    "Command injection": [
        r"(?i)(;\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b|\|\s*(cat|ls|whoami|id)\b)",
    ],
    "SSRF": [
        r"(?i)(http://169\.254\.169\.254|http://127\.0\.0\.1|http://localhost)",
    ],
}

def check_payload(text):
    """Return a list of matched threat names"""
    found = []
    for name, patterns in PATTERNS.items():
        for p in patterns:
            if re.search(p, text):
                found.append(name)
                break
    return found   