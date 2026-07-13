# VULNERABILITY: Server-Side Request Forgery (SSRF)
# SEVERITY: HIGH
# CWE: CWE-918
# OWASP: A10:2021 - Server-Side Request Forgery
# DESCRIPTION: Unvalidated URL fetch

import requests

def fetch_url(url):
    """Vulnerable to SSRF"""
    response = requests.get(url)
    return response.content

# EXPLOIT: http://169.254.169.254/latest/meta-data/
# IMPACT: Internal network scanning, cloud metadata access
