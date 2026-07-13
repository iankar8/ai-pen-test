# VULNERABILITY: Hardcoded Credentials
# SEVERITY: CRITICAL
# CWE: CWE-798
# OWASP: A07:2021 - Identification and Authentication Failures
# DESCRIPTION: Hardcoded admin password

def authenticate_admin(username, password):
    """Vulnerable to hardcoded credentials"""
    ADMIN_PASSWORD = "admin123"
    if username == "admin" and password == ADMIN_PASSWORD:
        return True
    return False

# EXPLOIT: admin / admin123
# IMPACT: Unauthorized administrative access
