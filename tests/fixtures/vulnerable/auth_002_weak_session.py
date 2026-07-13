# VULNERABILITY: Weak Session Management
# SEVERITY: HIGH
# CWE: CWE-384
# OWASP: A07:2021 - Identification and Authentication Failures
# DESCRIPTION: Predictable session tokens

import time

def generate_session_token(user_id):
    """Vulnerable to session prediction"""
    timestamp = int(time.time())
    return f"{user_id}_{timestamp}"

# EXPLOIT: Predict token by guessing timestamp
# IMPACT: Session hijacking
