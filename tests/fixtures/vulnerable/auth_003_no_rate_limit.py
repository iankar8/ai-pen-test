# VULNERABILITY: Missing Rate Limiting
# SEVERITY: MEDIUM
# CWE: CWE-307
# OWASP: A07:2021 - Identification and Authentication Failures
# DESCRIPTION: No rate limiting on login attempts

def login(username, password):
    """Vulnerable to brute force attacks"""
    user = database.get_user(username)
    if user and user.password == hash_password(password):
        return create_session(user)
    return None

# EXPLOIT: Automated brute force attack
# IMPACT: Password cracking via brute force
