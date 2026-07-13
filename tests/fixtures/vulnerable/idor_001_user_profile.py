# VULNERABILITY: Insecure Direct Object Reference (IDOR)
# SEVERITY: HIGH
# CWE: CWE-639
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: No authorization check on user profile access

def get_user_profile(user_id):
    """Vulnerable to IDOR - no access control"""
    return database.query(f"SELECT * FROM users WHERE id = {user_id}")

# EXPLOIT: Change user_id parameter to access other profiles
# IMPACT: Unauthorized data access
