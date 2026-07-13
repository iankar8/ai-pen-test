# VULNERABILITY: SQL Injection
# SEVERITY: CRITICAL
# CWE: CWE-89
# OWASP: A03:2021 - Injection
# DESCRIPTION: Unsanitized LIKE clause

def search_users(search_term):
    """Vulnerable to SQL injection in LIKE clause"""
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    return db.execute(query)

# EXPLOIT: %' OR '1'='1' --
# IMPACT: Information disclosure
