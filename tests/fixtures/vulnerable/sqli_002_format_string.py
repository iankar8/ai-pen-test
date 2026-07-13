# VULNERABILITY: SQL Injection
# SEVERITY: CRITICAL
# CWE: CWE-89
# OWASP: A03:2021 - Injection
# DESCRIPTION: String formatting in SQL query

def get_user_by_id(user_id):
    """Vulnerable to SQL injection via % formatting"""
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return database.execute(query)

# EXPLOIT: 1 OR 1=1
# IMPACT: Data access, privilege escalation
