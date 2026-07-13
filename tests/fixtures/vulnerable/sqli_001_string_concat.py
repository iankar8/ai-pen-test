# VULNERABILITY: SQL Injection
# SEVERITY: CRITICAL
# CWE: CWE-89
# OWASP: A03:2021 - Injection
# DESCRIPTION: Direct string concatenation in SQL query

def search_products(user_input):
    """Vulnerable to SQL injection via string concatenation"""
    query = f"SELECT * FROM products WHERE name = '{user_input}'"
    return database.execute(query)

# EXPLOIT: ' OR '1'='1
# IMPACT: Bypass authentication, data exfiltration
