# VULNERABILITY: SQL Injection
# SEVERITY: CRITICAL
# CWE: CWE-89
# OWASP: A03:2021 - Injection
# DESCRIPTION: UNION-based SQL injection

def get_product_details(product_id):
    """Vulnerable to UNION-based SQL injection"""
    query = "SELECT name, price FROM products WHERE id = " + product_id
    return database.query(query)

# EXPLOIT: 1 UNION SELECT username, password FROM users--
# IMPACT: Data exfiltration across tables
