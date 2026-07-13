# VULNERABILITY: SQL Injection
# SEVERITY: HIGH
# CWE: CWE-89
# OWASP: A03:2021 - Injection
# DESCRIPTION: Unsanitized ORDER BY clause

def list_products(sort_by):
    """Vulnerable to SQL injection in ORDER BY"""
    query = f"SELECT * FROM products ORDER BY {sort_by}"
    return database.execute(query)

# EXPLOIT: name; DROP TABLE products--
# IMPACT: Database manipulation, DoS
