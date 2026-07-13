# SECURE CODE: Parameterized SQL Query
# PATTERN: Using prepared statements with placeholders
# OWASP: A03:2021 - Injection (MITIGATED)

def search_products_safe(user_input):
    """Secure against SQL injection via parameterized queries"""
    query = "SELECT * FROM products WHERE name = ?"
    return database.execute(query, (user_input,))

# This is SAFE because:
# - Uses parameterized query (?)
# - Database driver handles escaping
# - User input never directly concatenated into SQL
