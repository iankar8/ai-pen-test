# SECURE CODE: Escaped HTML Output
# PATTERN: Using proper HTML escaping
# OWASP: A03:2021 - Injection (MITIGATED)

import html

def display_search_results_safe(search_term):
    """Secure against XSS via HTML escaping"""
    escaped_term = html.escape(search_term)
    return f"<h1>Search results for: {escaped_term}</h1>"

# This is SAFE because:
# - Uses html.escape() to sanitize user input
# - Special characters (<, >, &, etc.) are encoded
# - JavaScript cannot execute
