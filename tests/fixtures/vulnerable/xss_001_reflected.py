# VULNERABILITY: Cross-Site Scripting (XSS)
# SEVERITY: HIGH
# CWE: CWE-79
# OWASP: A03:2021 - Injection
# DESCRIPTION: Reflected XSS via unescaped user input

def display_search_results(search_term):
    """Vulnerable to reflected XSS"""
    return f"<h1>Search results for: {search_term}</h1>"

# EXPLOIT: <script>alert('XSS')</script>
# IMPACT: Session hijacking, credential theft
