# VULNERABILITY: Cross-Site Scripting (XSS)
# SEVERITY: HIGH
# CWE: CWE-79
# OWASP: A03:2021 - Injection
# DESCRIPTION: XSS via HTML attribute injection

def render_link(url):
    """Vulnerable to XSS in href attribute"""
    return f"<a href='{url}'>Click here</a>"

# EXPLOIT: javascript:alert('XSS')
# IMPACT: Code execution on click
