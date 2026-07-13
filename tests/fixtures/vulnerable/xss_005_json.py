# VULNERABILITY: Cross-Site Scripting (XSS)
# SEVERITY: HIGH
# CWE: CWE-79
# OWASP: A03:2021 - Injection
# DESCRIPTION: XSS via unescaped JSON

def render_user_data(user_input):
    """Vulnerable to XSS via JSON injection"""
    return f"""
    <script>
        var data = {{"name": "{user_input}"}};
        document.write(data.name);
    </script>
    """

# EXPLOIT: "; alert('XSS'); //
# IMPACT: JavaScript injection via JSON
