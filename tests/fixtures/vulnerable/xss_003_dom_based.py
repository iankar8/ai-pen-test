# VULNERABILITY: Cross-Site Scripting (XSS)
# SEVERITY: HIGH
# CWE: CWE-79
# OWASP: A03:2021 - Injection
# DESCRIPTION: DOM-based XSS

def render_user_profile():
    """Vulnerable to DOM-based XSS"""
    return """
    <script>
        var username = window.location.hash.substring(1);
        document.getElementById('profile').innerHTML = "Welcome " + username;
    </script>
    <div id='profile'></div>
    """

# EXPLOIT: #<img src=x onerror=alert('XSS')>
# IMPACT: Client-side code execution
