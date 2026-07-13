# VULNERABILITY: Cross-Site Scripting (XSS)
# SEVERITY: CRITICAL
# CWE: CWE-79
# OWASP: A03:2021 - Injection
# DESCRIPTION: Stored XSS via database

def save_comment(user_comment):
    """Vulnerable to stored XSS"""
    db.execute("INSERT INTO comments (text) VALUES (?)", (user_comment,))
    
def render_comments():
    comments = db.execute("SELECT text FROM comments")
    html = ""
    for comment in comments:
        html += f"<div class='comment'>{comment['text']}</div>"
    return html

# EXPLOIT: <img src=x onerror=alert('XSS')>
# IMPACT: Persistent XSS affecting all users
