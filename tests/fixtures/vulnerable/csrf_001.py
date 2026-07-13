# VULNERABILITY: Cross-Site Request Forgery (CSRF)
# SEVERITY: MEDIUM
# CWE: CWE-352
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: Missing CSRF token validation

def transfer_money(request):
    """Vulnerable to CSRF attacks"""
    amount = request.POST.get('amount')
    recipient = request.POST.get('recipient')
    # No CSRF token validation
    perform_transfer(amount, recipient)

# EXPLOIT: Malicious form on attacker site
# IMPACT: Unauthorized actions on behalf of user
