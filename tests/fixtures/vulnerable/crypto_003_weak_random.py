# VULNERABILITY: Weak Random Number Generation
# SEVERITY: MEDIUM
# CWE: CWE-338
# OWASP: A02:2021 - Cryptographic Failures
# DESCRIPTION: Using predictable random for security tokens

import random

def generate_reset_token():
    """Vulnerable to predictable token generation"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

# EXPLOIT: Predict token using random seed
# IMPACT: Account takeover via password reset
