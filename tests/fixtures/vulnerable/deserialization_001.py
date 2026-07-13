# VULNERABILITY: Insecure Deserialization
# SEVERITY: CRITICAL
# CWE: CWE-502
# OWASP: A08:2021 - Software and Data Integrity Failures
# DESCRIPTION: Unsafe pickle deserialization

import pickle

def load_user_data(data):
    """Vulnerable to deserialization attacks"""
    return pickle.loads(data)

# EXPLOIT: Craft malicious pickle payload
# IMPACT: Remote code execution
