# VULNERABILITY: Weak Cryptographic Hash
# SEVERITY: HIGH
# CWE: CWE-327
# OWASP: A02:2021 - Cryptographic Failures
# DESCRIPTION: Using MD5 for password hashing

import hashlib

def store_password(password):
    """Vulnerable to hash collision attacks"""
    hashed = hashlib.md5(password.encode()).hexdigest()
    database.save("password_hash", hashed)
    return hashed

# EXPLOIT: MD5 collision attacks, rainbow tables
# IMPACT: Password recovery from hash
