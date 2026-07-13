# SECURE CODE: Strong Password Hashing
# PATTERN: Using bcrypt for password storage
# OWASP: A02:2021 - Cryptographic Failures (MITIGATED)

import bcrypt

def store_password_safe(password):
    """Secure password hashing with bcrypt"""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    database.save("password_hash", hashed)
    return hashed

def verify_password_safe(password, stored_hash):
    """Secure password verification"""
    return bcrypt.checkpw(password.encode(), stored_hash)

# This is SAFE because:
# - Uses bcrypt (slow, adaptive hash)
# - Includes salt automatically
# - Configurable work factor (rounds=12)
