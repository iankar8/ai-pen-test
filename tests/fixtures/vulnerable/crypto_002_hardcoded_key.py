# VULNERABILITY: Hardcoded Encryption Key
# SEVERITY: CRITICAL
# CWE: CWE-321
# OWASP: A02:2021 - Cryptographic Failures
# DESCRIPTION: Hardcoded encryption key in source code

from cryptography.fernet import Fernet

def encrypt_data(data):
    """Vulnerable to hardcoded encryption key"""
    SECRET_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
    f = Fernet(SECRET_KEY)
    return f.encrypt(data.encode())

# EXPLOIT: Key is in source code
# IMPACT: All encrypted data can be decrypted
