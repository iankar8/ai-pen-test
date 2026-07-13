# VULNERABILITY: Path Traversal
# SEVERITY: CRITICAL
# CWE: CWE-22
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: Unsanitized file path allows directory traversal

def read_file(filename):
    """Vulnerable to path traversal"""
    filepath = f"/var/www/uploads/{filename}"
    with open(filepath, 'r') as f:
        return f.read()

# EXPLOIT: ../../../etc/passwd
# IMPACT: Arbitrary file read
