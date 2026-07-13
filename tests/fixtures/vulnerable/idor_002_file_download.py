# VULNERABILITY: Insecure Direct Object Reference (IDOR)
# SEVERITY: CRITICAL
# CWE: CWE-639
# OWASP: A01:2021 - Broken Access Control
# DESCRIPTION: No authorization on file downloads

def download_file(file_id):
    """Vulnerable to IDOR - access any file"""
    file_path = database.get_file_path(file_id)
    return send_file(file_path)

# EXPLOIT: Iterate file_id to download all files
# IMPACT: Unauthorized file access, data breach
