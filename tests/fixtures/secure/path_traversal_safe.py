# SECURE CODE: Path Traversal Prevention
# PATTERN: Using allowlist and path normalization
# OWASP: A01:2021 - Broken Access Control (MITIGATED)

import os
from pathlib import Path

def read_file_safe(filename):
    """Secure against path traversal"""
    # Define allowed directory
    ALLOWED_DIR = Path("/var/www/uploads").resolve()
    
    # Construct and normalize the path
    requested_path = (ALLOWED_DIR / filename).resolve()
    
    # Verify the resolved path is within allowed directory
    if not str(requested_path).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal attempt detected")
    
    with open(requested_path, 'r') as f:
        return f.read()

# This is SAFE because:
# - Uses Path.resolve() to normalize paths
# - Validates final path is within allowed directory
# - Prevents ../ traversal attempts
