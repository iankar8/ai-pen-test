# VULNERABILITY: Command Injection
# SEVERITY: CRITICAL
# CWE: CWE-78
# OWASP: A03:2021 - Injection
# DESCRIPTION: Unsanitized input passed to os.system

import os

def ping_host(hostname):
    """Vulnerable to command injection"""
    os.system(f"ping -c 1 {hostname}")

# EXPLOIT: 127.0.0.1; cat /etc/passwd
# IMPACT: Remote code execution
