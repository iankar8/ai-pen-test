# VULNERABILITY: XML External Entity (XXE)
# SEVERITY: HIGH
# CWE: CWE-611
# OWASP: A05:2021 - Security Misconfiguration
# DESCRIPTION: XML parser allows external entities

import xml.etree.ElementTree as ET

def parse_xml(xml_data):
    """Vulnerable to XXE attacks"""
    root = ET.fromstring(xml_data)
    return root.findall('.//data')

# EXPLOIT: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# IMPACT: File disclosure, SSRF, DoS
