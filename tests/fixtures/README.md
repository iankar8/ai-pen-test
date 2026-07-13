# Test Fixtures for ai-pen-test

This directory contains test fixtures for validating the security scanner.

## Structure

```
fixtures/
├── vulnerable/     # Intentionally vulnerable code samples (26 files)
└── secure/         # Secure code examples for false positive testing (5 files)
```

## Vulnerable Fixtures

### SQL Injection (5 files)
- `sqli_001_string_concat.py` - String concatenation
- `sqli_002_format_string.py` - String formatting
- `sqli_003_order_by.py` - ORDER BY clause
- `sqli_004_like_clause.py` - LIKE clause
- `sqli_005_union.py` - UNION-based injection

### Cross-Site Scripting (5 files)
- `xss_001_reflected.py` - Reflected XSS
- `xss_002_stored.py` - Stored XSS
- `xss_003_dom_based.py` - DOM-based XSS
- `xss_004_attribute.py` - Attribute injection
- `xss_005_json.py` - JSON injection

### Authentication Failures (3 files)
- `auth_001_hardcoded.py` - Hardcoded credentials
- `auth_002_weak_session.py` - Weak session management
- `auth_003_no_rate_limit.py` - Missing rate limiting

### Cryptographic Failures (3 files)
- `crypto_001_weak_hash.py` - Weak hash (MD5)
- `crypto_002_hardcoded_key.py` - Hardcoded encryption key
- `crypto_003_weak_random.py` - Weak random number generation

### Insecure Direct Object Reference (4 files)
- `idor_001_user_profile.py` - User profile access
- `idor_002_file_download.py` - File download
- `idor_003_order_access.py` - Order access
- `idor_004_api_endpoint.py` - API endpoint

### Other Critical Vulnerabilities (6 files)
- `path_traversal_001.py` - Directory traversal
- `command_injection_001.py` - OS command injection
- `xxe_001.py` - XML External Entity
- `ssrf_001.py` - Server-Side Request Forgery
- `deserialization_001.py` - Insecure deserialization
- `csrf_001.py` - Cross-Site Request Forgery

## Secure Fixtures (for False Positive Testing)

- `sqli_safe_parameterized.py` - Parameterized queries
- `xss_safe_escaped.py` - Proper HTML escaping
- `auth_safe_bcrypt.py` - Strong password hashing
- `idor_safe_authorization.py` - Proper authorization
- `path_traversal_safe.py` - Path validation

## Coverage

### OWASP Top 10 (2021)
- ✅ A01:2021 - Broken Access Control (IDOR, Path Traversal, CSRF)
- ✅ A02:2021 - Cryptographic Failures (Weak hash, Hardcoded keys)
- ✅ A03:2021 - Injection (SQL, XSS, Command Injection)
- ✅ A05:2021 - Security Misconfiguration (XXE)
- ✅ A07:2021 - Identification and Authentication Failures
- ✅ A08:2021 - Software and Data Integrity Failures (Deserialization)
- ✅ A10:2021 - Server-Side Request Forgery

### CWE Coverage
- CWE-22: Path Traversal
- CWE-78: OS Command Injection
- CWE-79: Cross-Site Scripting
- CWE-89: SQL Injection
- CWE-321: Hardcoded Encryption Key
- CWE-327: Weak Cryptographic Hash
- CWE-338: Weak Random
- CWE-352: CSRF
- CWE-384: Session Fixation
- CWE-502: Deserialization
- CWE-611: XXE
- CWE-639: IDOR
- CWE-798: Hardcoded Credentials
- CWE-918: SSRF

## Usage in Tests

```python
from pathlib import Path

# Load vulnerable fixture
vulnerable_code = Path('tests/fixtures/vulnerable/sqli_001_string_concat.py').read_text()

# Test detection
results = analyzer.analyze_code(vulnerable_code, {'language': 'python'}, 'sast')
assert len(results['findings']) > 0
assert any('SQL' in f['category'] for f in results['findings'])

# Load secure fixture
secure_code = Path('tests/fixtures/secure/sqli_safe_parameterized.py').read_text()

# Test no false positives
results = analyzer.analyze_code(secure_code, {'language': 'python'}, 'sast')
assert len(results['findings']) == 0
```

## Metadata Format

Each vulnerable fixture includes:
```python
# VULNERABILITY: <Type>
# SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
# CWE: <CWE-ID>
# OWASP: <OWASP Category>
# DESCRIPTION: <Brief description>

# ... vulnerable code ...

# EXPLOIT: <Example payload>
# IMPACT: <Security impact>
```

Each secure fixture includes:
```python
# SECURE CODE: <Pattern name>
# PATTERN: <Security pattern used>
# OWASP: <OWASP Category> (MITIGATED)

# ... secure code ...

# This is SAFE because:
# - <Reason 1>
# - <Reason 2>
```

## Testing Requirements

For Sprint 0 acceptance:
- ✅ 20+ vulnerable fixtures (we have 26)
- ✅ Covers OWASP Top 10
- ✅ Includes metadata
- ✅ Has secure examples for false positive testing

Created: November 16, 2025
Sprint: Sprint 0, TICKET-003
