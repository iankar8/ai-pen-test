# Static Application Security Testing (SAST) Instructions

## Objective
Perform comprehensive static code analysis to identify security vulnerabilities using semantic understanding and pattern-based detection.

## Analysis Framework

### 1. Injection Vulnerabilities
**Target**: SQL, NoSQL, OS Command, LDAP, XPath injection

**Analysis Steps**:
1. Identify all user input sources (HTTP params, headers, cookies, file uploads)
2. Trace data flow from input to sensitive operations (database queries, system calls, XML parsing)
3. Check for proper input validation and sanitization
4. Verify use of parameterized queries/prepared statements
5. Assess encoding and escaping mechanisms

**Key Patterns**:
- String concatenation in SQL queries
- Direct inclusion of user input in `os.system()`, `exec()`, `eval()`
- Unvalidated input in ORM query builders
- XML/JSON parsing without schema validation

**Example Vulnerable Code**:
```python
# SQL Injection
query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
# Should use: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Command Injection  
os.system(f"ping {user_input}")  # VULNERABLE
# Should use: subprocess.run(["ping", user_input], check=True)
```

---

### 2. Broken Authentication & Session Management

**Target**: Login, session handling, password storage, MFA, token management

**Analysis Steps**:
1. Review authentication logic for bypass opportunities
2. Check password storage (hashing algorithm, salting, pepper)
3. Verify session token generation (entropy, randomness)
4. Assess session fixation and hijacking vulnerabilities
5. Check logout/timeout handling
6. Review credential transmission (HTTPS enforcement)

**Key Patterns**:
- Weak password hashing (MD5, SHA1 without salt)
- Predictable session tokens
- Missing session expiration
- Credentials in URLs or logs
- Missing rate limiting on login attempts

**Example Vulnerable Code**:
```python
# Weak password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # VULNERABLE
# Should use: bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Predictable session token
session_id = str(user_id) + str(time.time())  # VULNERABLE
# Should use: secrets.token_urlsafe(32)
```

---

### 3. Sensitive Data Exposure

**Target**: PII, credentials, API keys, cryptographic material

**Analysis Steps**:
1. Identify sensitive data handling (storage, transmission, logging)
2. Check encryption at rest and in transit
3. Review key management practices
4. Assess data retention and deletion
5. Check for sensitive data in version control, logs, error messages

**Key Patterns**:
- Hardcoded credentials/API keys
- Unencrypted sensitive data in databases
- Sensitive data in GET parameters
- Verbose error messages exposing system details
- Secrets in environment variables without encryption

**Example Vulnerable Code**:
```python
# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # VULNERABLE
# Should use: API_KEY = os.environ.get('API_KEY')

# Logging sensitive data
logger.info(f"User login: {username}, password: {password}")  # VULNERABLE
# Should use: logger.info(f"User login: {username}")
```

---

### 4. XML External Entities (XXE)

**Target**: XML parsing, SOAP APIs, file uploads

**Analysis Steps**:
1. Identify XML parsing libraries and configurations
2. Check if external entity processing is disabled
3. Review file upload handling for XML files
4. Assess XML schema validation

**Key Patterns**:
- `lxml.etree.parse()` without `resolve_entities=False`
- `xml.etree.ElementTree` parsing untrusted XML
- Missing DTD/entity processing restrictions

---

### 5. Broken Access Control

**Target**: Authorization checks, role-based access, object-level permissions

**Analysis Steps**:
1. Map all authorization checks in the codebase
2. Identify horizontal privilege escalation opportunities (IDOR)
3. Check vertical privilege escalation (role bypass)
4. Review direct object references
5. Assess CORS and API endpoint protections

**Key Patterns**:
- Missing authorization checks on sensitive operations
- Relying on client-side access control
- Insecure direct object references (user can access others' data)
- CORS misconfiguration allowing unauthorized origins

**Example Vulnerable Code**:
```python
# IDOR vulnerability
@app.route('/user/<user_id>/profile')
def get_profile(user_id):
    return User.query.get(user_id)  # VULNERABLE - no ownership check
# Should verify: if current_user.id != user_id: abort(403)
```

---

### 6. Security Misconfiguration

**Target**: Framework configs, server settings, cloud resources, containers

**Analysis Steps**:
1. Review framework security settings (debug mode, CORS, CSP)
2. Check default credentials and unnecessary features
3. Assess cloud resource configurations (S3 buckets, IAM roles)
4. Review Docker/container security
5. Check dependency versions and known vulnerabilities

**Key Patterns**:
- Debug mode enabled in production
- Default credentials unchanged
- Overly permissive CORS policies
- Public S3 buckets or databases
- Missing security headers (CSP, HSTS, X-Frame-Options)

---

### 7. Cross-Site Scripting (XSS)

**Target**: User input rendering, template engines, DOM manipulation

**Analysis Steps**:
1. Identify all user input rendering points
2. Check output encoding/escaping
3. Review template auto-escaping configurations
4. Assess Content Security Policy (CSP)
5. Check for DOM-based XSS in JavaScript

**Key Patterns**:
- Rendering unsanitized user input in HTML
- Disabling template auto-escaping
- Using `innerHTML` with user data
- Missing CSP headers

---

### 8. Insecure Deserialization

**Target**: Pickle, YAML, JSON deserialization

**Analysis Steps**:
1. Identify deserialization of untrusted data
2. Check for object injection vulnerabilities
3. Review serialization library usage
4. Assess input validation before deserialization

**Key Patterns**:
- `pickle.loads()` on user input
- `yaml.load()` without SafeLoader
- Deserializing signed but unencrypted data

---

### 9. Using Components with Known Vulnerabilities

**Target**: Dependencies, libraries, frameworks

**Analysis Steps**:
1. Parse dependency manifests (requirements.txt, package.json, go.mod)
2. Check for outdated packages with known CVEs
3. Assess transitive dependencies
4. Review security advisories

---

### 10. Insufficient Logging & Monitoring

**Target**: Security event logging, error handling, audit trails

**Analysis Steps**:
1. Verify logging of authentication/authorization events
2. Check for sensitive data in logs
3. Assess log retention and protection
4. Review error handling and information disclosure

---

## Severity Assessment

Use the following criteria to assign severity:

- **Critical**: Remote code execution, authentication bypass, data breach
- **High**: Privilege escalation, SQL injection, XSS in admin panels
- **Medium**: CSRF, information disclosure, weak crypto
- **Low**: Missing security headers, verbose error messages
- **Info**: Best practice recommendations

## Output Format

For each finding, provide:

```json
{
  "id": "FINDING-001",
  "severity": "HIGH",
  "category": "SQL Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "file": "src/api/users.py",
  "line": 42,
  "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
  "description": "SQL injection vulnerability due to string concatenation in query construction",
  "impact": "Attacker can execute arbitrary SQL commands, leading to data theft or manipulation",
  "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
  "references": [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "CWE-89: SQL Injection"
  ],
  "cvss_score": 8.6,
  "confidence": "HIGH"
}
```

## False Positive Filtering

Apply these filters to reduce noise:

1. **Framework-specific protections**: Django ORM auto-escapes, Flask template auto-escaping
2. **Context-aware analysis**: Check if input validation exists upstream
3. **Dead code**: Skip unreachable code paths
4. **Test code**: Lower severity for vulnerabilities in test files
5. **Known exceptions**: Load from `resources/false_positive_filters.txt`

