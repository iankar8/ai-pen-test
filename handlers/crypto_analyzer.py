"""
Specialized Crypto Pattern Analyzer

Sub-agent focused exclusively on detecting weak cryptographic patterns,
including MD5/SHA-1 hash misuse, with aggressive detection tuning.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class CryptoSmell:
    """A crypto-related pattern that may indicate weakness"""
    pattern_type: str  # "weak_hash", "weak_cipher", "insecure_random", etc.
    function_name: str
    algorithm: str
    line_number: Optional[int]
    code_snippet: str
    context: str  # "password_hashing", "token_generation", "hmac", "checksum", etc.
    is_security_context: bool
    confidence: str  # HIGH, MEDIUM, LOW
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    

class CryptoAnalyzer:
    """
    Specialized analyzer for weak cryptographic patterns.
    
    Uses pattern library + context inference to detect:
    - MD5/SHA-1 for password hashing (CRITICAL)
    - MD5/SHA-1 for token generation (HIGH)
    - MD5/SHA-1 for HMAC (HIGH)
    - MD5/SHA-1 for checksum (LOW - non-security)
    
    Implements "crypto-aggressive" mode for higher recall.
    """
    
    # Pattern library for weak hash detection
    WEAK_HASH_PATTERNS = {
        'java': [
            # Direct MessageDigest usage (single arg)
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)', 'MessageDigest.getInstance("MD5")', 'MD5'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']\s*\)', 'MessageDigest.getInstance("SHA-1")', 'SHA-1'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']\s*\)', 'MessageDigest.getInstance("SHA1")', 'SHA-1'),
            # MessageDigest with provider (two args)
            (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*,', 'MessageDigest.getInstance("MD5", provider)', 'MD5'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']\s*,', 'MessageDigest.getInstance("SHA-1", provider)', 'SHA-1'),
            (r'MessageDigest\.getInstance\s*\(\s*["\']SHA1["\']\s*,', 'MessageDigest.getInstance("SHA1", provider)', 'SHA-1'),
            # DigestUtils (Apache Commons)
            (r'DigestUtils\.md5\s*\(', 'DigestUtils.md5()', 'MD5'),
            (r'DigestUtils\.md5Hex\s*\(', 'DigestUtils.md5Hex()', 'MD5'),
            (r'DigestUtils\.sha1\s*\(', 'DigestUtils.sha1()', 'SHA-1'),
            (r'DigestUtils\.sha1Hex\s*\(', 'DigestUtils.sha1Hex()', 'SHA-1'),
            (r'DigestUtils\.getSha1Digest\s*\(', 'DigestUtils.getSha1Digest()', 'SHA-1'),
            (r'DigestUtils\.getMd5Digest\s*\(', 'DigestUtils.getMd5Digest()', 'MD5'),
            # Guava
            (r'Hashing\.md5\s*\(\s*\)', 'Hashing.md5()', 'MD5'),
            (r'Hashing\.sha1\s*\(\s*\)', 'Hashing.sha1()', 'SHA-1'),
            # Spring Security (legacy)
            (r'new\s+Md5PasswordEncoder\s*\(', 'Md5PasswordEncoder', 'MD5'),
            (r'new\s+ShaPasswordEncoder\s*\(', 'ShaPasswordEncoder', 'SHA-1'),
            # Mac (HMAC) with weak hash
            (r'Mac\.getInstance\s*\(\s*["\']HmacMD5["\']\s*\)', 'Mac.getInstance("HmacMD5")', 'MD5'),
            (r'Mac\.getInstance\s*\(\s*["\']HmacSHA1["\']\s*\)', 'Mac.getInstance("HmacSHA1")', 'SHA-1'),
            (r'Mac\.getInstance\s*\(\s*["\']HMAC-SHA-1["\']\s*\)', 'Mac.getInstance("HMAC-SHA-1")', 'SHA-1'),
            (r'Mac\.getInstance\s*\(\s*["\']HMAC-MD5["\']\s*\)', 'Mac.getInstance("HMAC-MD5")', 'MD5'),
            (r'Mac\.getInstance\s*\(\s*["\']HmacMD5["\']\s*,', 'Mac.getInstance("HmacMD5", provider)', 'MD5'),
            (r'Mac\.getInstance\s*\(\s*["\']HmacSHA1["\']\s*,', 'Mac.getInstance("HmacSHA1", provider)', 'SHA-1'),
            # Config-based algorithm selection (potential weak hash from config)
            # Only flag when variable comes from property/config
            (r'\.getProperty\s*\(\s*["\'].*[Hh]ash.*["\']\s*,\s*["\'][^"\']*(?:MD5|SHA-?1)[^"\']*["\']\s*\)', 'getProperty("hashAlg", "MD5/SHA1")', 'MD5'),
            (r'\.getProperty\s*\(\s*["\'].*[Aa]lg.*["\']\s*,\s*["\'][^"\']*(?:MD5|SHA-?1)[^"\']*["\']\s*\)', 'getProperty("algorithm", "MD5/SHA1")', 'MD5'),
        ],
        'python': [
            # hashlib
            (r'hashlib\.md5\s*\(', 'hashlib.md5()', 'MD5'),
            (r'hashlib\.sha1\s*\(', 'hashlib.sha1()', 'SHA-1'),
            (r'hashlib\.new\s*\(\s*["\']md5["\']\s*\)', 'hashlib.new("md5")', 'MD5'),
            (r'hashlib\.new\s*\(\s*["\']sha1["\']\s*\)', 'hashlib.new("sha1")', 'SHA-1'),
            # Cryptography library (deprecated)
            (r'hashes\.MD5\s*\(\s*\)', 'hashes.MD5()', 'MD5'),
            (r'hashes\.SHA1\s*\(\s*\)', 'hashes.SHA1()', 'SHA-1'),
            # Django (legacy)
            (r'make_password.*md5', 'make_password with MD5', 'MD5'),
        ],
        'javascript': [
            # Node.js crypto
            (r'crypto\.createHash\s*\(\s*["\']md5["\']\s*\)', 'crypto.createHash("md5")', 'MD5'),
            (r'crypto\.createHash\s*\(\s*["\']sha1["\']\s*\)', 'crypto.createHash("sha1")', 'SHA-1'),
            # CryptoJS
            (r'CryptoJS\.MD5\s*\(', 'CryptoJS.MD5()', 'MD5'),
            (r'CryptoJS\.SHA1\s*\(', 'CryptoJS.SHA1()', 'SHA-1'),
            # js-md5
            (r'md5\s*\(', 'md5()', 'MD5'),
        ],
        'go': [
            (r'md5\.New\s*\(\s*\)', 'md5.New()', 'MD5'),
            (r'md5\.Sum\s*\(', 'md5.Sum()', 'MD5'),
            (r'sha1\.New\s*\(\s*\)', 'sha1.New()', 'SHA-1'),
            (r'sha1\.Sum\s*\(', 'sha1.Sum()', 'SHA-1'),
        ],
        'php': [
            (r'md5\s*\(', 'md5()', 'MD5'),
            (r'sha1\s*\(', 'sha1()', 'SHA-1'),
            (r'hash\s*\(\s*["\']md5["\']\s*,', 'hash("md5", ...)', 'MD5'),
            (r'hash\s*\(\s*["\']sha1["\']\s*,', 'hash("sha1", ...)', 'SHA-1'),
        ],
        'ruby': [
            (r'Digest::MD5', 'Digest::MD5', 'MD5'),
            (r'Digest::SHA1', 'Digest::SHA1', 'SHA-1'),
            (r'OpenSSL::Digest\.new\s*\(\s*["\']MD5["\']\s*\)', 'OpenSSL::Digest.new("MD5")', 'MD5'),
            (r'OpenSSL::Digest\.new\s*\(\s*["\']SHA1["\']\s*\)', 'OpenSSL::Digest.new("SHA1")', 'SHA-1'),
        ],
        'csharp': [
            (r'MD5\.Create\s*\(\s*\)', 'MD5.Create()', 'MD5'),
            (r'SHA1\.Create\s*\(\s*\)', 'SHA1.Create()', 'SHA-1'),
            (r'new\s+MD5CryptoServiceProvider\s*\(', 'MD5CryptoServiceProvider', 'MD5'),
            (r'new\s+SHA1CryptoServiceProvider\s*\(', 'SHA1CryptoServiceProvider', 'SHA-1'),
            (r'HashAlgorithm\.Create\s*\(\s*["\']MD5["\']\s*\)', 'HashAlgorithm.Create("MD5")', 'MD5'),
        ],
    }
    
    # Security context patterns (indicates security-relevant usage)
    SECURITY_CONTEXT_PATTERNS = [
        # Password-related
        r'password',
        r'passwd',
        r'pwd',
        r'credential',
        r'secret',
        r'auth',
        r'login',
        r'user.*pass',
        # Token-related
        r'token',
        r'session',
        r'jwt',
        r'cookie',
        r'api.?key',
        # HMAC-related
        r'hmac',
        r'signature',
        r'sign',
        r'verify',
        r'mac',
        # Encryption context
        r'encrypt',
        r'decrypt',
        r'cipher',
        r'key.?derivation',
        r'kdf',
        r'pbkdf',
        r'salt',
    ]
    
    # Non-security context patterns (may reduce severity)
    NON_SECURITY_PATTERNS = [
        r'checksum',
        r'etag',
        r'cache.?key',
        r'dedup',
        r'fingerprint',
        r'content.?hash',
        r'file.?hash',
        r'#\s*(?:legacy|deprecated|todo|fixme)',
        r'//\s*(?:legacy|deprecated|todo|fixme)',
    ]
    
    def __init__(self, aggressive_mode: bool = True):
        """
        Initialize crypto analyzer.
        
        Args:
            aggressive_mode: If True, flag all weak hash usage as potential issues.
                            If False, only flag security-context usage.
        """
        self.aggressive_mode = aggressive_mode
        
    def analyze(self, code: str, language: str, file_path: str = "") -> List[CryptoSmell]:
        """
        Analyze code for weak cryptographic patterns.
        
        Args:
            code: Source code content
            language: Programming language
            file_path: Path to file (for context)
            
        Returns:
            List of CryptoSmell objects
        """
        smells = []
        language = self._normalize_language(language)
        patterns = self.WEAK_HASH_PATTERNS.get(language, [])
        
        # Also check generic patterns
        patterns.extend(self._get_config_patterns())
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern, function_name, algorithm in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get surrounding context (5 lines before/after)
                    context_start = max(0, line_num - 6)
                    context_end = min(len(lines), line_num + 5)
                    context_lines = lines[context_start:context_end]
                    context = '\n'.join(context_lines)
                    
                    # Determine if this is security context
                    is_security, usage_context = self._classify_context(
                        line, context, file_path
                    )
                    
                    # Determine severity based on context
                    severity = self._calculate_severity(
                        algorithm, is_security, usage_context
                    )
                    
                    # Determine confidence
                    confidence = self._calculate_confidence(
                        algorithm, is_security, usage_context, line
                    )
                    
                    # In aggressive mode, flag all; otherwise only security context
                    if self.aggressive_mode or is_security:
                        smells.append(CryptoSmell(
                            pattern_type="weak_hash",
                            function_name=function_name,
                            algorithm=algorithm,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            context=usage_context,
                            is_security_context=is_security,
                            confidence=confidence,
                            severity=severity
                        ))
        
        return smells
    
    def _normalize_language(self, language: str) -> str:
        """Normalize language name to pattern key"""
        lang_map = {
            'py': 'python',
            'python': 'python',
            'js': 'javascript',
            'javascript': 'javascript',
            'ts': 'javascript',  # TypeScript uses same patterns
            'typescript': 'javascript',
            'java': 'java',
            'go': 'go',
            'golang': 'go',
            'php': 'php',
            'rb': 'ruby',
            'ruby': 'ruby',
            'cs': 'csharp',
            'csharp': 'csharp',
        }
        return lang_map.get(language.lower(), language.lower())
    
    def _get_config_patterns(self) -> List[tuple]:
        """Get patterns for config-based algorithm selection"""
        return [
            # Algorithm constants/configs
            (r'HASH_ALGORITHM\s*[:=]\s*["\']MD5["\']', 'HASH_ALGORITHM = "MD5"', 'MD5'),
            (r'HASH_ALGORITHM\s*[:=]\s*["\']SHA-?1["\']', 'HASH_ALGORITHM = "SHA1"', 'SHA-1'),
            (r'algorithm\s*[:=]\s*["\']md5["\']', 'algorithm = "md5"', 'MD5'),
            (r'algorithm\s*[:=]\s*["\']sha1["\']', 'algorithm = "sha1"', 'SHA-1'),
            # Properties files
            (r'hash\.algorithm\s*=\s*MD5', 'hash.algorithm=MD5', 'MD5'),
            (r'hash\.algorithm\s*=\s*SHA-?1', 'hash.algorithm=SHA1', 'SHA-1'),
        ]
    
    def _classify_context(
        self,
        line: str,
        context: str,
        file_path: str
    ) -> tuple:
        """
        Classify the usage context of the weak hash.
        
        Returns:
            (is_security_context, context_type)
        """
        combined = f"{line} {context} {file_path}".lower()
        
        # Check for explicit security context
        for pattern in self.SECURITY_CONTEXT_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                # Determine specific context type
                if re.search(r'password|passwd|pwd|credential', combined):
                    return True, "password_hashing"
                if re.search(r'token|session|jwt|cookie', combined):
                    return True, "token_generation"
                if re.search(r'hmac|signature|sign|mac', combined):
                    return True, "hmac"
                if re.search(r'encrypt|key|kdf|pbkdf', combined):
                    return True, "key_derivation"
                return True, "security_general"
        
        # Check for non-security context
        for pattern in self.NON_SECURITY_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return False, "non_security"
        
        # Default: assume could be security if in aggressive mode
        return self.aggressive_mode, "unknown"
    
    def _calculate_severity(
        self,
        algorithm: str,
        is_security: bool,
        context: str
    ) -> str:
        """Calculate severity based on algorithm and context"""
        
        if not is_security:
            return "LOW"  # Non-security usage (e.g., checksum)
        
        # Security context severity
        if context == "password_hashing":
            return "CRITICAL"  # Password hashing with MD5/SHA-1 is critical
        elif context == "token_generation":
            return "HIGH"  # Token generation is high
        elif context == "hmac":
            return "HIGH"  # HMAC with weak hash is high
        elif context == "key_derivation":
            return "CRITICAL"  # Key derivation is critical
        elif context == "security_general":
            return "HIGH"
        else:
            return "MEDIUM"  # Unknown but potentially security
    
    def _calculate_confidence(
        self,
        algorithm: str,
        is_security: bool,
        context: str,
        line: str
    ) -> str:
        """Calculate confidence level"""
        
        # Direct function call with known algorithm = HIGH confidence
        if algorithm in ("MD5", "SHA-1") and is_security:
            return "HIGH"
        
        # Config-based or constant-based = MEDIUM
        if algorithm == "UNKNOWN":
            return "MEDIUM"
        
        # Non-security context = MEDIUM (might still be issue)
        if not is_security:
            return "MEDIUM"
        
        return "HIGH"
    
    def to_findings(self, smells: List[CryptoSmell], file_path: str) -> List[Dict[str, Any]]:
        """
        Convert crypto smells to standard finding format.
        
        Args:
            smells: List of CryptoSmell objects
            file_path: Path to source file
            
        Returns:
            List of finding dicts compatible with SAST analyzer
        """
        findings = []
        
        for smell in smells:
            finding = {
                "category": "Weak Cryptographic Hash",
                "severity": smell.severity,
                "cwe": "CWE-328" if smell.algorithm == "MD5" else "CWE-328",
                "owasp": "A02:2021 Cryptographic Failures",
                "line": smell.line_number,
                "code_snippet": smell.code_snippet,
                "description": self._generate_description(smell),
                "impact": self._generate_impact(smell),
                "remediation": self._generate_remediation(smell),
                "references": [
                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    "https://cwe.mitre.org/data/definitions/328.html"
                ],
                "confidence": smell.confidence,
            }
            findings.append(finding)
        
        return findings
    
    def _generate_description(self, smell: CryptoSmell) -> str:
        """Generate detailed description for finding"""
        
        context_desc = {
            "password_hashing": "password hashing",
            "token_generation": "security token generation",
            "hmac": "message authentication (HMAC)",
            "key_derivation": "cryptographic key derivation",
            "security_general": "security-sensitive operations",
            "non_security": "operations (potentially security-relevant)",
            "unknown": "potentially security-sensitive operations",
        }
        
        context_text = context_desc.get(smell.context, "operations")
        
        return (
            f"Use of weak cryptographic hash algorithm {smell.algorithm} detected via "
            f"`{smell.function_name}`. This algorithm is used for {context_text}. "
            f"{smell.algorithm} is cryptographically broken and should not be used "
            f"for any security purposes. Collision attacks are practical and "
            f"preimage attacks are becoming feasible."
        )
    
    def _generate_impact(self, smell: CryptoSmell) -> str:
        """Generate impact description"""
        
        impacts = {
            "password_hashing": (
                "Attackers can crack password hashes using rainbow tables or GPU-based "
                "attacks in seconds. This enables account takeover at scale."
            ),
            "token_generation": (
                "Security tokens may be predictable or forgeable, enabling session "
                "hijacking, authentication bypass, or privilege escalation."
            ),
            "hmac": (
                "Message authentication can be bypassed through length extension attacks "
                "or collision-based forgery, compromising data integrity."
            ),
            "key_derivation": (
                "Derived keys provide inadequate security, potentially enabling "
                "decryption of sensitive data or impersonation attacks."
            ),
        }
        
        return impacts.get(smell.context, (
            "Use of weak cryptographic algorithms undermines security controls "
            "and may enable various attacks depending on the usage context."
        ))
    
    def _generate_remediation(self, smell: CryptoSmell) -> str:
        """Generate remediation guidance"""
        
        remediations = {
            "password_hashing": (
                "Replace with a modern password hashing algorithm:\n"
                "- bcrypt (recommended for most cases)\n"
                "- Argon2id (recommended for new applications)\n"
                "- scrypt (alternative)\n\n"
                "Example (Python): `from bcrypt import hashpw, gensalt`\n"
                "Example (Java): `BCrypt.hashpw(password, BCrypt.gensalt())`"
            ),
            "token_generation": (
                "Use cryptographically secure random token generation:\n"
                "- secrets.token_urlsafe() (Python)\n"
                "- crypto.randomBytes() (Node.js)\n"
                "- SecureRandom (Java)\n\n"
                "Do not use MD5/SHA-1 for generating security tokens."
            ),
            "hmac": (
                "Replace with SHA-256 or SHA-384 for HMAC:\n"
                "- HMAC-SHA256 (minimum recommended)\n"
                "- HMAC-SHA384/512 (preferred for high security)\n\n"
                "Example: `hmac.new(key, message, hashlib.sha256)`"
            ),
            "key_derivation": (
                "Use proper key derivation functions:\n"
                "- PBKDF2 with SHA-256 and high iteration count\n"
                "- Argon2 (recommended for new applications)\n"
                "- scrypt\n\n"
                "Example: `PBKDF2(password, salt, iterations=600000, dkLen=32, prf=sha256)`"
            ),
        }
        
        return remediations.get(smell.context, (
            "Replace MD5/SHA-1 with SHA-256 or stronger:\n"
            "- For hashing: SHA-256, SHA-384, or SHA-512\n"
            "- For passwords: bcrypt, Argon2id, or scrypt\n"
            "- For HMAC: HMAC-SHA256 or HMAC-SHA512\n"
            "- For checksums (non-security): SHA-256 is still recommended\n\n"
            "If legacy compatibility is required, document explicitly with "
            "a security exception comment."
        ))
    

# Few-shot exemplars for LLM analysis enhancement
WEAK_HASH_EXEMPLARS = """
## WEAK HASH DETECTION EXEMPLARS

### Exemplar 1: Password Hashing (CRITICAL)
```java
// VULNERABLE: Using MD5 for password storage
String hashedPassword = DigestUtils.md5Hex(password);
userRepository.save(new User(username, hashedPassword));
```
Finding: CRITICAL - CWE-328 - MD5 used for password hashing enables rainbow table attacks

### Exemplar 2: Token Generation (HIGH)
```python
# VULNERABLE: Using SHA-1 for session tokens
token = hashlib.sha1(f"{user_id}{timestamp}".encode()).hexdigest()
session.set_token(token)
```
Finding: HIGH - CWE-328 - SHA-1 token generation is predictable

### Exemplar 3: HMAC with Weak Hash (HIGH)
```javascript
// VULNERABLE: Using MD5 for HMAC signature
const signature = crypto.createHmac('md5', secret).update(data).digest('hex');
```
Finding: HIGH - CWE-328 - HMAC-MD5 vulnerable to length extension attacks

### Exemplar 4: Obfuscated Algorithm (MEDIUM)
```java
// VULNERABLE: Algorithm from config (often set to MD5)
String algorithm = config.getProperty("hash.algorithm"); // Could be MD5
MessageDigest md = MessageDigest.getInstance(algorithm);
```
Finding: MEDIUM - Review hash.algorithm config; ensure SHA-256 or stronger

### Exemplar 5: Non-Security Context (LOW)
```python
# ACCEPTABLE: MD5 for cache key deduplication (not security)
cache_key = hashlib.md5(content.encode()).hexdigest()
# This is acceptable IF: 1) Not security-sensitive, 2) Documented
```
Finding: LOW - MD5 for non-security purpose; consider SHA-256 for consistency

### ALWAYS FLAG AS HIGH UNLESS:
1. Explicitly documented as legacy non-security use
2. Used only for checksums/deduplication with no security implications
3. In test files with clear test data only
"""

