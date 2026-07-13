"""
Specialized XPath Injection Analyzer

Sub-agent focused on detecting XPath injection vulnerabilities,
including string concatenation, unsanitized parameters, and missing parameterization.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class XPathVulnerability:
    """Represents a potential XPath injection vulnerability"""
    pattern_type: str  # "concatenation", "string_format", "dynamic_query", etc.
    function_name: str
    line_number: Optional[int]
    code_snippet: str
    user_input_source: str  # Variable name or source of user input
    has_sanitization: bool
    confidence: str  # HIGH, MEDIUM, LOW
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


class XPathAnalyzer:
    """
    Specialized analyzer for XPath injection vulnerabilities.
    
    Detects:
    - String concatenation into XPath queries
    - Format string interpolation in XPath
    - Unsanitized user input in XPath
    - Missing parameterization
    - Unsafe XML document queries
    
    Based on OWASP XPath Injection cheat sheet patterns.
    """
    
    # XPath function/method patterns by language
    XPATH_PATTERNS = {
        'java': [
            # Java XPath API
            (r'xpath\.evaluate\s*\(', 'xpath.evaluate', 'xpath'),
            (r'xpath\.compile\s*\(', 'xpath.compile', 'xpath'),
            (r'XPathFactory\..*\.evaluate\s*\(', 'XPathFactory.evaluate', 'xpath'),
            (r'XPathExpression\.evaluate\s*\(', 'XPathExpression.evaluate', 'xpath'),
            # JDOM
            (r'\.selectNodes\s*\(', 'selectNodes', 'jdom'),
            (r'\.selectSingleNode\s*\(', 'selectSingleNode', 'jdom'),
            # DOM4J
            (r'document\.selectNodes\s*\(', 'document.selectNodes', 'dom4j'),
            (r'document\.selectSingleNode\s*\(', 'document.selectSingleNode', 'dom4j'),
        ],
        'python': [
            # lxml
            (r'\.xpath\s*\(', '.xpath', 'lxml'),
            (r'tree\.xpath\s*\(', 'tree.xpath', 'lxml'),
            (r'etree\.XPath\s*\(', 'etree.XPath', 'lxml'),
            # xml.etree
            (r'\.find\s*\(', '.find', 'xml.etree'),
            (r'\.findall\s*\(', '.findall', 'xml.etree'),
            (r'\.iterfind\s*\(', '.iterfind', 'xml.etree'),
            # defusedxml
            (r'defusedxml.*\.xpath\s*\(', 'defusedxml.xpath', 'defusedxml'),
        ],
        'javascript': [
            # DOM
            (r'document\.evaluate\s*\(', 'document.evaluate', 'dom'),
            (r'\.evaluate\s*\(.*XPathResult', 'evaluate with XPathResult', 'dom'),
            # xmldom
            (r'xpath\.select\s*\(', 'xpath.select', 'xmldom'),
            (r'xpath\.select1\s*\(', 'xpath.select1', 'xmldom'),
            # libxmljs
            (r'\.find\s*\(', '.find', 'libxmljs'),
        ],
        'php': [
            # SimpleXML
            (r'->xpath\s*\(', '->xpath', 'simplexml'),
            (r'simplexml_load.*->xpath\s*\(', 'simplexml->xpath', 'simplexml'),
            # DOMXPath
            (r'DOMXPath.*->query\s*\(', 'DOMXPath->query', 'domxpath'),
            (r'DOMXPath.*->evaluate\s*\(', 'DOMXPath->evaluate', 'domxpath'),
            (r'\$xpath->query\s*\(', '$xpath->query', 'domxpath'),
            (r'\$xpath->evaluate\s*\(', '$xpath->evaluate', 'domxpath'),
        ],
        'csharp': [
            # XPathNavigator
            (r'\.SelectNodes\s*\(', '.SelectNodes', 'xpath'),
            (r'\.SelectSingleNode\s*\(', '.SelectSingleNode', 'xpath'),
            (r'\.Evaluate\s*\(', '.Evaluate', 'xpath'),
            # LINQ to XML
            (r'XPathSelectElements\s*\(', 'XPathSelectElements', 'linq'),
            (r'XPathSelectElement\s*\(', 'XPathSelectElement', 'linq'),
            (r'XPathEvaluate\s*\(', 'XPathEvaluate', 'linq'),
        ],
        'ruby': [
            # Nokogiri
            (r'\.xpath\s*\(', '.xpath', 'nokogiri'),
            (r'\.at_xpath\s*\(', '.at_xpath', 'nokogiri'),
            (r'Nokogiri.*\.xpath\s*\(', 'Nokogiri.xpath', 'nokogiri'),
            # REXML
            (r'XPath\.first\s*\(', 'XPath.first', 'rexml'),
            (r'XPath\.each\s*\(', 'XPath.each', 'rexml'),
            (r'XPath\.match\s*\(', 'XPath.match', 'rexml'),
        ],
        'go': [
            # xmlquery
            (r'xmlquery\.Find\s*\(', 'xmlquery.Find', 'xmlquery'),
            (r'xmlquery\.FindOne\s*\(', 'xmlquery.FindOne', 'xmlquery'),
            # goquery
            (r'\.Find\s*\(', '.Find', 'goquery'),
            # etree
            (r'xmlpath\.MustCompile\s*\(', 'xmlpath.MustCompile', 'etree'),
        ],
    }
    
    # Patterns indicating user input (variables that likely come from users)
    USER_INPUT_PATTERNS = [
        r'request\.',
        r'req\.',
        r'params\[',
        r'query\[',
        r'body\[',
        r'form\[',
        r'input',
        r'user_?input',
        r'user_?data',
        r'param',
        r'\$_GET',
        r'\$_POST',
        r'\$_REQUEST',
        r'args\[',
        r'argv\[',
        r'getParameter',
        r'getAttribute',
        r'getHeader',
        r'session\.',
        r'cookie',
    ]
    
    # Concatenation patterns (string building)
    CONCATENATION_PATTERNS = [
        r'\+\s*[a-zA-Z_]',  # + variable
        r'[a-zA-Z_]\s*\+',  # variable +
        r'\"\s*\+',         # " + (string concat)
        r'\'\s*\+',         # ' + (string concat)
        r'\+\s*\"',         # + " (string concat)
        r'\+\s*\'',         # + ' (string concat)
        r'%\s*[a-zA-Z_]',   # % formatting
        r'%s',              # format string placeholder
        r'\$\{',            # Template literals
        r'f["\'].*\{',      # Python f-strings
        r'\.format\s*\(',   # .format()
        r'sprintf',         # sprintf
        r'String\.format',  # Java String.format
        r'String\.Format',  # C# String.Format
        r'concat\s*\(',     # concat function
        r'<<',              # Ruby/C++ concatenation
        r'\+\s*\w+\s*\+',   # var + var pattern
    ]
    
    # Sanitization/safe patterns
    SAFE_PATTERNS = [
        r'escape',
        r'sanitize',
        r'encode',
        r'validate',
        r'whitelist',
        r'allowlist',
        r'parameterize',
        r'bind',
        r'prepared',
        r'quote',
        r'XPathVariable',  # Java XPath parameterization
        r'add_namespace',  # Some libraries' safe param methods
    ]
    
    # Patterns indicating variable reassignment to safe value (reduces FP)
    SAFE_REASSIGNMENT_PATTERNS = [
        # Variable assigned to string literal
        r'=\s*"[^"]*"[;,\)]',
        r"=\s*'[^']*'[;,\)]",
        # Variable assigned from map.get with different key
        r'\.get\s*\(\s*"[^"]*"\s*\)',
        # Variable assigned from safe/hardcoded value
        r'=\s*"safe',
        r'=\s*"fixed',
        r'=\s*"default',
        # Constant assignment
        r'=\s*[A-Z_]+[;,\)]',
    ]
    
    def __init__(self):
        """Initialize XPath analyzer"""
        pass
    
    # Patterns that indicate XPath query strings (even without function calls)
    XPATH_QUERY_PATTERNS = [
        r'["\']//\w+',           # "//node" or '//node'
        r'["\']\.//\w+',         # ".//node"
        r'["\'].*\[@',           # XPath predicate with attribute
        r'@\w+\s*=',             # @attribute= pattern
    ]
    
    def analyze(self, code: str, language: str, file_path: str = "") -> List[XPathVulnerability]:
        """
        Analyze code for XPath injection vulnerabilities.
        
        Args:
            code: Source code content
            language: Programming language
            file_path: Path to file (for context)
            
        Returns:
            List of XPathVulnerability objects
        """
        vulnerabilities = []
        language = self._normalize_language(language)
        patterns = self.XPATH_PATTERNS.get(language, [])
        
        lines = code.split('\n')
        
        # Method 1: Check explicit XPath function calls
        for line_num, line in enumerate(lines, 1):
            for pattern, function_name, library in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get full context (all lines before + some after) for safe reassignment detection
                    context_before = '\n'.join(lines[:line_num])
                    context_after = '\n'.join(lines[line_num:min(len(lines), line_num + 5)])
                    context = f"{context_before}\n{context_after}"
                    
                    # Check for unsafe patterns
                    vuln = self._analyze_xpath_usage(
                        line=line,
                        context=context,
                        line_num=line_num,
                        function_name=function_name,
                        library=library
                    )
                    
                    if vuln:
                        vulnerabilities.append(vuln)
        
        # Method 2: Check for XPath query string patterns with concatenation
        # Use wider context for safe reassignment detection (look at all code before)
        full_code = '\n'.join(lines)
        
        for line_num, line in enumerate(lines, 1):
            # Skip if already found vulnerability on this line
            if any(v.line_number == line_num for v in vulnerabilities):
                continue
            
            # Check for XPath query string patterns
            has_xpath_query = any(
                re.search(p, line) for p in self.XPATH_QUERY_PATTERNS
            )
            
            if has_xpath_query:
                # Check for concatenation in same line
                has_concat = any(
                    re.search(p, line, re.IGNORECASE) 
                    for p in self.CONCATENATION_PATTERNS
                )
                
                if has_concat:
                    # Use all lines before this line for safe reassignment check
                    context_before = '\n'.join(lines[:line_num])
                    context_after = '\n'.join(lines[line_num:min(len(lines), line_num + 5)])
                    context = f"{context_before}\n{context_after}"
                    
                    vuln = self._analyze_xpath_query_string(
                        line=line,
                        context=context,
                        line_num=line_num
                    )
                    
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_xpath_query_string(
        self,
        line: str,
        context: str,
        line_num: int
    ) -> Optional[XPathVulnerability]:
        """
        Analyze an XPath query string (without explicit function call) for injection.
        """
        combined = f"{line} {context}".lower()
        
        # Check for user input sources
        user_input_source = None
        for pattern in self.USER_INPUT_PATTERNS:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                user_input_source = match.group(0)
                break
        
        # Check for sanitization
        has_sanitization = any(
            re.search(p, combined, re.IGNORECASE)
            for p in self.SAFE_PATTERNS
        )
        
        # Check if variable appears to be reassigned to a safe value
        # This reduces FPs where user input is overwritten before use
        has_safe_reassignment = self._check_safe_reassignment(line, context)
        
        # Determine severity
        if has_safe_reassignment:
            # Variable was reassigned to safe value - likely false positive
            return None
        elif user_input_source and not has_sanitization:
            severity = "HIGH"
            confidence = "HIGH"
            pattern_type = "xpath_query_concatenation"
        elif not has_sanitization:
            severity = "MEDIUM"
            confidence = "MEDIUM"
            pattern_type = "xpath_query_concatenation"
        else:
            # Has sanitization, lower severity
            severity = "LOW"
            confidence = "LOW"
            pattern_type = "xpath_query_concatenation_sanitized"
        
        return XPathVulnerability(
            pattern_type=pattern_type,
            function_name="XPath query string",
            line_number=line_num,
            code_snippet=line.strip(),
            user_input_source=user_input_source or "unknown",
            has_sanitization=has_sanitization,
            confidence=confidence,
            severity=severity
        )
    
    def _check_safe_reassignment(self, line: str, context: str) -> bool:
        """
        Check if the variable used in XPath appears to be reassigned to a safe value.
        
        This helps reduce false positives in cases like:
        - bar = userInput; bar = "safe"; xpath(bar)  -> safe (last assignment is safe)
        - bar = map.get("userKey"); bar = map.get("safeKey"); xpath(bar) -> safe
        
        Does NOT consider safe if:
        - bar = "";  bar = userInput; xpath(bar)  -> unsafe (empty string then user input)
        - bar = "default"; bar = param; xpath(bar)  -> unsafe (user input after safe)
        """
        # Extract variable name from XPath concatenation
        # Common patterns: + bar + , + bar), bar +
        var_match = re.search(r'\+\s*(\w+)\s*[\+\)]', line)
        if not var_match:
            var_match = re.search(r'[\"\'\s](\w+)\s*\+', line)
        
        if not var_match:
            return False
        
        var_name = var_match.group(1)
        
        # Skip common variable names that are too generic
        if var_name in ('expression', 'query', 'xpath', 'result', 'i', 'j'):
            return False
        
        # Track the LAST assignment type (safe vs unsafe)
        context_lines = context.split('\n')
        last_assignment_type = None  # None, 'safe', 'user_input', 'other'
        
        # Patterns for "meaningless" safe assignments (like empty string init)
        init_only_patterns = [
            r'=\s*""[;,\)]',        # Empty string
            r"=\s*''[;,\)]",        # Empty string (single quote)
            r'=\s*null[;,\)]',      # null
            r'=\s*0[;,\)]',         # zero
        ]
        
        for ctx_line in context_lines:
            # Check for assignment to this variable
            assign_pattern = rf'\b{re.escape(var_name)}\s*='
            if not re.search(assign_pattern, ctx_line, re.IGNORECASE):
                continue
            
            # Skip initialization-only assignments (empty string, null, etc.)
            if any(re.search(p, ctx_line) for p in init_only_patterns):
                continue
            
            # Check if it's a safe assignment (non-empty constant or safe getter)
            is_safe = False
            for p in self.SAFE_REASSIGNMENT_PATTERNS:
                if re.search(p, ctx_line):
                    # Make sure it's not just an empty string
                    if '""' not in ctx_line and "''" not in ctx_line:
                        is_safe = True
                        break
            
            # Check if it's a user input assignment
            is_user_input = any(
                re.search(p, ctx_line, re.IGNORECASE) 
                for p in self.USER_INPUT_PATTERNS
            )
            
            # Also check for common indirect user input patterns
            indirect_user_patterns = [
                r'new\s+String\s*\(',     # new String() wrapping
                r'\.getBytes\s*\(',       # byte conversion often wraps user input
                r'decode\s*\(',           # decoding user input
                r'Base64',                # Base64 encode/decode
                r'\.toString\s*\(',       # toString on user data
            ]
            if any(re.search(p, ctx_line, re.IGNORECASE) for p in indirect_user_patterns):
                is_user_input = True
            
            # Update last assignment type
            if is_safe and not is_user_input:
                last_assignment_type = 'safe'
            elif is_user_input:
                last_assignment_type = 'user_input'
            else:
                last_assignment_type = 'other'
        
        # Only return True (safe) if the LAST assignment was safe
        return last_assignment_type == 'safe'
    
    def _normalize_language(self, language: str) -> str:
        """Normalize language name"""
        lang_map = {
            'py': 'python',
            'python': 'python',
            'js': 'javascript',
            'javascript': 'javascript',
            'ts': 'javascript',
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
    
    def _analyze_xpath_usage(
        self,
        line: str,
        context: str,
        line_num: int,
        function_name: str,
        library: str
    ) -> Optional[XPathVulnerability]:
        """
        Analyze a specific XPath function usage for vulnerability.
        
        Returns:
            XPathVulnerability if vulnerable, None if safe
        """
        combined = f"{line} {context}".lower()
        
        # Check for string concatenation/interpolation
        has_concatenation = any(
            re.search(p, line, re.IGNORECASE) 
            for p in self.CONCATENATION_PATTERNS
        )
        
        # Check for user input sources
        user_input_source = None
        for pattern in self.USER_INPUT_PATTERNS:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                user_input_source = match.group(0)
                break
        
        # Check for sanitization
        has_sanitization = any(
            re.search(p, combined, re.IGNORECASE)
            for p in self.SAFE_PATTERNS
        )
        
        # Check if variable appears to be reassigned to a safe value
        has_safe_reassignment = self._check_safe_reassignment(line, context)
        
        # If safe reassignment detected, this is likely a false positive
        if has_safe_reassignment:
            return None
        
        # Determine if vulnerable
        is_vulnerable = False
        confidence = "LOW"
        severity = "MEDIUM"
        pattern_type = "dynamic_query"
        
        if has_concatenation and user_input_source:
            is_vulnerable = True
            pattern_type = "concatenation_with_user_input"
            confidence = "HIGH"
            severity = "HIGH"
            
            if not has_sanitization:
                severity = "CRITICAL"
        
        elif has_concatenation and not has_sanitization:
            is_vulnerable = True
            pattern_type = "concatenation"
            confidence = "MEDIUM"
            severity = "HIGH"
        
        elif user_input_source and not has_sanitization:
            is_vulnerable = True
            pattern_type = "unsanitized_input"
            confidence = "MEDIUM"
            severity = "HIGH"
        
        # Check for obvious dynamic query building
        dynamic_patterns = [
            r'"//' + r'\s*\+',
            r'"/[\w]+\[',
            r"'//\s*\+",
            r"'/[\w]+\[",
            r'xpath\s*=.*\+',
            r'query\s*=.*\+',
        ]
        
        for dp in dynamic_patterns:
            if re.search(dp, line, re.IGNORECASE):
                is_vulnerable = True
                pattern_type = "dynamic_query_building"
                confidence = "HIGH"
                severity = "HIGH" if not has_sanitization else "MEDIUM"
                break
        
        if not is_vulnerable:
            return None
        
        # Reduce severity if sanitization present
        if has_sanitization:
            if severity == "CRITICAL":
                severity = "HIGH"
            elif severity == "HIGH":
                severity = "MEDIUM"
            confidence = "MEDIUM"  # Lower confidence when sanitization exists
        
        return XPathVulnerability(
            pattern_type=pattern_type,
            function_name=function_name,
            line_number=line_num,
            code_snippet=line.strip(),
            user_input_source=user_input_source or "unknown",
            has_sanitization=has_sanitization,
            confidence=confidence,
            severity=severity
        )
    
    def to_findings(self, vulns: List[XPathVulnerability], file_path: str) -> List[Dict[str, Any]]:
        """
        Convert XPath vulnerabilities to standard finding format.
        
        Args:
            vulns: List of XPathVulnerability objects
            file_path: Path to source file
            
        Returns:
            List of finding dicts compatible with SAST analyzer
        """
        findings = []
        
        for vuln in vulns:
            finding = {
                "category": "XPath Injection",
                "severity": vuln.severity,
                "cwe": "CWE-643",
                "owasp": "A03:2021 Injection",
                "line": vuln.line_number,
                "code_snippet": vuln.code_snippet,
                "description": self._generate_description(vuln),
                "impact": self._generate_impact(vuln),
                "remediation": self._generate_remediation(vuln),
                "references": [
                    "https://owasp.org/www-community/attacks/XPATH_Injection",
                    "https://cwe.mitre.org/data/definitions/643.html",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
                ],
                "confidence": vuln.confidence,
            }
            findings.append(finding)
        
        return findings
    
    def _generate_description(self, vuln: XPathVulnerability) -> str:
        """Generate detailed description"""
        
        desc_parts = [
            f"Potential XPath injection vulnerability detected in `{vuln.function_name}` call."
        ]
        
        if vuln.pattern_type == "concatenation_with_user_input":
            desc_parts.append(
                f"User-controlled input from `{vuln.user_input_source}` is concatenated "
                f"directly into an XPath query without proper sanitization."
            )
        elif vuln.pattern_type == "concatenation":
            desc_parts.append(
                "String concatenation is used to build the XPath query, which may allow "
                "injection if any part of the query comes from untrusted sources."
            )
        elif vuln.pattern_type == "unsanitized_input":
            desc_parts.append(
                f"User input from `{vuln.user_input_source}` appears to be used in the "
                f"XPath query without proper sanitization or parameterization."
            )
        elif vuln.pattern_type == "dynamic_query_building":
            desc_parts.append(
                "Dynamic XPath query building detected. This pattern commonly leads to "
                "injection vulnerabilities when any query component is user-controlled."
            )
        
        if not vuln.has_sanitization:
            desc_parts.append(
                "No input sanitization or parameterization was detected in the surrounding code."
            )
        
        return " ".join(desc_parts)
    
    def _generate_impact(self, vuln: XPathVulnerability) -> str:
        """Generate impact description"""
        
        return (
            "An attacker can modify the XPath query logic to: "
            "(1) Bypass authentication checks by modifying login queries, "
            "(2) Extract sensitive data from XML documents by modifying query predicates, "
            "(3) Access unauthorized data by manipulating node selection, "
            "(4) Cause denial of service through malformed queries. "
            "XPath injection is analogous to SQL injection but targets XML data stores."
        )
    
    def _generate_remediation(self, vuln: XPathVulnerability) -> str:
        """Generate remediation guidance"""
        
        return """To prevent XPath injection:

1. **Use Parameterized XPath Queries** (Preferred):
   - Java: Use XPathVariableResolver
   - Python lxml: Use XPath variables with namespaces
   - Example: `tree.xpath("//user[@id=$id]", id=user_id)`

2. **Strict Input Validation**:
   - Whitelist allowed characters (alphanumeric only for most cases)
   - Reject any XPath metacharacters: `' " [ ] / @ = ( ) *`
   - Validate against expected format (e.g., numeric IDs only)

3. **Escape Special Characters**:
   - If parameterization isn't available, escape: `' " [ ] ( ) @ = / *`
   - Use library-specific escaping functions

4. **Avoid String Concatenation**:
   - Never concatenate user input directly into XPath queries
   - Use query builders or parameterized APIs

5. **Limit Query Capabilities**:
   - Run with minimal privileges
   - Restrict accessible nodes where possible

Example Safe Pattern (Python/lxml):
```python
# Safe: Using XPath variables
from lxml import etree
tree.xpath("//user[@name=$name]", name=user_input)
```

Example Safe Pattern (Java):
```java
// Safe: Using XPathVariableResolver
xpath.setXPathVariableResolver(new MapVariableResolver(params));
xpath.evaluate("//user[@id=$id]", doc);
```
"""


# Few-shot exemplars for LLM analysis enhancement
XPATH_INJECTION_EXEMPLARS = """
## XPATH INJECTION DETECTION EXEMPLARS

### Exemplar 1: Direct Concatenation (CRITICAL)
```java
// VULNERABLE: Direct string concatenation with user input
String username = request.getParameter("username");
String query = "//users/user[@name='" + username + "']/password";
Node result = (Node) xpath.evaluate(query, doc, XPathConstants.NODE);
```
Finding: CRITICAL - CWE-643 - User input directly concatenated into XPath query

Attack payload: `' or '1'='1` → Query becomes `//users/user[@name='' or '1'='1']/password`

### Exemplar 2: Format String Interpolation (HIGH)
```python
# VULNERABLE: F-string interpolation in XPath
username = request.form['username']
users = tree.xpath(f"//user[@name='{username}']")
```
Finding: HIGH - CWE-643 - User input interpolated into XPath via f-string

### Exemplar 3: PHP Dynamic Query (CRITICAL)
```php
// VULNERABLE: User input in SimpleXML xpath
$id = $_GET['id'];
$result = $xml->xpath("/items/item[@id='$id']");
```
Finding: CRITICAL - CWE-643 - GET parameter directly in XPath query

### Exemplar 4: JavaScript DOM XPath (HIGH)
```javascript
// VULNERABLE: Concatenating user input
const query = "//input[@name='" + userInput + "']";
const result = document.evaluate(query, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
```
Finding: HIGH - CWE-643 - User input concatenated into DOM XPath query

### Exemplar 5: Safe Parameterized Query (NOT VULNERABLE)
```python
# SAFE: Using XPath variables
from lxml import etree
users = tree.xpath("//user[@name=$username]", username=user_input)
```
Finding: None - Properly parameterized XPath query

### DETECTION RULES:
1. ANY string concatenation (+, ., format, f-string, sprintf) into XPath = FLAG
2. User input variables (request.*, params, $_GET, etc.) near XPath calls = FLAG
3. Missing sanitization/escape/parameterization = INCREASE SEVERITY
4. Presence of whitelist/validation = DECREASE SEVERITY but still FLAG for review
"""

