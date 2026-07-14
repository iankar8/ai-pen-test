"""
Static Application Security Testing (SAST) Analyzer

Orchestrates comprehensive static code analysis using Claude's semantic
understanding combined with pattern-based vulnerability detection.
"""

import os
import re
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import anthropic
from handlers.llm_provider import LLMProvider
from handlers.codebase_detector import CodebaseDetector, CodebaseContext, CodebaseType
from handlers.crypto_analyzer import CryptoAnalyzer, WEAK_HASH_EXEMPLARS
from handlers.xpath_analyzer import XPathAnalyzer, XPATH_INJECTION_EXEMPLARS


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(Enum):
    """OWASP Top 10 and common vulnerability categories"""
    INJECTION = "injection_attacks"
    BROKEN_AUTH = "authentication_authorization"
    DATA_EXPOSURE = "data_exposure"
    XXE = "xml_external_entities"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    XSS = "cross_site_scripting"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    CRYPTOGRAPHIC_ISSUES = "cryptographic_issues"
    BUSINESS_LOGIC = "business_logic_flaws"
    API_SECURITY = "api_security"
    CODE_EXECUTION = "code_execution"


@dataclass
class Finding:
    """Represents a security vulnerability finding"""
    id: str
    severity: str
    category: str
    cwe: Optional[str]
    owasp: Optional[str]
    file: str
    line: Optional[int]
    code_snippet: str
    description: str
    impact: str
    remediation: str
    references: List[str]
    cvss_score: Optional[float]
    confidence: str
    
    def to_dict(self):
        """Convert to dictionary"""
        return asdict(self)
    
    def fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication"""
        key = f"{self.file}:{self.line}:{self.category}:{self.code_snippet}"
        return hashlib.md5(key.encode()).hexdigest()


class SASTAnalyzer:
    """
    Orchestrates static application security testing using Claude's
    semantic code understanding combined with pattern-based detection.
    """
    
    def __init__(
        self,
        model: str = "claude",
        timeout_minutes: int = 20,
        api_key: Optional[str] = None,
        use_openrouter: bool = True,
        crypto_aggressive_mode: bool = True,
        backend: str = "openrouter"
    ):
        """
        Initialize SAST analyzer.

        Args:
            model: Model to use ('claude', 'gpt4o', etc. if use_openrouter=True,
                   or full Anthropic model name if use_openrouter=False)
            timeout_minutes: Max analysis time
            api_key: API key (OpenRouter or Anthropic depending on use_openrouter)
            use_openrouter: If True, use OpenRouter multi-LLM. If False, use direct Anthropic
            crypto_aggressive_mode: If True, flag all weak hash usage (higher recall, some FP)
            backend: 'openrouter' (default, metered API) or 'codex' (route the LLM call
                     through the Codex CLI so it bills to a ChatGPT/Codex subscription
                     instead of API credits). 'codex' requires the `codex` CLI installed
                     and signed in with ChatGPT; `model` is passed to `codex exec -m`.
        """
        self.model = model
        self.timeout = timeout_minutes
        self.backend = backend
        self.use_openrouter = use_openrouter
        self.crypto_aggressive_mode = crypto_aggressive_mode

        if backend == "codex":
            # LLM call is shelled out to the Codex CLI (subscription auth); no HTTP client.
            self.llm = None
            self.client = None
        elif use_openrouter:
            # Use new LLM Provider with OpenRouter
            self.llm = LLMProvider(primary_model=model, api_key=api_key)
            self.client = None  # Legacy client not used
        else:
            # Fallback to direct Anthropic client
            self.client = anthropic.Anthropic(api_key=api_key)
            self.llm = None
        
        self.vulnerability_categories = [
            VulnerabilityCategory.INJECTION,
            VulnerabilityCategory.BROKEN_AUTH,
            VulnerabilityCategory.DATA_EXPOSURE,
            VulnerabilityCategory.BROKEN_ACCESS_CONTROL,
            VulnerabilityCategory.SECURITY_MISCONFIGURATION,
            VulnerabilityCategory.XSS,
            VulnerabilityCategory.CRYPTOGRAPHIC_ISSUES,
            VulnerabilityCategory.API_SECURITY,
            VulnerabilityCategory.CODE_EXECUTION
        ]
        
        # Load instruction templates
        self.instructions = self._load_instructions()
        
        # Load false positive filters
        self.fp_filters = self._load_false_positive_filters()
        
        # Codebase detector for context-aware analysis
        self.codebase_detector = CodebaseDetector()
        self.codebase_context: Optional[CodebaseContext] = None
        
        # Specialized sub-analyzers for targeted detection
        self.crypto_analyzer = CryptoAnalyzer(aggressive_mode=crypto_aggressive_mode)
        self.xpath_analyzer = XPathAnalyzer()
    
    def analyze_codebase(
        self,
        repo_path: str,
        scope: str = "changed_files",
        changed_files: Optional[List[str]] = None,
        custom_policies: Optional[Dict] = None
    ) -> List[Finding]:
        """
        Performs comprehensive SAST analysis.
        
        Args:
            repo_path: Path to repository
            scope: "changed_files" (PR) or "full_codebase"
            changed_files: List of changed files (for PR analysis)
            custom_policies: Custom security policies
        
        Returns:
            List of Finding objects with severity, remediation guidance
        """
        print(f"[SAST] Starting analysis: {scope} in {repo_path}")
        
        # 0. Detect codebase type and gather context (reduces false positives)
        print(f"[SAST] Detecting codebase type...")
        self.codebase_context = self.codebase_detector.analyze(repo_path)
        print(f"[SAST] Codebase type: {self.codebase_context.codebase_type.value}")
        print(f"[SAST] Security rules: {self.codebase_context.get_security_rules()}")
        
        # 1. Collect files to analyze
        files_to_analyze = self._collect_files(repo_path, scope, changed_files)
        print(f"[SAST] Analyzing {len(files_to_analyze)} files")
        
        # 2. Analyze each file
        all_findings = []
        for file_path in files_to_analyze:
            findings = self._analyze_file(file_path, custom_policies)
            all_findings.extend(findings)
        
        # 3. Apply false positive filters
        filtered_findings = self.apply_false_positive_filters(all_findings)
        print(f"[SAST] Found {len(all_findings)} issues, {len(filtered_findings)} after filtering")
        
        # 4. Assign CVSS scores
        scored_findings = self._assign_cvss_scores(filtered_findings)
        
        # 5. Sort by severity
        sorted_findings = self._sort_by_severity(scored_findings)
        
        return sorted_findings
    
    def get_llm_stats(self) -> Optional[Dict]:
        """
        Get LLM usage statistics (requests, costs, tokens).
        Only available when use_openrouter=True.
        
        Returns:
            Stats dict or None if using legacy client
        """
        if self.use_openrouter and self.llm:
            return self.llm.get_stats()
        return None
    
    def _collect_files(
        self,
        repo_path: str,
        scope: str,
        changed_files: Optional[List[str]]
    ) -> List[str]:
        """Collect files for analysis based on scope"""
        
        if scope == "changed_files" and changed_files:
            # Only analyze changed files
            return [
                os.path.join(repo_path, f) for f in changed_files
                if self._should_analyze_file(f)
            ]
        
        # Full codebase scan
        files = []
        for root, dirs, filenames in os.walk(repo_path):
            # Skip common excluded directories
            dirs[:] = [d for d in dirs if d not in [
                '.git', 'node_modules', 'venv', '__pycache__',
                'build', 'dist', '.next', 'vendor'
            ]]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if self._should_analyze_file(file_path):
                    files.append(file_path)
        
        return files
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed"""
        
        # File extensions to analyze
        analyzable_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx',
            '.java', '.go', '.rb', '.php',
            '.yml', '.yaml', '.json', '.xml',
            '.tf', '.dockerfile', 'Dockerfile',
            '.sql', '.sh', '.bash', '.sol'
        }
        
        file_path_lower = file_path.lower()
        
        # Check extension
        if any(file_path_lower.endswith(ext) for ext in analyzable_extensions):
            return True
        
        # Check filename
        if any(name in file_path for name in ['Dockerfile', 'docker-compose']):
            return True
        
        return False
    
    def _analyze_file(
        self,
        file_path: str,
        custom_policies: Optional[Dict]
    ) -> List[Finding]:
        """Analyze a single file for vulnerabilities"""
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            print(f"[SAST] Error reading {file_path}: {e}")
            return []
        
        # Skip empty files
        if not code_content.strip():
            return []
        
        all_findings = []
        language = self._detect_file_type(file_path)
        
        # 1. Run specialized sub-analyzers first (pattern-based, high precision)
        specialized_findings = self._run_specialized_analyzers(
            code_content, language, file_path
        )
        all_findings.extend(specialized_findings)
        
        # 2. Build analysis prompt with few-shot exemplars
        prompt = self._build_analysis_prompt(
            file_path,
            code_content,
            custom_policies
        )
        
        # 3. Call LLM for semantic analysis
        try:
            findings_json = self._call_claude_analysis(prompt, code_content)
            llm_findings = self._parse_findings(findings_json, file_path)
            
            # 4. Merge and deduplicate findings
            merged_findings = self._merge_findings(all_findings, llm_findings, file_path)
            return merged_findings
        except Exception as e:
            print(f"[SAST] Error analyzing {file_path}: {e}")
            # Return specialized findings even if LLM fails
            return all_findings
    
    def _run_specialized_analyzers(
        self,
        code: str,
        language: str,
        file_path: str
    ) -> List[Finding]:
        """
        Run specialized pattern-based analyzers for targeted vulnerability classes.
        
        These sub-agents focus on categories where we need higher recall:
        - Weak Hash (MD5/SHA-1)
        - XPath Injection
        """
        findings = []
        
        # 1. Crypto Analyzer (Weak Hash Detection)
        crypto_smells = self.crypto_analyzer.analyze(code, language, file_path)
        if crypto_smells:
            crypto_findings = self.crypto_analyzer.to_findings(crypto_smells, file_path)
            for cf in crypto_findings:
                line_num = cf.get('line', 0)
                finding_id = hashlib.md5(f'{file_path}{line_num}'.encode()).hexdigest()[:8].upper()
                finding = Finding(
                    id=f"CRYPTO-{finding_id}",
                    severity=cf.get('severity', 'HIGH'),
                    category=cf.get('category', 'Weak Cryptographic Hash'),
                    cwe=cf.get('cwe', 'CWE-328'),
                    owasp=cf.get('owasp', 'A02:2021'),
                    file=file_path,
                    line=cf.get('line'),
                    code_snippet=cf.get('code_snippet', ''),
                    description=cf.get('description', ''),
                    impact=cf.get('impact', ''),
                    remediation=cf.get('remediation', ''),
                    references=cf.get('references', []),
                    cvss_score=None,
                    confidence=cf.get('confidence', 'HIGH')
                )
                findings.append(finding)
        
        # 2. XPath Analyzer
        xpath_vulns = self.xpath_analyzer.analyze(code, language, file_path)
        if xpath_vulns:
            xpath_findings = self.xpath_analyzer.to_findings(xpath_vulns, file_path)
            for xf in xpath_findings:
                line_num = xf.get('line', 0)
                finding_id = hashlib.md5(f'{file_path}{line_num}'.encode()).hexdigest()[:8].upper()
                finding = Finding(
                    id=f"XPATH-{finding_id}",
                    severity=xf.get('severity', 'HIGH'),
                    category=xf.get('category', 'XPath Injection'),
                    cwe=xf.get('cwe', 'CWE-643'),
                    owasp=xf.get('owasp', 'A03:2021'),
                    file=file_path,
                    line=xf.get('line'),
                    code_snippet=xf.get('code_snippet', ''),
                    description=xf.get('description', ''),
                    impact=xf.get('impact', ''),
                    remediation=xf.get('remediation', ''),
                    references=xf.get('references', []),
                    cvss_score=None,
                    confidence=xf.get('confidence', 'HIGH')
                )
                findings.append(finding)
        
        return findings
    
    def _merge_findings(
        self,
        specialized_findings: List[Finding],
        llm_findings: List[Finding],
        file_path: str
    ) -> List[Finding]:
        """
        Merge findings from specialized analyzers and LLM, avoiding duplicates.
        Specialized findings take precedence (more precise).
        """
        merged = list(specialized_findings)
        seen_lines = {(f.line, f.category.lower()) for f in specialized_findings}
        
        for finding in llm_findings:
            key = (finding.line, finding.category.lower())
            
            # Skip if we already have a finding at same line for same category
            if key in seen_lines:
                continue
            
            # Check for similar category variations
            is_duplicate = False
            for spec_finding in specialized_findings:
                if finding.line == spec_finding.line:
                    # Check category similarity
                    if self._categories_similar(finding.category, spec_finding.category):
                        is_duplicate = True
                        break
            
            if not is_duplicate:
                merged.append(finding)
                seen_lines.add(key)
        
        return merged
    
    def _categories_similar(self, cat1: str, cat2: str) -> bool:
        """Check if two vulnerability categories refer to the same issue"""
        cat1_lower = cat1.lower()
        cat2_lower = cat2.lower()
        
        # Weak hash variations
        weak_hash_terms = ['weak hash', 'weak crypto', 'md5', 'sha-1', 'sha1', 'cryptographic']
        if any(t in cat1_lower for t in weak_hash_terms) and any(t in cat2_lower for t in weak_hash_terms):
            return True
        
        # XPath injection variations
        xpath_terms = ['xpath', 'xml injection', 'xml query']
        if any(t in cat1_lower for t in xpath_terms) and any(t in cat2_lower for t in xpath_terms):
            return True
        
        return False
    
    def _build_analysis_prompt(
        self,
        file_path: str,
        code_content: str,
        custom_policies: Optional[Dict]
    ) -> str:
        """Build analysis prompt for Claude"""
        
        file_type = self._detect_file_type(file_path)
        
        # Get codebase context
        codebase_type = "unknown"
        security_rules = {}
        file_context_info = ""
        parent_has_auth = False
        
        if self.codebase_context:
            codebase_type = self.codebase_context.codebase_type.value
            security_rules = self.codebase_context.get_security_rules()
            
            # Get file-specific context
            file_ctx = self.codebase_detector.get_file_context(self.codebase_context, file_path)
            if file_ctx:
                file_context_info = f"""
FILE CONTEXT:
- Is test file: {file_ctx.is_test_file}
- Is mock: {file_ctx.is_mock}
- Has auth checks: {file_ctx.has_auth_check}
- Parent classes: {', '.join(file_ctx.parent_classes) if file_ctx.parent_classes else 'None'}
"""
                parent_has_auth = self.codebase_detector.get_parent_has_auth(self.codebase_context, file_path)
                if parent_has_auth:
                    file_context_info += "- Parent class HAS authentication checks\n"
        
        # Build anti-false-positive rules based on codebase type
        anti_fp_rules = self._build_anti_fp_rules(codebase_type, security_rules, parent_has_auth)
        
        prompt = f"""Act as an application security reviewer and audit the source file below for exploitable vulnerabilities.

FILE: {file_path}
TYPE: {file_type}
CODEBASE TYPE: {codebase_type}
{file_context_info}

INSTRUCTIONS:
{self.instructions['security-review']}

{anti_fp_rules}

Analyze the code for security vulnerabilities in these categories:
- SQL/NoSQL Injection
- Cross-Site Scripting (XSS)
- Authentication/Authorization flaws
- Sensitive data exposure
- Cryptographic weaknesses (MD5, SHA-1 - see exemplars below)
- Access control issues
- Security misconfigurations
- API security issues
- Command injection
- XPath Injection (see exemplars below)
- Insecure deserialization

## SPECIAL ATTENTION: WEAK CRYPTOGRAPHIC HASH DETECTION

Be especially vigilant for weak hash algorithms. Here are patterns to FLAG AS HIGH/CRITICAL:

{WEAK_HASH_EXEMPLARS}

## SPECIAL ATTENTION: XPATH INJECTION DETECTION

Be especially suspicious of any XML/XPath queries that incorporate user-controlled input.

{XPATH_INJECTION_EXEMPLARS}

For each finding, provide:
1. Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
2. Category (e.g., "SQL Injection")
3. CWE ID
4. OWASP mapping
5. Line number
6. Code snippet (exact vulnerable code)
7. Description of vulnerability
8. Impact (what attacker can achieve)
9. Remediation (how to fix with code example)
10. References (relevant links)
11. Confidence (HIGH/MEDIUM/LOW)

OUTPUT FORMAT: JSON array of findings. Return empty array [] if no real vulnerabilities found.
"""
        
        if custom_policies:
            prompt += f"\n\nCUSTOM POLICIES:\n{json.dumps(custom_policies, indent=2)}"
        
        return prompt
    
    def _build_anti_fp_rules(
        self,
        codebase_type: str,
        security_rules: Dict,
        parent_has_auth: bool
    ) -> str:
        """Build anti-false-positive rules based on context"""
        
        rules = """
## CRITICAL: FALSE POSITIVE PREVENTION

You MUST avoid these common false positives:

1. **Security checks ARE the fix, not the problem**
   - Code like `if not authenticated: raise AuthenticationError` is CORRECT behavior
   - Do NOT flag authentication/authorization CHECKS as vulnerabilities
   - If code raises an error for unauthenticated access, that's the SECURITY CONTROL

2. **Standard data operations are NOT vulnerabilities**
   - `json.loads()` on API responses = SAFE (normal parsing)
   - Loading PEM keys from configuration = SAFE (expected for API auth)
   - `**kwargs` or `**response` unpacking = SAFE (standard Python)
   - Only flag: `pickle.loads(user_input)`, `yaml.unsafe_load(untrusted_data)`

3. **Test files have different standards**
   - Hardcoded "test-api-key" in test fixtures = ACCEPTABLE
   - Mock servers without full auth = ACCEPTABLE (it's a mock)
   - Only flag REAL secrets that look like production keys

4. **Confidence calibration**
   - HIGH = Clear exploitable pattern with attack vector
   - MEDIUM = Potential issue, context-dependent
   - LOW = Theoretical concern only
"""
        
        # Add codebase-specific rules
        if codebase_type == "client_sdk":
            rules += """
5. **CLIENT SDK SPECIFIC RULES**
   - This is a CLIENT LIBRARY that calls external APIs
   - Authorization is handled SERVER-SIDE by the API, not in this client
   - Do NOT flag missing authorization checks - the server enforces these
   - Do NOT flag "IDOR" - clients pass IDs to servers which validate ownership
   - API response deserialization is TRUSTED (server is the authority)
   - Methods like `get_account(uuid)` are correct - server validates access
"""
        
        if parent_has_auth:
            rules += """
6. **PARENT CLASS CONTEXT**
   - The parent/base class ALREADY contains authentication checks
   - Child class methods inherit this protection
   - Do NOT flag missing auth if the parent class handles it
"""
        
        if not security_rules.get("deserialization_strict", True):
            rules += """
7. **DESERIALIZATION CONTEXT**
   - This codebase receives data from trusted API endpoints
   - JSON/response parsing is normal SDK behavior, not insecure deserialization
   - Only flag actual dangerous patterns: pickle, yaml.load(), eval()
"""
        
        return rules
    
    def _call_codex(self, prompt: str, code_content: str) -> str:
        """
        Route the analysis through the Codex CLI so it bills to a ChatGPT/Codex
        subscription instead of API credits. Runs `codex exec` headless (no tools,
        read-only sandbox) and returns the model's raw text answer for _parse_findings.

        Requires: `codex` on PATH, signed in with ChatGPT (`~/.codex/auth.json`).
        Note this executes the Codex *agent* around the prompt, not a raw single-turn
        completion — see benchmark/README for the labeling caveat.
        """
        import shutil, subprocess, tempfile, os as _os
        codex_bin = shutil.which("codex")
        if not codex_bin:
            raise RuntimeError(
                "backend='codex' needs the Codex CLI on PATH, signed in with ChatGPT. "
                "Run `codex login` first, or use backend='openrouter' with an API key."
            )
        full_prompt = (
            f"{prompt}\n\nAnalyze this code for security vulnerabilities and return "
            f"ONLY the JSON described above, no prose:\n\n```\n{code_content}\n```"
        )
        # --ignore-user-config is REQUIRED: it skips the user's Codex hooks and
        # config so (a) their prompt-time context is NOT injected into the analysis
        # (benchmark contamination) and (b) it doesn't hang on hook execution.
        # -o writes only the final agent message; --ephemeral leaves no session on disk.
        with tempfile.NamedTemporaryFile("r", suffix=".txt", delete=False) as tf:
            out_path = tf.name
        try:
            # --disable plugins/plugin_sharing/remote_plugin roughly halves per-call
            # token overhead (~13.7k -> ~6.6k). The ~129 runtime skills can't be
            # stripped further, so ~6.6k is the floor.
            cmd = [codex_bin, "exec", "-m", self.model,
                   "--ignore-user-config", "--ephemeral",
                   "--disable", "plugins", "--disable", "plugin_sharing",
                   "--disable", "remote_plugin",
                   "-s", "read-only", "--skip-git-repo-check",
                   "-o", out_path, full_prompt]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout * 60
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"codex exec failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
                )
            with open(out_path) as fh:
                answer = fh.read()
            # Fall back to stdout if -o produced nothing (older/newer CLI variance).
            return answer if answer.strip() else proc.stdout
        finally:
            try:
                _os.unlink(out_path)
            except OSError:
                pass

    def _call_claude_analysis(self, prompt: str, code_content: str) -> str:
        """Call LLM API for code analysis"""

        if self.backend == "codex":
            return self._call_codex(prompt, code_content)

        if self.use_openrouter and self.llm:
            # Use new LLM Provider (OpenRouter multi-LLM)
            result = self.llm.analyze_code(
                code=code_content,
                context={'language': 'auto-detect', 'file_path': 'analyzing'},
                task='sast',
                custom_prompt=prompt
            )
            
            if result.error:
                raise RuntimeError(f"LLM analysis failed: {result.error}")
            
            return result.raw_response
        else:
            # Fallback to direct Anthropic client
            message = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                temperature=0,  # Deterministic for security analysis
                system=prompt,
                messages=[{
                    "role": "user",
                    "content": f"Analyze this code for security vulnerabilities:\n\n```\n{code_content}\n```"
                }]
            )
            
            return message.content[0].text
    
    def _parse_findings(self, claude_response: str, file_path: str) -> List[Finding]:
        """Parse Claude's response into Finding objects"""
        
        findings = []
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\[.*\]', claude_response, re.DOTALL)
            if not json_match:
                return findings
            
            findings_data = json.loads(json_match.group(0))
            
            for idx, item in enumerate(findings_data):
                finding = Finding(
                    id=f"FIND-{hashlib.md5(f'{file_path}{idx}'.encode()).hexdigest()[:8].upper()}",
                    severity=item.get('severity', 'MEDIUM'),
                    category=item.get('category', 'Unknown'),
                    cwe=item.get('cwe'),
                    owasp=item.get('owasp'),
                    file=file_path,
                    line=item.get('line'),
                    code_snippet=item.get('code_snippet', ''),
                    description=item.get('description', ''),
                    impact=item.get('impact', ''),
                    remediation=item.get('remediation', ''),
                    references=item.get('references', []),
                    cvss_score=item.get('cvss_score'),
                    confidence=item.get('confidence', 'MEDIUM')
                )
                findings.append(finding)
        
        except json.JSONDecodeError as e:
            print(f"[SAST] Failed to parse Claude response as JSON: {e}")
        
        return findings
    
    def apply_false_positive_filters(self, findings: List[Finding]) -> List[Finding]:
        """
        Reduces noise through semantic filtering.
        Removes low-impact findings, known exceptions.
        Uses codebase context for smarter filtering.
        """
        
        filtered = []
        security_rules = {}
        
        if self.codebase_context:
            security_rules = self.codebase_context.get_security_rules()
        
        for finding in findings:
            # Skip if low confidence
            if finding.confidence == "LOW":
                continue
            
            # Check against known false positive patterns
            if self._is_false_positive(finding):
                continue
            
            # Context-aware filtering based on codebase type
            if self._is_context_false_positive(finding, security_rules):
                continue
            
            # Filter test files (lower priority)
            if self._is_test_file(finding.file):
                if finding.severity in ["LOW", "INFO"]:
                    continue
                # Don't flag hardcoded test keys in test files
                if not security_rules.get("flag_hardcoded_keys_in_tests", True):
                    if "hardcoded" in finding.description.lower() or "test" in finding.code_snippet.lower():
                        continue
            
            filtered.append(finding)
        
        return filtered
    
    def _is_context_false_positive(self, finding: Finding, security_rules: Dict) -> bool:
        """Check if finding is a false positive based on codebase context"""
        
        category_lower = finding.category.lower()
        desc_lower = finding.description.lower()
        snippet_lower = finding.code_snippet.lower()
        
        # SDK-specific filtering
        if not security_rules.get("check_client_side_auth", True):
            # Don't flag missing auth in SDK clients
            auth_fp_categories = [
                "access control",
                "authorization",
                "broken access",
                "idor",
                "missing auth",
            ]
            if any(cat in category_lower for cat in auth_fp_categories):
                # Check if it's about missing server-side checks (false positive for SDK)
                if "missing" in desc_lower or "does not" in desc_lower:
                    return True
            
            # SDK endpoints don't need client-side auth - server handles it
            if "sensitive data exposure" in category_lower:
                if "api endpoint" in desc_lower or "endpoint" in snippet_lower:
                    if "without" in desc_lower and ("auth" in desc_lower or "check" in desc_lower):
                        return True
        
        # Don't flag standard deserialization in SDKs
        if not security_rules.get("deserialization_strict", True):
            if "deserialization" in category_lower:
                # Only keep if it's actually dangerous (pickle, yaml.load)
                dangerous_patterns = ["pickle", "yaml.load(", "yaml.unsafe", "eval(", "exec("]
                if not any(p in snippet_lower for p in dangerous_patterns):
                    return True
        
        # Check if the finding is about auth checks being present (incorrectly flagged)
        auth_check_patterns = [
            "if not.*authenticated",
            "raise.*authenticationerror",
            "raise.*authorizationerror",
            "check.*auth",
            "verify.*token",
        ]
        for pattern in auth_check_patterns:
            if re.search(pattern, snippet_lower):
                # This IS a security control, not a vulnerability
                if "authentication" in category_lower or "authorization" in category_lower:
                    return True
        
        # SDK-specific: loading PEM keys is expected behavior, not a vulnerability
        if not security_rules.get("deserialization_strict", True):
            if "sensitive data" in category_lower or "exposure" in category_lower:
                if "pem" in snippet_lower or "private_key" in snippet_lower or "api_secret" in snippet_lower:
                    if "load" in snippet_lower or "serialize" in snippet_lower:
                        return True
        
        # "Missing logging" is not a security vulnerability for SDKs
        if "insufficient logging" in category_lower or "no logging" in desc_lower:
            return True
        
        # "Security misconfiguration" for public endpoints in SDKs is expected
        if not security_rules.get("check_client_side_auth", True):
            if "misconfiguration" in category_lower:
                if "public" in desc_lower or "endpoint" in snippet_lower:
                    return True
        
        # Mock/test server findings are false positives
        if not security_rules.get("flag_mock_without_auth", True):
            if "mock" in finding.file.lower() or "test" in finding.file.lower():
                if "websocket" in category_lower or "handler" in snippet_lower:
                    return True
        
        # Documentation/docstrings mentioning API keys are not vulnerabilities
        if "sensitive data" in category_lower:
            if "optional (str)" in snippet_lower or "**" in snippet_lower and "param" in snippet_lower:
                return True
            # Docstrings describing parameters
            if "- **api_key" in snippet_lower or "- **api_secret" in snippet_lower:
                return True
        
        # Standard Python inheritance (**response, **kwargs) is not deserialization
        if "deserialization" in category_lower or "sensitive data" in category_lower:
            # super().__init__(**response) is standard Python pattern
            if "super().__init__(**" in snippet_lower:
                return True
            if "**kwargs" in snippet_lower and "setattr" not in snippet_lower:
                return True
        
        # uuid.uuid4() is cryptographically secure, not a weakness
        if "session" in category_lower or "authentication" in category_lower:
            if "uuid" in snippet_lower or "uuid4" in desc_lower:
                if "predictable" not in snippet_lower:
                    return True
        
        # Test files testing auth errors are correct behavior
        if self._is_test_file(finding.file):
            if "authentication" in category_lower or "authorization" in category_lower:
                # Tests that verify auth errors are raised are correct
                if "subscribe" in snippet_lower or "unauthenticated" in desc_lower:
                    return True
        
        # GitHub Actions using secrets properly is not a vulnerability
        if ".github" in finding.file.lower() or ".yml" in finding.file.lower():
            if "secrets." in snippet_lower:
                # Using ${{ secrets.X }} is the CORRECT way to handle secrets
                return True
        
        # API design warnings about rate limiting aren't vulnerabilities in client SDKs
        if not security_rules.get("check_client_side_auth", True):
            if "api" in category_lower and ("rate" in desc_lower or "limit" in desc_lower):
                return True
        
        return False
    
    def _is_false_positive(self, finding: Finding) -> bool:
        """Check if finding matches false positive patterns"""
        
        for pattern in self.fp_filters:
            if re.search(pattern, finding.code_snippet, re.IGNORECASE):
                return True
        
        # Framework-specific protections
        if "Django" in finding.file or "django" in finding.code_snippet:
            # Django ORM auto-escapes
            if finding.category == "SQL Injection" and ".objects." in finding.code_snippet:
                return True
        
        if "Flask" in finding.file or "flask" in finding.code_snippet:
            # Flask templates auto-escape
            if finding.category == "XSS" and "render_template" in finding.code_snippet:
                return True
        
        return False
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if file is a test file"""
        test_indicators = ['test_', '_test.', '/tests/', '/test/', 'spec.', '.spec.']
        return any(indicator in file_path.lower() for indicator in test_indicators)
    
    def _assign_cvss_scores(self, findings: List[Finding]) -> List[Finding]:
        """Assign CVSS v3.1 scores to findings"""
        
        severity_scores = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 0.0
        }
        
        for finding in findings:
            if not finding.cvss_score:
                finding.cvss_score = severity_scores.get(finding.severity, 5.0)
        
        return findings
    
    def _sort_by_severity(self, findings: List[Finding]) -> List[Finding]:
        """Sort findings by severity"""
        
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4
        }
        
        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.cvss_score or 0)
        )
    
    def _load_instructions(self) -> Dict[str, str]:
        """Load instruction files"""
        
        instructions_dir = Path(__file__).parent.parent / "instructions"
        instructions = {}
        
        try:
            with open(instructions_dir / "security-review.md", 'r') as f:
                instructions['security-review'] = f.read()
        except Exception as e:
            print(f"[SAST] Warning: Could not load instructions: {e}")
            instructions['security-review'] = "Perform security code review."
        
        return instructions
    
    def _load_false_positive_filters(self) -> List[str]:
        """Load false positive filter patterns"""
        
        filters_file = Path(__file__).parent.parent / "resources" / "false_positive_filters.txt"
        
        try:
            with open(filters_file, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            # Default filters
            return [
                r'# nosec',  # Bandit ignore comment
                r'# skipcq',  # CodeQL ignore
                r'# type: ignore',
                r'# noqa',
            ]
    
    def _detect_file_type(self, file_path: str) -> str:
        """Detect programming language/file type"""
        
        ext_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.jsx': 'React/JSX',
            '.ts': 'TypeScript',
            '.tsx': 'TypeScript/React',
            '.java': 'Java',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.yml': 'YAML',
            '.yaml': 'YAML',
            '.json': 'JSON',
            '.tf': 'Terraform',
            '.sql': 'SQL',
            '.sol': 'Solidity'
        }
        
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        
        if 'Dockerfile' in file_path:
            return 'Docker'
        
        return 'Unknown'
    
    def export_findings(self, findings: List[Finding], output_path: str, format: str = "json"):
        """Export findings to file"""
        
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump([f.to_dict() for f in findings], f, indent=2)
        
        elif format == "csv":
            import csv
            with open(output_path, 'w', newline='') as f:
                if findings:
                    writer = csv.DictWriter(f, fieldnames=findings[0].to_dict().keys())
                    writer.writeheader()
                    for finding in findings:
                        writer.writerow(finding.to_dict())
        
        print(f"[SAST] Exported {len(findings)} findings to {output_path}")

