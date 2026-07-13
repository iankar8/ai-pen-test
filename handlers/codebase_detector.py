"""
Codebase Type Detector

Analyzes repository structure to determine codebase type, frameworks,
and gather context that reduces false positives in security scanning.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class CodebaseType(Enum):
    """Types of codebases with different security contexts"""
    CLIENT_SDK = "client_sdk"          # API client libraries
    WEB_APP = "web_app"                # Full web applications
    BACKEND_API = "backend_api"        # REST/GraphQL APIs
    CLI_TOOL = "cli_tool"              # Command-line tools
    LIBRARY = "library"                # General-purpose libraries
    UNKNOWN = "unknown"


class Framework(Enum):
    """Detected frameworks with security implications"""
    # Python
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    # JavaScript
    EXPRESS = "express"
    REACT = "react"
    VUE = "vue"
    NEXTJS = "nextjs"
    # Other
    SPRING = "spring"
    RAILS = "rails"
    NONE = "none"


@dataclass
class FileContext:
    """Context about a specific file"""
    path: str
    parent_classes: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    has_auth_check: bool = False
    has_input_validation: bool = False
    is_test_file: bool = False
    is_mock: bool = False
    exports_api: bool = False


@dataclass
class CodebaseContext:
    """Full context about the codebase"""
    codebase_type: CodebaseType
    frameworks: List[Framework]
    has_server_routes: bool
    has_auth_middleware: bool
    has_api_client_pattern: bool
    test_directories: List[str]
    file_contexts: Dict[str, FileContext]
    inheritance_map: Dict[str, List[str]]  # file -> parent files
    auth_files: List[str]  # Files containing auth logic
    
    def get_security_rules(self) -> Dict[str, any]:
        """Get security scanning rules based on codebase type"""
        rules = {
            "check_client_side_auth": True,
            "flag_missing_server_auth": True,
            "flag_hardcoded_keys_in_tests": False,
            "flag_mock_without_auth": False,
            "deserialization_strict": True,
        }
        
        if self.codebase_type == CodebaseType.CLIENT_SDK:
            rules["check_client_side_auth"] = False  # Server handles auth
            rules["flag_missing_server_auth"] = False
            rules["flag_hardcoded_keys_in_tests"] = False
            rules["deserialization_strict"] = False  # API responses are trusted
            
        elif self.codebase_type == CodebaseType.LIBRARY:
            rules["flag_missing_server_auth"] = False  # Library users handle auth
            
        return rules


class CodebaseDetector:
    """
    Detects codebase type and gathers context for smarter security scanning.
    
    Usage:
        detector = CodebaseDetector()
        context = detector.analyze("/path/to/repo")
        
        # Use context in SAST analysis
        if context.codebase_type == CodebaseType.CLIENT_SDK:
            # Skip client-side auth checks
    """
    
    # Patterns for detecting codebase types
    SDK_INDICATORS = [
        r'setup\.py',
        r'pyproject\.toml',
        r'api_?client',
        r'sdk',
        r'rest_?client',
        r'\.get\s*\(\s*endpoint',
        r'\.post\s*\(\s*endpoint',
        r'requests\.(get|post|put|delete)',
        r'httpx\.(get|post|put|delete)',
    ]
    
    WEBAPP_INDICATORS = [
        r'@app\.route',
        r'@router\.(get|post|put|delete)',
        r'render_template',
        r'templates/',
        r'static/',
        r'\.html',
        r'views\.py',
    ]
    
    API_INDICATORS = [
        r'@(api_view|APIView)',
        r'FastAPI\(\)',
        r'@app\.(get|post|put|delete)\(',
        r'endpoints/',
        r'routes/',
        r'serializers\.py',
    ]
    
    CLI_INDICATORS = [
        r'argparse',
        r'click\.',
        r'@click\.command',
        r'typer\.',
        r'if __name__ == [\'"]__main__[\'"]',
    ]
    
    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        Framework.DJANGO: [r'from django', r'import django', r'INSTALLED_APPS', r'manage\.py'],
        Framework.FLASK: [r'from flask', r'Flask\(__name__\)', r'@app\.route'],
        Framework.FASTAPI: [r'from fastapi', r'FastAPI\(\)', r'@app\.(get|post)'],
        Framework.EXPRESS: [r'require\([\'"]express[\'"]\)', r'express\(\)', r'app\.use\('],
        Framework.REACT: [r'from [\'"]react[\'"]', r'import React', r'ReactDOM', r'useState'],
        Framework.VUE: [r'from [\'"]vue[\'"]', r'Vue\.component', r'createApp'],
        Framework.NEXTJS: [r'next/router', r'getServerSideProps', r'getStaticProps'],
        Framework.SPRING: [r'@SpringBootApplication', r'@RestController', r'@Autowired'],
        Framework.RAILS: [r'class.*<.*ApplicationController', r'Rails\.application'],
    }
    
    # Auth-related patterns
    AUTH_PATTERNS = [
        r'is_authenticated',
        r'check_auth',
        r'verify_token',
        r'jwt\.',
        r'authenticate',
        r'authorization',
        r'@login_required',
        r'@requires_auth',
        r'Bearer ',
        r'api_key',
        r'api_secret',
    ]
    
    # Input validation patterns
    VALIDATION_PATTERNS = [
        r'validate\(',
        r'sanitize',
        r'escape\(',
        r'clean\(',
        r'Validator',
        r'Schema\(',
        r'pydantic',
        r'marshmallow',
    ]
    
    def __init__(self):
        self.file_cache: Dict[str, str] = {}
    
    def analyze(self, repo_path: str) -> CodebaseContext:
        """
        Analyze repository and return full context.
        
        Args:
            repo_path: Path to repository root
            
        Returns:
            CodebaseContext with type, frameworks, and file-level context
        """
        repo_path = Path(repo_path)
        
        # Gather all analyzable files
        files = self._collect_files(repo_path)
        
        # Detect frameworks
        frameworks = self._detect_frameworks(files)
        
        # Detect codebase type
        codebase_type = self._detect_codebase_type(files, frameworks)
        
        # Analyze each file for context
        file_contexts = {}
        for file_path in files:
            ctx = self._analyze_file(file_path, repo_path)
            rel_path = str(file_path.relative_to(repo_path))
            file_contexts[rel_path] = ctx
        
        # Build inheritance map
        inheritance_map = self._build_inheritance_map(file_contexts)
        
        # Find auth-containing files
        auth_files = self._find_auth_files(file_contexts)
        
        # Determine test directories
        test_dirs = self._find_test_directories(repo_path)
        
        return CodebaseContext(
            codebase_type=codebase_type,
            frameworks=frameworks,
            has_server_routes=self._has_server_routes(files),
            has_auth_middleware=len(auth_files) > 0,
            has_api_client_pattern=self._has_api_client_pattern(files),
            test_directories=test_dirs,
            file_contexts=file_contexts,
            inheritance_map=inheritance_map,
            auth_files=auth_files,
        )
    
    def _collect_files(self, repo_path: Path) -> List[Path]:
        """Collect all analyzable files"""
        files = []
        
        skip_dirs = {'.git', 'node_modules', 'venv', '__pycache__', 
                     'build', 'dist', '.next', 'vendor', '.tox', 'egg-info'}
        
        analyzable_exts = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', 
                          '.go', '.rb', '.php', '.yml', '.yaml', '.json'}
        
        for root, dirs, filenames in os.walk(repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith('.egg-info')]
            
            for filename in filenames:
                file_path = Path(root) / filename
                if file_path.suffix in analyzable_exts:
                    files.append(file_path)
        
        return files
    
    def _read_file(self, file_path: Path) -> str:
        """Read file with caching"""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.file_cache[path_str] = f.read()
            except Exception:
                self.file_cache[path_str] = ""
        return self.file_cache[path_str]
    
    def _detect_frameworks(self, files: List[Path]) -> List[Framework]:
        """Detect frameworks used in codebase"""
        frameworks = []
        all_content = ""
        
        # Sample files for framework detection
        sample_files = files[:100]  # Limit for performance
        for file_path in sample_files:
            all_content += self._read_file(file_path) + "\n"
        
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_content, re.IGNORECASE):
                    frameworks.append(framework)
                    break
        
        return frameworks if frameworks else [Framework.NONE]
    
    def _detect_codebase_type(self, files: List[Path], frameworks: List[Framework]) -> CodebaseType:
        """Determine codebase type from indicators"""
        all_content = ""
        file_paths_str = " ".join(str(f) for f in files)
        
        for file_path in files[:100]:
            all_content += self._read_file(file_path) + "\n"
        
        combined = all_content + file_paths_str
        
        # Score each type
        scores = {
            CodebaseType.CLIENT_SDK: 0,
            CodebaseType.WEB_APP: 0,
            CodebaseType.BACKEND_API: 0,
            CodebaseType.CLI_TOOL: 0,
            CodebaseType.LIBRARY: 0,
        }
        
        # Check SDK indicators
        for pattern in self.SDK_INDICATORS:
            if re.search(pattern, combined, re.IGNORECASE):
                scores[CodebaseType.CLIENT_SDK] += 1
        
        # Check webapp indicators
        for pattern in self.WEBAPP_INDICATORS:
            if re.search(pattern, combined, re.IGNORECASE):
                scores[CodebaseType.WEB_APP] += 1
        
        # Check API indicators
        for pattern in self.API_INDICATORS:
            if re.search(pattern, combined, re.IGNORECASE):
                scores[CodebaseType.BACKEND_API] += 1
        
        # Check CLI indicators
        for pattern in self.CLI_INDICATORS:
            if re.search(pattern, combined, re.IGNORECASE):
                scores[CodebaseType.CLI_TOOL] += 1
        
        # Framework boosts
        if Framework.DJANGO in frameworks or Framework.FLASK in frameworks:
            scores[CodebaseType.WEB_APP] += 2
        if Framework.FASTAPI in frameworks:
            scores[CodebaseType.BACKEND_API] += 2
        if Framework.REACT in frameworks or Framework.VUE in frameworks:
            scores[CodebaseType.WEB_APP] += 1
        
        # SDK detection boost: no routes + has API client pattern
        has_routes = bool(re.search(r'@(app\.|router\.)(route|get|post)', combined))
        has_api_client = bool(re.search(r'(requests|httpx|aiohttp)\.(get|post)', combined))
        
        if not has_routes and has_api_client:
            scores[CodebaseType.CLIENT_SDK] += 3
        
        # setup.py without routes = likely library/SDK
        if 'setup.py' in file_paths_str or 'pyproject.toml' in file_paths_str:
            if not has_routes:
                scores[CodebaseType.CLIENT_SDK] += 2
                scores[CodebaseType.LIBRARY] += 2
        
        # Get highest scoring type
        max_score = max(scores.values())
        if max_score == 0:
            return CodebaseType.UNKNOWN
        
        for ctype, score in scores.items():
            if score == max_score:
                return ctype
        
        return CodebaseType.UNKNOWN
    
    def _analyze_file(self, file_path: Path, repo_path: Path) -> FileContext:
        """Analyze a single file for context"""
        content = self._read_file(file_path)
        rel_path = str(file_path.relative_to(repo_path))
        
        # Detect parent classes
        parent_classes = re.findall(r'class\s+\w+\s*\(\s*([^)]+)\s*\)', content)
        parents = []
        for p in parent_classes:
            # Split multiple inheritance
            parents.extend([c.strip() for c in p.split(',')])
        
        # Detect imports
        imports = re.findall(r'(?:from\s+(\S+)\s+import|import\s+(\S+))', content)
        import_list = [i[0] or i[1] for i in imports]
        
        # Check for auth patterns
        has_auth = any(re.search(p, content, re.IGNORECASE) for p in self.AUTH_PATTERNS)
        
        # Check for validation patterns
        has_validation = any(re.search(p, content, re.IGNORECASE) for p in self.VALIDATION_PATTERNS)
        
        # Check if test file
        is_test = any(ind in rel_path.lower() for ind in ['test_', '_test.', '/tests/', '/test/', 'spec.'])
        
        # Check if mock
        is_mock = 'mock' in rel_path.lower() or 'Mock' in content
        
        # Check if exports API (for SDKs)
        exports_api = bool(re.search(r'def (get|post|put|delete|request)\s*\(', content))
        
        return FileContext(
            path=rel_path,
            parent_classes=parents,
            imports=import_list,
            has_auth_check=has_auth,
            has_input_validation=has_validation,
            is_test_file=is_test,
            is_mock=is_mock,
            exports_api=exports_api,
        )
    
    def _build_inheritance_map(self, file_contexts: Dict[str, FileContext]) -> Dict[str, List[str]]:
        """Map files to their parent class files"""
        # Build class-to-file mapping
        class_to_file = {}
        for path, ctx in file_contexts.items():
            # Extract class definitions
            for parent in ctx.parent_classes:
                # Try to find which file defines this class
                base_name = parent.split('.')[-1]
                for other_path, other_ctx in file_contexts.items():
                    if base_name.lower() in other_path.lower():
                        if path not in class_to_file:
                            class_to_file[path] = []
                        class_to_file[path].append(other_path)
        
        return class_to_file
    
    def _find_auth_files(self, file_contexts: Dict[str, FileContext]) -> List[str]:
        """Find files containing auth logic"""
        return [path for path, ctx in file_contexts.items() if ctx.has_auth_check]
    
    def _find_test_directories(self, repo_path: Path) -> List[str]:
        """Find test directories"""
        test_dirs = []
        for item in repo_path.iterdir():
            if item.is_dir() and item.name.lower() in ['tests', 'test', 'spec', '__tests__']:
                test_dirs.append(item.name)
        return test_dirs
    
    def _has_server_routes(self, files: List[Path]) -> bool:
        """Check if codebase has server routes"""
        route_patterns = [
            r'@app\.route',
            r'@router\.',
            r'app\.(get|post|put|delete)\(',
            r'@api_view',
        ]
        
        for file_path in files[:50]:
            content = self._read_file(file_path)
            for pattern in route_patterns:
                if re.search(pattern, content):
                    return True
        return False
    
    def _has_api_client_pattern(self, files: List[Path]) -> bool:
        """Check if codebase has API client patterns"""
        client_patterns = [
            r'requests\.(get|post|put|delete)',
            r'httpx\.',
            r'aiohttp\.',
            r'self\.(get|post|put|delete)\s*\(',
            r'\.json\(\)',
        ]
        
        for file_path in files[:50]:
            content = self._read_file(file_path)
            matches = sum(1 for p in client_patterns if re.search(p, content))
            if matches >= 2:
                return True
        return False
    
    def get_file_context(self, context: CodebaseContext, file_path: str) -> Optional[FileContext]:
        """Get context for a specific file"""
        # Normalize path
        normalized = file_path.lstrip('./')
        return context.file_contexts.get(normalized)
    
    def get_parent_has_auth(self, context: CodebaseContext, file_path: str) -> bool:
        """Check if any parent class file has auth checks"""
        normalized = file_path.lstrip('./')
        parent_files = context.inheritance_map.get(normalized, [])
        
        for parent_file in parent_files:
            parent_ctx = context.file_contexts.get(parent_file)
            if parent_ctx and parent_ctx.has_auth_check:
                return True
        return False

