"""
Unit tests for SAST analyzer
"""

import unittest
import tempfile
import os
import json
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from handlers.sast_analyzer import SASTAnalyzer, Finding, Severity


class TestSASTAnalyzer(unittest.TestCase):
    """Test cases for SAST analyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Use legacy Anthropic client for existing tests (use_openrouter=False)
        self.analyzer = SASTAnalyzer(api_key="test_key", use_openrouter=False)
        
        # Create temporary test directory
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directory
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_should_analyze_python_file(self):
        """Test that Python files are marked for analysis"""
        self.assertTrue(self.analyzer._should_analyze_file("test.py"))
        self.assertTrue(self.analyzer._should_analyze_file("/path/to/script.py"))
    
    def test_should_analyze_javascript_file(self):
        """Test that JavaScript files are marked for analysis"""
        self.assertTrue(self.analyzer._should_analyze_file("app.js"))
        self.assertTrue(self.analyzer._should_analyze_file("component.jsx"))
        self.assertTrue(self.analyzer._should_analyze_file("module.ts"))
    
    def test_should_skip_non_code_files(self):
        """Test that non-code files are skipped"""
        self.assertFalse(self.analyzer._should_analyze_file("README.md"))
        self.assertFalse(self.analyzer._should_analyze_file("image.png"))
        self.assertFalse(self.analyzer._should_analyze_file("data.csv"))
    
    def test_detect_python_file_type(self):
        """Test file type detection for Python"""
        file_type = self.analyzer._detect_file_type("script.py")
        self.assertEqual(file_type, "Python")
    
    def test_detect_javascript_file_type(self):
        """Test file type detection for JavaScript"""
        file_type = self.analyzer._detect_file_type("app.js")
        self.assertEqual(file_type, "JavaScript")
    
    def test_is_test_file_detection(self):
        """Test identification of test files"""
        self.assertTrue(self.analyzer._is_test_file("test_module.py"))
        self.assertTrue(self.analyzer._is_test_file("module_test.py"))
        self.assertTrue(self.analyzer._is_test_file("/tests/integration.py"))
        self.assertTrue(self.analyzer._is_test_file("component.spec.ts"))
        
        self.assertFalse(self.analyzer._is_test_file("module.py"))
        self.assertFalse(self.analyzer._is_test_file("application.js"))
    
    def test_finding_fingerprint_generation(self):
        """Test that finding fingerprints are generated correctly"""
        finding1 = Finding(
            id="TEST-001",
            severity="HIGH",
            category="SQL Injection",
            cwe="CWE-89",
            owasp="A03:2021",
            file="api/users.py",
            line=42,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            description="SQL injection vulnerability",
            impact="Data breach",
            remediation="Use parameterized queries",
            references=[],
            cvss_score=8.5,
            confidence="HIGH"
        )
        
        finding2 = Finding(
            id="TEST-002",
            severity="HIGH",
            category="SQL Injection",
            cwe="CWE-89",
            owasp="A03:2021",
            file="api/users.py",
            line=42,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            description="SQL injection vulnerability",
            impact="Data breach",
            remediation="Use parameterized queries",
            references=[],
            cvss_score=8.5,
            confidence="HIGH"
        )
        
        # Same findings should have same fingerprint
        self.assertEqual(finding1.fingerprint(), finding2.fingerprint())
    
    def test_severity_sorting(self):
        """Test that findings are sorted correctly by severity"""
        findings = [
            Finding(
                id="1", severity="LOW", category="Test", cwe=None, owasp=None,
                file="test.py", line=1, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=3.0, confidence="HIGH"
            ),
            Finding(
                id="2", severity="CRITICAL", category="Test", cwe=None, owasp=None,
                file="test.py", line=2, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=9.5, confidence="HIGH"
            ),
            Finding(
                id="3", severity="MEDIUM", category="Test", cwe=None, owasp=None,
                file="test.py", line=3, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=5.0, confidence="HIGH"
            ),
        ]
        
        sorted_findings = self.analyzer._sort_by_severity(findings)
        
        self.assertEqual(sorted_findings[0].severity, "CRITICAL")
        self.assertEqual(sorted_findings[1].severity, "MEDIUM")
        self.assertEqual(sorted_findings[2].severity, "LOW")
    
    def test_cvss_score_assignment(self):
        """Test CVSS score assignment based on severity"""
        findings = [
            Finding(
                id="1", severity="CRITICAL", category="Test", cwe=None, owasp=None,
                file="test.py", line=1, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=None, confidence="HIGH"
            ),
        ]
        
        scored = self.analyzer._assign_cvss_scores(findings)
        
        self.assertIsNotNone(scored[0].cvss_score)
        self.assertGreaterEqual(scored[0].cvss_score, 9.0)  # Critical = 9-10
    
    def test_false_positive_filtering(self):
        """Test false positive filtering"""
        findings = [
            # Should be filtered - test file with low severity
            Finding(
                id="1", severity="LOW", category="Test", cwe=None, owasp=None,
                file="test_module.py", line=1, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=2.0, confidence="LOW"
            ),
            # Should pass - production file with high severity
            Finding(
                id="2", severity="HIGH", category="SQL Injection", cwe="CWE-89", owasp=None,
                file="api/users.py", line=1, code_snippet="", description="",
                impact="", remediation="", references=[], cvss_score=8.0, confidence="HIGH"
            ),
        ]
        
        filtered = self.analyzer.apply_false_positive_filters(findings)
        
        # Should have filtered out the low-confidence test file finding
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "2")
    
    def test_collect_files_changed_scope(self):
        """Test file collection for changed files scope"""
        # Create test files
        test_file1 = os.path.join(self.test_dir, "test1.py")
        test_file2 = os.path.join(self.test_dir, "test2.js")
        
        with open(test_file1, 'w') as f:
            f.write("print('test')")
        with open(test_file2, 'w') as f:
            f.write("console.log('test');")
        
        changed_files = ["test1.py", "test2.js"]
        files = self.analyzer._collect_files(
            self.test_dir,
            "changed_files",
            changed_files
        )
        
        self.assertEqual(len(files), 2)
    
    def test_export_findings_json(self):
        """Test exporting findings to JSON"""
        findings = [
            Finding(
                id="TEST-001", severity="HIGH", category="SQL Injection",
                cwe="CWE-89", owasp="A03:2021", file="test.py", line=1,
                code_snippet="test", description="test", impact="test",
                remediation="test", references=[], cvss_score=8.0, confidence="HIGH"
            )
        ]
        
        output_path = os.path.join(self.test_dir, "findings.json")
        self.analyzer.export_findings(findings, output_path, format="json")
        
        self.assertTrue(os.path.exists(output_path))
        
        with open(output_path, 'r') as f:
            exported = json.load(f)
        
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]['id'], "TEST-001")


class TestFinding(unittest.TestCase):
    """Test cases for Finding class"""
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = Finding(
            id="TEST-001",
            severity="CRITICAL",
            category="SQL Injection",
            cwe="CWE-89",
            owasp="A03:2021",
            file="test.py",
            line=42,
            code_snippet="test code",
            description="Test description",
            impact="Test impact",
            remediation="Test remediation",
            references=["https://example.com"],
            cvss_score=9.5,
            confidence="HIGH"
        )
        
        finding_dict = finding.to_dict()
        
        self.assertEqual(finding_dict['id'], "TEST-001")
        self.assertEqual(finding_dict['severity'], "CRITICAL")
        self.assertEqual(finding_dict['cvss_score'], 9.5)
        self.assertIsInstance(finding_dict['references'], list)


if __name__ == '__main__':
    unittest.main()

