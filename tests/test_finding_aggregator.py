"""
Unit tests for Finding Aggregator
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from handlers.finding_aggregator import FindingAggregator, AttackChain
from handlers.sast_analyzer import Finding


class TestFindingAggregator(unittest.TestCase):
    """Test cases for finding aggregation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.aggregator = FindingAggregator()
    
    def test_deduplicate_identical_findings(self):
        """Test deduplication of identical findings"""
        finding1 = Finding(
            id="1", severity="HIGH", category="SQL Injection", cwe="CWE-89",
            owasp="A03", file="api.py", line=42, code_snippet="query = f'...'",
            description="Test", impact="Test", remediation="Test",
            references=[], cvss_score=8.0, confidence="HIGH"
        )
        
        finding2 = Finding(
            id="2", severity="HIGH", category="SQL Injection", cwe="CWE-89",
            owasp="A03", file="api.py", line=42, code_snippet="query = f'...'",
            description="Test", impact="Test", remediation="Test",
            references=[], cvss_score=8.0, confidence="HIGH"
        )
        
        findings = [finding1, finding2]
        unique = self.aggregator.deduplicate(findings)
        
        self.assertEqual(len(unique), 1)
    
    def test_deduplicate_keeps_highest_severity(self):
        """Test that deduplication keeps highest severity finding"""
        finding1 = Finding(
            id="1", severity="MEDIUM", category="SQL Injection", cwe="CWE-89",
            owasp="A03", file="api.py", line=42, code_snippet="query = f'...'",
            description="Test", impact="Test", remediation="Test",
            references=[], cvss_score=5.0, confidence="HIGH"
        )
        
        finding2 = Finding(
            id="2", severity="CRITICAL", category="SQL Injection", cwe="CWE-89",
            owasp="A03", file="api.py", line=42, code_snippet="query = f'...'",
            description="Test", impact="Test", remediation="Test",
            references=[], cvss_score=9.0, confidence="HIGH"
        )
        
        findings = [finding1, finding2]
        unique = self.aggregator.deduplicate(findings)
        
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0].severity, "CRITICAL")
    
    def test_identify_auth_bypass_attack_chain(self):
        """Test identification of auth bypass → data access chain"""
        auth_finding = Finding(
            id="AUTH-001", severity="CRITICAL", category="authentication_bypass",
            cwe="CWE-287", owasp="A07", file="auth.py", line=10,
            code_snippet="if username:", description="Auth bypass",
            impact="Unauthorized access", remediation="Fix auth",
            references=[], cvss_score=9.0, confidence="HIGH"
        )
        
        idor_finding = Finding(
            id="IDOR-001", severity="HIGH", category="idor_data_exposure",
            cwe="CWE-639", owasp="A01", file="api.py", line=50,
            code_snippet="User.get(id)", description="IDOR",
            impact="Data access", remediation="Check ownership",
            references=[], cvss_score=7.5, confidence="HIGH"
        )
        
        findings = [auth_finding, idor_finding]
        chains = self.aggregator.identify_attack_chains(findings)
        
        self.assertGreater(len(chains), 0)
        self.assertEqual(chains[0].severity, "CRITICAL")
    
    def test_calculate_statistics(self):
        """Test statistics calculation"""
        findings = [
            Finding(
                id="1", severity="CRITICAL", category="SQL Injection", cwe="CWE-89",
                owasp="A03", file="api.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=9.0, confidence="HIGH"
            ),
            Finding(
                id="2", severity="HIGH", category="XSS", cwe="CWE-79",
                owasp="A03", file="ui.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=7.5, confidence="HIGH"
            ),
            Finding(
                id="3", severity="HIGH", category="XSS", cwe="CWE-79",
                owasp="A03", file="ui.py", line=2, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=7.0, confidence="MEDIUM"
            ),
        ]
        
        stats = self.aggregator._calculate_statistics(findings)
        
        self.assertEqual(stats['total_findings'], 3)
        self.assertEqual(stats['by_severity']['CRITICAL'], 1)
        self.assertEqual(stats['by_severity']['HIGH'], 2)
        self.assertEqual(stats['by_category']['XSS'], 2)
        self.assertEqual(stats['by_category']['SQL Injection'], 1)
        self.assertGreater(stats['avg_cvss_score'], 7.0)
    
    def test_prioritize_findings(self):
        """Test finding prioritization"""
        findings = [
            Finding(
                id="1", severity="MEDIUM", category="XSS", cwe="CWE-79",
                owasp="A03", file="ui.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=5.0, confidence="HIGH"
            ),
            Finding(
                id="2", severity="CRITICAL", category="SQL Injection", cwe="CWE-89",
                owasp="A03", file="api.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=9.0, confidence="HIGH"
            ),
        ]
        
        prioritized = self.aggregator.prioritize_findings(findings)
        
        # Critical should come first
        self.assertEqual(prioritized[0].severity, "CRITICAL")
        self.assertEqual(prioritized[1].severity, "MEDIUM")
    
    def test_filter_by_severity(self):
        """Test filtering findings by minimum severity"""
        findings = [
            Finding(
                id="1", severity="INFO", category="Test", cwe=None,
                owasp=None, file="test.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=0.0, confidence="HIGH"
            ),
            Finding(
                id="2", severity="MEDIUM", category="Test", cwe=None,
                owasp=None, file="test.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=5.0, confidence="HIGH"
            ),
            Finding(
                id="3", severity="HIGH", category="Test", cwe=None,
                owasp=None, file="test.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=7.5, confidence="HIGH"
            ),
        ]
        
        filtered = self.aggregator.filter_by_severity(findings, "MEDIUM")
        
        self.assertEqual(len(filtered), 2)
        self.assertNotIn("INFO", [f.severity for f in filtered])
    
    def test_group_by_file(self):
        """Test grouping findings by file"""
        findings = [
            Finding(
                id="1", severity="HIGH", category="Test", cwe=None,
                owasp=None, file="api.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=7.0, confidence="HIGH"
            ),
            Finding(
                id="2", severity="HIGH", category="Test", cwe=None,
                owasp=None, file="api.py", line=2, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=7.0, confidence="HIGH"
            ),
            Finding(
                id="3", severity="MEDIUM", category="Test", cwe=None,
                owasp=None, file="ui.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=5.0, confidence="HIGH"
            ),
        ]
        
        by_file = self.aggregator.group_by_file(findings)
        
        self.assertEqual(len(by_file), 2)
        self.assertEqual(len(by_file['api.py']), 2)
        self.assertEqual(len(by_file['ui.py']), 1)
    
    def test_export_summary(self):
        """Test summary export"""
        findings = [
            Finding(
                id="1", severity="CRITICAL", category="SQL Injection", cwe="CWE-89",
                owasp="A03", file="api.py", line=1, code_snippet="test",
                description="Test", impact="Test", remediation="Test",
                references=[], cvss_score=9.0, confidence="HIGH"
            ),
        ]
        
        summary = self.aggregator.export_summary(findings)
        
        self.assertIn("PENETRATION TEST FINDINGS SUMMARY", summary)
        self.assertIn("Total Findings: 1", summary)
        self.assertIn("Critical: 1", summary)


if __name__ == '__main__':
    unittest.main()

