"""
Simple baseline tests using fixture files directly.
Tests basic functionality without requiring API calls.
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestFixtureStructure(unittest.TestCase):
    """Test that fixtures are properly structured"""
    
    @classmethod
    def setUpClass(cls):
        """Set up fixture paths"""
        cls.fixtures_dir = Path(__file__).parent / "fixtures"
        cls.vulnerable_dir = cls.fixtures_dir / "vulnerable"
        cls.secure_dir = cls.fixtures_dir / "secure"
    
    def test_vulnerable_fixtures_exist(self):
        """Verify vulnerable fixtures directory exists"""
        self.assertTrue(self.vulnerable_dir.exists())
        self.assertTrue(self.vulnerable_dir.is_dir())
    
    def test_secure_fixtures_exist(self):
        """Verify secure fixtures directory exists"""
        self.assertTrue(self.secure_dir.exists())
        self.assertTrue(self.secure_dir.is_dir())
    
    def test_vulnerable_fixture_count(self):
        """Verify we have 20+ vulnerable fixtures"""
        vuln_files = list(self.vulnerable_dir.glob("*.py"))
        self.assertGreaterEqual(len(vuln_files), 20,
                               f"Expected 20+ vulnerable fixtures, found {len(vuln_files)}")
    
    def test_secure_fixture_count(self):
        """Verify we have 5+ secure fixtures"""
        secure_files = list(self.secure_dir.glob("*.py"))
        self.assertGreaterEqual(len(secure_files), 5,
                               f"Expected 5+ secure fixtures, found {len(secure_files)}")
    
    def test_sqli_fixtures_exist(self):
        """Verify SQL injection fixtures exist"""
        sqli_files = list(self.vulnerable_dir.glob("sqli_*.py"))
        self.assertGreaterEqual(len(sqli_files), 5,
                               f"Expected 5+ SQL injection fixtures, found {len(sqli_files)}")
    
    def test_xss_fixtures_exist(self):
        """Verify XSS fixtures exist"""
        xss_files = list(self.vulnerable_dir.glob("xss_*.py"))
        self.assertGreaterEqual(len(xss_files), 5,
                               f"Expected 5+ XSS fixtures, found {len(xss_files)}")
    
    def test_auth_fixtures_exist(self):
        """Verify authentication fixtures exist"""
        auth_files = list(self.vulnerable_dir.glob("auth_*.py"))
        self.assertGreaterEqual(len(auth_files), 3,
                               f"Expected 3+ auth fixtures, found {len(auth_files)}")
    
    def test_crypto_fixtures_exist(self):
        """Verify cryptographic failure fixtures exist"""
        crypto_files = list(self.vulnerable_dir.glob("crypto_*.py"))
        self.assertGreaterEqual(len(crypto_files), 3,
                               f"Expected 3+ crypto fixtures, found {len(crypto_files)}")
    
    def test_idor_fixtures_exist(self):
        """Verify IDOR fixtures exist"""
        idor_files = list(self.vulnerable_dir.glob("idor_*.py"))
        self.assertGreaterEqual(len(idor_files), 4,
                               f"Expected 4+ IDOR fixtures, found {len(idor_files)}")
    
    def test_fixtures_have_metadata(self):
        """Verify fixtures have proper metadata headers"""
        vuln_files = list(self.vulnerable_dir.glob("*.py"))
        
        for fixture_file in vuln_files[:5]:  # Check first 5
            content = fixture_file.read_text()
            self.assertIn("# VULNERABILITY:", content,
                         f"{fixture_file.name} missing VULNERABILITY metadata")
            self.assertIn("# SEVERITY:", content,
                         f"{fixture_file.name} missing SEVERITY metadata")
            self.assertIn("# CWE:", content,
                         f"{fixture_file.name} missing CWE metadata")
            self.assertIn("# OWASP:", content,
                         f"{fixture_file.name} missing OWASP metadata")
    
    def test_secure_fixtures_have_metadata(self):
        """Verify secure fixtures have proper metadata"""
        secure_files = list(self.secure_dir.glob("*.py"))
        
        for fixture_file in secure_files:
            content = fixture_file.read_text()
            self.assertIn("# SECURE CODE:", content,
                         f"{fixture_file.name} missing SECURE CODE metadata")
            self.assertIn("# PATTERN:", content,
                         f"{fixture_file.name} missing PATTERN metadata")
    
    def test_owasp_coverage(self):
        """Verify fixtures cover major OWASP categories"""
        vuln_files = [f.name for f in self.vulnerable_dir.glob("*.py")]
        
        owasp_coverage = {
            'sqli': any('sqli' in f for f in vuln_files),
            'xss': any('xss' in f for f in vuln_files),
            'auth': any('auth' in f for f in vuln_files),
            'crypto': any('crypto' in f for f in vuln_files),
            'idor': any('idor' in f for f in vuln_files),
            'command_injection': any('command' in f for f in vuln_files),
            'xxe': any('xxe' in f for f in vuln_files),
            'ssrf': any('ssrf' in f for f in vuln_files),
        }
        
        missing = [cat for cat, present in owasp_coverage.items() if not present]
        self.assertEqual(len(missing), 0,
                        f"Missing OWASP categories: {missing}")
    
    def test_readme_exists(self):
        """Verify fixtures README exists"""
        readme = self.fixtures_dir / "README.md"
        self.assertTrue(readme.exists())
        
        content = readme.read_text()
        self.assertGreater(len(content), 500,
                          "README should have substantial documentation")
        self.assertIn("OWASP", content,
                     "README should mention OWASP")
        self.assertIn("CWE", content,
                     "README should mention CWE")


if __name__ == '__main__':
    unittest.main()
