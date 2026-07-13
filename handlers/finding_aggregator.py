"""
Finding Aggregator

Combines findings from multiple sources (SAST, dynamic testing),
deduplicates, correlates, and identifies attack chains.
"""

import hashlib
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class AttackChain:
    """Represents a multi-step attack scenario"""
    id: str
    steps: List[str]  # Finding IDs
    impact: str
    severity: str
    description: str
    
    def to_dict(self):
        return {
            "id": self.id,
            "steps": self.steps,
            "impact": self.impact,
            "severity": self.severity,
            "description": self.description
        }


class FindingAggregator:
    """
    Combines results from multiple security testing phases,
    deduplicates findings, and identifies attack chains.
    """
    
    def __init__(self):
        self.findings_by_fingerprint: Dict[str, any] = {}
        self.findings_by_category: Dict[str, List] = defaultdict(list)
        self.attack_chains: List[AttackChain] = []
    
    def aggregate(
        self,
        sast_findings: List = None,
        dynamic_findings: List = None,
        infrastructure_findings: List = None
    ) -> Dict:
        """
        Aggregate findings from all sources.
        
        Args:
            sast_findings: Static analysis findings
            dynamic_findings: Dynamic testing results
            infrastructure_findings: Infrastructure scan results
        
        Returns:
            Aggregated and deduplicated findings
        """
        
        all_findings = []
        
        if sast_findings:
            all_findings.extend(sast_findings)
        
        if dynamic_findings:
            all_findings.extend(dynamic_findings)
        
        if infrastructure_findings:
            all_findings.extend(infrastructure_findings)
        
        # Deduplicate
        unique_findings = self.deduplicate(all_findings)
        
        # Group by category
        self._group_by_category(unique_findings)
        
        # Identify attack chains
        self.attack_chains = self.identify_attack_chains(unique_findings)
        
        return {
            "findings": unique_findings,
            "attack_chains": self.attack_chains,
            "statistics": self._calculate_statistics(unique_findings)
        }
    
    def deduplicate(self, findings: List) -> List:
        """
        Remove duplicate findings based on fingerprint.
        When duplicates found, keep the highest severity.
        """
        
        unique = {}
        
        for finding in findings:
            fingerprint = self._generate_fingerprint(finding)
            
            if fingerprint in unique:
                # Keep highest severity
                existing = unique[fingerprint]
                if self._severity_rank(finding.severity) < self._severity_rank(existing.severity):
                    unique[fingerprint] = finding
            else:
                unique[fingerprint] = finding
        
        return list(unique.values())
    
    def _generate_fingerprint(self, finding) -> str:
        """Generate unique fingerprint for a finding"""
        
        # Use file, line, category, and code snippet
        key_parts = [
            finding.file,
            str(finding.line or ''),
            finding.category,
            finding.code_snippet[:100] if hasattr(finding, 'code_snippet') else ''
        ]
        
        key = ":".join(key_parts)
        return hashlib.md5(key.encode()).hexdigest()
    
    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank (lower = more severe)"""
        ranks = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4
        }
        return ranks.get(severity, 5)
    
    def _group_by_category(self, findings: List):
        """Group findings by vulnerability category"""
        
        self.findings_by_category.clear()
        
        for finding in findings:
            self.findings_by_category[finding.category].append(finding)
    
    def identify_attack_chains(self, findings: List) -> List[AttackChain]:
        """
        Identify multi-step attack scenarios where exploiting one
        vulnerability enables exploitation of another.
        """
        
        chains = []
        
        # Common attack chain patterns
        
        # Pattern 1: Auth Bypass → Data Access (IDOR/Data Exposure)
        auth_bypasses = [f for f in findings if 'auth' in f.category.lower() and f.severity in ['CRITICAL', 'HIGH']]
        data_access = [f for f in findings if any(cat in f.category.lower() for cat in ['idor', 'data_exposure', 'access_control'])]
        
        if auth_bypasses and data_access:
            for auth in auth_bypasses:
                for data in data_access:
                    chain = AttackChain(
                        id=f"CHAIN-{len(chains)+1:03d}",
                        steps=[auth.id, data.id],
                        impact="Complete unauthorized data access via authentication bypass followed by insecure direct object reference",
                        severity="CRITICAL",
                        description=f"Attacker bypasses authentication ({auth.description[:50]}...) then accesses sensitive data ({data.description[:50]}...)"
                    )
                    chains.append(chain)
        
        # Pattern 2: XSS → Session Hijacking
        xss_findings = [f for f in findings if 'xss' in f.category.lower()]
        session_issues = [f for f in findings if 'session' in f.description.lower() or 'cookie' in f.description.lower()]
        
        if xss_findings and session_issues:
            for xss in xss_findings:
                for session in session_issues:
                    chain = AttackChain(
                        id=f"CHAIN-{len(chains)+1:03d}",
                        steps=[xss.id, session.id],
                        impact="Session hijacking via XSS to steal session cookies",
                        severity="HIGH",
                        description=f"Attacker injects malicious script to steal session tokens with insecure cookie configuration"
                    )
                    chains.append(chain)
        
        # Pattern 3: SQL Injection → Privilege Escalation
        sqli_findings = [f for f in findings if 'sql' in f.category.lower() and 'injection' in f.category.lower()]
        
        for sqli in sqli_findings:
            if 'admin' in sqli.file.lower() or 'auth' in sqli.file.lower():
                chain = AttackChain(
                    id=f"CHAIN-{len(chains)+1:03d}",
                    steps=[sqli.id],
                    impact="SQL injection in authentication logic enables privilege escalation to admin",
                    severity="CRITICAL",
                    description=f"SQL injection allows attacker to modify authentication queries and gain admin privileges"
                )
                chains.append(chain)
        
        # Pattern 4: SSRF → Cloud Metadata Access
        ssrf_findings = [f for f in findings if 'ssrf' in f.category.lower()]
        cloud_findings = [f for f in findings if any(cloud in f.file.lower() for cloud in ['aws', 'azure', 'gcp', 'cloud'])]
        
        if ssrf_findings:
            for ssrf in ssrf_findings:
                chain = AttackChain(
                    id=f"CHAIN-{len(chains)+1:03d}",
                    steps=[ssrf.id],
                    impact="SSRF enables access to cloud metadata service (169.254.169.254) to steal credentials",
                    severity="CRITICAL",
                    description="Server-Side Request Forgery can be exploited to access AWS/GCP metadata and obtain IAM credentials"
                )
                chains.append(chain)
        
        return chains
    
    def _calculate_statistics(self, findings: List) -> Dict:
        """Calculate statistics about findings"""
        
        stats = {
            "total_findings": len(findings),
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "by_confidence": defaultdict(int),
            "avg_cvss_score": 0.0
        }
        
        cvss_scores = []
        
        for finding in findings:
            stats["by_severity"][finding.severity] += 1
            stats["by_category"][finding.category] += 1
            
            if hasattr(finding, 'confidence'):
                stats["by_confidence"][finding.confidence] += 1
            
            if hasattr(finding, 'cvss_score') and finding.cvss_score:
                cvss_scores.append(finding.cvss_score)
        
        if cvss_scores:
            stats["avg_cvss_score"] = sum(cvss_scores) / len(cvss_scores)
        
        # Convert defaultdicts to regular dicts
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_category"] = dict(stats["by_category"])
        stats["by_confidence"] = dict(stats["by_confidence"])
        
        return stats
    
    def prioritize_findings(self, findings: List, context: Optional[Dict] = None) -> List:
        """
        Prioritize findings for remediation.
        
        Args:
            findings: List of findings
            context: Optional context (e.g., production vs staging)
        
        Returns:
            Sorted list with highest priority first
        """
        
        def priority_score(finding):
            """Calculate priority score (lower = higher priority)"""
            
            severity_scores = {
                "CRITICAL": 0,
                "HIGH": 100,
                "MEDIUM": 200,
                "LOW": 300,
                "INFO": 400
            }
            
            score = severity_scores.get(finding.severity, 500)
            
            # Boost priority for certain categories
            high_priority_categories = [
                'injection', 'authentication', 'code_execution',
                'data_exposure', 'access_control'
            ]
            
            if any(cat in finding.category.lower() for cat in high_priority_categories):
                score -= 50
            
            # Boost if high confidence
            if hasattr(finding, 'confidence') and finding.confidence == 'HIGH':
                score -= 25
            
            # Adjust based on CVSS
            if hasattr(finding, 'cvss_score') and finding.cvss_score:
                score -= finding.cvss_score
            
            # Context-based adjustments
            if context:
                # Higher priority if production
                if context.get('environment') == 'production':
                    score -= 100
                
                # Higher priority if PII involved
                if context.get('contains_pii'):
                    score -= 75
            
            return score
        
        return sorted(findings, key=priority_score)
    
    def filter_by_severity(self, findings: List, min_severity: str = "MEDIUM") -> List:
        """Filter findings by minimum severity level"""
        
        severity_hierarchy = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_index = severity_hierarchy.index(min_severity)
        
        return [
            f for f in findings
            if f.severity in severity_hierarchy[min_index:]
        ]
    
    def group_by_file(self, findings: List) -> Dict[str, List]:
        """Group findings by file path"""
        
        by_file = defaultdict(list)
        
        for finding in findings:
            by_file[finding.file].append(finding)
        
        return dict(by_file)
    
    def export_summary(self, findings: List) -> str:
        """Generate text summary of findings"""
        
        stats = self._calculate_statistics(findings)
        
        summary = f"""
PENETRATION TEST FINDINGS SUMMARY
================================

Total Findings: {stats['total_findings']}

BY SEVERITY:
  Critical: {stats['by_severity'].get('CRITICAL', 0)}
  High:     {stats['by_severity'].get('HIGH', 0)}
  Medium:   {stats['by_severity'].get('MEDIUM', 0)}
  Low:      {stats['by_severity'].get('LOW', 0)}
  Info:     {stats['by_severity'].get('INFO', 0)}

AVERAGE CVSS SCORE: {stats['avg_cvss_score']:.1f}

TOP CATEGORIES:
"""
        
        # Sort categories by count
        sorted_categories = sorted(
            stats['by_category'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        for category, count in sorted_categories[:5]:
            summary += f"  {category}: {count}\n"
        
        if self.attack_chains:
            summary += f"\nIDENTIFIED ATTACK CHAINS: {len(self.attack_chains)}\n"
            for chain in self.attack_chains[:3]:
                summary += f"  - {chain.description}\n"
        
        return summary

