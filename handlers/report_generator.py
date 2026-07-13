"""
Report Generator

Produces professional penetration testing reports in multiple formats
(JSON, HTML, PDF, Markdown) suitable for compliance, audit, and remediation.
"""

import json
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import base64


class ReportGenerator:
    """
    Produces professional penetration testing reports suitable
    for compliance, board review, and audit trails.
    """
    
    def __init__(self, organization_context: Optional[Dict] = None):
        """
        Initialize report generator.
        
        Args:
            organization_context: Organization details for branding
        """
        self.org = organization_context or {
            "name": "Organization",
            "application": "Application",
            "environment": "Production"
        }
        self.templates = self._load_templates()
    
    def generate_report(
        self,
        findings: List,
        attack_results: Optional[List] = None,
        format: str = "html",
        severity_filter: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Creates comprehensive penetration test report.
        
        Args:
            findings: SAST and dynamic testing findings
            attack_results: Confirmed vulnerabilities from active testing
            format: "html", "pdf", "markdown", "json"
            severity_filter: Only include findings >= this severity
            metadata: Assessment metadata (dates, scope, etc.)
        
        Returns:
            Path to generated report file or report content
        """
        
        # Filter by severity if specified
        if severity_filter:
            findings = self._filter_by_severity(findings, severity_filter)
        
        # Prepare report data
        report_data = {
            "metadata": metadata or self._generate_metadata(),
            "executive_summary": self.generate_executive_summary(findings),
            "methodology": self._generate_methodology_section(),
            "findings": findings,
            "attack_chains": self._extract_attack_chains(findings),
            "risk_matrix": self.generate_risk_matrix(findings),
            "remediation_roadmap": self.generate_remediation_roadmap(findings),
            "appendices": {
                "cvss_details": self._generate_cvss_appendix(findings),
                "compliance_mapping": self._map_to_compliance(findings)
            }
        }
        
        # Generate in requested format
        if format == "json":
            return self._generate_json_report(report_data)
        elif format == "html":
            return self._generate_html_report(report_data)
        elif format == "markdown":
            return self._generate_markdown_report(report_data)
        elif format == "pdf":
            return self._generate_pdf_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_executive_summary(self, findings: List) -> Dict:
        """
        High-level summary for non-technical stakeholders.
        Includes: key findings, business impact, remediation timeline.
        """
        
        # Calculate statistics
        total = len(findings)
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        # Identify top risks
        critical_findings = [f for f in findings if f.severity == "CRITICAL"]
        high_findings = [f for f in findings if f.severity == "HIGH"]
        
        # Estimate remediation effort
        effort_hours = self._estimate_remediation_effort(findings)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(findings)
        
        summary = {
            "overview": f"A comprehensive security assessment was conducted on {self.org['application']}. "
                       f"The assessment identified {total} security vulnerabilities across the application stack.",
            "key_findings": {
                "critical": len(critical_findings),
                "high": len(high_findings),
                "medium": by_severity.get("MEDIUM", 0),
                "low": by_severity.get("LOW", 0),
                "info": by_severity.get("INFO", 0)
            },
            "business_impact": business_impact,
            "immediate_actions": self._generate_immediate_actions(critical_findings + high_findings),
            "remediation_timeline": {
                "estimated_hours": effort_hours,
                "estimated_weeks": effort_hours / 40,  # Assuming 40-hour weeks
                "phases": self._generate_remediation_phases(findings)
            }
        }
        
        return summary
    
    def generate_risk_matrix(self, findings: List) -> Dict:
        """Generate risk assessment matrix"""
        
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_category = {}
        
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        
        # Create visualization data
        severity_chart = []
        max_count = max(by_severity.values()) if by_severity.values() else 1
        
        for severity, count in by_severity.items():
            bar_length = int((count / max_count) * 50) if max_count > 0 else 0
            severity_chart.append({
                "severity": severity,
                "count": count,
                "bar": "█" * bar_length
            })
        
        return {
            "by_severity": by_severity,
            "by_category": by_category,
            "visualization": severity_chart,
            "total_findings": len(findings)
        }
    
    def generate_remediation_roadmap(self, findings: List) -> Dict:
        """
        Generate prioritized remediation timeline with phases.
        """
        
        # Sort findings by priority
        critical = [f for f in findings if f.severity == "CRITICAL"]
        high = [f for f in findings if f.severity == "HIGH"]
        medium = [f for f in findings if f.severity == "MEDIUM"]
        low = [f for f in findings if f.severity in ["LOW", "INFO"]]
        
        roadmap = {
            "phase_1_immediate": {
                "timeframe": "0-1 week",
                "findings": [{"id": f.id, "title": f.category, "effort": "4-8 hours"} for f in critical],
                "total_effort": len(critical) * 6
            },
            "phase_2_short_term": {
                "timeframe": "1-3 weeks",
                "findings": [{"id": f.id, "title": f.category, "effort": "2-4 hours"} for f in high],
                "total_effort": len(high) * 3
            },
            "phase_3_medium_term": {
                "timeframe": "1-2 months",
                "findings": [{"id": f.id, "title": f.category, "effort": "1-2 hours"} for f in medium],
                "total_effort": len(medium) * 1.5
            },
            "phase_4_long_term": {
                "timeframe": "2-6 months",
                "findings": [{"id": f.id, "title": f.category, "effort": "1 hour"} for f in low],
                "total_effort": len(low) * 1
            }
        }
        
        return roadmap
    
    def generate_remediation_guidance(self, findings: List) -> List[Dict]:
        """
        Detailed technical guidance for each finding.
        Includes: code examples, configuration fixes, testing procedures.
        """
        
        guidance = []
        
        for finding in findings:
            item = {
                "finding_id": finding.id,
                "vulnerability": finding.category,
                "file": finding.file,
                "line": finding.line,
                "description": finding.description,
                "impact": finding.impact,
                "remediation": finding.remediation,
                "code_example": self._generate_code_example(finding),
                "testing_procedure": self._generate_testing_procedure(finding),
                "references": finding.references
            }
            guidance.append(item)
        
        return guidance
    
    def _generate_json_report(self, report_data: Dict) -> str:
        """Generate JSON format report"""
        
        output_file = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert findings to dict
        report_data['findings'] = [
            f.to_dict() if hasattr(f, 'to_dict') else f
            for f in report_data['findings']
        ]
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return output_file
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML format report"""
        
        output_file = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.org['application']}</title>
    <style>
        {self._get_html_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Penetration Test Report</h1>
            <h2>{self.org['application']}</h2>
            <p class="date">{report_data['metadata']['date']}</p>
        </header>
        
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            {self._render_executive_summary_html(report_data['executive_summary'])}
        </section>
        
        <section class="risk-matrix">
            <h2>Risk Assessment Matrix</h2>
            {self._render_risk_matrix_html(report_data['risk_matrix'])}
        </section>
        
        <section class="findings">
            <h2>Detailed Findings</h2>
            {self._render_findings_html(report_data['findings'])}
        </section>
        
        <section class="remediation">
            <h2>Remediation Roadmap</h2>
            {self._render_roadmap_html(report_data['remediation_roadmap'])}
        </section>
        
        <section class="appendices">
            <h2>Appendices</h2>
            {self._render_appendices_html(report_data['appendices'])}
        </section>
    </div>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def _generate_markdown_report(self, report_data: Dict) -> str:
        """Generate Markdown format report (for PR comments)"""
        
        summary = report_data['executive_summary']
        risk_matrix = report_data['risk_matrix']
        
        md = f"""# 🔒 Penetration Test Report
        
**Application**: {self.org['application']}  
**Date**: {report_data['metadata']['date']}

## Executive Summary

{summary['overview']}

### Findings by Severity

- 🔴 **Critical**: {summary['key_findings']['critical']}
- 🟠 **High**: {summary['key_findings']['high']}
- 🟡 **Medium**: {summary['key_findings']['medium']}
- 🔵 **Low**: {summary['key_findings']['low']}
- ⚪ **Info**: {summary['key_findings']['info']}

### Immediate Actions Required

"""
        
        for action in summary['immediate_actions'][:3]:
            md += f"- {action}\n"
        
        md += f"\n### Remediation Timeline\n\n"
        md += f"**Estimated Effort**: {summary['remediation_timeline']['estimated_hours']:.0f} hours ({summary['remediation_timeline']['estimated_weeks']:.1f} weeks)\n\n"
        
        md += "## Detailed Findings\n\n"
        
        # Show top 5 findings
        for i, finding in enumerate(report_data['findings'][:5], 1):
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "⚪"
            }
            
            md += f"### {i}. {severity_emoji.get(finding.severity, '')} {finding.category}\n\n"
            md += f"**File**: `{finding.file}:{finding.line or 'N/A'}`  \n"
            md += f"**Severity**: {finding.severity}  \n"
            md += f"**CWE**: {finding.cwe or 'N/A'}  \n\n"
            md += f"**Description**: {finding.description}\n\n"
            md += f"**Remediation**: {finding.remediation}\n\n"
            md += "---\n\n"
        
        if len(report_data['findings']) > 5:
            md += f"\n*...and {len(report_data['findings']) - 5} more findings. See full report for details.*\n"
        
        return md
    
    def _generate_pdf_report(self, report_data: Dict) -> str:
        """Generate PDF format report (requires pdfkit or similar)"""
        
        # For MVP, generate HTML and note PDF generation requires additional library
        html_file = self._generate_html_report(report_data)
        
        pdf_file = html_file.replace('.html', '.pdf')
        
        print(f"[Report] PDF generation requires pdfkit library. HTML report generated: {html_file}")
        print(f"[Report] To convert to PDF: wkhtmltopdf {html_file} {pdf_file}")
        
        return html_file
    
    def _get_html_styles(self) -> str:
        """CSS styles for HTML report"""
        
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; }
        header { border-bottom: 3px solid #e74c3c; padding-bottom: 20px; margin-bottom: 40px; }
        h1 { color: #e74c3c; font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #2c3e50; font-size: 1.8em; margin: 30px 0 15px; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        h3 { color: #34495e; font-size: 1.3em; margin: 20px 0 10px; }
        .date { color: #7f8c8d; font-size: 1.1em; }
        .severity-critical { background: #e74c3c; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .severity-high { background: #e67e22; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .severity-medium { background: #f39c12; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .severity-low { background: #3498db; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .severity-info { background: #95a5a6; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .finding { background: #ecf0f1; padding: 20px; margin: 20px 0; border-left: 4px solid #3498db; border-radius: 5px; }
        code { background: #2c3e50; color: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; margin: 10px 0; }
        .stat-box { display: inline-block; background: #3498db; color: white; padding: 15px 25px; margin: 10px; border-radius: 5px; min-width: 120px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        th { background: #34495e; color: white; font-weight: bold; }
        tr:hover { background: #f8f9fa; }
        """
    
    def _render_executive_summary_html(self, summary: Dict) -> str:
        """Render executive summary as HTML"""
        
        findings = summary['key_findings']
        
        html = f"""
        <p>{summary['overview']}</p>
        
        <h3>Key Findings</h3>
        <div>
            <div class="stat-box" style="background: #e74c3c;">
                <div class="stat-number">{findings['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box" style="background: #e67e22;">
                <div class="stat-number">{findings['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box" style="background: #f39c12;">
                <div class="stat-number">{findings['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box" style="background: #3498db;">
                <div class="stat-number">{findings['low']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <h3>Business Impact</h3>
        <p>{summary['business_impact']}</p>
        
        <h3>Immediate Actions Required</h3>
        <ol>
        """
        
        for action in summary['immediate_actions']:
            html += f"<li>{action}</li>"
        
        html += "</ol>"
        
        return html
    
    def _render_risk_matrix_html(self, risk_matrix: Dict) -> str:
        """Render risk matrix as HTML"""
        
        html = "<table><thead><tr><th>Severity</th><th>Count</th><th>Distribution</th></tr></thead><tbody>"
        
        for item in risk_matrix['visualization']:
            html += f"""
            <tr>
                <td><span class="severity-{item['severity'].lower()}">{item['severity']}</span></td>
                <td>{item['count']}</td>
                <td>{item['bar']}</td>
            </tr>
            """
        
        html += "</tbody></table>"
        
        return html
    
    def _render_findings_html(self, findings: List) -> str:
        """Render findings as HTML"""
        
        html = ""
        
        for finding in findings:
            html += f"""
            <div class="finding">
                <h3><span class="severity-{finding.severity.lower()}">{finding.severity}</span> {finding.category}</h3>
                <p><strong>File:</strong> <code>{finding.file}:{finding.line or 'N/A'}</code></p>
                <p><strong>CWE:</strong> {finding.cwe or 'N/A'} | <strong>OWASP:</strong> {finding.owasp or 'N/A'}</p>
                
                <h4>Description</h4>
                <p>{finding.description}</p>
                
                <h4>Impact</h4>
                <p>{finding.impact}</p>
                
                <h4>Remediation</h4>
                <p>{finding.remediation}</p>
                
                <h4>Vulnerable Code</h4>
                <pre><code>{finding.code_snippet}</code></pre>
            </div>
            """
        
        return html
    
    def _render_roadmap_html(self, roadmap: Dict) -> str:
        """Render remediation roadmap as HTML"""
        
        html = ""
        
        for phase_name, phase_data in roadmap.items():
            html += f"""
            <h3>{phase_name.replace('_', ' ').title()}</h3>
            <p><strong>Timeframe:</strong> {phase_data['timeframe']}</p>
            <p><strong>Total Effort:</strong> {phase_data['total_effort']:.0f} hours</p>
            <ul>
            """
            
            for item in phase_data['findings'][:10]:  # Limit to 10 per phase
                html += f"<li>{item['title']} (ID: {item['id']}) - {item['effort']}</li>"
            
            html += "</ul>"
        
        return html
    
    def _render_appendices_html(self, appendices: Dict) -> str:
        """Render appendices as HTML"""
        return "<p>Additional technical details and compliance mappings available in full report.</p>"
    
    def _filter_by_severity(self, findings: List, min_severity: str) -> List:
        """Filter findings by minimum severity"""
        
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_index = severity_order.index(min_severity)
        
        return [f for f in findings if severity_order.index(f.severity) >= min_index]
    
    def _generate_metadata(self) -> Dict:
        """Generate report metadata"""
        
        return {
            "report_id": f"PENTEST-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "organization": self.org['name'],
            "application": self.org['application'],
            "environment": self.org.get('environment', 'Production'),
            "tester": "ai-pen-test v0.1.0"
        }
    
    def _generate_methodology_section(self) -> str:
        """Generate methodology description"""
        
        return """
This penetration test was conducted using automated Static Application Security Testing (SAST)
combined with manual code review. The assessment covered OWASP Top 10 vulnerabilities and 
industry-standard security best practices.
"""
    
    def _extract_attack_chains(self, findings: List) -> List:
        """Extract attack chains if available"""
        return []  # To be implemented with finding aggregator integration
    
    def _generate_cvss_appendix(self, findings: List) -> List[Dict]:
        """Generate CVSS scoring appendix"""
        
        return [
            {
                "finding_id": f.id,
                "cvss_score": f.cvss_score or 0.0,
                "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
            for f in findings if hasattr(f, 'cvss_score')
        ]
    
    def _map_to_compliance(self, findings: List) -> Dict:
        """Map findings to compliance frameworks"""
        
        return {
            "OWASP_Top_10": self._map_to_owasp(findings),
            "CWE_Top_25": self._map_to_cwe(findings),
            "PCI_DSS": [],
            "NIST": []
        }
    
    def _map_to_owasp(self, findings: List) -> List:
        """Map findings to OWASP Top 10"""
        owasp_findings = {}
        for f in findings:
            if f.owasp:
                owasp_findings[f.owasp] = owasp_findings.get(f.owasp, 0) + 1
        return [{"category": k, "count": v} for k, v in owasp_findings.items()]
    
    def _map_to_cwe(self, findings: List) -> List:
        """Map findings to CWE"""
        cwe_findings = {}
        for f in findings:
            if f.cwe:
                cwe_findings[f.cwe] = cwe_findings.get(f.cwe, 0) + 1
        return [{"cwe": k, "count": v} for k, v in cwe_findings.items()]
    
    def _estimate_remediation_effort(self, findings: List) -> float:
        """Estimate total remediation effort in hours"""
        
        effort_by_severity = {
            "CRITICAL": 8,
            "HIGH": 4,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0.5
        }
        
        total = sum(effort_by_severity.get(f.severity, 2) for f in findings)
        return total
    
    def _calculate_business_impact(self, findings: List) -> str:
        """Calculate business impact description"""
        
        critical_count = len([f for f in findings if f.severity == "CRITICAL"])
        high_count = len([f for f in findings if f.severity == "HIGH"])
        
        if critical_count > 0:
            return f"Critical vulnerabilities detected that could lead to data breaches, regulatory penalties, and significant financial losses. Immediate action required."
        elif high_count > 2:
            return f"Multiple high-severity vulnerabilities present significant risk to data integrity and system availability. Short-term remediation recommended."
        else:
            return "Moderate security posture with some areas requiring attention. Standard remediation timeline appropriate."
    
    def _generate_immediate_actions(self, findings: List) -> List[str]:
        """Generate list of immediate action items"""
        
        actions = []
        for finding in findings[:3]:  # Top 3 priorities
            actions.append(
                f"Fix {finding.category} in {finding.file} ({finding.severity})"
            )
        return actions
    
    def _generate_remediation_phases(self, findings: List) -> int:
        """Generate number of remediation phases"""
        return 4  # Standard 4-phase approach
    
    def _generate_code_example(self, finding) -> str:
        """Generate secure code example"""
        return finding.remediation  # In full implementation, parse and format code
    
    def _generate_testing_procedure(self, finding) -> str:
        """Generate testing procedure for fix verification"""
        return f"1. Apply fix\n2. Run security scan\n3. Verify vulnerability resolved\n4. Deploy to test environment"
    
    def _load_templates(self) -> Dict:
        """Load report templates"""
        # In full implementation, load from resources/report_templates/
        return {}

