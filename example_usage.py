#!/usr/bin/env python3
"""
Example usage of ai-pen-test

This script demonstrates basic usage of the core modules.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from handlers.sast_analyzer import SASTAnalyzer
from handlers.finding_aggregator import FindingAggregator
from handlers.report_generator import ReportGenerator


def main():
    """Main example execution"""

    print("ai-pen-test - Example Usage\n")

    # ===== Example 1: Basic SAST Analysis =====
    print("=" * 60)
    print("Example 1: Basic SAST Analysis")
    print("=" * 60)

    # Initialize analyzer
    analyzer = SASTAnalyzer(
        model="claude-opus-4-1-20250805",
        timeout_minutes=20
    )

    # Analyze test fixtures
    print("\nAnalyzing vulnerable code fixtures...")

    findings = analyzer.analyze_codebase(
        repo_path="./tests/fixtures/vulnerable",
        scope="full_codebase"
    )

    print(f"Analysis complete! Found {len(findings)} security issues\n")

    # Display findings summary
    severity_counts = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    print("Severity Breakdown:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")

    # ===== Example 2: Finding Aggregation =====
    print("\n" + "=" * 60)
    print("Example 2: Finding Aggregation & Attack Chain Detection")
    print("=" * 60)

    aggregator = FindingAggregator()

    # Aggregate findings
    result = aggregator.aggregate(sast_findings=findings)

    print(f"\nAggregation Results:")
    print(f"  Total findings: {result['statistics']['total_findings']}")
    print(f"  Attack chains identified: {len(result['attack_chains'])}")

    # Display attack chains
    if result['attack_chains']:
        print("\nAttack Chains:")
        for chain in result['attack_chains'][:3]:  # Show first 3
            print(f"  - {chain.description[:80]}...")

    # Print summary
    print("\n" + aggregator.export_summary(findings))

    # ===== Example 3: Report Generation =====
    print("\n" + "=" * 60)
    print("Example 3: Security Report Generation")
    print("=" * 60)

    report_gen = ReportGenerator(organization_context={
        "name": "Example Organization",
        "application": "Test Application",
        "environment": "Development"
    })

    # Generate HTML report
    print("\nGenerating HTML report...")
    html_report = report_gen.generate_report(
        findings=findings,
        format="html",
        metadata={
            "date": "2025-10-31",
            "scope": "Test Fixtures Analysis"
        }
    )
    print(f"HTML report generated: {html_report}")

    # Generate JSON report
    print("\nGenerating JSON report...")
    json_report = report_gen.generate_report(
        findings=findings,
        format="json"
    )
    print(f"JSON report generated: {json_report}")

    # Generate Markdown summary
    print("\nGenerating Markdown summary...")
    md_summary = report_gen.generate_report(
        findings=findings,
        format="markdown"
    )
    print(f"\n{md_summary[:500]}...")  # Show first 500 chars

    # ===== Example 4: Filtering & Prioritization =====
    print("\n" + "=" * 60)
    print("Example 4: Filtering & Prioritization")
    print("=" * 60)

    # Filter by severity
    critical_findings = aggregator.filter_by_severity(findings, "CRITICAL")
    high_findings = aggregator.filter_by_severity(findings, "HIGH")

    print(f"\nCritical findings: {len(critical_findings)}")
    print(f"High+ findings: {len(high_findings)}")

    # Prioritize for remediation
    prioritized = aggregator.prioritize_findings(
        findings,
        context={"environment": "production", "contains_pii": True}
    )

    print("\nTop 3 Priority Findings:")
    for i, finding in enumerate(prioritized[:3], 1):
        print(f"\n  {i}. [{finding.severity}] {finding.category}")
        print(f"     File: {finding.file}:{finding.line}")
        print(f"     CVSS: {finding.cvss_score}")

    # ===== Example 5: Export Findings =====
    print("\n" + "=" * 60)
    print("Example 5: Export Findings")
    print("=" * 60)

    # Export to JSON
    analyzer.export_findings(findings, "example_findings.json", format="json")
    print("Findings exported to: example_findings.json")

    # Export to CSV
    analyzer.export_findings(findings, "example_findings.csv", format="csv")
    print("Findings exported to: example_findings.csv")

    print("\n" + "=" * 60)
    print("Example execution complete!")
    print("=" * 60)


if __name__ == "__main__":
    # Check for API key
    if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        print("Warning: OPENROUTER_API_KEY not set")
        print("Set it with: export OPENROUTER_API_KEY='your-key'")
        print("\nRunning example with mock data...\n")

    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
