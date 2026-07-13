#!/usr/bin/env python3
"""
ai-pen-test - LLM-backed semantic SAST engine

AI-powered static security analysis CLI.

Usage:
    ai-pen-test scan <directory>        - Run SAST code scan
    ai-pen-test report <findings.json>  - Generate report from findings
    ai-pen-test init                    - Initialize configuration
    ai-pen-test version                 - Show version
    ai-pen-test help                    - Show help
"""

import argparse
import sys
import os
from pathlib import Path
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from handlers.sast_analyzer import SASTAnalyzer
from handlers.finding_aggregator import FindingAggregator
from handlers.report_generator import ReportGenerator
from datetime import datetime


__version__ = "0.1.0"


class SASTCLI:
    """Main CLI application"""

    def __init__(self):
        self.config_file = Path.home() / ".ai-pen-test" / "config.json"
        self.config = self.load_config()

    def load_config(self):
        """Load configuration"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {
            "api_key": os.environ.get('OPENROUTER_API_KEY', '') or os.environ.get('ANTHROPIC_API_KEY', ''),
            "default_severity": "MEDIUM",
            "output_format": "html",
            "organization": "My Company"
        }

    def save_config(self, config):
        """Save configuration"""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Configuration saved to: {self.config_file}")

    def cmd_init(self, args):
        """Initialize configuration"""
        print("ai-pen-test - Setup")
        print("=" * 60)
        print()

        config = {}

        print("Let's configure your security scanning environment.\n")

        # API Key
        current_key = self.config.get('api_key', '')
        api_key = input(f"OpenRouter/Anthropic API Key [{current_key[:10]}...]: ").strip()
        config['api_key'] = api_key if api_key else current_key

        # Organization
        current_org = self.config.get('organization', 'My Company')
        org = input(f"Organization Name [{current_org}]: ").strip()
        config['organization'] = org if org else current_org

        # Default severity
        print("\nDefault minimum severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
        severity = input(f"Severity threshold [MEDIUM]: ").strip().upper()
        config['default_severity'] = severity if severity else "MEDIUM"

        # Output format
        print("\nDefault report format (html, json, markdown, pdf)")
        fmt = input(f"Output format [html]: ").strip().lower()
        config['output_format'] = fmt if fmt else "html"

        self.save_config(config)

        print()
        print("Setup complete!")
        print()
        print("Next steps:")
        print("  1. Run a code scan: ai-pen-test scan tests/fixtures/vulnerable")
        print("  2. See help: ai-pen-test help")
        print()

    def cmd_scan(self, args):
        """Run security scan"""
        target = args.directory

        if not os.path.exists(target):
            print(f"Error: Directory not found: {target}")
            sys.exit(1)

        print(f"ai-pen-test - Security Scan")
        print("=" * 60)
        print(f"Target: {target}")
        print(f"Scope: {args.scope}")
        print(f"Severity: {args.severity}")
        print(f"Model: {args.model}")

        # Show parallel config if enabled
        parallel_workers = getattr(args, 'parallel', 1)
        if parallel_workers > 1:
            print(f"Parallel: {parallel_workers} workers")
            print(f"   Batch size: {args.batch_size} files")
        print()

        # Check API key (OpenRouter or Anthropic)
        api_key = args.api_key or self.config.get('api_key') or os.environ.get('OPENROUTER_API_KEY') or os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            print("Warning: OPENROUTER_API_KEY not set")
            print("   Analysis will be limited")
            print("   Set with: ai-pen-test init")
            print()

        # Use parallel analyzer if workers > 1
        if parallel_workers > 1:
            import asyncio
            from handlers.parallel_sast import ParallelSASTAnalyzer

            print(f"Initializing parallel SAST analyzer...")
            analyzer = ParallelSASTAnalyzer(
                max_workers=parallel_workers,
                batch_size=args.batch_size,
                model=args.model,
                api_key=api_key,
                strategy='asyncio'
            )

            def progress(completed, total):
                pct = (completed / total) * 100
                print(f"\r   Progress: {completed}/{total} batches ({pct:.0f}%)", end='', flush=True)

            print(f"Scanning {target} in parallel...")
            findings, stats = asyncio.run(analyzer.analyze_parallel(
                repo_path=target,
                scope=args.scope,
                progress_callback=progress
            ))
            print()  # Newline after progress

            print(f"\nParallel scan complete: {len(findings)} findings")
            print(f"\nPerformance:")
            print(f"   Total time: {stats.total_time:.1f}s")
            print(f"   Speedup: {stats.speedup:.1f}x")
            print(f"   Files/sec: {stats.files_per_second:.1f}")
            print(f"   Batches: {stats.total_batches}")

        else:
            # Sequential analyzer
            print(f"Initializing SAST analyzer with {args.model}...")
            analyzer = SASTAnalyzer(model=args.model, api_key=api_key, use_openrouter=True)

            print(f"Scanning {target}...")
            findings = analyzer.analyze_codebase(
                repo_path=target,
                scope=args.scope
            )

            print(f"\nScan complete: {len(findings)} findings")

            # Show LLM usage stats if available
            llm_stats = analyzer.get_llm_stats()
            if llm_stats:
                print(f"\nLLM Usage:")
                print(f"   Requests: {llm_stats['requests']}")
                print(f"   Tokens: {llm_stats['total_tokens']:,}")
                print(f"   Cost: ${llm_stats['total_cost']:.4f}")

        # Filter by severity
        if args.severity != "INFO":
            aggregator = FindingAggregator()
            findings = aggregator.filter_by_severity(findings, args.severity)
            print(f"   After severity filter: {len(findings)} findings")

        # Show summary
        severity_counts = {}
        if findings:
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

            print("\nSeverity Breakdown:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in severity_counts:
                    print(f"   {sev}: {severity_counts[sev]}")

        # Export findings
        output_file = args.output or "findings.json"
        analyzer.export_findings(findings, output_file, format="json")
        print(f"\nFindings saved: {output_file}")

        # Generate report if requested
        if args.report:
            print(f"\nGenerating {args.format} report...")
            report_gen = ReportGenerator(organization_context={
                "name": self.config.get('organization', 'Organization'),
                "application": Path(target).name,
                "environment": "Security Assessment"
            })

            report_file = report_gen.generate_report(
                findings=findings,
                format=args.format
            )
            print(f"Report generated: {report_file}")

        # Summary
        print()
        print("=" * 60)
        print("Scan complete!")
        print()
        if findings:
            critical_count = severity_counts.get('CRITICAL', 0)
            high_count = severity_counts.get('HIGH', 0)

            if critical_count > 0 or high_count > 0:
                print(f"Found {critical_count} CRITICAL and {high_count} HIGH severity issues")
                print("   Immediate review recommended!")
            else:
                print("No critical or high severity issues found")
        else:
            print("No security issues detected")
        print()

    def cmd_report(self, args):
        """Generate report from findings file"""
        findings_file = args.findings_file

        if not os.path.exists(findings_file):
            print(f"Error: Findings file not found: {findings_file}")
            sys.exit(1)

        print(f"Generating Report")
        print("=" * 60)
        print(f"Input: {findings_file}")
        print(f"Format: {args.format}")
        print()

        # Load findings
        with open(findings_file, 'r') as f:
            findings_data = json.load(f)

        # Convert to Finding objects
        from handlers.sast_analyzer import Finding
        findings = []
        for item in findings_data:
            if isinstance(item, dict):
                findings.append(Finding(
                    id=item.get('id', 'UNKNOWN'),
                    severity=item.get('severity', 'MEDIUM'),
                    category=item.get('category', 'Unknown'),
                    cwe=item.get('cwe'),
                    owasp=item.get('owasp'),
                    file=item.get('file', ''),
                    line=item.get('line'),
                    code_snippet=item.get('code_snippet', ''),
                    description=item.get('description', ''),
                    impact=item.get('impact', ''),
                    remediation=item.get('remediation', ''),
                    references=item.get('references', []),
                    cvss_score=item.get('cvss_score'),
                    confidence=item.get('confidence', 'MEDIUM')
                ))

        print(f"Loaded {len(findings)} findings")

        # Generate report
        report_gen = ReportGenerator(organization_context={
            "name": self.config.get('organization', 'Organization'),
            "application": "Security Assessment"
        })

        report_file = report_gen.generate_report(
            findings=findings,
            format=args.format,
            severity_filter=args.severity if args.severity != 'INFO' else None
        )

        print(f"Report generated: {report_file}")
        print()

    def cmd_version(self, args):
        """Show version"""
        print(f"ai-pen-test v{__version__}")
        print("LLM-backed semantic SAST engine")
        print()
        print(f"Installation: {Path(__file__).parent}")
        print(f"Config: {self.config_file}")
        print()

    def cmd_help(self, args):
        """Show help"""
        print(__doc__)


def main():
    """Main CLI entry point"""

    cli = SASTCLI()

    parser = argparse.ArgumentParser(
        description="ai-pen-test - LLM-backed semantic SAST engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Init command
    parser_init = subparsers.add_parser('init', help='Initialize configuration')

    # Scan command (SAST)
    parser_scan = subparsers.add_parser('scan', help='Run SAST code security scan')
    parser_scan.add_argument('directory', help='Directory to scan')
    parser_scan.add_argument('--scope', choices=['changed_files', 'full_codebase'],
                             default='full_codebase', help='Scan scope')
    parser_scan.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                             default='MEDIUM', help='Minimum severity to report')
    parser_scan.add_argument('--output', '-o', help='Output file (default: findings.json)')
    parser_scan.add_argument('--report', '-r', action='store_true', help='Generate report')
    parser_scan.add_argument('--format', choices=['html', 'json', 'markdown', 'pdf'],
                             default='html', help='Report format')
    parser_scan.add_argument('--api-key', help='OpenRouter/Anthropic API key')
    parser_scan.add_argument('--model', choices=['claude', 'claude-3.7-sonnet', 'claude-opus-4.5', 'gpt4o', 'gpt4o-mini', 'llama'],
                             default='claude-3.7-sonnet', help='AI model to use (default: claude-3.7-sonnet)')
    parser_scan.add_argument('--parallel', '-p', type=int, default=1, metavar='N',
                             help='Number of parallel workers (1=sequential, 2-16 recommended)')
    parser_scan.add_argument('--batch-size', type=int, default=5,
                             help='Files per batch for parallel scanning (default: 5)')

    # Report command
    parser_report = subparsers.add_parser('report', help='Generate report from findings')
    parser_report.add_argument('findings_file', help='Findings JSON file')
    parser_report.add_argument('--format', choices=['html', 'json', 'markdown', 'pdf'],
                               default='html', help='Output format')
    parser_report.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                               default='INFO', help='Minimum severity to include')

    # Version command
    parser_version = subparsers.add_parser('version', help='Show version')

    # Help command
    parser_help = subparsers.add_parser('help', help='Show help')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Route to command
    commands = {
        'init': cli.cmd_init,
        'scan': cli.cmd_scan,
        'report': cli.cmd_report,
        'version': cli.cmd_version,
        'help': cli.cmd_help
    }

    if args.command in commands:
        try:
            commands[args.command](args)
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            if os.environ.get('DEBUG'):
                traceback.print_exc()
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
