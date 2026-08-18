"""
Scanwell CLI Entry Point

Command-line interface for Scanwell sensitive data scanner.

Usage:
    scanwell scan <path> [--similarity <file>] [--no-yara] [--max-size <MB>]
    scanwell report <results.json> [--format csv|json|txt|pdf] [--output <dir>]
    scanwell config [--show|--reset]
    scanwell version
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from .core.scanner import SensitiveDataScanner
from .core.config_manager import ConfigManager
from .utils.report_generator import ReportGenerator

__version__ = "2.0.0"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def cmd_scan(args, config):
    """Execute a scan against a file or directory."""
    target = Path(args.path)
    if not target.exists():
        logger.error(f"Path does not exist: {target}")
        sys.exit(1)
    
    max_size = args.max_size * 1024 * 1024 if args.max_size else config.get("resource_limits", {}).get("max_file_size_mb", 50) * 1024 * 1024
    use_yara = not args.no_yara and config.get("scan_settings", {}).get("use_yara", True)
    
    scanner = SensitiveDataScanner(
        max_file_size=max_size,
        use_yara=use_yara,
    )
    
    def progress(msg):
        logger.info(msg)
    
    logger.info(f"Scanning: {target}")
    
    if target.is_file():
        results = scanner.scan_file(str(target), args.similarity)
        results = {str(target): results} if results else {}
    else:
        results = scanner.scan_directory(str(target), args.similarity, progress)
    
    if not results:
        logger.info("Scan complete: No sensitive data found.")
        sys.exit(0)
    
    # Summary
    total_files = len(results)
    total_findings = sum(
        sum(len(matches) for cat, matches in file_findings.items() 
            if isinstance(matches, dict) 
            for matches in matches.values()
            if isinstance(matches, list))
        for file_findings in results.values()
    )
    logger.info(f"Scan complete: {total_findings} finding(s) across {total_files} file(s)")
    
    # Save JSON results for later reporting
    output_json = Path(args.output or ".") / "scanwell_results.json"
    with open(output_json, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"Results saved to: {output_json}")
    
    # Auto-generate report
    if args.format:
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(results, args.format)
        if report_path:
            logger.info(f"Report generated: {report_path}")


def cmd_report(args, config):
    """Generate a report from existing JSON results."""
    results_path = Path(args.results)
    if not results_path.exists():
        logger.error(f"Results file not found: {results_path}")
        sys.exit(1)
    
    with open(results_path, 'r') as f:
        results = json.load(f)
    
    output_dir = args.output if args.output else None
    report_gen = ReportGenerator(output_dir=output_dir)
    report_path = report_gen.generate_report(results, args.format)
    
    if report_path:
        logger.info(f"Report generated: {report_path}")
    else:
        logger.error(f"Failed to generate {args.format} report")
        sys.exit(1)


def cmd_config(args, config):
    """Show or reset configuration."""
    if args.reset:
        config.config = config.get_default_config()
        config.save_config()
        logger.info("Configuration reset to defaults.")
    else:
        print(json.dumps(config.config, indent=2))


def cmd_version(args, config):
    """Display version information."""
    print(f"Scanwell v{__version__}")
    print(f"Config file: {config.config_file}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='scanwell',
        description='Scanwell - Sensitive Data Scanner',
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a file or directory')
    scan_parser.add_argument('path', help='File or directory to scan')
    scan_parser.add_argument('--similarity', '-s', help='Reference file for similarity scoring')
    scan_parser.add_argument('--no-yara', action='store_true', help='Disable YARA, use regex only')
    scan_parser.add_argument('--max-size', type=int, help='Max file size in MB')
    scan_parser.add_argument('--format', '-f', choices=['csv', 'json', 'txt', 'pdf'],
                            help='Auto-generate report in this format')
    scan_parser.add_argument('--output', '-o', help='Output directory for results/report')
    
    # report command
    report_parser = subparsers.add_parser('report', help='Generate report from JSON results')
    report_parser.add_argument('results', help='Path to scanwell_results.json')
    report_parser.add_argument('--format', '-f', choices=['csv', 'json', 'txt', 'pdf'],
                              default='csv', help='Report format (default: csv)')
    report_parser.add_argument('--output', '-o', help='Output directory')
    
    # config command
    config_parser = subparsers.add_parser('config', help='View or reset configuration')
    config_parser.add_argument('--reset', action='store_true', help='Reset to defaults')
    config_parser.add_argument('--show', action='store_true', default=True, help='Show current config')
    
    # version command
    version_parser = subparsers.add_parser('version', help='Show version')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    config = ConfigManager()
    
    if args.command == 'scan':
        cmd_scan(args, config)
    elif args.command == 'report':
        cmd_report(args, config)
    elif args.command == 'config':
        cmd_config(args, config)
    elif args.command == 'version':
        cmd_version(args, config)


if __name__ == '__main__':
    main()
