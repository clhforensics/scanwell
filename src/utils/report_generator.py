"""
Scanwell Report Generator

Generates scan reports in CSV, TXT, JSON, and PDF formats.
All formats are fully implemented — no stubs.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate scan results reports in multiple formats."""

    def __init__(self, output_dir: str = None):
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path.home() / "Scanwell Reports"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, results: dict, format_type: str = "csv") -> Optional[Path]:
        """
        Generate a report from scan results.
        
        Args:
            results: dict mapping file paths to finding dicts
            format_type: one of 'csv', 'txt', 'json', 'pdf'
        
        Returns:
            Path to generated report file, or None on failure.
        """
        format_type = format_type.lower().strip()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"scanwell_report_{timestamp}.{format_type}"

        try:
            if format_type == "csv":
                self._generate_csv(results, filename)
            elif format_type == "txt":
                self._generate_txt(results, filename)
            elif format_type == "json":
                self._generate_json(results, filename)
            elif format_type == "pdf":
                self._generate_pdf(results, filename)
            else:
                logger.error(f"Unknown format: {format_type}")
                return None

            logger.info(f"Report generated: {filename}")
            return filename

        except Exception as e:
            logger.error(f"Failed to generate {format_type} report: {e}")
            return None

    def _flatten_results(self, results: dict) -> list[dict]:
        """Flatten results into a list of finding rows for CSV/tabular output."""
        rows = []
        for file_path, file_findings in results.items():
            for category, category_data in file_findings.items():
                if category == "similarity_score":
                    continue
                if isinstance(category_data, dict):
                    for pattern_type, matches in category_data.items():
                        if isinstance(matches, list):
                            count = len(matches)
                            sample = matches[0] if matches else ""
                            rows.append({
                                "file_path": file_path,
                                "category": category,
                                "pattern_type": pattern_type,
                                "count": count,
                                "sample_masked": sample,
                            })
                        else:
                            rows.append({
                                "file_path": file_path,
                                "category": category,
                                "pattern_type": pattern_type,
                                "count": 1,
                                "sample_masked": str(matches),
                            })
                elif isinstance(category_data, (int, float)):
                    rows.append({
                        "file_path": file_path,
                        "category": category,
                        "pattern_type": "metric",
                        "count": category_data,
                        "sample_masked": "",
                    })
        return rows

    def _generate_csv(self, results: dict, filename: Path):
        """Generate CSV report with all findings."""
        rows = self._flatten_results(results)
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "file_path", "category", "pattern_type", "count", "sample_masked"
            ])
            writer.writeheader()
            writer.writerows(rows)

    def _generate_txt(self, results: dict, filename: Path):
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 70)
        lines.append("SCANWELL SENSITIVE DATA SCAN REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append("")

        if not results:
            lines.append("No sensitive data found.")
        else:
            total_findings = 0
            for file_path, file_findings in results.items():
                lines.append(f"\nFile: {file_path}")
                lines.append("-" * 70)
                for category, category_data in file_findings.items():
                    if category == "similarity_score":
                        lines.append(f"  Similarity Score: {category_data}/10")
                        continue
                    if isinstance(category_data, dict):
                        for pattern_type, matches in category_data.items():
                            count = len(matches) if isinstance(matches, list) else 1
                            total_findings += count
                            sample = matches[0] if isinstance(matches, list) and matches else str(matches)
                            lines.append(f"  [{category}] {pattern_type}: {count} match(es)")
                            lines.append(f"    Sample: {sample}")
                    else:
                        lines.append(f"  [{category}]: {category_data}")
                lines.append("")

            lines.append("=" * 70)
            lines.append(f"SUMMARY: {total_findings} finding(s) across {len(results)} file(s)")
            lines.append("=" * 70)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def _generate_json(self, results: dict, filename: Path):
        """Generate JSON report."""
        report = {
            "scan_date": datetime.now().isoformat(),
            "tool": "Scanwell",
            "version": "2.0.0",
            "files_scanned": len(results),
            "findings": results,
        }
        total = 0
        for file_findings in results.values():
            for category, data in file_findings.items():
                if category == "similarity_score":
                    continue
                if isinstance(data, dict):
                    for matches in data.values():
                        total += len(matches) if isinstance(matches, list) else 1
        report["total_findings"] = total
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def _generate_pdf(self, results: dict, filename: Path):
        """Generate PDF report using reportlab."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        )
        from reportlab.lib.styles import getSampleStyleSheet

        doc = SimpleDocTemplate(str(filename), pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        # Title
        elements.append(Paragraph("Scanwell Sensitive Data Scan Report", styles['Title']))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 20))

        # Summary
        total_findings = 0
        total_files = len(results)
        for file_findings in results.values():
            for category, data in file_findings.items():
                if category == "similarity_score":
                    continue
                if isinstance(data, dict):
                    for matches in data.values():
                        total_findings += len(matches) if isinstance(matches, list) else 1

        elements.append(Paragraph(
            f"<b>Files with findings:</b> {total_files}<br/>"
            f"<b>Total findings:</b> {total_findings}",
            styles['Normal']
        ))
        elements.append(Spacer(1, 20))

        # Findings table
        rows = self._flatten_results(results)
        if rows:
            table_data = [["File", "Category", "Pattern", "Count", "Sample"]]
            for row in rows:
                # Truncate long file paths for table display
                short_path = row["file_path"]
                if len(short_path) > 40:
                    short_path = "..." + short_path[-37:]
                table_data.append([
                    short_path,
                    row["category"],
                    row["pattern_type"],
                    str(row["count"]),
                    row["sample_masked"][:30],
                ])

            table = Table(table_data, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            elements.append(table)
        else:
            elements.append(Paragraph("No sensitive data found.", styles['Normal']))

        doc.build(elements)
