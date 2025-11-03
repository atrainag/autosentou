"""
Report Generator V2 - Clean and Dynamic

Generates reports with proper section numbering and clean formatting.
All sections are collected first, then TOC is generated dynamically.
"""

import os
import json
import zipfile
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from models import Phase, Job
from database import SessionLocal
from services.utils.output_manager import get_output_manager

from .executive_summary import generate_executive_summary_section
from .vulnerability_report import generate_vulnerability_sections
from .network_services_report import generate_network_services_section
from .web_report import generate_web_enumeration_section
from .sqli_report import generate_sqli_section
from .auth_report import generate_auth_section
from .recommendations import generate_recommendations_section, generate_conclusion_section
from .appendix import generate_appendix_section
from .converters import convert_markdown_to_html, convert_html_to_pdf, convert_markdown_to_docx
from .detailed_findings_report import generate_detailed_findings_report
from .rag_remediation import enhance_finding_with_rag


class ReportSection:
    """Represents a section in the report."""
    def __init__(self, title: str, content: str, subsections: List[str] = None):
        self.title = title
        self.content = content
        self.subsections = subsections or []
        self.number = None  # Will be assigned dynamically


class ReportGenerator:
    """Dynamic report generator with proper section numbering."""

    def __init__(self, job: Job, phases_data: Dict[str, Any]):
        self.job = job
        self.phases_data = phases_data
        self.sections: List[ReportSection] = []

    def collect_sections(self):
        """Collect all sections that should be included in the report."""

        # 1. Executive Summary (always included)
        exec_summary = generate_executive_summary_section(self.job, self.phases_data)
        self.sections.append(ReportSection(
            "Executive Summary",
            exec_summary,
            ["Key Findings"]
        ))

        # 2. Scope and Methodology (always included)
        scope_content = self._generate_scope_and_methodology()
        self.sections.append(ReportSection(
            "Scope and Methodology",
            scope_content,
            [
                "Scope and Limitations",
                "Target Information",
                "Testing Methodology",
                "Risk Rating Methodology"
            ]
        ))

        # 3. Network Services (if data available)
        network_services = generate_network_services_section(self.phases_data)
        if network_services:
            # Count subsections in network services
            subsections = []
            if "2.5.1" in network_services:
                subsections.append("Port Scan Summary")
            if "2.5.2" in network_services:
                subsections.append("Operating System Detection")
            if "2.5.3" in network_services:
                subsections.append("Detailed Port and Service Information")
            if "2.5.4" in network_services:
                subsections.append("Services by Category")
            if "2.5.5" in network_services:
                subsections.append("Security Implications")

            self.sections.append(ReportSection(
                "Network Services Discovered",
                network_services,
                subsections
            ))

        # 4. Vulnerability Summary (always included)
        vuln_sections = generate_vulnerability_sections(self.phases_data)
        self.sections.append(ReportSection(
            "Vulnerability Summary",
            vuln_sections,
            [
                "Master Vulnerability Table",
                "OWASP TOP 10 2021 Distribution",
                "Information Gathering",
                "Detailed Vulnerability Findings"
            ]
        ))

        # 5. Web Application Testing (if data available)
        web_section = generate_web_enumeration_section(self.phases_data)
        if web_section:
            subsections = ["Directory Enumeration Results"]
            if "4.2" in web_section:
                subsections.append("High Risk Paths")
            if "4.3" in web_section:
                subsections.append("Sensitive Information Exposure")

            self.sections.append(ReportSection(
                "Web Application Testing",
                web_section,
                subsections
            ))

        # 6. SQL Injection Testing (if data available)
        sqli_section = generate_sqli_section(self.phases_data)
        if sqli_section:
            subsections = ["Testing Summary"]
            sqli_data = self.phases_data.get('sqli_testing', {})
            if sqli_data.get('vulnerable_endpoints', 0) > 0:
                subsections.extend(["Vulnerable Endpoints", "Detailed SQL Injection Findings"])

            self.sections.append(ReportSection(
                "SQL Injection Testing",
                sqli_section,
                subsections
            ))

        # 7. Authentication Testing (if data available)
        auth_section = generate_auth_section(self.phases_data)
        if auth_section:
            subsections = ["Login Page Security Analysis"]
            auth_data = self.phases_data.get('authentication_testing', {})
            if auth_data and auth_data.get('login_pages_tested', 0) > 0:
                subsections.append("Detailed Authentication Findings")

            self.sections.append(ReportSection(
                "Authentication Security Testing",
                auth_section,
                subsections
            ))

        # 8. Recommendations (always included)
        recommendations = generate_recommendations_section(self.phases_data)
        self.sections.append(ReportSection(
            "Overall Recommendations",
            recommendations,
            []
        ))

        # 9. Conclusion (always included)
        conclusion = generate_conclusion_section(self.phases_data)
        self.sections.append(ReportSection(
            "Conclusion",
            conclusion,
            []
        ))

        # 10. Appendix (always included)
        appendix = generate_appendix_section(self.phases_data)
        self.sections.append(ReportSection(
            "Appendix",
            appendix,
            ["Tools and Versions", "OWASP TOP 10 2021 Reference"]
        ))

    def assign_section_numbers(self):
        """Assign section numbers dynamically."""
        for idx, section in enumerate(self.sections, 1):
            section.number = idx

    def generate_table_of_contents(self) -> str:
        """Generate table of contents dynamically based on collected sections."""
        lines = []
        lines.append("## Table of Contents\n\n")

        for section in self.sections:
            # Main section on its own line
            lines.append(f"**{section.number}. {section.title}**\n")

            # Subsections indented on new lines
            if section.subsections:
                for sub_idx, subsection in enumerate(section.subsections, 1):
                    lines.append(f"   {section.number}.{sub_idx}. {subsection}\n")
                lines.append("\n")
            else:
                lines.append("\n")

        return ''.join(lines)

    def _generate_scope_and_methodology(self) -> str:
        """Generate Scope and Methodology section."""
        info_data = self.phases_data.get('information_gathering', {})
        is_local_target = info_data.get('is_local_target', False)

        lines = []

        # 2.1 Scope and Limitations
        lines.append("### Scope and Limitations\n\n")
        lines.append("This penetration testing assessment was conducted using automated scanning tools and follows a standardized methodology. The following limitations apply:\n\n")
        lines.append("- **Automated Testing Only**: This assessment utilizes automated security scanning tools. Manual penetration testing and human exploitation attempts were not performed.\n")
        lines.append("- **Non-Destructive Testing**: All tests are designed to identify vulnerabilities without causing service disruption or data loss.\n")
        lines.append("- **Scope**: Testing was limited to the target IP/domain provided. Internal networks, adjacent systems, and physical security were not assessed.\n")
        lines.append(f"- **Timing**: Scan executed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Results represent the security posture at the time of testing.\n")
        lines.append("- **Out of Scope**: Social engineering, denial-of-service attacks, and physical security assessments were not performed.\n\n")

        if is_local_target:
            lines.append("**Note**: This is a local/private network target. WHOIS and DNS enumeration were not performed as they are not applicable to private IP ranges.\n\n")

        # 2.2 Target Information
        lines.append("### Target Information\n\n")
        lines.append(f"- **Target**: {self.job.target}\n")
        lines.append(f"- **Target Type**: {'Local/Private Network' if is_local_target else 'Public/External Network'}\n")
        lines.append(f"- **Scan Type**: Comprehensive\n\n")

        # 2.3 Testing Methodology
        lines.append("### Testing Methodology\n\n")
        lines.append("The assessment followed industry-standard penetration testing methodology:\n\n")
        lines.append("1. **Information Gathering** - Network reconnaissance and service identification\n")
        lines.append("2. **Vulnerability Analysis** - CVE analysis and vulnerability assessment\n")
        lines.append("3. **Web Application Testing** - Directory enumeration and web security analysis\n")
        lines.append("4. **SQL Injection Testing** - Automated injection testing on identified endpoints\n")
        lines.append("5. **Authentication Testing** - Login page security analysis\n")
        lines.append("6. **Report Generation** - Comprehensive documentation of findings\n\n")

        # 2.4 Risk Rating Methodology
        lines.append("### Risk Rating Methodology\n\n")
        lines.append("Vulnerabilities are classified using the following severity levels:\n\n")
        lines.append("- **Critical**: Vulnerabilities that can be exploited immediately with severe impact (e.g., remote code execution, complete system compromise)\n")
        lines.append("- **High**: Vulnerabilities that are likely exploitable and could lead to significant security breaches (e.g., SQL injection, authentication bypass)\n")
        lines.append("- **Medium**: Vulnerabilities that require specific conditions to exploit or have moderate impact (e.g., information disclosure, weak configurations)\n")
        lines.append("- **Low**: Vulnerabilities with minimal immediate risk or require significant effort to exploit (e.g., minor information leakage, non-sensitive exposure)\n\n")
        lines.append("Severity is determined through a combination of:\n\n")
        lines.append("1. Exploit difficulty\n")
        lines.append("2. Potential impact on confidentiality, integrity, and availability\n")
        lines.append("3. OWASP TOP 10 2021 classification\n")
        lines.append("4. AI-powered risk assessment\n")

        return ''.join(lines)

    def renumber_content(self, content: str, section_number: int) -> str:
        """Renumber headings in content to match assigned section number."""
        import re

        # Replace ### headings (subsections like 3.1, 3.2, etc.)
        # Pattern: ### X.Y becomes ### N.Y where N is the new section number
        content = re.sub(
            r'###\s+\d+\.(\d+)',
            f'### {section_number}.\\1',
            content
        )

        # Replace ## headings (main section like ## 3.)
        content = re.sub(
            r'##\s+\d+\.',
            f'## {section_number}.',
            content
        )

        # Replace #### headings if any (sub-subsections)
        content = re.sub(
            r'####\s+\d+\.(\d+)\.(\d+)',
            f'#### {section_number}.\\1.\\2',
            content
        )

        return content

    def generate_markdown(self) -> str:
        """Generate complete markdown report."""
        lines = []

        # Header
        lines.append("# Penetration Testing Report\n\n")
        lines.append(f"**Target:** {self.job.target}\n\n")
        lines.append(f"**Report Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        lines.append(f"**Job ID:** {self.job.id}\n\n")
        lines.append("---\n\n")

        # Table of Contents
        toc = self.generate_table_of_contents()
        lines.append(toc)
        lines.append("---\n\n")

        # Add all sections with proper numbering
        for section in self.sections:
            # Section header
            anchor = section.title.lower().replace(' ', '-').replace('&', 'and')
            lines.append(f"## {section.number}. {section.title}\n\n")

            # Renumber content to match assigned section number
            content = self.renumber_content(section.content, section.number)
            lines.append(content)
            lines.append("\n---\n\n")

        return ''.join(lines)


def generate_markdown_report(job: Job, phases_data: Dict[str, Any]) -> str:
    """
    Generate comprehensive markdown report with dynamic section numbering.
    """
    generator = ReportGenerator(job, phases_data)
    generator.collect_sections()
    generator.assign_section_numbers()
    return generator.generate_markdown()


def create_raw_outputs_zip(job: Job, phases_data: Dict[str, Any]) -> str:
    """
    Create a ZIP file containing all raw tool outputs.
    """
    report_dir = f"reports/{job.id}"
    raw_outputs_dir = os.path.join(report_dir, "raw_outputs")

    os.makedirs(raw_outputs_dir, exist_ok=True)

    raw_files = []

    # Information Gathering outputs
    info_data = phases_data.get('information_gathering', {})
    if info_data:
        nmap_output = info_data.get('nmap', {}).get('raw_output', '')
        if nmap_output:
            nmap_file = os.path.join(raw_outputs_dir, 'nmap_scan.txt')
            with open(nmap_file, 'w') as f:
                f.write(nmap_output)
            raw_files.append(nmap_file)

    # Vulnerability Analysis outputs
    vuln_data = phases_data.get('vulnerability_analysis', {})
    if vuln_data:
        vuln_json = os.path.join(raw_outputs_dir, 'vulnerability_analysis.json')
        with open(vuln_json, 'w') as f:
            json.dump(vuln_data, f, indent=2, default=str)
        raw_files.append(vuln_json)

    # Web Enumeration outputs
    web_data = phases_data.get('web_enumeration', {})
    if web_data:
        web_json = os.path.join(raw_outputs_dir, 'web_enumeration.json')
        with open(web_json, 'w') as f:
            json.dump(web_data, f, indent=2, default=str)
        raw_files.append(web_json)

    # SQLi Testing outputs
    sqli_data = phases_data.get('sqli_testing', {})
    if sqli_data:
        for idx, result in enumerate(sqli_data.get('sqli_results', [])):
            if result.get('output_file'):
                output_file = result['output_file']
                if os.path.exists(output_file):
                    raw_files.append(output_file)

    # Create ZIP file
    target_safe = job.target.replace(':', '_').replace('/', '_').replace('.', '_')
    zip_filename = f"{target_safe}_raw_outputs.zip"
    zip_path = os.path.join(report_dir, zip_filename)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in raw_files:
            if os.path.exists(file_path):
                arcname = os.path.basename(file_path)
                zipf.write(file_path, arcname)

    print(f"✓ Created raw outputs ZIP: {zip_path}")
    return zip_path




def run_report_generation_phase(db_session, job: Job, all_phases_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Generate final penetration testing report with all outputs.
    Now includes findings population and summary-only PDF report.
    """
    phase = Phase(
        job_id=job.id,
        phase_name="Report Generation",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)

    try:
        print("\n" + "="*60)
        print("REPORT GENERATION PHASE STARTED")
        print("="*60)

        # Create report directory
        report_dir = f"reports/{job.id}"
        os.makedirs(report_dir, exist_ok=True)

        # 0. Populate findings table (NEW!)
        print("→ Extracting and categorizing findings...")
        from services.findings_populator import populate_findings_for_job
        from models import Finding, FindingsSummaryResponse
        from sqlalchemy import func

        findings_count = populate_findings_for_job(db_session, job, all_phases_data)
        print(f"✓ Extracted and categorized {findings_count} findings")

        # Enhance findings with RAG-powered remediation
        print("→ Enhancing findings with intelligent remediation...")
        from models import Finding
        findings_to_enhance = db_session.query(Finding).filter(Finding.job_id == job.id).all()
        enhanced_count = 0
        for finding in findings_to_enhance:
            try:
                enhance_finding_with_rag(finding)
                enhanced_count += 1
            except Exception as e:
                print(f"  ⚠ Could not enhance finding {finding.id}: {e}")
        if enhanced_count > 0:
            db_session.commit()
            print(f"✓ Enhanced {enhanced_count} findings with smart remediation")

        # Get summary statistics for the report
        total_findings = db_session.query(func.count(Finding.id)).filter(Finding.job_id == job.id).scalar() or 0
        severity_counts = db_session.query(
            Finding.severity,
            func.count(Finding.id)
        ).filter(Finding.job_id == job.id).group_by(Finding.severity).all()
        by_severity = {severity: count for severity, count in severity_counts}

        owasp_counts = db_session.query(
            Finding.owasp_category,
            func.count(Finding.id)
        ).filter(Finding.job_id == job.id).group_by(Finding.owasp_category).all()
        by_owasp_category = {category: count for category, count in owasp_counts if category}

        type_counts = db_session.query(
            Finding.finding_type,
            func.count(Finding.id)
        ).filter(Finding.job_id == job.id).group_by(Finding.finding_type).all()
        by_finding_type = {ftype: count for ftype, count in type_counts}

        summary_data = {
            'total_findings': total_findings,
            'by_severity': by_severity,
            'by_owasp_category': by_owasp_category,
            'by_finding_type': by_finding_type,
            'critical_findings': by_severity.get('Critical', 0),
            'high_findings': by_severity.get('High', 0),
            'medium_findings': by_severity.get('Medium', 0),
            'low_findings': by_severity.get('Low', 0)
        }

        # 1. Generate SUMMARY-ONLY markdown report
        print("→ Generating summary-only markdown report...")
        from .summary_report import generate_summary_report
        summary_markdown = generate_summary_report(job, summary_data)

        # Save summary markdown
        summary_md_path = os.path.join(report_dir, "executive_summary.md")
        with open(summary_md_path, 'w', encoding='utf-8') as f:
            f.write(summary_markdown)
        print(f"✓ Summary markdown saved: {summary_md_path}")

        # 2. Generate DETAILED FINDINGS REPORT (NEW!)
        print("→ Generating detailed findings report...")
        detailed_findings_markdown = generate_detailed_findings_report(job, all_phases_data, db_session)

        # Save detailed findings markdown
        detailed_findings_md_path = os.path.join(report_dir, "detailed_findings_report.md")
        with open(detailed_findings_md_path, 'w', encoding='utf-8') as f:
            f.write(detailed_findings_markdown)
        print(f"✓ Detailed findings report saved: {detailed_findings_md_path}")

        # 3. Generate legacy detailed markdown report with dynamic numbering (for backward compatibility)
        print("→ Generating detailed markdown report...")
        markdown_content = generate_markdown_report(job, all_phases_data)

        # Save detailed markdown (for backup/reference)
        markdown_path = os.path.join(report_dir, "pentest_report_detailed.md")
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"✓ Detailed markdown report saved: {markdown_path}")

        # 4. Convert SUMMARY to HTML (for PDF generation)
        print("→ Converting summary to HTML...")
        summary_html = convert_markdown_to_html(summary_markdown, f"Executive Summary - {job.target}")

        # Save summary HTML
        summary_html_path = os.path.join(report_dir, "executive_summary.html")
        with open(summary_html_path, 'w', encoding='utf-8') as f:
            f.write(summary_html)
        print(f"✓ Summary HTML saved: {summary_html_path}")

        # 5. Convert summary to PDF (QUICK SUMMARY REPORT)
        print("→ Converting summary to PDF...")
        summary_pdf_path = os.path.join(report_dir, "executive_summary.pdf")
        summary_pdf_success = False
        try:
            summary_pdf_success = convert_html_to_pdf(summary_html, summary_pdf_path)
            print(f"✓ Summary PDF generated: {summary_pdf_path}")
        except Exception as pdf_error:
            print(f"⚠ Summary PDF conversion failed: {pdf_error}")
            print("  Continuing with other formats...")

        # 6. Convert DETAILED FINDINGS REPORT to HTML
        print("→ Converting detailed findings report to HTML...")
        detailed_findings_html = convert_markdown_to_html(detailed_findings_markdown, f"Detailed Findings Report - {job.target}")

        # Save detailed findings HTML
        detailed_findings_html_path = os.path.join(report_dir, "detailed_findings_report.html")
        with open(detailed_findings_html_path, 'w', encoding='utf-8') as f:
            f.write(detailed_findings_html)
        print(f"✓ Detailed findings HTML saved: {detailed_findings_html_path}")

        # 7. Convert detailed findings report to PDF (PRIMARY COMPREHENSIVE REPORT)
        print("→ Converting detailed findings report to PDF...")
        pdf_path = os.path.join(report_dir, "pentest_report_detailed.pdf")
        pdf_success = False
        try:
            pdf_success = convert_html_to_pdf(detailed_findings_html, pdf_path)
            print(f"✓ Detailed findings PDF generated: {pdf_path}")
        except Exception as pdf_error:
            print(f"⚠ Detailed findings PDF conversion failed: {pdf_error}")
            print("  Continuing with other formats...")

        # 8. Also convert legacy detailed report to HTML (for web viewing)
        print("→ Converting legacy detailed report to HTML...")
        html_content = convert_markdown_to_html(markdown_content, f"Detailed Penetration Testing Report - {job.target}")
        html_path = os.path.join(report_dir, "pentest_report_legacy.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✓ Legacy HTML report saved: {html_path}")

        # 9. Convert detailed findings report to DOCX
        print("→ Converting detailed findings report to DOCX...")
        docx_path = os.path.join(report_dir, "pentest_report_detailed.docx")
        docx_success = False
        try:
            docx_success = convert_markdown_to_docx(detailed_findings_markdown, docx_path)
            print(f"✓ Detailed findings DOCX generated: {docx_path}")
        except Exception as docx_error:
            print(f"⚠ DOCX conversion failed: {docx_error}")
            print("  Continuing with other formats...")

        # 10. Save JSON data
        print("→ Saving JSON data...")
        json_path = os.path.join(report_dir, "pentest_data.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(all_phases_data, f, indent=2, default=str)
        print(f"✓ JSON data saved: {json_path}")

        # 11. Create raw outputs ZIP using OutputManager
        print("→ Creating evidence archive...")
        output_manager = get_output_manager(job.id)
        zip_path = output_manager.create_evidence_archive()
        if not zip_path:
            # Fallback to legacy ZIP creation if OutputManager fails
            print("  ⚠ OutputManager archive failed, using legacy method...")
            zip_path = create_raw_outputs_zip(job, all_phases_data)

        # Update phase data
        phase.data = {
            # Executive summary reports
            'summary_markdown': summary_md_path,
            'summary_html': summary_html_path,
            'summary_pdf': summary_pdf_path if summary_pdf_success else None,

            # Detailed findings reports (NEW - PRIMARY REPORTS)
            'detailed_findings_markdown': detailed_findings_md_path,
            'detailed_findings_html': detailed_findings_html_path,
            'detailed_findings_pdf': pdf_path if pdf_success else None,
            'detailed_findings_docx': docx_path if docx_success else None,

            # Legacy detailed reports (for backward compatibility)
            'legacy_markdown': markdown_path,
            'legacy_html': html_path,

            # Data and evidence
            'json_data': json_path,
            'raw_outputs_zip': zip_path,

            # Statistics
            'findings_extracted': findings_count,
            'findings_enhanced': enhanced_count,
            'findings_summary': summary_data,

            # Status flags
            'report_generated': True,
            'summary_pdf_generated': summary_pdf_success,
            'detailed_pdf_generated': pdf_success,
            'detailed_docx_generated': docx_success,
            'generation_timestamp': datetime.now().isoformat()
        }
        phase.status = "success"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)

        print("\n" + "="*60)
        print("REPORT GENERATION COMPLETED")
        print("="*60)
        print("\n📊 EXECUTIVE SUMMARY REPORTS:")
        print(f"  → Markdown: {summary_md_path}")
        print(f"  → HTML: {summary_html_path}")
        if summary_pdf_success:
            print(f"  → PDF: {summary_pdf_path}")
        else:
            print(f"  ⚠ PDF: Failed to generate")

        print("\n📋 DETAILED FINDINGS REPORTS (PRIMARY):")
        print(f"  → Markdown: {detailed_findings_md_path}")
        print(f"  → HTML: {detailed_findings_html_path}")
        if pdf_success:
            print(f"  → PDF: {pdf_path}")
        else:
            print(f"  ⚠ PDF: Failed to generate")
        if docx_success:
            print(f"  → DOCX: {docx_path}")
        else:
            print(f"  ⚠ DOCX: Failed to generate")

        print("\n📦 DATA & EVIDENCE:")
        print(f"  → JSON: {json_path}")
        print(f"  → Raw Outputs: {zip_path}")

        print("\n📈 STATISTICS:")
        print(f"  → Findings Extracted: {findings_count}")
        print(f"  → Findings Enhanced with RAG: {enhanced_count}")
        print(f"  → Critical: {summary_data.get('critical_findings', 0)}")
        print(f"  → High: {summary_data.get('high_findings', 0)}")
        print(f"  → Medium: {summary_data.get('medium_findings', 0)}")
        print(f"  → Low: {summary_data.get('low_findings', 0)}")
        print("="*60 + "\n")

        return phase

    except Exception as e:
        import traceback
        error_msg = str(e)
        trace = traceback.format_exc()

        print(f"\n✗ Report generation failed: {error_msg}")
        print(trace)

        phase.data = {
            "error": error_msg,
            "traceback": trace
        }
        phase.status = "failed"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)

        return phase
