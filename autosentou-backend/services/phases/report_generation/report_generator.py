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

        # 1. Generate markdown report with dynamic numbering
        print("→ Generating markdown report with dynamic section numbering...")
        markdown_content = generate_markdown_report(job, all_phases_data)

        # Save markdown
        markdown_path = os.path.join(report_dir, "pentest_report.md")
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"✓ Markdown report saved: {markdown_path}")

        # 2. Convert to simple HTML
        print("→ Converting to clean HTML...")
        html_content = convert_markdown_to_html(markdown_content, f"Penetration Testing Report - {job.target}")

        # Save HTML
        html_path = os.path.join(report_dir, "pentest_report.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✓ HTML report saved: {html_path}")

        # 3. Convert to PDF
        print("→ Converting to PDF...")
        pdf_path = os.path.join(report_dir, "pentest_report.pdf")
        pdf_success = False
        try:
            pdf_success = convert_html_to_pdf(html_content, pdf_path)
        except Exception as pdf_error:
            print(f"⚠ PDF conversion failed: {pdf_error}")
            print("  Continuing with other formats...")

        # 4. Convert to DOCX
        print("→ Converting to DOCX...")
        docx_path = os.path.join(report_dir, "pentest_report.docx")
        docx_success = False
        try:
            docx_success = convert_markdown_to_docx(markdown_content, docx_path)
        except Exception as docx_error:
            print(f"⚠ DOCX conversion failed: {docx_error}")
            print("  Continuing with other formats...")

        # 5. Save JSON data
        print("→ Saving JSON data...")
        json_path = os.path.join(report_dir, "pentest_data.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(all_phases_data, f, indent=2, default=str)
        print(f"✓ JSON data saved: {json_path}")

        # 6. Create raw outputs ZIP using OutputManager
        print("→ Creating evidence archive...")
        output_manager = get_output_manager(job.id)
        zip_path = output_manager.create_evidence_archive()
        if not zip_path:
            # Fallback to legacy ZIP creation if OutputManager fails
            print("  ⚠ OutputManager archive failed, using legacy method...")
            zip_path = create_raw_outputs_zip(job, all_phases_data)

        # Update phase data
        phase.data = {
            'markdown_report': markdown_path,
            'html_report': html_path,
            'pdf_report': pdf_path if pdf_success else None,
            'docx_report': docx_path if docx_success else None,
            'json_data': json_path,
            'raw_outputs_zip': zip_path,
            'report_generated': True,
            'pdf_generated': pdf_success,
            'docx_generated': docx_success,
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
        print(f"→ Markdown: {markdown_path}")
        print(f"→ HTML: {html_path}")
        if pdf_success:
            print(f"→ PDF: {pdf_path}")
        else:
            print(f"⚠ PDF: Failed to generate")
        if docx_success:
            print(f"→ DOCX: {docx_path}")
        else:
            print(f"⚠ DOCX: Failed to generate")
        print(f"→ JSON: {json_path}")
        print(f"→ Raw Outputs: {zip_path}")
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
