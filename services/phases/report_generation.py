# autosentou/services/phases/report_generation.py
import os
import json
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
from autosentou.models import Phase, Job


def generate_markdown_report(job: Job, all_phases_data: Dict[str, Any]) -> str:
    """
    Generate a comprehensive markdown report based on all pentesting phases.
    """
    target = job.target
    report_date = datetime.utcnow().strftime("%Y-%m-%d")
    
    # Start building the markdown report
    markdown_content = f"""# Penetration Testing Report

**Target:** {target}  
**Date:** {report_date}  
**Job ID:** {job.id}  
**Status:** {job.status}

---

## Executive Summary

This report presents the findings of an automated penetration test conducted on {target}. The assessment included information gathering, vulnerability analysis, web enumeration, SQL injection testing, and brute force testing.

### Key Findings

"""
    
    # Add executive summary based on findings
    total_vulns = 0
    high_risk_findings = 0
    successful_logins = 0
    vulnerable_endpoints = 0
    
    # Count findings from each phase
    if 'vulnerability_analysis' in all_phases_data:
        vuln_data = all_phases_data['vulnerability_analysis']
        total_vulns = vuln_data.get('cve_analysis', {}).get('total_vulns', 0)
        high_risk_findings = vuln_data.get('cve_analysis', {}).get('high_severity', 0)
    
    if 'sqli_testing' in all_phases_data:
        sqli_data = all_phases_data['sqli_testing']
        vulnerable_endpoints = sqli_data.get('total_vulnerable', 0)
    
    if 'brute_force_testing' in all_phases_data:
        bf_data = all_phases_data['brute_force_testing']
        successful_logins = bf_data.get('total_successful_logins', 0)
    
    markdown_content += f"""
- **Total Vulnerabilities Found:** {total_vulns}
- **High Risk Findings:** {high_risk_findings}
- **SQL Injection Vulnerabilities:** {vulnerable_endpoints}
- **Successful Brute Force Attacks:** {successful_logins}

---

## Information Gathering

"""
    
    # Add information gathering results
    if 'info_gathering' in all_phases_data:
        info_data = all_phases_data['info_gathering']
        nmap_data = info_data.get('nmap', {})
        
        markdown_content += f"""
### Network Scan Results

**Target:** {info_data.get('target', target)}

#### Open Ports and Services

"""
        
        for service in nmap_data.get('parsed_ports', []):
            markdown_content += f"""
- **Port {service.get('port')}** ({service.get('proto')}) - {service.get('service')} {service.get('version')} - {service.get('state')}
"""
        
        # Add whois information if available
        whois_data = info_data.get('whois', {})
        if whois_data.get('raw'):
            markdown_content += f"""
### WHOIS Information

```
{whois_data.get('raw', '')[:500]}...
```

"""
    
    # Add vulnerability analysis results
    if 'vulnerability_analysis' in all_phases_data:
        vuln_data = all_phases_data['vulnerability_analysis']
        markdown_content += f"""
## Vulnerability Analysis

### CVE Analysis Results

**Total Vulnerabilities:** {vuln_data.get('cve_analysis', {}).get('total_vulns', 0)}  
**High Severity:** {vuln_data.get('cve_analysis', {}).get('high_severity', 0)}  
**Medium Severity:** {vuln_data.get('cve_analysis', {}).get('medium_severity', 0)}  
**Low Severity:** {vuln_data.get('cve_analysis', {}).get('low_severity', 0)}

#### Detailed Vulnerabilities

"""
        
        for vuln in vuln_data.get('cve_analysis', {}).get('vulnerabilities', []):
            markdown_content += f"""
**{vuln.get('service', 'Unknown Service')}** (Port {vuln.get('port', 'Unknown')})
- **Severity:** {vuln.get('severity', 'Unknown')}
- **Description:** {vuln.get('description', 'No description available')}
- **CVE References:** {', '.join(vuln.get('cve_references', []))}
- **CVSS Score:** {vuln.get('cvss_score', 'N/A')}

"""
    
    # Add web enumeration results
    if 'web_enumeration' in all_phases_data:
        web_data = all_phases_data['web_enumeration']
        markdown_content += f"""
## Web Enumeration

### Directory Discovery Results

**Target URL:** {web_data.get('target_url', 'N/A')}  
**Total Paths Discovered:** {web_data.get('dirsearch_results', {}).get('total_paths', 0)}  
**High Risk Paths:** {len(web_data.get('ai_analysis', {}).get('high_risk_paths', []))}  
**Medium Risk Paths:** {len(web_data.get('ai_analysis', {}).get('medium_risk_paths', []))}

#### High Risk Discoveries

"""
        
        for path in web_data.get('ai_analysis', {}).get('high_risk_paths', []):
            markdown_content += f"""
- **{path.get('url', 'Unknown URL')}** (Status: {path.get('status', 'Unknown')})
  - **Risk Level:** {path.get('risk_level', 'Unknown')}
  - **Matched Patterns:** {', '.join(path.get('matched_patterns', []))}
  - **AI Recommendation:** {path.get('ai_recommendation', 'No recommendation')}

"""
    
    # Add SQL injection testing results
    if 'sqli_testing' in all_phases_data:
        sqli_data = all_phases_data['sqli_testing']
        markdown_content += f"""
## SQL Injection Testing

### Test Results

**Endpoints Tested:** {sqli_data.get('total_tested', 0)}  
**Vulnerable Endpoints:** {sqli_data.get('total_vulnerable', 0)}

#### Vulnerable Endpoints

"""
        
        for vuln_endpoint in sqli_data.get('vulnerable_endpoints', []):
            markdown_content += f"""
- **{vuln_endpoint.get('url', 'Unknown URL')}**
  - **Injection Type:** {vuln_endpoint.get('injection_type', 'Unknown')}
  - **Confidence:** {vuln_endpoint.get('confidence', 'Unknown')}
  - **Payloads:** {', '.join(vuln_endpoint.get('payloads', [])[:3])}

"""
    
    # Add brute force testing results
    if 'brute_force_testing' in all_phases_data:
        bf_data = all_phases_data['brute_force_testing']
        markdown_content += f"""
## Brute Force Testing

### Test Results

**Endpoints Tested:** {bf_data.get('total_endpoints_tested', 0)}  
**Successful Logins:** {bf_data.get('total_successful_logins', 0)}

#### Successful Login Attempts

"""
        
        for login in bf_data.get('successful_logins', []):
            markdown_content += f"""
- **Username:** {login.get('username', 'Unknown')} | **Password:** {login.get('password', 'Unknown')}

"""
    
    # Add recommendations and conclusion
    markdown_content += f"""
## Recommendations

Based on the findings of this penetration test, the following recommendations are made:

1. **Immediate Actions Required:**
   - Address all high-severity vulnerabilities immediately
   - Implement proper input validation to prevent SQL injection
   - Strengthen authentication mechanisms

2. **Security Improvements:**
   - Regular security updates and patch management
   - Implement web application firewall (WAF)
   - Conduct regular security assessments

3. **Monitoring and Maintenance:**
   - Implement continuous security monitoring
   - Regular penetration testing
   - Security awareness training for staff

## Conclusion

This automated penetration test identified {total_vulns} vulnerabilities and {successful_logins} successful brute force attacks. Immediate action is required to address the identified security issues.

---

**Report Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Generated by:** Automated Penetration Testing Tool
"""
    
    return markdown_content


def convert_markdown_to_pdf(markdown_content: str, output_path: str) -> bool:
    """
    Convert markdown content to PDF using pandoc with comprehensive options.
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write markdown to temporary file
        temp_md = output_path.replace('.pdf', '.md')
        with open(temp_md, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Try multiple PDF engines in order of preference
        pdf_engines = ['xelatex', 'pdflatex', 'lualatex']
        success = False
        
        for engine in pdf_engines:
            try:
                # Enhanced pandoc command with better options
                cmd = [
                    'pandoc',
                    temp_md,
                    '-o', output_path,
                    f'--pdf-engine={engine}',
                    '--template=default',
                    '--variable', 'geometry:margin=1in',
                    '--variable', 'fontsize=11pt',
                    '--variable', 'documentclass=article',
                    '--variable', 'colorlinks=true',
                    '--variable', 'linkcolor=blue',
                    '--variable', 'urlcolor=blue',
                    '--variable', 'toccolor=black',
                    '--toc',  # Table of contents
                    '--toc-depth=3',
                    '--number-sections',  # Number sections
                    '--highlight-style=tango',  # Code highlighting
                    '--metadata', 'title=Penetration Testing Report',
                    '--metadata', 'author=Automated Pentesting Tool',
                    '--metadata', 'date=' + datetime.utcnow().strftime('%Y-%m-%d'),
                    '--standalone',  # Standalone document
                    '--self-contained',  # Self-contained HTML
                    '--css=style.css' if os.path.exists('style.css') else '',
                ]
                
                # Remove empty CSS option if no style file exists
                cmd = [arg for arg in cmd if arg]
                
                print(f"Converting to PDF using {engine}...")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0 and os.path.exists(output_path):
                    success = True
                    print(f"PDF generated successfully using {engine}")
                    break
                else:
                    print(f"Failed with {engine}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                print(f"Timeout with {engine}")
                continue
            except Exception as e:
                print(f"Error with {engine}: {e}")
                continue
        
        # If all engines failed, try basic conversion
        if not success:
            print("Trying basic pandoc conversion...")
            basic_cmd = [
                'pandoc',
                temp_md,
                '-o', output_path,
                '--pdf-engine=pdflatex',
                '--standalone'
            ]
            
            result = subprocess.run(basic_cmd, capture_output=True, text=True, timeout=60)
            success = result.returncode == 0 and os.path.exists(output_path)
        
        # Clean up temporary file
        if os.path.exists(temp_md):
            os.remove(temp_md)
        
        return success
        
    except Exception as e:
        print(f"Error converting markdown to PDF: {e}")
        return False


def convert_markdown_to_html(markdown_content: str, output_path: str) -> bool:
    """
    Convert markdown content to HTML as a fallback.
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write markdown to temporary file
        temp_md = output_path.replace('.html', '.md')
        with open(temp_md, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Convert to HTML using pandoc
        cmd = [
            'pandoc',
            temp_md,
            '-o', output_path,
            '--standalone',
            '--self-contained',
            '--toc',
            '--toc-depth=3',
            '--number-sections',
            '--highlight-style=tango',
            '--metadata', 'title=Penetration Testing Report',
            '--metadata', 'author=Automated Pentesting Tool',
            '--metadata', 'date=' + datetime.utcnow().strftime('%Y-%m-%d'),
            '--css=style.css' if os.path.exists('style.css') else '',
        ]
        
        # Remove empty CSS option if no style file exists
        cmd = [arg for arg in cmd if arg]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        # Clean up temporary file
        if os.path.exists(temp_md):
            os.remove(temp_md)
        
        return result.returncode == 0 and os.path.exists(output_path)
        
    except Exception as e:
        print(f"Error converting markdown to HTML: {e}")
        return False


def run_report_generation_phase(db_session, job: Job, all_phases_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Run report generation phase to create comprehensive markdown and PDF reports.
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
        print("Starting report generation...")
        
        # Create reports directory
        reports_dir = f"reports/{job.id}"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate markdown report
        markdown_content = generate_markdown_report(job, all_phases_data)
        
        # Save markdown report
        markdown_path = os.path.join(reports_dir, f"report_{job.id}.md")
        with open(markdown_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Convert to PDF
        pdf_path = os.path.join(reports_dir, f"report_{job.id}.pdf")
        pdf_success = convert_markdown_to_pdf(markdown_content, pdf_path)
        
        # Convert to HTML as fallback
        html_path = os.path.join(reports_dir, f"report_{job.id}.html")
        html_success = convert_markdown_to_html(markdown_content, html_path)
        
        # Prepare results
        report_data = {
            'target': job.target,
            'markdown_path': markdown_path,
            'pdf_path': pdf_path if pdf_success else None,
            'html_path': html_path if html_success else None,
            'pdf_generation_success': pdf_success,
            'html_generation_success': html_success,
            'report_size': len(markdown_content),
            'generation_timestamp': datetime.utcnow().isoformat(),
        }
        
        phase.data = report_data
        phase.status = "success"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        
        print(f"Report generation completed. Markdown: {markdown_path}, PDF: {pdf_path if pdf_success else 'Failed'}")
        return phase
        
    except Exception as e:
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        print(f"Report generation failed: {str(e)}")
        return phase
