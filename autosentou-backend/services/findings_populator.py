"""
Findings Populator Service
Extracts vulnerability findings from all scan phases and stores them in the database
with intelligent KB-first matching and AI-powered categorization fallback
"""
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from models import Finding, Job
from services.ai.vulnerability_categorizer import get_categorizer
from services.ai.ai_categorizer import ai_categorize_finding
import services.knowledge_base_service as kb_service

logger = logging.getLogger(__name__)


class FindingsPopulator:
    """
    Extracts findings from scan phase data and populates the findings table.
    """

    def __init__(self, db_session: Session, job: Job, phases_data: Dict[str, Any]):
        self.db_session = db_session
        self.job = job
        self.phases_data = phases_data
        self.categorizer = get_categorizer()
        self.kb_matches = 0  # Track number of KB matches
        self.ai_categorizations = 0  # Track number of AI categorizations

    def _intelligent_categorize_and_link(self, finding: Finding, finding_data: Dict[str, Any]) -> bool:
        """
        Intelligent categorization flow:
        1. Search KB using RAG for similar vulnerabilities
        2. If good match found (similarity >= threshold) → Use KB categorization
        3. If no match → Use AI to categorize + Add to KB for future reference
        4. Link finding to KB entry

        Args:
            finding: The Finding object to categorize
            finding_data: Dictionary with finding details for AI categorization

        Returns:
            True if categorized successfully, False otherwise
        """
        try:
            # Step 1: Search KB using RAG
            threshold = kb_service.get_similarity_threshold(self.db_session)

            match_result = kb_service.match_finding_to_kb(
                db=self.db_session,
                finding_description=finding.description,
                finding_title=finding.title,
                threshold=threshold
            )

            # Step 2: If good match found, use KB categorization
            if match_result and match_result['matched']:
                kb_entry = match_result['kb_entry']
                similarity_score = match_result['similarity_score']

                # Link the finding to the KB entry
                success = kb_service.link_finding_to_kb(
                    db=self.db_session,
                    finding_id=finding.id,
                    kb_id=kb_entry.id,
                    similarity_score=similarity_score
                )

                if success:
                    self.kb_matches += 1
                    logger.info(f"  ✓ KB Match: {kb_entry.name} (score: {similarity_score:.2f})")
                    return True

            # Step 3: No KB match - Use AI categorization
            logger.info(f"  → No KB match, using AI categorization...")
            ai_result = ai_categorize_finding(finding_data)

            if not ai_result:
                logger.warning(f"  ✗ AI categorization failed")
                finding.is_categorized = False
                return False

            # Update finding with AI categorization
            finding.severity = ai_result.get('severity', 'Medium')
            finding.owasp_category = ai_result.get('owasp_category', 'A05:2021 - Security Misconfiguration')
            if ai_result.get('remediation'):
                finding.remediation = ai_result['remediation']

            self.db_session.flush()  # Flush to save changes

            # Step 4: Add AI-categorized finding to KB for future reference
            kb_entry = kb_service.create_kb_from_finding(
                db=self.db_session,
                finding_data=finding_data,
                ai_categorization=ai_result
            )

            if kb_entry:
                # Link finding to the newly created KB entry
                kb_service.link_finding_to_kb(
                    db=self.db_session,
                    finding_id=finding.id,
                    kb_id=kb_entry.id,
                    similarity_score=1.0  # Perfect match since we just created it
                )

                self.ai_categorizations += 1
                logger.info(f"  ✓ AI Categorized + Added to KB: {ai_result['severity']} / {ai_result.get('category', 'N/A')}")
                return True
            else:
                # Even if KB creation failed, we still have AI categorization
                finding.is_categorized = True
                self.ai_categorizations += 1
                logger.info(f"  ✓ AI Categorized: {ai_result['severity']} (KB creation failed)")
                return True

        except Exception as e:
            logger.error(f"  ✗ Categorization error: {e}", exc_info=True)
            finding.is_categorized = False
            return False

    def populate_all_findings(self) -> int:
        """
        Extract and store all findings from all phases.
        Returns the total number of findings stored.
        """
        logger.info(f"Populating findings for job {self.job.id}")

        # Clear existing findings for this job (in case of re-generation)
        self.db_session.query(Finding).filter(Finding.job_id == self.job.id).delete()
        self.db_session.commit()

        total_findings = 0

        # Extract findings from each phase
        total_findings += self._extract_cve_findings()
        total_findings += self._extract_sqli_findings()
        total_findings += self._extract_auth_findings()
        total_findings += self._extract_web_exposure_findings()

        self.db_session.commit()

        logger.info(f"✓ Populated {total_findings} findings for job {self.job.id}")
        logger.info(f"  📚 {self.kb_matches} findings matched to existing KB entries")
        logger.info(f"  🤖 {self.ai_categorizations} findings AI-categorized and added to KB")
        logger.info(f"  ❌ {total_findings - self.kb_matches - self.ai_categorizations} findings uncategorized")
        return total_findings

    def _extract_cve_findings(self) -> int:
        """Extract CVE vulnerabilities from vulnerability analysis phase."""
        vuln_data = self.phases_data.get('vulnerability_analysis', {})
        vuln_results = vuln_data.get('vulnerability_results', [])

        findings_count = 0

        for service_result in vuln_results:
            service = service_result.get('service', 'Unknown')
            port = service_result.get('port', 0)
            vulnerabilities = service_result.get('vulnerabilities', [])

            for vuln in vulnerabilities:
                # Prepare finding data for categorization
                finding_data = {
                    'title': vuln.get('cve_id', 'CVE Vulnerability'),
                    'description': vuln.get('description', ''),
                    'finding_type': 'cve',
                    'cve_id': vuln.get('cve_id'),
                    'cvss_score': vuln.get('cvss_score'),
                    'severity': vuln.get('severity')
                }

                # Categorize
                severity, owasp_category = self.categorizer.categorize(finding_data)

                # Create Finding object
                finding = Finding(
                    job_id=self.job.id,
                    title=vuln.get('cve_id', 'CVE Vulnerability'),
                    description=vuln.get('description', 'No description available'),
                    finding_type='cve',
                    severity=severity,
                    owasp_category=owasp_category,
                    service=service,
                    port=port,
                    cve_id=vuln.get('cve_id'),
                    cvss_score=vuln.get('cvss_score'),
                    remediation=vuln.get('remediation', 'Update to latest version'),
                    evidence={
                        'exploit_urls': vuln.get('exploit_urls', []),
                        'exploitdb_id': vuln.get('exploitdb_id'),
                        'references': vuln.get('references', [])
                    }
                )

                self.db_session.add(finding)
                self.db_session.flush()  # Flush to get the finding ID

                # Intelligent categorization: KB match or AI categorization
                self._intelligent_categorize_and_link(finding, finding_data)

                findings_count += 1

        logger.info(f"Extracted {findings_count} CVE findings")
        return findings_count

    def _extract_sqli_findings(self) -> int:
        """Extract SQL injection vulnerabilities."""
        sqli_data = self.phases_data.get('sqli_testing', {})
        sqli_results = sqli_data.get('sqli_results', [])

        findings_count = 0

        for result in sqli_results:
            if not result.get('vulnerable', False):
                continue

            url = result.get('url', '')
            injection_type = result.get('injection_type', 'SQL Injection')
            parameter = result.get('parameter', '')

            # Prepare finding data for categorization
            finding_data = {
                'title': f'SQL Injection - {injection_type}',
                'description': f'SQL injection vulnerability detected at {url}',
                'finding_type': 'sqli',
                'severity': result.get('severity', 'High')
            }

            # Categorize
            severity, owasp_category = self.categorizer.categorize(finding_data)

            # Create Finding object
            finding = Finding(
                job_id=self.job.id,
                title=f'SQL Injection - {injection_type}',
                description=f'SQL injection vulnerability detected in parameter "{parameter}" at {url}. '
                           f'The application is vulnerable to {injection_type} injection attacks.',
                finding_type='sqli',
                severity=severity,
                owasp_category=owasp_category,
                url=url,
                remediation='Use parameterized queries (prepared statements) instead of string concatenation. '
                           'Implement input validation and sanitization. Consider using an ORM framework.',
                poc=result.get('poc', ''),
                evidence={
                    'injection_type': injection_type,
                    'parameter': parameter,
                    'payload': result.get('payload', ''),
                    'database': result.get('database_info', {}),
                    'confidence': result.get('confidence', 'Unknown')
                }
            )

            self.db_session.add(finding)
            self.db_session.flush()  # Flush to get the finding ID

            # Intelligent categorization: KB match or AI categorization
            self._intelligent_categorize_and_link(finding, finding_data)

            findings_count += 1

        logger.info(f"Extracted {findings_count} SQL injection findings")
        return findings_count

    def _extract_auth_findings(self) -> int:
        """Extract authentication vulnerabilities."""
        auth_data = self.phases_data.get('authentication_testing', {})
        login_tests = auth_data.get('login_response_tests', [])

        findings_count = 0

        for test in login_tests:
            ai_analysis = test.get('ai_analysis', {})

            # Account enumeration
            if ai_analysis.get('account_enumeration_possible', False):
                url = test.get('url', '')
                classification = ai_analysis.get('classification', {})

                finding_data = {
                    'title': 'Account Enumeration Vulnerability',
                    'description': f'Account enumeration possible at {url}',
                    'finding_type': 'authentication',
                    'severity': classification.get('severity', 'Medium')
                }

                severity, owasp_category = self.categorizer.categorize(finding_data)

                finding = Finding(
                    job_id=self.job.id,
                    title='Account Enumeration Vulnerability',
                    description=f'The login page at {url} reveals whether usernames exist through '
                               f'different error messages or response times. This allows attackers to '
                               f'enumerate valid usernames.',
                    finding_type='authentication',
                    severity=severity,
                    owasp_category=owasp_category,
                    url=url,
                    remediation='Implement consistent error messages for both valid and invalid usernames. '
                               'Use generic messages like "Invalid username or password". '
                               'Ensure response times are consistent.',
                    evidence={
                        'response_pattern': ai_analysis.get('response_pattern_analysis', {}),
                        'timing_attack_possible': ai_analysis.get('timing_attack_possible', False),
                        'rate_limiting': test.get('rate_limiting_detected', False)
                    }
                )

                self.db_session.add(finding)
                self.db_session.flush()  # Flush to get the finding ID

                # Intelligent categorization: KB match or AI categorization
                self._intelligent_categorize_and_link(finding, finding_data)

                findings_count += 1

            # Weak security controls
            security_controls = test.get('security_controls', {})
            if not security_controls.get('rate_limiting', False):
                url = test.get('url', '')

                finding_data = {
                    'title': 'Missing Rate Limiting on Login Page',
                    'description': f'No rate limiting detected on login page',
                    'finding_type': 'authentication',
                    'severity': 'Medium'
                }

                severity, owasp_category = self.categorizer.categorize(finding_data)

                finding = Finding(
                    job_id=self.job.id,
                    title='Missing Rate Limiting on Login Page',
                    description=f'The login page at {url} does not implement rate limiting, '
                               f'making it vulnerable to brute force attacks.',
                    finding_type='authentication',
                    severity=severity,
                    owasp_category=owasp_category,
                    url=url,
                    remediation='Implement rate limiting to restrict the number of login attempts per IP address. '
                               'Consider using account lockout mechanisms after multiple failed attempts. '
                               'Implement CAPTCHA after a certain number of failed logins.',
                    evidence={
                        'captcha_present': security_controls.get('captcha', False),
                        'mfa_available': security_controls.get('mfa', False)
                    }
                )

                self.db_session.add(finding)
                self.db_session.flush()  # Flush to get the finding ID

                # Intelligent categorization: KB match or AI categorization
                self._intelligent_categorize_and_link(finding, finding_data)

                findings_count += 1

        logger.info(f"Extracted {findings_count} authentication findings")
        return findings_count

    def _extract_web_exposure_findings(self) -> int:
        """Extract web exposure/misconfiguration findings."""
        web_data = self.phases_data.get('web_enumeration', {})
        path_analysis = web_data.get('path_analysis', {}).get('analysis', {})
        findings_list = path_analysis.get('findings', [])

        findings_count = 0

        for web_finding in findings_list:
            risk = web_finding.get('risk', '').lower()

            # Only store high and critical findings
            if risk not in ['high', 'critical']:
                continue

            path = web_finding.get('clean_path', web_finding.get('path', ''))
            category = web_finding.get('category', 'Web Exposure')

            finding_data = {
                'title': f'{category} - {path}',
                'description': web_finding.get('description', ''),
                'finding_type': 'web_exposure',
                'severity': risk.capitalize()
            }

            severity, owasp_category = self.categorizer.categorize(finding_data)

            # Build base URL
            web_services = web_data.get('web_services', [])
            base_url = web_services[0] if web_services else ''
            full_url = f"{base_url}{path}" if base_url else path

            finding = Finding(
                job_id=self.job.id,
                title=f'{category} Exposed',
                description=web_finding.get('description') or f'{category} found at {path}',
                finding_type='web_exposure',
                severity=severity,
                owasp_category=owasp_category,
                url=full_url,
                remediation='Review and secure exposed resources. Remove unnecessary files and directories. '
                           'Implement proper access controls. Disable directory listing.',
                evidence={
                    'category': category,
                    'path': path,
                    'status_code': web_finding.get('status_code'),
                    'content_length': web_finding.get('content_length')
                }
            )

            self.db_session.add(finding)
            self.db_session.flush()  # Flush to get the finding ID

            # Intelligent categorization: KB match or AI categorization
            self._intelligent_categorize_and_link(finding, finding_data)

            findings_count += 1

        logger.info(f"Extracted {findings_count} web exposure findings")
        return findings_count


def populate_findings_for_job(db_session: Session, job: Job, phases_data: Dict[str, Any]) -> int:
    """
    Convenience function to populate findings for a job.

    Args:
        db_session: Database session
        job: Job object
        phases_data: Dictionary containing all phase data

    Returns:
        Number of findings created
    """
    populator = FindingsPopulator(db_session, job, phases_data)
    return populator.populate_all_findings()
