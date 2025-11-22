"""
Findings Populator Service
Extracts vulnerability findings from all scan phases and stores them in the database
with intelligent KB-first matching and AI-powered categorization fallback
"""
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from models import Finding, Job
from services.ai.vulnerability_categorizer import get_categorizer
from services.ai.ai_categorizer import ai_categorize_finding, ai_categorize_findings_batch
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
        self.last_ai_call_time = 0  # Track last AI API call for rate limiting
        self.skipped_recategorizations = 0  # Track number of skipped re-categorizations

    def _batch_intelligent_categorize(self, findings_data: List[Tuple[Finding, Dict[str, Any]]]) -> int:
        """
        Batch categorize multiple findings efficiently.

        Workflow:
        1. Try KB matching for all findings first (fast, no cost)
        2. Batch AI categorization for unmatched findings (20 per API call)
        3. Add AI-categorized findings to KB for future reference

        Args:
            findings_data: List of (Finding, finding_data) tuples

        Returns:
            Number of successfully categorized findings
        """
        if not findings_data:
            return 0

        categorized_count = 0
        unmatched = []

        # Step 1: Try KB matching for all findings first
        logger.info(f"  [Batch] Trying KB matching for {len(findings_data)} findings...")
        for finding, data in findings_data:
            threshold = kb_service.get_similarity_threshold(self.db_session)
            match_result = kb_service.match_finding_to_kb(
                db=self.db_session,
                finding_description=data.get('description', ''),
                finding_title=data.get('title', ''),
                threshold=threshold
            )

            if match_result and match_result['matched']:
                # Good KB match found!
                kb_entry = match_result['kb_entry']
                similarity_score = match_result['similarity_score']

                success = kb_service.link_finding_to_kb(
                    db=self.db_session,
                    finding_id=finding.id,
                    kb_id=kb_entry.id,
                    similarity_score=similarity_score
                )

                if success:
                    self.kb_matches += 1
                    categorized_count += 1
                    logger.debug(f"    ✓ KB Match: {kb_entry.name} (score: {similarity_score:.2f})")
            else:
                # No KB match - queue for AI categorization
                unmatched.append((finding, data))

        if unmatched:
            logger.info(f"  [Batch] {len(unmatched)} findings need AI categorization")

            # Step 2: Batch AI categorization (20 findings per API call)
            BATCH_SIZE = 20
            for i in range(0, len(unmatched), BATCH_SIZE):
                batch = unmatched[i:i + BATCH_SIZE]
                batch_findings = [finding for finding, _ in batch]
                batch_data = [data for _, data in batch]

                # Rate limiting
                time_since_last_call = time.time() - self.last_ai_call_time
                if time_since_last_call < 6:
                    sleep_time = 6 - time_since_last_call
                    logger.info(f"    ⏱ Rate limit: waiting {sleep_time:.1f}s before batch AI call...")
                    time.sleep(sleep_time)

                self.last_ai_call_time = time.time()

                # Batch AI call
                logger.info(f"    🤖 Batch AI categorizing {len(batch)} findings...")
                ai_results = ai_categorize_findings_batch(batch_data)

                # Step 3: Apply AI results and add to KB
                for (finding, data), ai_result in zip(batch, ai_results):
                    if ai_result:
                        # Update finding with AI categorization
                        finding.severity = ai_result.get('severity', 'Medium')
                        finding.owasp_category = ai_result.get('owasp_category', 'A05:2021 - Security Misconfiguration')
                        if ai_result.get('remediation'):
                            finding.remediation = ai_result['remediation']
                        finding.is_categorized = True

                        self.db_session.flush()

                        # Add to KB for future reference
                        kb_entry = kb_service.create_kb_from_finding(
                            db=self.db_session,
                            finding_data=data,
                            ai_categorization=ai_result
                        )

                        if kb_entry:
                            kb_service.link_finding_to_kb(
                                db=self.db_session,
                                finding_id=finding.id,
                                kb_id=kb_entry.id,
                                similarity_score=1.0
                            )

                        self.ai_categorizations += 1
                        categorized_count += 1
                        logger.debug(f"    ✓ AI: {ai_result['severity']} / {ai_result.get('category', 'N/A')}")
                    else:
                        finding.is_categorized = False
                        logger.warning(f"    ✗ Failed to categorize: {data.get('title', 'Unknown')}")

        return categorized_count

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

            # Rate limiting: Gemini allows 10 req/min = 1 request every 6 seconds
            # Add delay to avoid hitting rate limit
            time_since_last_call = time.time() - self.last_ai_call_time
            if time_since_last_call < 6:  # 6 seconds between requests
                sleep_time = 6 - time_since_last_call
                logger.info(f"  ⏱ Rate limit: waiting {sleep_time:.1f}s before AI call...")
                time.sleep(sleep_time)

            self.last_ai_call_time = time.time()
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
        deleted_count = self.db_session.query(Finding).filter(Finding.job_id == self.job.id).delete()
        self.db_session.commit()
        logger.info(f"  Cleared {deleted_count} existing findings")

        total_findings = 0

        # Extract findings from each phase
        logger.info("  Extracting CVE findings...")
        cve_count = self._extract_cve_findings()
        total_findings += cve_count
        logger.info(f"    → {cve_count} CVE findings")

        logger.info("  Extracting Web Analysis findings...")
        web_count = self._extract_web_analysis_findings()  # Real vulnerabilities from AI analysis
        total_findings += web_count
        logger.info(f"    → {web_count} Web Analysis findings")

        logger.info("  Extracting SQLi findings...")
        sqli_count = self._extract_sqli_findings()
        total_findings += sqli_count
        logger.info(f"    → {sqli_count} SQLi findings")

        logger.info("  Extracting Auth findings...")
        auth_count = self._extract_auth_findings()
        total_findings += auth_count
        logger.info(f"    → {auth_count} Auth findings")
        # total_findings += self._extract_web_exposure_findings()  # REMOVED: Path analysis is for prioritization, not findings
        # Web enumeration + path analyzer are used to prioritize paths for web_analysis
        # Only web_analysis (which actually tests paths) should create findings

        self.db_session.commit()

        logger.info(f"✓ Populated {total_findings} findings for job {self.job.id}")
        logger.info(f"  ⚡ {self.skipped_recategorizations} findings skipped re-categorization (already AI-categorized)")
        logger.info(f"  📚 {self.kb_matches} findings matched to existing KB entries")
        logger.info(f"  🤖 {self.ai_categorizations} findings AI-categorized and added to KB")
        uncategorized = total_findings - self.skipped_recategorizations - self.kb_matches - self.ai_categorizations
        logger.info(f"  ❌ {uncategorized} findings uncategorized")
        return total_findings

    def _extract_cve_findings(self) -> int:
        """Extract CVE and exploit-based vulnerabilities from vulnerability analysis phase."""
        vuln_data = self.phases_data.get('vulnerability_analysis', {})

        # ✅ FIXED: Read from vulnerability_results which contains the formatted vulnerabilities
        # (both CVE-based and exploit_available types)
        vuln_results = vuln_data.get('vulnerability_results', [])

        logger.info(f"[DEBUG] Vulnerability analysis keys: {list(vuln_data.keys())}")
        logger.info(f"[DEBUG] vulnerability_results has {len(vuln_results)} services")

        findings_count = 0

        for service_result in vuln_results:
            service = service_result.get('service', 'Unknown')
            version = service_result.get('version', '')
            port = service_result.get('port', 0)
            vulnerabilities = service_result.get('vulnerabilities', [])

            logger.info(f"[DEBUG]   Service {service} {version}:{port} has {len(vulnerabilities)} vulnerabilities")

            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'cve')

                if vuln_type == 'exploit_available':
                    # Handle exploit-based vulnerability
                    exploit_count = vuln.get('exploit_count', 0)
                    title = f"Public Exploits for {service} {version}".strip()

                    finding_data = {
                        'title': title,
                        'description': vuln.get('description', ''),
                        'finding_type': 'exploit_available',
                        'severity': vuln.get('severity', 'High')
                    }

                    # Use pre-defined OWASP category for exploit-based findings
                    severity = vuln.get('severity', 'High')
                    owasp_category = vuln.get('owasp_category', 'A06:2021 – Vulnerable and Outdated Components')

                    # Create Finding object
                    finding = Finding(
                        job_id=self.job.id,
                        title=title,
                        description=vuln.get('description', 'Public exploits available for this service version'),
                        finding_type='cve',  # Use 'cve' for database compatibility
                        severity=severity,
                        owasp_category=owasp_category,
                        service=service,
                        port=port,
                        cve_id='N/A',
                        remediation=vuln.get('mitigation', 'Update to latest version'),
                        evidence={
                            'exploit_count': exploit_count,
                            'exploit_evidence': vuln.get('exploit_evidence', []),
                            'type': 'exploit_available'
                        }
                    )
                else:
                    # Handle CVE-based vulnerability
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
                        remediation=vuln.get('mitigation', 'Update to latest version'),
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

        logger.info(f"[DEBUG] Successfully extracted {findings_count} CVE/exploit findings")
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

    def _extract_web_analysis_findings(self) -> int:
        """
        Extract findings from Web Analysis phase (Playwright + LLM analysis).
        These findings include screenshots and detailed vulnerability analysis.
        """
        web_analysis_data = self.phases_data.get('web_analysis', {})
        findings_list = web_analysis_data.get('findings', [])

        logger.info(f"[DEBUG] Web analysis data keys: {list(web_analysis_data.keys())}")
        logger.info(f"[DEBUG] Web analysis findings count in data: {len(findings_list)}")

        findings_count = 0

        for web_finding in findings_list:
            # Extract finding details
            title = web_finding.get('title', web_finding.get('vector', 'Web Vulnerability'))
            description = web_finding.get('description', web_finding.get('evidence', ''))
            url = web_finding.get('url', '')
            vector = web_finding.get('vector', 'Unknown')
            owasp_cat = web_finding.get('owasp_category', 'A05:2021 - Security Misconfiguration')
            risk_level = web_finding.get('risk_level', 'Medium')

            # Prepare finding data for categorization
            finding_data = {
                'title': title,
                'description': description,
                'finding_type': 'web_analysis',
                'severity': risk_level,
                'vector': vector,
                'owasp_category': owasp_cat
            }

            # Map risk_level to severity
            severity_mapping = {
                'High': 'High',
                'Medium': 'Medium',
                'Low': 'Low',
                'Critical': 'Critical'
            }
            severity = severity_mapping.get(risk_level, 'Medium')

            # Create Finding object
            finding = Finding(
                job_id=self.job.id,
                title=f"{vector} at {url}" if url else title,
                description=description,
                finding_type='web_analysis',
                severity=severity,
                owasp_category=owasp_cat,
                url=url,
                remediation=web_finding.get('remediation', 'Review and fix the identified vulnerability'),
                poc=web_finding.get('evidence', ''),
                evidence={
                    'finding_id': web_finding.get('id'),
                    'vector': vector,
                    'method': web_finding.get('method'),
                    'parameters': web_finding.get('parameters', []),
                    'payload': web_finding.get('payload', []),
                    'affected_urls': web_finding.get('affected_urls', []),
                    'page_type': web_finding.get('page_type'),
                    'screenshot_path': web_finding.get('screenshot_path'),  # IMPORTANT: Include screenshot
                }
            )

            self.db_session.add(finding)
            self.db_session.flush()  # Flush to get the finding ID

            # ✅ SKIP AI RE-CATEGORIZATION for web_analysis findings!
            # They're already AI-categorized during web_analysis phase with full page context
            # Just try KB matching for future optimization (no AI fallback)
            if web_finding.get('owasp_category'):
                threshold = kb_service.get_similarity_threshold(self.db_session)
                match_result = kb_service.match_finding_to_kb(
                    db=self.db_session,
                    finding_description=finding_data.get('description', ''),
                    finding_title=finding_data.get('title', ''),
                    threshold=threshold
                )

                if match_result and match_result['matched']:
                    # Link to KB for tracking (optional)
                    kb_service.link_finding_to_kb(
                        db=self.db_session,
                        finding_id=finding.id,
                        kb_id=match_result['kb_entry'].id,
                        similarity_score=match_result['similarity_score']
                    )
                    self.kb_matches += 1

                self.skipped_recategorizations += 1
                finding.is_categorized = True
            else:
                # Fallback: If somehow missing OWASP category, use intelligent categorization
                self._intelligent_categorize_and_link(finding, finding_data)

            findings_count += 1

        logger.info(f"[DEBUG] Successfully extracted {findings_count} web analysis findings ({self.skipped_recategorizations} skipped re-categorization)")
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
