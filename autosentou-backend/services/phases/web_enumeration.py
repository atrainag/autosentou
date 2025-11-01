"""
services/phases/web_enumeration_v2.py
Refactored Web Enumeration Phase with integrated PathAnalyzer, AuthAnalyzer, and RAG
"""
import os
import re
import requests
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from services.utils.system import run_command
from services.utils.path_analyzer import PathAnalyzer
from services.utils.auth_analyzer import AuthAnalyzer
from services.ai.knowledge_manager import get_knowledge_manager
from models import Phase, Job
from services.utils.output_manager import get_output_manager

logger = logging.getLogger(__name__)

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebEnumerationPhase:
    """
    Comprehensive web enumeration with intelligent analysis.

    Workflow:
    1. Fingerprint web servers (technology stack, security headers)
    2. Directory brute-forcing with feroxbuster
    3. Web crawling with gospider
    4. Intelligent path analysis with PathAnalyzer + RAG
    5. Authentication security analysis with AuthAnalyzer
    6. Attack surface mapping
    """

    def __init__(self, db_session, job: Job):
        self.db = db_session
        self.job = job
        self.output_dir = f"reports/{job.id}/web_enumeration"
        os.makedirs(self.output_dir, exist_ok=True)

        # Initialize analyzers
        self.knowledge_manager = get_knowledge_manager()
        self.path_analyzer = PathAnalyzer(knowledge_manager=self.knowledge_manager)
        self.auth_analyzer = AuthAnalyzer()

        logger.info(f"WebEnumerationPhase initialized for job {job.id}")

    def execute(self, info_data: Dict[str, Any], custom_wordlist: Optional[str] = None) -> Phase:
        """
        Execute web enumeration phase.

        Args:
            info_data: Information gathering phase data
            custom_wordlist: Optional custom wordlist path

        Returns:
            Phase object with results
        """
        phase = Phase(
            job_id=self.job.id,
            phase_name="Web Enumeration",
            data={},
            log_path=None,
            status="ongoing",
        )
        self.db.add(phase)
        self.db.commit()
        self.db.refresh(phase)

        try:
            # Initialize output manager
            output_mgr = get_output_manager(self.job.id)

            logger.info("=" * 80)
            logger.info(f"[Job {self.job.id}] STARTING WEB ENUMERATION PHASE V2")
            logger.info("=" * 80)

            # Step 1: Identify web services
            web_services = self._identify_web_services(info_data)
            if not web_services:
                logger.warning(f"[Job {self.job.id}] No web services detected")
                web_services = self._try_common_ports()

            # Step 2: Server fingerprinting
            logger.info(f"[Job {self.job.id}] === STEP 1: Server Fingerprinting ===")
            fingerprints = self._fingerprint_servers(web_services)

            # Step 3: Directory brute-forcing
            logger.info(f"[Job {self.job.id}] === STEP 2: Directory Brute-Forcing ===")
            bruteforce_results = self._run_directory_bruteforce(web_services, custom_wordlist)
            
            # SAVE DIRSEARCH/FEROXBUSTER OUTPUTS
            if bruteforce_results:
                for idx, result in enumerate(bruteforce_results):
                    if result and isinstance(result, dict):
                        try:
                            dirsearch_paths = output_mgr.save_web_enum_output(
                                tool_name='feroxbuster',
                                raw_output=result.get('raw_output', ''),
                                parsed_data=result
                            )
                            result['saved_files'] = dirsearch_paths
                        except Exception as e:
                            logger.warning(f"Could not save feroxbuster output {idx}: {e}")
        
            # Step 4: Web Crawling
            logger.info(f"[Job {self.job.id}] === STEP 3: Web Crawling ===")
            crawl_results = self._run_web_crawling(web_services, bruteforce_results)
            
            # SAVE GOSPIDER OUTPUT
            if crawl_results:
                for idx, result in enumerate(crawl_results):
                    if result and isinstance(result, dict):
                        try:
                            gospider_paths = output_mgr.save_web_enum_output(
                                tool_name='gospider',
                                raw_output=result.get('raw_output', ''),
                                parsed_data=result
                            )
                            result['saved_files'] = gospider_paths
                        except Exception as e:
                            logger.warning(f"Could not save gospider output {idx}: {e}")

            # Step 5: Merge and analyze paths
            logger.info(f"[Job {self.job.id}] === STEP 4: Path Analysis with RAG ===")
            all_paths = self._merge_discovered_paths(bruteforce_results, crawl_results)
            path_analysis = self._analyze_paths_intelligent(all_paths, web_services[0]['url'] if web_services else '')

            # Step 6: Authentication analysis
            logger.info(f"[Job {self.job.id}] === STEP 5: Authentication Analysis ===")
            login_pages = self._extract_login_pages(all_paths, fingerprints, path_analysis)
            auth_analysis = self._analyze_authentication(login_pages)

            # Step 7: Generate attack surface summary
            logger.info(f"[Job {self.job.id}] === STEP 6: Attack Surface Mapping ===")
            attack_surface = self._generate_attack_surface(path_analysis, auth_analysis, fingerprints)

            # Compile final results WITH FILE PATHS
            results = {
                'web_services_detected': len(web_services) > 0,
                'web_ports_detected': [ws['port'] for ws in web_services],
                'fingerprints': fingerprints,
                'directory_bruteforce': bruteforce_results,
                'crawl_results': crawl_results,
                'server_fingerprints': fingerprints,
                'directory_enumeration': {
                    'total_paths': len(all_paths),
                    'bruteforce_paths': sum(len(r['discovered_paths']) for r in bruteforce_results),
                    'crawled_paths': sum(r.get('total_urls', 0) for r in crawl_results)
                },
                'path_analysis': path_analysis,
                'authentication_analysis': auth_analysis,
                'attack_surface': attack_surface,
                'wordlist_used': custom_wordlist or 'default',
                'timestamp': datetime.now().isoformat(),
                'analysis_version': '2.0'
            }

            # SAVE COMPLETE PHASE DATA
            phase_data_path = output_mgr.save_phase_data('web_enumeration', results)
            results['phase_data_file'] = phase_data_path
            
            phase.data = results
            phase.status = "success"
            phase.updated_at = datetime.now()
            self.db.commit()

            logger.info("=" * 80)
            logger.info(f"[Job {self.job.id}] WEB ENUMERATION PHASE COMPLETED")
            logger.info(f"[Job {self.job.id}] Total paths: {len(all_paths)}")
            logger.info(f"[Job {self.job.id}] Critical findings: {attack_surface['risk_summary']['critical']}")
            logger.info(f"[Job {self.job.id}] High risk findings: {attack_surface['risk_summary']['high']}")
            logger.info("=" * 80)

            return phase

        except Exception as e:
            import traceback
            logger.error(f"[Job {self.job.id}] ✗ Web enumeration failed: {str(e)}", exc_info=True)

            phase.data = {
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            phase.status = "failed"
            phase.updated_at = datetime.now()
            self.db.commit()

            return phase

    def _identify_web_services(self, info_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify web services from nmap results."""
        nmap_data = info_data.get('nmap', {})
        parsed_ports = nmap_data.get('parsed_ports', [])

        web_services = []
        for port_info in parsed_ports:
            service = port_info.get('service', '').lower()
            port = port_info.get('port')
            state = port_info.get('state', '')

            if state == 'open' and service in ['http', 'https', 'http-proxy', 'ssl/http']:
                scheme = 'https' if 'ssl' in service or 'https' in service or port == 443 else 'http'
                web_services.append({
                    'port': port,
                    'service': service,
                    'url': f"{scheme}://{self.job.target}:{port}"
                })

        return web_services

    def _try_common_ports(self) -> List[Dict[str, Any]]:
        """Try common web ports when nmap doesn't detect web services."""
        logger.info(f"[Job {self.job.id}] Trying common web ports...")
        web_services = []

        for port in [80, 443, 8080, 8443]:
            scheme = 'https' if port in [443, 8443] else 'http'
            web_services.append({
                'port': port,
                'service': scheme,
                'url': f"{scheme}://{self.job.target}:{port}"
            })

        return web_services

    def _fingerprint_servers(self, web_services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fingerprint web servers."""
        fingerprints = []

        for web_service in web_services:
            url = web_service['url']
            logger.info(f"[Job {self.job.id}] Fingerprinting {url}...")

            fingerprint = self._fingerprint_single_server(url)
            fingerprints.append(fingerprint)

            # Log interesting findings
            if fingerprint.get('server'):
                logger.info(f"[Job {self.job.id}]   Server: {fingerprint['server']}")
            if fingerprint.get('technologies'):
                tech_names = [t['name'] for t in fingerprint['technologies']]
                logger.info(f"[Job {self.job.id}]   Technologies: {', '.join(tech_names)}")
            if fingerprint.get('cms'):
                logger.info(f"[Job {self.job.id}]   CMS: {fingerprint['cms']}")
            if fingerprint.get('missing_security_headers'):
                count = len(fingerprint['missing_security_headers'])
                logger.warning(f"[Job {self.job.id}]   ⚠️ Missing {count} security headers")

        return fingerprints

    def _fingerprint_single_server(self, url: str) -> Dict[str, Any]:
        """Fingerprint a single web server."""
        return fingerprint_web_server(url)

    def _run_directory_bruteforce(
        self,
        web_services: List[Dict[str, Any]],
        custom_wordlist: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Run directory brute-forcing with feroxbuster."""
        results = []

        for web_service in web_services:
            url = web_service['url']
            logger.info(f"[Job {self.job.id}] Brute-forcing {url}...")

            result = self._run_feroxbuster(url, custom_wordlist)
            results.append(result)

            logger.info(f"[Job {self.job.id}]   Found {result['total_found']} paths")

        return results

    def _run_feroxbuster(self, url: str, custom_wordlist: Optional[str]) -> Dict[str, Any]:
        """Run feroxbuster."""
        return run_feroxbuster(url, self.output_dir, custom_wordlist)

    def _run_web_crawling(
        self,
        web_services: List[Dict[str, Any]],
        bruteforce_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Run web crawling with gospider."""
        crawl_results = []

        # Crawl base URLs
        for web_service in web_services:
            url = web_service['url']
            logger.info(f"[Job {self.job.id}] Crawling {url}...")

            result = run_gospider(url, self.output_dir)
            crawl_results.append(result)

            logger.info(f"[Job {self.job.id}]   Found {result['total_urls']} URLs")

        # Deep crawl interesting paths (limit to top 10)
        all_bruteforce_paths = []
        for bf_result in bruteforce_results:
            all_bruteforce_paths.extend(bf_result.get('discovered_paths', []))

        interesting_paths = [
            p for p in all_bruteforce_paths
            if p.get('status') == 200 and not p.get('url', '').endswith(('.jpg', '.png', '.css', '.js'))
        ][:10]

        for path_info in interesting_paths:
            url = path_info.get('url')
            if url:
                logger.info(f"[Job {self.job.id}] Deep crawling {url}...")
                result = run_gospider(url, self.output_dir, depth=2)
                crawl_results.append(result)

        return crawl_results

    def _merge_discovered_paths(
        self,
        bruteforce_results: List[Dict[str, Any]],
        crawl_results: List[Dict[str, Any]]
    ) -> List[str]:
        """Merge all discovered paths and remove duplicates."""
        all_paths = set()

        # Add bruteforce paths
        for result in bruteforce_results:
            for path in result.get('discovered_paths', []):
                url = path.get('url')
                if url:
                    all_paths.add(url)

        # Add crawled paths
        for result in crawl_results:
            for url_info in result.get('discovered_urls', []):
                url = url_info.get('url')
                if url:
                    all_paths.add(url)

        logger.info(f"[Job {self.job.id}] Merged {len(all_paths)} unique paths")
        return list(all_paths)

    def _analyze_paths_intelligent(
        self,
        paths: List[str],
        base_url: str
    ) -> Dict[str, Any]:
        """
        Intelligent path analysis using PathAnalyzer and RAG.

        Args:
            paths: List of discovered paths
            base_url: Base URL

        Returns:
            Analysis results
        """
        logger.info(f"[Job {self.job.id}] Analyzing {len(paths)} paths with PathAnalyzer + RAG...")

        # Use PathAnalyzer for intelligent analysis
        analysis = self.path_analyzer.analyze_paths(
            paths=paths,
            base_url=base_url,
            context={
                'target': self.job.target,
                'job_id': self.job.id
            }
        )

        # Get attack surface summary
        attack_surface = self.path_analyzer.get_attack_surface_summary(analysis)

        logger.info(f"[Job {self.job.id}] Path analysis complete:")
        logger.info(f"[Job {self.job.id}]   Critical: {analysis['risk_summary']['critical']}")
        logger.info(f"[Job {self.job.id}]   High: {analysis['risk_summary']['high']}")
        logger.info(f"[Job {self.job.id}]   Medium: {analysis['risk_summary']['medium']}")

        return {
            'analysis': analysis,
            'attack_surface': attack_surface
        }

    def _extract_login_pages(
        self,
        all_paths: List[str],
        fingerprints: List[Dict[str, Any]],
        path_analysis: Dict[str, Any]
    ) -> List[str]:
        """Extract potential login pages from discovered paths."""
        login_pages = []

        # From fingerprints
        for fp in fingerprints:
            if fp.get('login_indicators'):
                url = fp.get('url')
                if url and url not in login_pages:
                    login_pages.append(url)

        # From path analysis (auth category)
        analysis = path_analysis.get('analysis', {})
        auth_paths = analysis.get('categories', {}).get('Authentication', [])
        for path in auth_paths:
            if path not in login_pages:
                login_pages.append(path)

        # Pattern-based detection
        login_patterns = ['/login', '/signin', '/auth', '/sso', '/admin/login']
        for path in all_paths:
            for pattern in login_patterns:
                if pattern in path.lower() and path not in login_pages:
                    login_pages.append(path)
                    break

        logger.info(f"[Job {self.job.id}] Identified {len(login_pages)} login pages")
        return login_pages[:10]  # Limit to top 10

    def _analyze_authentication(self, login_pages: List[str]) -> Dict[str, Any]:
        """
        Analyze authentication endpoints using AuthAnalyzer.

        Args:
            login_pages: List of login page URLs

        Returns:
            Authentication analysis results
        """
        if not login_pages:
            logger.info(f"[Job {self.job.id}] No login pages to analyze")
            return {
                'tested': False,
                'reason': 'No login pages identified'
            }

        logger.info(f"[Job {self.job.id}] Analyzing {len(login_pages)} login pages...")

        # Batch analyze login pages
        analysis = self.auth_analyzer.batch_analyze_login_pages(login_pages)

        logger.info(f"[Job {self.job.id}] Authentication analysis:")
        logger.info(f"[Job {self.job.id}]   Vulnerable: {analysis['vulnerable']}")
        logger.info(f"[Job {self.job.id}]   Secure: {analysis['secure']}")
        logger.info(f"[Job {self.job.id}]   Errors: {analysis['errors']}")

        return analysis

    def _generate_attack_surface(
        self,
        path_analysis: Dict[str, Any],
        auth_analysis: Dict[str, Any],
        fingerprints: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate comprehensive attack surface summary."""
        analysis = path_analysis.get('analysis', {})

        attack_surface = {
            'risk_summary': analysis.get('risk_summary', {}),
            'total_findings': analysis.get('total_paths', 0),
            'priority_targets': [],
            'attack_vectors': [],
            'security_issues': [],
            'recommendations': analysis.get('recommended_tests', [])
        }

        # Priority targets from path analysis
        findings = analysis.get('findings', [])
        critical_high = [
            f for f in findings
            if f.get('risk') in ['critical', 'high']
        ]
        attack_surface['priority_targets'] = critical_high[:15]

        # Attack vectors
        attack_vectors = set()
        for finding in findings:
            if finding.get('attack_type'):
                attack_vectors.add(finding['attack_type'])
            if finding.get('potential_attack_vectors'):
                attack_vectors.update(finding['potential_attack_vectors'])

        attack_surface['attack_vectors'] = list(attack_vectors)

        # Security issues from fingerprints
        for fp in fingerprints:
            missing_headers = fp.get('missing_security_headers', [])
            for header in missing_headers:
                if header.get('risk') in ['Medium', 'High', 'Critical']:
                    attack_surface['security_issues'].append({
                        'type': 'Missing Security Header',
                        'url': fp.get('url'),
                        'header': header.get('header'),
                        'risk': header.get('risk'),
                        'description': header.get('description')
                    })

        # Authentication issues
        if auth_analysis.get('vulnerable', 0) > 0:
            attack_surface['security_issues'].append({
                'type': 'Username Enumeration',
                'count': auth_analysis['vulnerable'],
                'risk': 'Low',
                'description': 'Login pages vulnerable to username enumeration'
            })

        return attack_surface


# Helper functions for web enumeration

def fingerprint_web_server(url: str) -> Dict[str, Any]:
    """
    Fingerprint web server to detect technologies, security headers, and login pages.
    """
    logger.info(f"Fingerprinting web server: {url}")

    fingerprint = {
        'url': url,
        'server': None,
        'technologies': [],
        'cms': None,
        'framework': None,
        'security_headers': {},
        'missing_security_headers': [],
        'powered_by': None,
        'cookies': [],
        'login_indicators': [],
        'status_code': None,
        'response_time_ms': None
    }

    try:
        import time
        start_time = time.time()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )

        end_time = time.time()
        fingerprint['response_time_ms'] = int((end_time - start_time) * 1000)
        fingerprint['status_code'] = response.status_code

        headers = response.headers
        content = response.text[:10000]

        # Extract Server header
        if 'Server' in headers:
            fingerprint['server'] = headers['Server']

        # Extract X-Powered-By
        if 'X-Powered-By' in headers:
            fingerprint['powered_by'] = headers['X-Powered-By']

        # Check security headers
        security_headers_check = {
            'X-Frame-Options': 'Protects against clickjacking',
            'X-Content-Type-Options': 'Prevents MIME-type sniffing',
            'X-XSS-Protection': 'XSS filter',
            'Strict-Transport-Security': 'HSTS - Forces HTTPS',
            'Content-Security-Policy': 'CSP - Prevents XSS',
            'Referrer-Policy': 'Controls referrer information',
        }

        for header, description in security_headers_check.items():
            if header in headers:
                fingerprint['security_headers'][header] = {
                    'value': headers[header],
                    'description': description
                }
            else:
                fingerprint['missing_security_headers'].append({
                    'header': header,
                    'description': description,
                    'risk': 'Medium' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'Low'
                })

        # Login page detection
        login_patterns = [
            r'<input[^>]*type=["\']password["\']',
            r'<form[^>]*login',
            r'href=["\'][^"\']*login',
        ]

        for pattern in login_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                fingerprint['login_indicators'].append(pattern)

    except Exception as e:
        fingerprint['error'] = str(e)
        logger.error(f"Error fingerprinting {url}: {e}")

    return fingerprint


def run_feroxbuster(url: str, output_dir: str, custom_wordlist: Optional[str] = None) -> Dict[str, Any]:
    """
    Run feroxbuster directory brute-forcing.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Determine wordlist
    if custom_wordlist and os.path.exists(custom_wordlist):
        wordlist = custom_wordlist
    else:
        wordlist = "wordlists/common.txt"
        if not os.path.exists(wordlist):
            os.makedirs("wordlists", exist_ok=True)
            default_paths = [
                'admin', 'login', 'wp-admin', 'phpmyadmin', 'backup',
                'config', '.git', '.env', 'api', 'uploads'
            ]
            with open(wordlist, 'w') as f:
                f.write('\n'.join(default_paths))

    safe_url = url.replace(':', '_').replace('/', '_').replace('?', '_')
    output_file = os.path.join(output_dir, f"feroxbuster_{safe_url}.json")

    cmd = [
        'feroxbuster',
        '-u', url,
        '-o', output_file,
        '-t', '50',
        '-w', wordlist,
        '-x', 'php,html,txt,js,json,xml,bak,old',
        '--timeout', '10',
        '--depth', '3',
        '--redirects',
        '--json',
        '--silent'
    ]

    logger.info(f"Running feroxbuster on {url}")
    result = run_command(cmd, timeout=600)

    discovered_paths = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get('type') == 'response':
                        discovered_paths.append({
                            'url': entry.get('url'),
                            'status': entry.get('status'),
                            'content_length': entry.get('content_length'),
                        })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning(f"Output file not found: {output_file}")

    return {
        'url': url,
        'discovered_paths': discovered_paths,
        'output_file': output_file,
        'wordlist_used': wordlist,
        'total_found': len(discovered_paths),
        'return_code': result.get('returncode', -1)
    }


def run_gospider(url: str, output_dir: str, depth: int = 3) -> Dict[str, Any]:
    """
    Run gospider for web crawling.
    """
    os.makedirs(output_dir, exist_ok=True)

    safe_url = url.replace(':', '_').replace('/', '_')
    output_folder = os.path.join(output_dir, f"gospider_{safe_url}")

    cmd = [
        'gospider',
        '-s', url,
        '-d', str(depth),
        '-c', '10',
        '-t', '10',
        '-o', output_folder,
        '--sitemap',
        '--robots',
        '--other-source',
        '--include-subs',
    ]

    logger.info(f"Running gospider on {url}")
    result = run_command(cmd, timeout=180)

    discovered_urls = []
    discovered_forms = []

    try:
        if os.path.exists(output_folder):
            for filename in os.listdir(output_folder):
                filepath = os.path.join(output_folder, filename)
                if not os.path.isfile(filepath):
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('[url]'):
                                url_str = line.replace('[url]', '').strip()
                                discovered_urls.append({
                                    'url': url_str,
                                    'source': 'gospider',
                                    'has_params': '?' in url_str
                                })
                            elif line.startswith('[form]'):
                                form_str = line.replace('[form]', '').strip()
                                if ' - ' in form_str:
                                    form_url, method = form_str.split(' - ', 1)
                                    discovered_forms.append({
                                        'action': form_url.strip(),
                                        'method': method.strip().upper(),
                                        'inputs': []
                                    })
                except Exception as e:
                    logger.error(f"Error parsing gospider file: {e}")
    except Exception as e:
        logger.error(f"Error reading gospider output: {e}")

    # Remove duplicates
    unique_urls = []
    seen = set()
    for url_info in discovered_urls:
        url_str = url_info['url']
        if url_str not in seen:
            unique_urls.append(url_info)
            seen.add(url_str)

    return {
        'url': url,
        'discovered_urls': unique_urls,
        'discovered_forms': discovered_forms,
        'total_urls': len(unique_urls),
        'total_forms': len(discovered_forms),
        'urls_with_params': len([u for u in unique_urls if u['has_params']]),
        'output_folder': output_folder
    }


def run_web_enumeration_phase(
    db_session,
    job: Job,
    info_data: Dict[str, Any],
    custom_wordlist: Optional[str] = None
) -> Optional[Phase]:
    """
    Run web enumeration phase (refactored v2).

    Args:
        db_session: Database session
        job: Job object
        info_data: Information gathering phase data
        custom_wordlist: Optional custom wordlist path

    Returns:
        Phase object
    """
    phase_executor = WebEnumerationPhase(db_session, job)
    return phase_executor.execute(info_data, custom_wordlist)
