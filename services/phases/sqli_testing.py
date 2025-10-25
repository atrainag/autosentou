# autosentou/services/phases/sqli_testing.py
import os
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job


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
    
    print(f"Running SQLMap on {url}...")
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
    Run SQL injection testing phase using sqlmap.
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
        print("Starting SQL injection testing...")
        
        # Check if web enumeration was successful
        if not web_enum_data.get('web_services_detected', True):
            phase.data = {
                'target': job.target,
                'web_services_detected': False,
                'message': 'No web services detected, skipping SQL injection testing',
            }
            phase.status = "success"
            phase.updated_at = datetime.utcnow()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Identify potential SQL injection endpoints
        potential_endpoints = identify_sql_injection_endpoints(web_enum_data)
        
        if not potential_endpoints:
            phase.data = {
                'target': job.target,
                'potential_endpoints': [],
                'message': 'No potential SQL injection endpoints identified',
            }
            phase.status = "success"
            phase.updated_at = datetime.utcnow()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Create output directory
        output_dir = f"reports/{job.id}/sqli_testing"
        
        # Test each endpoint with sqlmap
        sqlmap_results = []
        vulnerable_endpoints = []
        
        for endpoint in potential_endpoints:
            print(f"Testing endpoint: {endpoint['url']}")
            result = run_sqlmap_test(endpoint, output_dir)
            sqlmap_results.append(result)
            
            if result['vulnerable']:
                vulnerable_endpoints.append({
                    'url': endpoint['url'],
                    'injection_type': result['injection_type'],
                    'payloads': result['payloads'],
                    'confidence': endpoint['confidence'],
                })
        
        # Combine results
        combined_data = {
            'target': job.target,
            'potential_endpoints': potential_endpoints,
            'sqlmap_results': sqlmap_results,
            'vulnerable_endpoints': vulnerable_endpoints,
            'total_tested': len(sqlmap_results),
            'total_vulnerable': len(vulnerable_endpoints),
            'testing_timestamp': datetime.utcnow().isoformat(),
        }

        phase.data = combined_data
        phase.status = "success"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        
        print(f"SQL injection testing completed. Tested {len(sqlmap_results)} endpoints, found {len(vulnerable_endpoints)} vulnerable.")
        return phase
        
    except Exception as e:
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        print(f"SQL injection testing failed: {str(e)}")
        return phase
