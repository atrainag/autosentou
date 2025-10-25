# autosentou/services/phases/brute_force_testing.py
import os
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job


def identify_login_endpoints(web_enum_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Identify potential login endpoints from web enumeration results.
    """
    login_endpoints = []
    
    # Common login endpoint patterns
    login_patterns = [
        r'login', r'signin', r'auth', r'admin', r'wp-login',
        r'user', r'account', r'session', r'portal'
    ]
    
    # Common file extensions for login pages
    login_extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.htm']
    
    discovered_paths = web_enum_data.get('dirsearch_results', {}).get('discovered_paths', [])
    
    for path in discovered_paths:
        url = path.get('url', '')
        status = path.get('status', 0)
        
        # Only test 200 status codes
        if status == 200:
            url_lower = url.lower()
            
            # Check for login patterns
            for pattern in login_patterns:
                if re.search(pattern, url_lower):
                    # Check if it has a login-related extension
                    has_login_extension = any(ext in url_lower for ext in login_extensions)
                    
                    login_endpoints.append({
                        'url': url,
                        'status': status,
                        'pattern_matched': pattern,
                        'has_extension': has_login_extension,
                        'confidence': 'High' if has_login_extension else 'Medium',
                        'reason': f'Login pattern matched: {pattern}',
                    })
                    break  # Only add once per URL
    
    # Remove duplicates
    unique_endpoints = []
    seen_urls = set()
    
    for endpoint in login_endpoints:
        if endpoint['url'] not in seen_urls:
            unique_endpoints.append(endpoint)
            seen_urls.add(endpoint['url'])
    
    return unique_endpoints


def run_hydra_brute_force(endpoint: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """
    Run hydra brute force attack on a login endpoint with comprehensive testing.
    """
    url = endpoint['url']
    safe_url = url.replace(':', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    output_file = os.path.join(output_dir, f"hydra_{safe_url}.txt")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Determine if it's HTTP or HTTPS
    protocol = 'https' if url.startswith('https') else 'http'
    
    # Enhanced hydra command with better options
    cmd = [
        "hydra",
        "-L", "/usr/share/wordlists/rockyou.txt",  # Username list
        "-P", "/usr/share/wordlists/rockyou.txt",  # Password list
        "-f",  # Stop on first success
        "-o", output_file,
        "-t", "4",  # Threads
        "-w", "30",  # Wait time
        "-V",  # Verbose
        "-I",  # Ignore previous restore file
        "-s", "80" if protocol == 'http' else "443",  # Port
        "-e", "ns",  # Try null password and username as password
        "-u",  # Try usernames as passwords
        f"{protocol}-post-form",
        f"{url}:username=^USER^&password=^PASS^:Invalid username or password"
    ]
    
    print(f"Running Hydra on {url}...")
    result = run_command(cmd, timeout=600)  # 10 minute timeout
    
    # Parse hydra results
    hydra_results = {
        'url': url,
        'command': ' '.join(cmd),
        'return_code': result.get('returncode', -1),
        'stdout': result.get('stdout', ''),
        'stderr': result.get('stderr', ''),
        'successful_logins': [],
        'failed_attempts': 0,
        'total_attempts': 0,
        'success_rate': 0.0,
        'attack_duration': 0,
        'error_messages': []
    }
    
    stdout = result.get('stdout', '')
    stderr = result.get('stderr', '')
    
    # Parse successful logins from output
    if 'login:' in stdout and 'password:' in stdout:
        # Extract successful login attempts with better regex
        login_patterns = [
            r'login:\s*([^\s]+)\s*password:\s*([^\s]+)',
            r'\[80\]\[http-post-form\] host:.*?login:\s*([^\s]+)\s*password:\s*([^\s]+)',
            r'\[443\]\[https-post-form\] host:.*?login:\s*([^\s]+)\s*password:\s*([^\s]+)',
            r'\[80\]\[http-post-form\] host:.*?login:\s*([^\s]+)\s*password:\s*([^\s]+)',
            r'\[443\]\[https-post-form\] host:.*?login:\s*([^\s]+)\s*password:\s*([^\s]+)'
        ]
        
        for pattern in login_patterns:
            login_matches = re.findall(pattern, stdout, re.IGNORECASE)
            for username, password in login_matches:
                hydra_results['successful_logins'].append({
                    'username': username,
                    'password': password,
                    'method': 'http-post-form'
                })
    
    # Count failed attempts
    failed_patterns = [
        r'\[ATTEMPT\]',
        r'\[80\]\[http-post-form\]',
        r'\[443\]\[https-post-form\]'
    ]
    
    for pattern in failed_patterns:
        failed_matches = re.findall(pattern, stdout)
        hydra_results['failed_attempts'] += len(failed_matches)
    
    # Count total attempts
    total_patterns = [
        r'\[ATTEMPT\]',
        r'\[80\]\[http-post-form\]',
        r'\[443\]\[https-post-form\]'
    ]
    
    for pattern in total_patterns:
        total_matches = re.findall(pattern, stdout)
        hydra_results['total_attempts'] += len(total_matches)
    
    # Calculate success rate
    if hydra_results['total_attempts'] > 0:
        hydra_results['success_rate'] = (len(hydra_results['successful_logins']) / hydra_results['total_attempts']) * 100
    
    # Extract attack duration
    duration_match = re.search(r'completed in ([\d.]+) seconds', stdout)
    if duration_match:
        hydra_results['attack_duration'] = float(duration_match.group(1))
    
    # Extract error messages
    error_patterns = [
        r'ERROR: (.+)',
        r'Error: (.+)',
        r'error: (.+)'
    ]
    
    for pattern in error_patterns:
        error_matches = re.findall(pattern, stderr, re.IGNORECASE)
        hydra_results['error_messages'].extend(error_matches)
    
    # Remove duplicates
    hydra_results['successful_logins'] = list({(login['username'], login['password']): login for login in hydra_results['successful_logins']}.values())
    
    return hydra_results


def run_medusa_brute_force(endpoint: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """
    Run medusa brute force attack on a login endpoint with comprehensive testing.
    """
    url = endpoint['url']
    safe_url = url.replace(':', '_').replace('/', '_').replace('?', '_').replace('&', '_')
    output_file = os.path.join(output_dir, f"medusa_{safe_url}.txt")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Determine if it's HTTP or HTTPS
    protocol = 'https' if url.startswith('https') else 'http'
    
    # Enhanced medusa command with better options
    cmd = [
        "medusa",
        "-h", url,
        "-U", "/usr/share/wordlists/rockyou.txt",  # Username list
        "-P", "/usr/share/wordlists/rockyou.txt",  # Password list
        "-M", "http",
        "-m", f"DIR:{url}",
        "-m", "FORM:username:password",
        "-m", "USER:username",
        "-m", "PASS:password",
        "-f",  # Stop on first success
        "-O", output_file,
        "-t", "4",  # Threads
        "-T", "30",  # Timeout
        "-n", "80" if protocol == 'http' else "443",  # Port
        "-v", "6",  # Verbose level
        "-e", "ns",  # Try null password and username as password
        "-u",  # Try usernames as passwords
        "-r", "0",  # Retry attempts
        "-L",  # Log successful attempts
        "-q"  # Quiet mode
    ]
    
    print(f"Running Medusa on {url}...")
    result = run_command(cmd, timeout=600)  # 10 minute timeout
    
    # Parse medusa results
    medusa_results = {
        'url': url,
        'command': ' '.join(cmd),
        'return_code': result.get('returncode', -1),
        'stdout': result.get('stdout', ''),
        'stderr': result.get('stderr', ''),
        'successful_logins': [],
        'failed_attempts': 0,
        'total_attempts': 0,
        'success_rate': 0.0,
        'attack_duration': 0,
        'error_messages': []
    }
    
    stdout = result.get('stdout', '')
    stderr = result.get('stderr', '')
    
    # Parse successful logins from output
    if 'SUCCESS' in stdout:
        # Extract successful login attempts with better regex
        success_patterns = [
            r'SUCCESS.*?(\w+):(\w+)',
            r'SUCCESS.*?username:\s*(\w+).*?password:\s*(\w+)',
            r'SUCCESS.*?user:\s*(\w+).*?pass:\s*(\w+)',
            r'SUCCESS.*?login:\s*(\w+).*?password:\s*(\w+)'
        ]
        
        for pattern in success_patterns:
            success_matches = re.findall(pattern, stdout, re.IGNORECASE)
            for username, password in success_matches:
                medusa_results['successful_logins'].append({
                    'username': username,
                    'password': password,
                    'method': 'http-form'
                })
    
    # Count failed attempts
    failed_patterns = [
        r'FAIL',
        r'ERROR',
        r'\[FAIL\]',
        r'\[ERROR\]'
    ]
    
    for pattern in failed_patterns:
        failed_matches = re.findall(pattern, stdout, re.IGNORECASE)
        medusa_results['failed_attempts'] += len(failed_matches)
    
    # Count total attempts
    total_patterns = [
        r'\[ATTEMPT\]',
        r'\[INFO\]',
        r'\[SUCCESS\]',
        r'\[FAIL\]'
    ]
    
    for pattern in total_patterns:
        total_matches = re.findall(pattern, stdout, re.IGNORECASE)
        medusa_results['total_attempts'] += len(total_matches)
    
    # Calculate success rate
    if medusa_results['total_attempts'] > 0:
        medusa_results['success_rate'] = (len(medusa_results['successful_logins']) / medusa_results['total_attempts']) * 100
    
    # Extract attack duration
    duration_match = re.search(r'completed in ([\d.]+) seconds', stdout)
    if duration_match:
        medusa_results['attack_duration'] = float(duration_match.group(1))
    
    # Extract error messages
    error_patterns = [
        r'ERROR: (.+)',
        r'Error: (.+)',
        r'error: (.+)',
        r'\[ERROR\] (.+)'
    ]
    
    for pattern in error_patterns:
        error_matches = re.findall(pattern, stderr, re.IGNORECASE)
        medusa_results['error_messages'].extend(error_matches)
    
    # Remove duplicates
    medusa_results['successful_logins'] = list({(login['username'], login['password']): login for login in medusa_results['successful_logins']}.values())
    
    return medusa_results


def run_brute_force_testing_phase(db_session, job: Job, web_enum_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Run brute force testing phase on identified login endpoints.
    """
    phase = Phase(
        job_id=job.id,
        phase_name="Brute Force Testing",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)

    try:
        print("Starting brute force testing...")
        
        # Check if web enumeration was successful
        if not web_enum_data.get('web_services_detected', True):
            phase.data = {
                'target': job.target,
                'web_services_detected': False,
                'message': 'No web services detected, skipping brute force testing',
            }
            phase.status = "success"
            phase.updated_at = datetime.utcnow()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Identify potential login endpoints
        login_endpoints = identify_login_endpoints(web_enum_data)
        
        if not login_endpoints:
            phase.data = {
                'target': job.target,
                'login_endpoints': [],
                'message': 'No login endpoints identified',
            }
            phase.status = "success"
            phase.updated_at = datetime.utcnow()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Create output directory
        output_dir = f"reports/{job.id}/brute_force_testing"
        
        # Test each endpoint with both hydra and medusa
        brute_force_results = []
        successful_logins = []
        
        for endpoint in login_endpoints:
            print(f"Testing login endpoint: {endpoint['url']}")
            
            # Try hydra first
            hydra_result = run_hydra_brute_force(endpoint, output_dir)
            brute_force_results.append({
                'endpoint': endpoint,
                'tool': 'hydra',
                'result': hydra_result,
            })
            
            if hydra_result['successful_logins']:
                successful_logins.extend(hydra_result['successful_logins'])
            
            # Try medusa as backup
            medusa_result = run_medusa_brute_force(endpoint, output_dir)
            brute_force_results.append({
                'endpoint': endpoint,
                'tool': 'medusa',
                'result': medusa_result,
            })
            
            if medusa_result['successful_logins']:
                successful_logins.extend(medusa_result['successful_logins'])
        
        # Combine results
        combined_data = {
            'target': job.target,
            'login_endpoints': login_endpoints,
            'brute_force_results': brute_force_results,
            'successful_logins': successful_logins,
            'total_endpoints_tested': len(login_endpoints),
            'total_successful_logins': len(successful_logins),
            'testing_timestamp': datetime.utcnow().isoformat(),
        }

        phase.data = combined_data
        phase.status = "success"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        
        print(f"Brute force testing completed. Tested {len(login_endpoints)} endpoints, found {len(successful_logins)} successful logins.")
        return phase
        
    except Exception as e:
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        print(f"Brute force testing failed: {str(e)}")
        return phase
