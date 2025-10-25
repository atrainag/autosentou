# autosentou/services/phases/web_enumeration.py
import os
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job


def run_dirsearch(target: str, output_dir: str) -> Dict[str, Any]:
    """
    Run dirsearch to enumerate web directories and files.
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Clean target for filename
    safe_target = target.replace(':', '_').replace('/', '_').replace('\\', '_')
    output_file = os.path.join(output_dir, f"dirsearch_{safe_target}.txt")
    
    # Enhanced dirsearch command with better options
    cmd = [
        "dirsearch", 
        "-u", target,
        "-o", output_file,
        "--format", "json",
        "--threads", "10",
        "--timeout", "10",
        "--max-retries", "1",
        "--recursive", "1",  # 1 level of recursion
        "--exclude-status", "404,403",  # Exclude common non-interesting status codes
        "--wordlist", "/usr/share/wordlists/dirb/common.txt",  # Use common wordlist
        "--extensions", "php,asp,aspx,jsp,html,htm,txt,json,xml",  # Common extensions
        "--quiet"  # Reduce verbose output
    ]
    
    print(f"Running dirsearch on {target}...")
    result = run_command(cmd, timeout=600)  # 10 minute timeout
    
    # Parse results from both stdout and output file
    discovered_paths = []
    
    # First, try to parse JSON output from stdout
    stdout_lines = result.get('stdout', '').split('\n')
    for line in stdout_lines:
        if line.strip():
            try:
                data = json.loads(line)
                if 'url' in data and 'status' in data:
                    discovered_paths.append({
                        'url': data['url'],
                        'status': data['status'],
                        'content_length': data.get('content_length', 0),
                        'redirect': data.get('redirect', ''),
                        'response_time': data.get('response_time', 0),
                        'method': data.get('method', 'GET')
                    })
            except json.JSONDecodeError:
                continue
    
    # Also try to parse the output file if it exists
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Parse JSON output from file
                for line in content.split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'url' in data and 'status' in data:
                                # Avoid duplicates
                                url = data['url']
                                if not any(p['url'] == url for p in discovered_paths):
                                    discovered_paths.append({
                                        'url': data['url'],
                                        'status': data['status'],
                                        'content_length': data.get('content_length', 0),
                                        'redirect': data.get('redirect', ''),
                                        'response_time': data.get('response_time', 0),
                                        'method': data.get('method', 'GET')
                                    })
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error parsing dirsearch output file: {e}")
    
    # If no JSON output, try to parse plain text output
    if not discovered_paths and result.get('stdout'):
        plain_text_paths = parse_dirsearch_plain_output(result.get('stdout', ''))
        discovered_paths.extend(plain_text_paths)
    
    # Sort by status code for better organization
    discovered_paths.sort(key=lambda x: (x['status'], x['url']))
    
    return {
        'raw_output': result.get('stdout', ''),
        'error_output': result.get('stderr', ''),
        'return_code': result.get('returncode', -1),
        'discovered_paths': discovered_paths,
        'total_paths': len(discovered_paths),
        'output_file': output_file,
        'successful_paths': len([p for p in discovered_paths if p['status'] in [200, 301, 302, 403]]),
        'failed_paths': len([p for p in discovered_paths if p['status'] in [404, 500, 503]])
    }


def parse_dirsearch_plain_output(output: str) -> List[Dict[str, Any]]:
    """Parse dirsearch plain text output when JSON is not available."""
    discovered_paths = []
    
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('[') or line.startswith('_'):
            continue
        
        # Look for lines with status codes
        status_match = re.search(r'(\d{3})\s+(\d+)\w*\s+(.+)', line)
        if status_match:
            status = int(status_match.group(1))
            content_length = int(status_match.group(2))
            url = status_match.group(3).strip()
            
            discovered_paths.append({
                'url': url,
                'status': status,
                'content_length': content_length,
                'redirect': '',
                'response_time': 0,
                'method': 'GET'
            })
    
    return discovered_paths


def run_ai_directory_discovery(target: str, discovered_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Use AI to analyze discovered paths and identify potentially vulnerable directories.
    This is a placeholder for the browser-use integration you mentioned.
    """
    # This would integrate with browser-use or similar AI tool
    # For now, we'll do basic pattern matching
    
    vulnerable_patterns = [
        r'admin', r'login', r'wp-admin', r'phpmyadmin', r'backup',
        r'config', r'api', r'test', r'dev', r'staging', r'old',
        r'upload', r'files', r'database', r'sql', r'logs'
    ]
    
    ai_analysis = []
    for path in discovered_paths:
        url = path.get('url', '').lower()
        status = path.get('status', 0)
        
        # Check for potentially interesting paths
        interesting = False
        matched_patterns = []
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, url):
                interesting = True
                matched_patterns.append(pattern)
        
        # AI analysis (simplified)
        if interesting or status in [200, 301, 302, 403]:
            ai_analysis.append({
                'url': path.get('url'),
                'status': status,
                'risk_level': 'High' if status in [200, 301, 302] and interesting else 'Medium',
                'matched_patterns': matched_patterns,
                'ai_recommendation': f"Investigate {path.get('url')} - potential admin panel or sensitive directory",
                'confidence': 0.8 if interesting else 0.5,
            })
    
    return {
        'ai_analysis': ai_analysis,
        'high_risk_paths': [p for p in ai_analysis if p['risk_level'] == 'High'],
        'medium_risk_paths': [p for p in ai_analysis if p['risk_level'] == 'Medium'],
        'total_analyzed': len(ai_analysis),
    }


def run_web_enumeration_phase(db_session, job: Job, info_gathering_data: Dict[str, Any]) -> Optional[Phase]:
    """
    Run web enumeration phase including directory discovery and AI analysis.
    """
    phase = Phase(
        job_id=job.id,
        phase_name="Web Enumeration",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)

    try:
        print("Starting web enumeration...")
        
        # Extract target from info gathering
        target = job.target
        
        # Check if target is a web service (has HTTP/HTTPS ports)
        nmap_data = info_gathering_data.get('nmap', {})
        web_ports = []
        
        for service in nmap_data.get('parsed_ports', []):
            port = service.get('port')
            service_name = service.get('service', '').lower()
            if port in [80, 443, 8080, 8443, 8000, 3000] or 'http' in service_name:
                web_ports.append(port)
        
        if not web_ports:
            # No web services detected
            phase.data = {
                'target': target,
                'web_services_detected': False,
                'message': 'No web services detected on common ports',
            }
            phase.status = "success"
            phase.updated_at = datetime.utcnow()
            db_session.add(phase)
            db_session.commit()
            db_session.refresh(phase)
            return phase
        
        # Determine target URL
        if target.startswith('http'):
            target_url = target
        else:
            # Default to HTTP, but check for HTTPS if port 443 is open
            protocol = 'https' if 443 in web_ports else 'http'
            port_suffix = f':{web_ports[0]}' if web_ports[0] not in [80, 443] else ''
            target_url = f"{protocol}://{target}{port_suffix}"
        
        # Create output directory
        output_dir = f"reports/{job.id}/web_enumeration"
        
        # Run dirsearch
        dirsearch_results = run_dirsearch(target_url, output_dir)
        
        # Run AI analysis
        ai_analysis = run_ai_directory_discovery(target_url, dirsearch_results['discovered_paths'])
        
        # Combine results
        combined_data = {
            'target': target,
            'target_url': target_url,
            'web_ports_detected': web_ports,
            'dirsearch_results': dirsearch_results,
            'ai_analysis': ai_analysis,
            'enumeration_timestamp': datetime.utcnow().isoformat(),
        }

        phase.data = combined_data
        phase.status = "success"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        
        print(f"Web enumeration completed. Found {dirsearch_results['total_paths']} paths, {ai_analysis['total_analyzed']} analyzed by AI.")
        return phase
        
    except Exception as e:
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        print(f"Web enumeration failed: {str(e)}")
        return phase
