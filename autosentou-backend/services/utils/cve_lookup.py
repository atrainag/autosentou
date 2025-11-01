#  services/utils/cve_lookup.py
import requests
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime


class CVEDatabase:
    """CVE database integration for vulnerability lookup."""
    
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_mitre_base = "https://cve.mitre.org/cgi-bin/cvekey.cgi"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AutoSentou-Pentest-Tool/1.0'
        })
    
    def lookup_service_vulnerabilities(self, service: str, version: str = "") -> List[Dict[str, Any]]:
        """Look up vulnerabilities for a specific service and version."""
        vulnerabilities = []
        
        # Clean service name for better matching
        service_clean = self._clean_service_name(service)
        
        # Try NVD API first
        nvd_vulns = self._query_nvd_api(service_clean, version)
        vulnerabilities.extend(nvd_vulns)
        
        # Add local vulnerability patterns as fallback
        local_vulns = self._check_local_patterns(service_clean, version)
        vulnerabilities.extend(local_vulns)
        
        return vulnerabilities
    
    def _clean_service_name(self, service: str) -> str:
        """Clean service name for better CVE matching."""
        service = service.lower().strip()
        
        # Common service name mappings
        mappings = {
            'apache httpd': 'apache',
            'apache http server': 'apache',
            'nginx': 'nginx',
            'microsoft iis': 'iis',
            'openssh': 'openssh',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'microsoft sql server': 'sql server',
            'oracle database': 'oracle',
            'mongodb': 'mongodb',
            'redis': 'redis',
            'elasticsearch': 'elasticsearch',
            'tomcat': 'tomcat',
            'jetty': 'jetty',
            'node.js': 'node.js',
            'php': 'php',
            'python': 'python',
            'ruby': 'ruby',
            'java': 'java',
            'dotnet': '.net',
            'iis': 'iis'
        }
        
        for key, value in mappings.items():
            if key in service:
                return value
        
        return service
    
    def _query_nvd_api(self, service: str, version: str) -> List[Dict[str, Any]]:
        """Query NVD API for vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Build search query
            query_params = {
                'keywordSearch': service,
                'resultsPerPage': 50,
                'startIndex': 0
            }
            
            if version:
                query_params['keywordSearch'] = f"{service} {version}"
            
            response = self.session.get(self.nvd_api_base, params=query_params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    # Extract CVSS score
                    cvss_score = 0.0
                    cvss_vector = ""
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        cvss_vector = cvss_data.get('vectorString', '')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        cvss_vector = cvss_data.get('vectorString', '')
                    
                    # Determine severity
                    severity = self._determine_severity(cvss_score)
                    
                    # Extract description
                    descriptions = cve_data.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Check if version is affected
                    is_affected = self._check_version_affected(cve_data, version)
                    
                    vulnerabilities.append({
                        'cve_id': cve_id,
                        'description': description,
                        'severity': severity,
                        'cvss_score': cvss_score,
                        'cvss_vector': cvss_vector,
                        'service': service,
                        'version_affected': is_affected,
                        'published_date': cve_data.get('published', ''),
                        'last_modified': cve_data.get('lastModified', ''),
                        'source': 'NVD'
                    })
            
        except Exception as e:
            print(f"Error querying NVD API: {e}")
        
        return vulnerabilities
    
    def _check_local_patterns(self, service: str, version: str) -> List[Dict[str, Any]]:
        """Check against local vulnerability patterns."""
        vulnerabilities = []
        
        # Common vulnerability patterns
        patterns = {
            'apache': [
                {'version': '2.2', 'cve': 'CVE-2017-15715', 'severity': 'High', 'score': 7.5},
                {'version': '2.4.0', 'cve': 'CVE-2017-15710', 'severity': 'Medium', 'score': 6.1},
                {'version': '2.4.1', 'cve': 'CVE-2017-15710', 'severity': 'Medium', 'score': 6.1},
            ],
            'nginx': [
                {'version': '1.0', 'cve': 'CVE-2017-7529', 'severity': 'High', 'score': 7.5},
                {'version': '1.1', 'cve': 'CVE-2017-7529', 'severity': 'High', 'score': 7.5},
            ],
            'openssh': [
                {'version': '7.0', 'cve': 'CVE-2016-0777', 'severity': 'Medium', 'score': 5.0},
                {'version': '7.1', 'cve': 'CVE-2016-0777', 'severity': 'Medium', 'score': 5.0},
            ],
            'mysql': [
                {'version': '5.0', 'cve': 'CVE-2016-6662', 'severity': 'Critical', 'score': 9.1},
                {'version': '5.1', 'cve': 'CVE-2016-6662', 'severity': 'Critical', 'score': 9.1},
                {'version': '5.5', 'cve': 'CVE-2016-6662', 'severity': 'Critical', 'score': 9.1},
            ],
            'postgresql': [
                {'version': '9.0', 'cve': 'CVE-2017-8806', 'severity': 'High', 'score': 7.5},
                {'version': '9.1', 'cve': 'CVE-2017-8806', 'severity': 'High', 'score': 7.5},
            ]
        }
        
        if service in patterns:
            for pattern in patterns[service]:
                if version and pattern['version'] in version:
                    vulnerabilities.append({
                        'cve_id': pattern['cve'],
                        'description': f'Known vulnerability in {service} version {pattern["version"]}',
                        'severity': pattern['severity'],
                        'cvss_score': pattern['score'],
                        'cvss_vector': '',
                        'service': service,
                        'version_affected': True,
                        'published_date': '',
                        'last_modified': '',
                        'source': 'Local Database'
                    })
        
        return vulnerabilities
    
    def _determine_severity(self, cvss_score: float) -> str:
        """Determine severity based on CVSS score."""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0.0:
            return 'Low'
        else:
            return 'Unknown'
    
    def _check_version_affected(self, cve_data: Dict[str, Any], version: str) -> bool:
        """Check if specific version is affected by CVE."""
        if not version:
            return True
        
        # This is a simplified check - in reality, you'd need to parse
        # the CVE configuration to determine affected versions
        configurations = cve_data.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_match = node.get('cpeMatch', [])
                for match in cpe_match:
                    criteria = match.get('criteria', '')
                    if version in criteria:
                        return True
        
        return False
    
    def get_exploit_info(self, cve_id: str) -> Dict[str, Any]:
        """Get exploit information for a CVE."""
        # This would integrate with exploit databases like ExploitDB
        # For now, return basic info
        return {
            'cve_id': cve_id,
            'exploit_available': False,
            'exploit_difficulty': 'Unknown',
            'exploit_url': '',
            'poc_available': False
        }


# Global CVE database instance
cve_db = CVEDatabase()
