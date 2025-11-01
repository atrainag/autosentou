#  services/config.py
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ScanConfig:
    """Configuration for pentesting scans."""
    target: str
    description: Optional[str] = None
    scan_type: str = "comprehensive"  # comprehensive, quick, web_only, network_only
    include_brute_force: bool = True
    include_sqli_testing: bool = True
    include_web_enumeration: bool = True
    include_vulnerability_analysis: bool = True
    custom_wordlist: Optional[str] = None
    max_threads: int = 10
    timeout: int = 300
    nmap_ports: str = "1-65535"
    nmap_timing: str = "T4"
    dirsearch_threads: int = 10
    hydra_threads: int = 4
    sqlmap_threads: int = 1
    report_format: str = "pdf"  # pdf, html, markdown


@dataclass
class ToolConfig:
    """Configuration for individual tools."""
    # Nmap configuration
    nmap_path: str = "nmap"
    nmap_script_path: str = "/usr/share/nmap/scripts"
    
    # Dirsearch configuration
    dirsearch_path: str = "dirsearch"
    dirsearch_wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    
    # Hydra configuration
    hydra_path: str = "hydra"
    hydra_username_list: str = "/usr/share/wordlists/rockyou.txt"
    hydra_password_list: str = "/usr/share/wordlists/rockyou.txt"
    
    # Medusa configuration
    medusa_path: str = "medusa"
    medusa_username_list: str = "/usr/share/wordlists/rockyou.txt"
    medusa_password_list: str = "/usr/share/wordlists/rockyou.txt"
    
    # SQLMap configuration
    sqlmap_path: str = "sqlmap"
    sqlmap_tamper_scripts: str = "/usr/share/sqlmap/tamper"
    
    # Report generation
    pandoc_path: str = "pandoc"
    report_template: str = "default"


class ConfigManager:
    """Manages configuration for the pentesting tool."""
    
    def __init__(self):
        self.tool_config = ToolConfig()
        self._load_environment_config()
    
    def _load_environment_config(self):
        """Load configuration from environment variables."""
        # Tool paths
        self.tool_config.nmap_path = os.getenv('NMAP_PATH', self.tool_config.nmap_path)
        self.tool_config.dirsearch_path = os.getenv('DIRSEARCH_PATH', self.tool_config.dirsearch_path)
        self.tool_config.hydra_path = os.getenv('HYDRA_PATH', self.tool_config.hydra_path)
        self.tool_config.medusa_path = os.getenv('MEDUSA_PATH', self.tool_config.medusa_path)
        self.tool_config.sqlmap_path = os.getenv('SQLMAP_PATH', self.tool_config.sqlmap_path)
        self.tool_config.pandoc_path = os.getenv('PANDOC_PATH', self.tool_config.pandoc_path)
        
        # Wordlists
        self.tool_config.dirsearch_wordlist = os.getenv('DIRSEARCH_WORDLIST', self.tool_config.dirsearch_wordlist)
        self.tool_config.hydra_username_list = os.getenv('HYDRA_USERNAME_LIST', self.tool_config.hydra_username_list)
        self.tool_config.hydra_password_list = os.getenv('HYDRA_PASSWORD_LIST', self.tool_config.hydra_password_list)
        self.tool_config.medusa_username_list = os.getenv('MEDUSA_USERNAME_LIST', self.tool_config.medusa_username_list)
        self.tool_config.medusa_password_list = os.getenv('MEDUSA_PASSWORD_LIST', self.tool_config.medusa_password_list)
    
    def create_scan_config(self, target: str, **kwargs) -> ScanConfig:
        """Create a scan configuration with the given parameters."""
        return ScanConfig(
            target=target,
            description=kwargs.get('description'),
            scan_type=kwargs.get('scan_type', 'comprehensive'),
            include_brute_force=kwargs.get('include_brute_force', True),
            include_sqli_testing=kwargs.get('include_sqli_testing', True),
            include_web_enumeration=kwargs.get('include_web_enumeration', True),
            include_vulnerability_analysis=kwargs.get('include_vulnerability_analysis', True),
            custom_wordlist=kwargs.get('custom_wordlist'),
            max_threads=kwargs.get('max_threads', 10),
            timeout=kwargs.get('timeout', 300),
            nmap_ports=kwargs.get('nmap_ports', '1-65535'),
            nmap_timing=kwargs.get('nmap_timing', 'T4'),
            dirsearch_threads=kwargs.get('dirsearch_threads', 10),
            hydra_threads=kwargs.get('hydra_threads', 4),
            sqlmap_threads=kwargs.get('sqlmap_threads', 1),
            report_format=kwargs.get('report_format', 'pdf'),
        )
    
    def validate_tools(self) -> Dict[str, bool]:
        """Validate that all required tools are available."""
        tools = {
            'nmap': self._check_tool(self.tool_config.nmap_path),
            'dirsearch': self._check_tool(self.tool_config.dirsearch_path),
            'hydra': self._check_tool(self.tool_config.hydra_path),
            'medusa': self._check_tool(self.tool_config.medusa_path),
            'sqlmap': self._check_tool(self.tool_config.sqlmap_path),
            'pandoc': self._check_tool(self.tool_config.pandoc_path),
        }
        return tools
    
    def _check_tool(self, tool_path: str) -> bool:
        """Check if a tool is available."""
        from  services.utils.system import check_tool_availability
        return check_tool_availability(tool_path)
    
    def get_scan_phases(self, scan_config: ScanConfig) -> list:
        """Get the list of phases to run based on scan configuration."""
        phases = ['Information Gathering']
        
        if scan_config.include_vulnerability_analysis:
            phases.append('Vulnerability Analysis')
        
        if scan_config.include_web_enumeration:
            phases.append('Web Enumeration')
        
        if scan_config.include_sqli_testing:
            phases.append('SQL Injection Testing')
        
        if scan_config.include_brute_force:
            phases.append('Brute Force Testing')
        
        phases.append('Report Generation')
        
        return phases


# Global configuration manager instance
config_manager = ConfigManager()
