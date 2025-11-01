"""
Output Manager - Centralized management of all scan outputs

Ensures all tool outputs are saved to disk and can be retrieved during report generation.
"""
import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class OutputManager:
    """
    Manages all scan output files - ensures everything is saved to disk.
    """
    
    def __init__(self, job_id: str, base_dir: str = "reports"):
        self.job_id = job_id
        self.base_dir = base_dir
        self.job_dir = os.path.join(base_dir, job_id)
        self.raw_outputs_dir = os.path.join(self.job_dir, "raw_outputs")
        self.evidence_dir = os.path.join(self.job_dir, "evidence")
        self.logs_dir = os.path.join(self.job_dir, "logs")
        
        # Create directory structure
        self._init_directories()
        
        logger.info(f"OutputManager initialized for job {job_id}")
    
    def _init_directories(self):
        """Create all necessary directories."""
        directories = [
            self.job_dir,
            self.raw_outputs_dir,
            self.evidence_dir,
            self.logs_dir,
            os.path.join(self.raw_outputs_dir, "nmap"),
            os.path.join(self.raw_outputs_dir, "web_enum"),
            os.path.join(self.raw_outputs_dir, "sqli"),
            os.path.join(self.raw_outputs_dir, "auth"),
            os.path.join(self.raw_outputs_dir, "vuln_analysis"),
            os.path.join(self.evidence_dir, "screenshots"),
            os.path.join(self.evidence_dir, "payloads"),
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    # ===== SAVE METHODS =====
    
    def save_nmap_output(self, raw_output: str, parsed_data: Dict[str, Any]) -> Dict[str, str]:
        """Save nmap scan outputs."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        paths = {
            "raw_output": os.path.join(self.raw_outputs_dir, "nmap", f"nmap_scan_{timestamp}.txt"),
            "parsed_json": os.path.join(self.raw_outputs_dir, "nmap", f"nmap_parsed_{timestamp}.json"),
            "xml_output": os.path.join(self.raw_outputs_dir, "nmap", f"nmap_scan_{timestamp}.xml")
        }
        
        # Save raw output
        with open(paths["raw_output"], 'w', encoding='utf-8') as f:
            f.write(raw_output)
        
        # Save parsed JSON
        with open(paths["parsed_json"], 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=2, default=str)
        
        logger.info(f"✓ Saved nmap outputs to {self.raw_outputs_dir}/nmap/")
        return paths
    
    def save_web_enum_output(self, tool_name: str, raw_output: str, parsed_data: Dict[str, Any]) -> Dict[str, str]:
        """Save web enumeration outputs (dirsearch, feroxbuster, gospider)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tool_dir = os.path.join(self.raw_outputs_dir, "web_enum", tool_name)
        os.makedirs(tool_dir, exist_ok=True)
        
        paths = {
            "raw_output": os.path.join(tool_dir, f"{tool_name}_output_{timestamp}.txt"),
            "parsed_json": os.path.join(tool_dir, f"{tool_name}_parsed_{timestamp}.json")
        }
        
        # Save raw output
        with open(paths["raw_output"], 'w', encoding='utf-8') as f:
            f.write(raw_output)
        
        # Save parsed data
        with open(paths["parsed_json"], 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=2, default=str)
        
        logger.info(f"✓ Saved {tool_name} outputs")
        return paths
    
    def save_sqli_output(self, endpoint: str, raw_output: str, parsed_data: Dict[str, Any]) -> Dict[str, str]:
        """Save SQLMap outputs."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_endpoint = endpoint.replace('/', '_').replace(':', '_').replace('?', '_')[:50]
        
        paths = {
            "raw_output": os.path.join(self.raw_outputs_dir, "sqli", f"sqlmap_{safe_endpoint}_{timestamp}.txt"),
            "parsed_json": os.path.join(self.raw_outputs_dir, "sqli", f"sqlmap_{safe_endpoint}_{timestamp}.json")
        }
        
        # Save raw output
        with open(paths["raw_output"], 'w', encoding='utf-8') as f:
            f.write(raw_output)
        
        # Save parsed data
        with open(paths["parsed_json"], 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=2, default=str)
        
        logger.info(f"✓ Saved SQLi test outputs for {endpoint}")
        return paths
    
    def save_auth_test_output(self, url: str, test_data: Dict[str, Any]) -> Dict[str, str]:
        """Save authentication testing outputs."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = url.replace('/', '_').replace(':', '_').replace('?', '_')[:50]
        
        paths = {
            "test_json": os.path.join(self.raw_outputs_dir, "auth", f"auth_test_{safe_url}_{timestamp}.json"),
            "responses": os.path.join(self.raw_outputs_dir, "auth", f"auth_responses_{safe_url}_{timestamp}.json")
        }
        
        # Save test data
        with open(paths["test_json"], 'w', encoding='utf-8') as f:
            json.dump(test_data, f, indent=2, default=str)
        
        # Save detailed responses
        responses = {
            "invalid_user": test_data.get('invalid_username_response', {}),
            "invalid_pass": test_data.get('invalid_password_response', {})
        }
        with open(paths["responses"], 'w', encoding='utf-8') as f:
            json.dump(responses, f, indent=2, default=str)
        
        logger.info(f"✓ Saved auth test outputs for {url}")
        return paths
    
    def save_vulnerability_analysis(self, vuln_data: Dict[str, Any]) -> str:
        """Save vulnerability analysis results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.raw_outputs_dir, "vuln_analysis", f"vulnerabilities_{timestamp}.json")
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(vuln_data, f, indent=2, default=str)
        
        logger.info(f"✓ Saved vulnerability analysis")
        return path
    
    def save_screenshot(self, url: str, screenshot_data: bytes, format: str = "png") -> str:
        """Save screenshot evidence."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = url.replace('/', '_').replace(':', '_').replace('?', '_')[:50]
        
        filename = f"screenshot_{safe_url}_{timestamp}.{format}"
        path = os.path.join(self.evidence_dir, "screenshots", filename)
        
        with open(path, 'wb') as f:
            f.write(screenshot_data)
        
        logger.info(f"✓ Saved screenshot for {url}")
        return path
    
    def save_payload_file(self, payload_name: str, content: str) -> str:
        """Save payload or exploit file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{payload_name}_{timestamp}.txt"
        path = os.path.join(self.evidence_dir, "payloads", filename)
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"✓ Saved payload: {payload_name}")
        return path
    
    def save_phase_data(self, phase_name: str, phase_data: Dict[str, Any]) -> str:
        """Save complete phase data to JSON."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_phase_name = phase_name.lower().replace(' ', '_')
        
        filename = f"{safe_phase_name}_{timestamp}.json"
        path = os.path.join(self.raw_outputs_dir, filename)
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(phase_data, f, indent=2, default=str)
        
        logger.info(f"✓ Saved phase data: {phase_name}")
        return path
    
    # ===== LOAD METHODS =====
    
    def load_latest_phase_data(self, phase_name: str) -> Optional[Dict[str, Any]]:
        """Load the most recent phase data from disk."""
        safe_phase_name = phase_name.lower().replace(' ', '_')
        pattern = f"{safe_phase_name}_*.json"
        
        try:
            files = list(Path(self.raw_outputs_dir).glob(pattern))
            if not files:
                logger.warning(f"No saved data found for phase: {phase_name}")
                return None
            
            # Get most recent file
            latest_file = max(files, key=os.path.getmtime)
            
            with open(latest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            logger.info(f"✓ Loaded phase data: {phase_name} from {latest_file}")
            return data
            
        except Exception as e:
            logger.error(f"Error loading phase data {phase_name}: {e}")
            return None
    
    def load_all_nmap_outputs(self) -> List[Dict[str, Any]]:
        """Load all nmap scan outputs."""
        nmap_dir = os.path.join(self.raw_outputs_dir, "nmap")
        outputs = []
        
        try:
            for json_file in Path(nmap_dir).glob("nmap_parsed_*.json"):
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    outputs.append(data)
            
            return outputs
        except Exception as e:
            logger.error(f"Error loading nmap outputs: {e}")
            return []
    
    def load_all_sqli_outputs(self) -> List[Dict[str, Any]]:
        """Load all SQLi test outputs."""
        sqli_dir = os.path.join(self.raw_outputs_dir, "sqli")
        outputs = []
        
        try:
            for json_file in Path(sqli_dir).glob("sqlmap_*_parsed_*.json"):
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    outputs.append(data)
            
            return outputs
        except Exception as e:
            logger.error(f"Error loading SQLi outputs: {e}")
            return []
    
    def load_all_auth_outputs(self) -> List[Dict[str, Any]]:
        """Load all authentication test outputs."""
        auth_dir = os.path.join(self.raw_outputs_dir, "auth")
        outputs = []
        
        try:
            for json_file in Path(auth_dir).glob("auth_test_*.json"):
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    outputs.append(data)
            
            return outputs
        except Exception as e:
            logger.error(f"Error loading auth outputs: {e}")
            return []
    
    def get_all_screenshots(self) -> List[str]:
        """Get list of all screenshot files."""
        screenshot_dir = os.path.join(self.evidence_dir, "screenshots")
        try:
            return [str(f) for f in Path(screenshot_dir).glob("screenshot_*.png")]
        except Exception as e:
            logger.error(f"Error getting screenshots: {e}")
            return []
    
    def create_evidence_archive(self) -> str:
        """Create ZIP archive of all evidence files."""
        import zipfile
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"evidence_{self.job_id}_{timestamp}.zip"
        archive_path = os.path.join(self.job_dir, archive_name)
        
        try:
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add all files from raw_outputs
                for root, dirs, files in os.walk(self.raw_outputs_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.job_dir)
                        zipf.write(file_path, arcname)
                
                # Add evidence files
                for root, dirs, files in os.walk(self.evidence_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.job_dir)
                        zipf.write(file_path, arcname)
            
            logger.info(f"✓ Created evidence archive: {archive_path}")
            return archive_path
            
        except Exception as e:
            logger.error(f"Error creating evidence archive: {e}")
            return ""
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all saved outputs."""
        summary = {
            "job_id": self.job_id,
            "job_dir": self.job_dir,
            "directories": {
                "raw_outputs": self.raw_outputs_dir,
                "evidence": self.evidence_dir,
                "logs": self.logs_dir
            },
            "file_counts": {}
        }
        
        try:
            # Count files in each directory
            for name, dir_path in summary["directories"].items():
                if os.path.exists(dir_path):
                    file_count = sum([len(files) for _, _, files in os.walk(dir_path)])
                    summary["file_counts"][name] = file_count
                else:
                    summary["file_counts"][name] = 0
            
            # Get specific counts
            summary["nmap_scans"] = len(list(Path(self.raw_outputs_dir).glob("nmap/nmap_parsed_*.json")))
            summary["sqli_tests"] = len(list(Path(self.raw_outputs_dir).glob("sqli/sqlmap_*.json")))
            summary["auth_tests"] = len(list(Path(self.raw_outputs_dir).glob("auth/auth_test_*.json")))
            summary["screenshots"] = len(self.get_all_screenshots())
            
        except Exception as e:
            logger.error(f"Error getting summary: {e}")
        
        return summary


# Factory function
def get_output_manager(job_id: str) -> OutputManager:
    """Get OutputManager instance for a job."""
    return OutputManager(job_id)