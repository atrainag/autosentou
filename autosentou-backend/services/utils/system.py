import subprocess
import logging
import select
import sys
import pty
import os
from typing import List, Dict, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_command(cmd: List[str], timeout: int = None, cwd: Optional[str] = None) -> Dict[str, object]:
    """
    Run subprocess command with enhanced error handling and logging.
    
    Args:
        cmd: Command to run as list of strings
        timeout: Timeout in seconds
        cwd: Working directory for the command
        
    Returns:
        Dictionary with stdout, stderr, returncode, and execution info
    """
    start_time = datetime.now()
    
    try:
        logger.info(f"Running command: {' '.join(cmd)}")
        
        proc = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            cwd=cwd,
            encoding='utf-8',
            errors='replace'  # Handle encoding errors gracefully
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result = {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "duration": duration,
            "command": ' '.join(cmd),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }
        
        if proc.returncode == 0:
            logger.info(f"Command completed successfully in {duration:.2f}s")
        else:
            logger.warning(f"Command failed with return code {proc.returncode} in {duration:.2f}s")
            if proc.stderr:
                logger.warning(f"Error output: {proc.stderr[:500]}...")
        
        return result
        
    except subprocess.TimeoutExpired as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.error(f"Command timed out after {duration:.2f}s: {' '.join(cmd)}")
        
        return {
            "stdout": e.stdout or "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
            "duration": duration,
            "command": ' '.join(cmd),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "timeout": True
        }
        
    except FileNotFoundError as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.error(f"Command not found: {e}")
        
        return {
            "stdout": "",
            "stderr": f"Command not found: {e}",
            "returncode": -1,
            "duration": duration,
            "command": ' '.join(cmd),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "file_not_found": True
        }
        
    except PermissionError as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.error(f"Permission denied: {e}")
        
        return {
            "stdout": "",
            "stderr": f"Permission denied: {e}",
            "returncode": -1,
            "duration": duration,
            "command": ' '.join(cmd),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "permission_error": True
        }
        
    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.error(f"Unexpected error running command: {e}")
        
        return {
            "stdout": "",
            "stderr": f"Unexpected error: {str(e)}",
            "returncode": -1,
            "duration": duration,
            "command": ' '.join(cmd),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "unexpected_error": True
        }


def check_tool_availability(tool_name: str) -> bool:
    """
    Check if a tool is available in the system PATH.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool is available, False otherwise
    """
    test_cases = [
        [tool_name, '--version'],
        [tool_name, '-v'],
        [tool_name, '--help'],
        [tool_name, '-h'],
        [tool_name],
    ]

    # Test until one of the test cases succeeds
    for test_case in test_cases:
        try:
            result = run_command(test_case, timeout=5)
            
            # For most tools, return code 0 means success
            if result['returncode'] == 0:
                return True
            
            # For hydra and medusa, they might return non-zero codes but still be available
            # Check if it's not a "command not found" error (127) and has some output
            if tool_name in ['hydra', 'medusa'] and result['returncode'] != 127:
                # If we get any output (stdout or stderr), consider it available
                if result.get('stdout', '').strip() or result.get('stderr', '').strip():
                    return True
                    
        except Exception:
            pass
    
    return False


def validate_command_success(result: Dict[str, object], expected_return_codes: List[int] = [0]) -> bool:
    """
    Validate if a command execution was successful.
    
    Args:
        result: Result dictionary from run_command
        expected_return_codes: List of expected return codes
        
    Returns:
        True if command was successful, False otherwise
    """
    return result.get('returncode', -1) in expected_return_codes


def get_command_error_summary(result: Dict[str, object]) -> str:
    """
    Get a summary of command execution errors.
    
    Args:
        result: Result dictionary from run_command
        
    Returns:
        Error summary string
    """
    if result.get('timeout'):
        return f"Command timed out after {result.get('duration', 0):.2f}s"
    elif result.get('file_not_found'):
        return "Command or tool not found in system PATH"
    elif result.get('permission_error'):
        return "Permission denied - insufficient privileges"
    elif result.get('unexpected_error'):
        return f"Unexpected error: {result.get('stderr', 'Unknown error')}"
    elif result.get('returncode', 0) != 0:
        return f"Command failed with return code {result.get('returncode', -1)}: {result.get('stderr', 'No error details')}"
    else:
        return "Unknown error"
