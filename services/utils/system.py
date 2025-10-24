import subprocess
from typing import List, Dict


def run_command(cmd: List[str], timeout: int = None) -> Dict[str, object]:
    """Run subprocess command and return stdout/stderr/returncode."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": f"command not found: {e}", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}
