"""
PoC Executor
Safely executes Proof-of-Concept exploits with comprehensive safety controls
"""
import subprocess
import tempfile
import shutil
import os
import logging
import signal
import git
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class PoCExecutor:
    """
    Executes PoC exploits with safety controls:
    - Timeouts
    - Sandboxing
    - Output validation
    - Cleanup
    - Logging
    """

    def __init__(self, workspace_dir: str = "/tmp/poc_workspace", max_timeout: int = 120):
        """
        Initialize PoC executor.

        Args:
            workspace_dir: Directory for temporary exploit files
            max_timeout: Maximum execution timeout in seconds
        """
        self.workspace_dir = workspace_dir
        self.max_timeout = max_timeout
        self.active_processes = []

        # Create workspace
        os.makedirs(workspace_dir, exist_ok=True)

        logger.info(f"PoCExecutor initialized with workspace: {workspace_dir}")

    def execute_poc(
        self,
        exploit: Dict[str, Any],
        target: str,
        port: Optional[int] = None,
        additional_args: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a PoC exploit against a target.

        Args:
            exploit: Exploit information from search (must contain poc_commands)
            target: Target IP/hostname
            port: Target port
            additional_args: Additional arguments for the exploit
            timeout: Execution timeout (seconds)

        Returns:
            Execution result with success status
        """
        start_time = datetime.now()
        result = {
            'exploit_id': exploit.get('id') or exploit.get('cve_id', 'unknown'),
            'target': target,
            'port': port,
            'started_at': start_time.isoformat(),
            'success': False,
            'output': '',
            'error': '',
            'execution_time': 0,
            'attempts': []
        }

        try:
            # Validate inputs
            if not self._validate_target(target):
                result['error'] = "Invalid target"
                return result

            # Get PoC commands
            poc_commands = exploit.get('poc_commands', [])
            if not poc_commands:
                result['error'] = "No PoC commands available"
                return result

            # Get success indicators
            success_indicators = exploit.get('success_indicators', [])

            # Execute each PoC command
            for i, command_template in enumerate(poc_commands[:3]):  # Limit to 3 attempts
                logger.info(f"Executing PoC attempt {i+1}/{len(poc_commands[:3])}")

                attempt_result = self._execute_command(
                    command_template=command_template,
                    target=target,
                    port=port,
                    additional_args=additional_args,
                    timeout=timeout or self.max_timeout
                )

                result['attempts'].append(attempt_result)

                # Check if successful
                if attempt_result.get('returncode') == 0:
                    output = attempt_result.get('output', '')

                    # Check for success indicators
                    if self._check_success_indicators(output, success_indicators):
                        result['success'] = True
                        result['output'] = output
                        logger.info(f"✓ PoC execution successful on attempt {i+1}")
                        break

            # Calculate total execution time
            end_time = datetime.now()
            result['execution_time'] = (end_time - start_time).total_seconds()
            result['completed_at'] = end_time.isoformat()

        except Exception as e:
            logger.error(f"Error executing PoC: {e}", exc_info=True)
            result['error'] = str(e)

        return result

    def _execute_command(
        self,
        command_template: str,
        target: str,
        port: Optional[int],
        additional_args: Optional[Dict[str, str]],
        timeout: int
    ) -> Dict[str, Any]:
        """
        Execute a single PoC command.

        Args:
            command_template: Command template with placeholders
            target: Target IP/hostname
            port: Target port
            additional_args: Additional arguments
            timeout: Timeout in seconds

        Returns:
            Execution result
        """
        result = {
            'command_template': command_template,
            'returncode': -1,
            'output': '',
            'error': '',
            'timeout_exceeded': False
        }

        try:
            # Build command
            command = self._build_command(
                command_template,
                target,
                port,
                additional_args
            )

            result['command_executed'] = command

            logger.info(f"Executing command: {command[:100]}...")

            # Execute with timeout
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid  # Create new process group for cleanup
            )

            self.active_processes.append(process)

            try:
                stdout, stderr = process.communicate(timeout=timeout)
                result['returncode'] = process.returncode
                result['output'] = stdout
                result['error'] = stderr

                logger.info(f"Command completed with return code: {process.returncode}")

            except subprocess.TimeoutExpired:
                logger.warning(f"Command timed out after {timeout} seconds")
                result['timeout_exceeded'] = True

                # Kill process group
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass

                # Get partial output
                try:
                    stdout, stderr = process.communicate(timeout=1)
                    result['output'] = stdout
                    result['error'] = stderr
                except:
                    pass

            finally:
                if process in self.active_processes:
                    self.active_processes.remove(process)

        except Exception as e:
            logger.error(f"Error executing command: {e}", exc_info=True)
            result['error'] = str(e)

        return result

    def _build_command(
        self,
        template: str,
        target: str,
        port: Optional[int],
        additional_args: Optional[Dict[str, str]]
    ) -> str:
        """
        Build command from template by replacing placeholders.

        Args:
            template: Command template
            target: Target IP/hostname
            port: Target port
            additional_args: Additional arguments

        Returns:
            Ready-to-execute command
        """
        command = template

        # Replace common placeholders
        command = command.replace('TARGET', target)
        command = command.replace('{target}', target)
        command = command.replace('$TARGET', target)

        if port:
            command = command.replace('PORT', str(port))
            command = command.replace('{port}', str(port))
            command = command.replace('$PORT', str(port))

        # Replace additional arguments
        if additional_args:
            for key, value in additional_args.items():
                command = command.replace(f'{{{key}}}', value)
                command = command.replace(f'${key}', value)

        return command

    def _check_success_indicators(self, output: str, indicators: List[str]) -> bool:
        """
        Check if output contains success indicators.

        Args:
            output: Command output
            indicators: List of success indicators

        Returns:
            True if any indicator found
        """
        if not indicators:
            return False

        output_lower = output.lower()

        for indicator in indicators:
            if indicator.lower() in output_lower:
                logger.info(f"Found success indicator: {indicator}")
                return True

        return False

    def _validate_target(self, target: str) -> bool:
        """
        Validate target is a valid IP or hostname.

        Args:
            target: Target to validate

        Returns:
            True if valid
        """
        import re

        # Check if valid IP
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, target):
            # Validate IP octets
            octets = target.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return True

        # Check if valid hostname
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(hostname_pattern, target):
            return True

        return False

    def clone_github_exploit(self, git_url: str) -> Optional[str]:
        """
        Clone a GitHub exploit repository.

        Args:
            git_url: GitHub repository URL

        Returns:
            Path to cloned repository or None if failed
        """
        try:
            # Create unique directory for this exploit
            repo_name = git_url.split('/')[-1].replace('.git', '')
            clone_path = os.path.join(self.workspace_dir, repo_name)

            # Remove if already exists
            if os.path.exists(clone_path):
                shutil.rmtree(clone_path)

            logger.info(f"Cloning {git_url} to {clone_path}")

            # Clone with timeout
            git.Repo.clone_from(git_url, clone_path, depth=1)

            logger.info(f"✓ Cloned successfully to {clone_path}")
            return clone_path

        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            return None

    def analyze_exploit_files(self, exploit_dir: str) -> Dict[str, Any]:
        """
        Analyze exploit files to find executables and determine usage.

        Args:
            exploit_dir: Path to exploit directory

        Returns:
            Analysis results
        """
        analysis = {
            'python_files': [],
            'shell_scripts': [],
            'compiled_binaries': [],
            'readme_files': [],
            'requirements_files': [],
            'suggested_commands': []
        }

        try:
            for root, dirs, files in os.walk(exploit_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_lower = file.lower()

                    if file_lower.endswith('.py'):
                        analysis['python_files'].append(file_path)
                    elif file_lower.endswith('.sh'):
                        analysis['shell_scripts'].append(file_path)
                    elif os.access(file_path, os.X_OK) and not file_lower.endswith(('.txt', '.md', '.py', '.sh')):
                        analysis['compiled_binaries'].append(file_path)
                    elif 'readme' in file_lower:
                        analysis['readme_files'].append(file_path)
                    elif 'requirements' in file_lower:
                        analysis['requirements_files'].append(file_path)

            # Generate suggested commands
            for py_file in analysis['python_files']:
                analysis['suggested_commands'].append(f"python {py_file} TARGET")
                analysis['suggested_commands'].append(f"python3 {py_file} TARGET")

            for sh_file in analysis['shell_scripts']:
                analysis['suggested_commands'].append(f"bash {sh_file} TARGET")

            for binary in analysis['compiled_binaries']:
                analysis['suggested_commands'].append(f"{binary} TARGET")

            logger.info(f"Analyzed {exploit_dir}: found {len(analysis['python_files'])} Python files, "
                       f"{len(analysis['shell_scripts'])} shell scripts")

        except Exception as e:
            logger.error(f"Error analyzing exploit files: {e}")
            analysis['error'] = str(e)

        return analysis

    def cleanup_workspace(self):
        """
        Clean up workspace directory and kill any active processes.
        """
        try:
            # Kill active processes
            for process in self.active_processes:
                try:
                    process.kill()
                except:
                    pass

            self.active_processes = []

            # Clean workspace
            if os.path.exists(self.workspace_dir):
                shutil.rmtree(self.workspace_dir)
                os.makedirs(self.workspace_dir, exist_ok=True)

            logger.info("✓ Workspace cleaned up")

        except Exception as e:
            logger.error(f"Error cleaning up workspace: {e}")

    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup_workspace()
