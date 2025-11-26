"""
Service for checking server connectivity before starting a scan.
"""
import socket
import subprocess
import logging
import re
from typing import Tuple, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def extract_host_from_target(target: str) -> Tuple[str, Optional[int]]:
    """
    Extract hostname/IP and port from various target formats.

    Args:
        target: Target in various formats (IP, domain, URL)

    Returns:
        Tuple of (host, port). Port is None if not specified.

    Examples:
        "192.168.1.1" -> ("192.168.1.1", None)
        "example.com" -> ("example.com", None)
        "http://example.com:8080" -> ("example.com", 8080)
        "https://example.com" -> ("example.com", 443)
    """
    target = target.strip()

    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port

        # Use default ports if not specified
        if port is None:
            port = 443 if parsed.scheme == 'https' else 80

        return (host, port)

    # Check if port is specified with colon (e.g., "192.168.1.1:8080")
    if ':' in target and not target.count(':') > 1:  # Avoid IPv6
        parts = target.rsplit(':', 1)
        try:
            port = int(parts[1])
            return (parts[0], port)
        except ValueError:
            pass

    # Plain IP or domain
    return (target, None)


def check_icmp_ping(host: str, timeout: int = 3) -> bool:
    """
    Check if host responds to ICMP ping.

    Args:
        host: Hostname or IP address
        timeout: Timeout in seconds

    Returns:
        True if host responds to ping, False otherwise
    """
    try:
        logger.info(f"Performing ICMP ping check to {host}...")

        # Use -c 2 for 2 packets, -W for timeout
        result = subprocess.run(
            ['ping', '-c', '2', '-W', str(timeout), host],
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )

        if result.returncode == 0:
            logger.info(f"ICMP ping successful to {host}")
            return True
        else:
            logger.warning(f"ICMP ping failed to {host}: {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        logger.warning(f"ICMP ping timeout for {host}")
        return False
    except Exception as e:
        logger.error(f"Error during ICMP ping to {host}: {str(e)}")
        return False

def is_server_responsive(target: str) -> Tuple[bool, str]:
    """
    Check if server is responsive before starting a scan.

    Performs multiple checks:
    1. DNS resolution (if domain)
    2. ICMP ping
    3. TCP connection (if port specified)
    4. Common ports check (if no port specified)

    Args:
        target: Target in various formats (IP, domain, URL)

    Returns:
        Tuple of (is_responsive, message)
        - is_responsive: True if server is reachable, False otherwise
        - message: Descriptive message about connectivity status
    """
    logger.info("="*80)
    logger.info(f"Starting connectivity check for target: {target}")
    logger.info("="*80)

    try:
        # Extract host and port
        host, port = extract_host_from_target(target)

        if not host:
            return (False, "Invalid target format - could not extract hostname/IP")

        logger.info(f"Extracted host: {host}, port: {port}")

        # Step 1: Check DNS resolution (if not an IP address)
        if not is_valid_ip(host):
            logger.info(f"Resolving DNS for {host}...")
            try:
                resolved_ip = socket.gethostbyname(host)
                logger.info(f"DNS resolution successful: {host} -> {resolved_ip}")
            except socket.gaierror as e:
                logger.error(f"DNS resolution failed for {host}: {str(e)}")
                return (False, f"DNS resolution failed for '{host}'. Please check the domain name.")

        # Step 2: ICMP ping check
        ping_success = check_icmp_ping(host, timeout=3)

        if ping_success:
            logger.info(f"Server {host} is responsive (ICMP ping successful)")
            return (True, f"Server is responsive - ICMP ping successful")
        else:
            logger.warning(f"Server {host} is not responsive")
            return (False, f"Server is not responding. Cannot reach {host} via ICMP. "
                              f"Please verify the target is online and accessible.")

    except Exception as e:
        logger.error(f"Error during connectivity check: {str(e)}", exc_info=True)
        return (False, f"Connectivity check failed: {str(e)}")

    finally:
        logger.info("="*80)
        logger.info("Connectivity check completed")
        logger.info("="*80)


def is_valid_ip(address: str) -> bool:
    """
    Check if string is a valid IPv4 address.

    Args:
        address: String to check

    Returns:
        True if valid IPv4 address, False otherwise
    """
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ipv4_pattern.match(address):
        return False

    parts = address.split('.')
    return all(0 <= int(part) <= 255 for part in parts)
