#  services/phases/info_gathering.py
import re
import socket
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from  services.utils.system import run_command
from  models import Phase, Job
from  database import SessionLocal
from services.utils.output_manager import get_output_manager

logger = logging.getLogger(__name__)


def run_nmap(target: str) -> Dict[str, Any]:
    """Run nmap and parse output into detailed JSON summary."""
    # First, run a quick scan to identify open ports
    # Using -sT (TCP connect) instead of -sS (SYN scan) to avoid requiring root privileges
    quick_cmd = ["nmap", "-sT",  "-Pn", "-p1-65535", "-oG", "-", target]
    quick_res = run_command(quick_cmd)
    
    # Parse quick scan results
    open_ports = []
    quick_stdout = quick_res.get("stdout", "") or ""
    
    for line in quick_stdout.splitlines():
        if "Ports:" in line:
            ports_field = re.search(r"Ports:\s*(.+)$", line)
            if ports_field:
                for port_info in ports_field.group(1).split(","):
                    parts = port_info.split("/")
                    if len(parts) >= 2:
                        try:
                            port_num = int(parts[0].strip())
                            state = parts[1].strip()
                            if state == "open":
                                open_ports.append(port_num)
                        except (ValueError, IndexError):
                            continue
    
    # If no ports found, try common ports as a fallback
    if not open_ports:
        open_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 27017]
    
    # Run detailed scan on open ports, including OS detection
    # Using -sT (TCP connect) along with -sV (version), -sC (scripts), and -O (OS detection)
    # Added --privileged for better OS detection if running as root
    if open_ports:
        ports_str = ",".join(map(str, open_ports))
        detailed_cmd = ["nmap", "-sT", "-sV", "-sC", "-O", "--privileged", "-T4", "-p", ports_str, target]
    else:
        detailed_cmd = ["nmap", "-sT", "-sV", "-sC", "-O", "--privileged", "-T4", "-p", "1-1000", target]

    res = run_command(detailed_cmd)
    stdout = res.get("stdout", "") or ""
    parsed_ports = []
    host_info = {}
    os_detection = {
        "os_matches": [],
        "os_classes": [],
        "running": None,
        "os_details": None
    }

    # Flag to indicate we are in the port scanning section of the output
    parsing_ports = False
    parsing_os_guesses = False

    for line in stdout.splitlines():
        # Parse host information
        if line.startswith("Nmap scan report for"):
            host_match = re.search(r"Nmap scan report for\s*(\S+)\s*\((\S+)\)", line)
            if host_match:
                host_info["hostname"] = host_match.group(1)
                host_info["ip"] = host_match.group(2)
            else:
                host_match = re.search(r"Nmap scan report for\s*(\S+)", line)
                if host_match:
                    # Handle cases where hostname and IP are the same (e.g., scanning an IP directly)
                    hostname = host_match.group(1)
                    host_info["hostname"] = hostname
                    try:
                        # If the hostname is an IP, get the actual hostname
                        host_info["hostname"] = socket.gethostbyaddr(hostname)[0]
                        host_info["ip"] = hostname
                    except (socket.herror, socket.gaierror):
                        host_info["ip"] = hostname


        # Start parsing ports after the header
        if line.startswith("PORT"):
            parsing_ports = True
            continue

        # Stop parsing ports if we hit a blank line after starting
        if parsing_ports and not line.strip():
            parsing_ports = False

        if parsing_ports:
            # Regex to capture port, protocol, state, service, and version
            match = re.match(r"(\d+)/(\w+)\s+(open)\s+(\S+)\s*(.*)", line)
            if match:
                port_num = int(match.group(1))
                proto = match.group(2)
                state = match.group(3)
                service = match.group(4)
                version = match.group(5).strip()

                parsed_ports.append({
                    "port": port_num,
                    "state": state,
                    "proto": proto,
                    "service": service,
                    "version": version,
                    "extra_info": "", # This would require more complex parsing of script outputs
                    "banner": ""
                })

        # Parse OS information from various nmap output lines
        if "Running:" in line:
            os_detection["running"] = line.split("Running:", 1)[1].strip()
        elif "OS details:" in line:
            os_detection["os_details"] = line.split("OS details:", 1)[1].strip()
            # Also add as first os_match with high confidence
            if os_detection["os_details"]:
                os_detection["os_matches"].append({
                    "name": os_detection["os_details"],
                    "accuracy": "95",
                    "type": "General"
                })
        elif "Aggressive OS guesses:" in line:
            parsing_os_guesses = True
            # Parse the first guess on the same line
            guesses_text = line.split("Aggressive OS guesses:", 1)[1].strip()
            if guesses_text:
                # Parse first guess: "OS Name (accuracy%)"
                first_guess = guesses_text.split(',')[0].strip()
                match = re.match(r"(.+?)\s*\((\d+)%\)", first_guess)
                if match:
                    os_detection["os_matches"].append({
                        "name": match.group(1),
                        "accuracy": match.group(2),
                        "type": "Guess"
                    })
        elif parsing_os_guesses and line.strip() and not line.startswith("No exact"):
            # Continue parsing OS guesses on subsequent lines
            if '(' in line and '%' in line:
                parts = line.strip().split(',')
                for part in parts:
                    match = re.match(r"(.+?)\s*\((\d+)%\)", part.strip())
                    if match:
                        os_detection["os_matches"].append({
                            "name": match.group(1),
                            "accuracy": match.group(2),
                            "type": "Guess"
                        })
            else:
                parsing_os_guesses = False

        # Parse OS CPE (Common Platform Enumeration) for OS classes
        if "OS CPE:" in line:
            cpe = line.split("OS CPE:", 1)[1].strip()
            # Extract OS info from CPE (format: cpe:/o:vendor:os:version)
            cpe_parts = cpe.split(':')
            if len(cpe_parts) >= 4:
                vendor = cpe_parts[2] if len(cpe_parts) > 2 else "Unknown"
                osfamily = cpe_parts[3] if len(cpe_parts) > 3 else "Unknown"
                osgen = cpe_parts[4] if len(cpe_parts) > 4 else ""
                os_detection["os_classes"].append({
                    "vendor": vendor.replace('_', ' ').title(),
                    "osfamily": osfamily.replace('_', ' ').title(),
                    "osgen": osgen,
                    "accuracy": "90"
                })
    
    return {
        "raw": stdout,
        "parsed_ports": parsed_ports,
        "host_info": host_info,
        "os_detection": os_detection,
        "open_ports_count": len([p for p in parsed_ports if p["state"] == "open"]),
        "meta": {"returncode": res.get("returncode"), "stderr": res.get("stderr")},
    }


def run_whois(target: str) -> Dict[str, Any]:
    """Run whois and parse output into structured data."""
    cmd = ["whois", target]
    res = run_command(cmd, timeout=30)
    raw_output = res.get("stdout", "")
    
    # Parse whois output
    parsed_data = {
        "domain": target,
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "name_servers": [],
        "admin_contact": {},
        "tech_contact": {},
        "raw": raw_output
    }
    
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith('%') or line.startswith('#'):
            continue
            
        # Parse different whois fields
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if 'registrar' in key:
                parsed_data["registrar"] = value
            elif 'creation' in key or 'created' in key:
                parsed_data["creation_date"] = value
            elif 'expiration' in key or 'expires' in key:
                parsed_data["expiration_date"] = value
            elif 'name server' in key or 'nserver' in key:
                if value not in parsed_data["name_servers"]:
                    parsed_data["name_servers"].append(value)
            elif 'admin' in key and 'email' in key:
                parsed_data["admin_contact"]["email"] = value
            elif 'admin' in key and 'name' in key:
                parsed_data["admin_contact"]["name"] = value
            elif 'tech' in key and 'email' in key:
                parsed_data["tech_contact"]["email"] = value
            elif 'tech' in key and 'name' in key:
                parsed_data["tech_contact"]["name"] = value
    
    return {
        "raw": raw_output,
        "parsed": parsed_data,
        "meta": {"returncode": res.get("returncode"), "stderr": res.get("stderr")},
    }


def run_dnsenum(target: str) -> Dict[str, Any]:
    """Run dnsenum and parse output into structured data."""
    cmd = ["dnsenum", "--threads", "5", "--timeout", "10", target]
    res = run_command(cmd, timeout=300)
    raw_output = res.get("stdout", "")
    
    # Parse dnsenum output
    parsed_data = {
        "target": target,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_records": [],
        "subdomains": [],
        "wildcard_test": False,
        "raw": raw_output
    }
    
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
            
        # Parse A records
        if line.startswith(target) and 'A' in line:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                parsed_data["a_records"].append({
                    "domain": target,
                    "ip": ip_match.group(1)
                })
        
        # Parse subdomains
        elif '.' in line and target in line and not line.startswith(';'):
            if 'A' in line:
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[0]
                    ip = parts[-1]
                    if domain != target and domain.endswith(target):
                        parsed_data["subdomains"].append({
                            "domain": domain,
                            "ip": ip,
                            "type": "A"
                        })
        
        # Parse MX records
        elif 'MX' in line and 'preference' in line:
            mx_match = re.search(r'(\S+)\s+MX\s+preference\s+(\d+),\s+mail\s+exchanger\s+(\S+)', line)
            if mx_match:
                parsed_data["mx_records"].append({
                    "domain": mx_match.group(1),
                    "preference": int(mx_match.group(2)),
                    "mail_exchanger": mx_match.group(3)
                })
        
        # Parse NS records
        elif 'NS' in line and 'nameserver' in line:
            ns_match = re.search(r'(\S+)\s+NS\s+nameserver\s+(\S+)', line)
            if ns_match:
                parsed_data["ns_records"].append({
                    "domain": ns_match.group(1),
                    "nameserver": ns_match.group(2)
                })
        
        # Parse TXT records
        elif 'TXT' in line:
            txt_match = re.search(r'(\S+)\s+TXT\s+"([^"]+)"', line)
            if txt_match:
                parsed_data["txt_records"].append({
                    "domain": txt_match.group(1),
                    "text": txt_match.group(2)
                })
        
        # Check for wildcard
        elif 'Wildcard' in line:
            parsed_data["wildcard_test"] = True
    
    return {
        "raw": raw_output,
        "parsed": parsed_data,
        "meta": {"returncode": res.get("returncode"), "stderr": res.get("stderr")},
    }



def run_info_gathering_phase(db_session, job: Job) -> Optional[Phase]:
    """
    Create a Phase row, run nmap/whois/dns, store results into phase.data, return Phase
    db_session: SQLAlchemy session already opened by caller (so commits are in same transaction if desired)
    """
    logger.info(f"[Job {job.id}] Starting information gathering phase for target: {job.target}")

    phase = Phase(
        job_id=job.id,
        phase_name="Information Gathering",
        data={},
        log_path=None,
        status="ongoing",
    )
    db_session.add(phase)
    db_session.commit()
    db_session.refresh(phase)
    logger.info(f"[Job {job.id}] Information gathering phase record created in database")

    try:
        # Initialize output manager
        output_mgr = get_output_manager(job.id)
        logger.info(f"[Job {job.id}] Output manager initialized")
        
        # Check if target is local/private IP
        is_local = is_local_target(job.target)
        logger.info(f"[Job {job.id}] Target type: {'LOCAL/PRIVATE' if is_local else 'PUBLIC/EXTERNAL'}")

        logger.info(f"[Job {job.id}] Running nmap scan on {job.target}...")
        nmap_res = run_nmap(job.target)
        
        # SAVE NMAP OUTPUT TO DISK
        nmap_paths = output_mgr.save_nmap_output(
            raw_output=nmap_res.get('raw', ''),
            parsed_data=nmap_res
        )
        nmap_res['saved_files'] = nmap_paths
        
        logger.info(f"[Job {job.id}] Nmap scan completed - Found {nmap_res.get('open_ports_count', 0)} open ports")
        logger.debug(f"[Job {job.id}] Nmap results: {nmap_res}")

        # Only run WHOIS and DNS for public/external targets
        if is_local:
            logger.info(f"[Job {job.id}] Target {job.target} is local - skipping WHOIS and DNSenum")
            whois_res = {
                "skipped": True,
                "reason": "Local target - WHOIS not applicable",
                "raw": "",
                "parsed": {},
                "meta": {}
            }
            dns_res = {
                "skipped": True,
                "reason": "Local target - DNS enumeration not applicable",
                "raw": "",
                "parsed": {},
                "meta": {}
            }
        else:
            logger.info(f"[Job {job.id}] Running WHOIS lookup on {job.target}...")
            whois_res = run_whois(job.target)
            logger.info(f"[Job {job.id}] WHOIS lookup completed")
            logger.debug(f"[Job {job.id}] WHOIS results: {whois_res}")

            logger.info(f"[Job {job.id}] Running DNSenum on {job.target}...")
            dns_res = run_dnsenum(job.target)
            logger.info(f"[Job {job.id}] DNSenum completed")
            logger.debug(f"[Job {job.id}] DNSenum results: {dns_res}")

        # Compile results
        results = {
            'target': job.target,
            'is_local_target': is_local,
            'nmap': nmap_res,
            'whois': whois_res,
            'dnsenum': dns_res,
            'saved_files': nmap_paths  # Include file paths
        }
        
        # SAVE COMPLETE PHASE DATA
        phase_data_path = output_mgr.save_phase_data('information_gathering', results)
        results['phase_data_file'] = phase_data_path
        
        phase.data = results
        phase.status = "success"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        logger.info(f"[Job {job.id}] Information gathering phase completed successfully")
        return phase
    except Exception as e:
        logger.error(f"[Job {job.id}] Information gathering phase failed: {str(e)}", exc_info=True)
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.now()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        return phase


def is_local_target(target: str) -> bool:
    """
    Determine if target is a local/private IP address.
    Returns True for private IPs, localhost, and local hostnames.
    """
    import ipaddress
    
    # Check for localhost
    if target.lower() in ['localhost', '127.0.0.1', '::1']:
        return True
    
    try:
        # Try to parse as IP address
        ip = ipaddress.ip_address(target)
        
        # Check if it's a private IP
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # Not a valid IP, might be a hostname
        # Try to resolve it
        try:
            resolved_ip = socket.gethostbyname(target)
            ip = ipaddress.ip_address(resolved_ip)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except (socket.gaierror, ValueError):
            # Can't resolve or invalid IP
            # Assume it's a local hostname if it doesn't contain a dot
            return '.' not in target
    
    return False
