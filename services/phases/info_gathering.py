# autosentou/services/phases/info_gathering.py
import re
import socket
from datetime import datetime
from typing import Dict, Any, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job
from autosentou.database import SessionLocal


def run_nmap(target: str) -> Dict[str, Any]:
    """Run nmap and parse output into detailed JSON summary."""
    # First, run a quick scan to identify open ports
    quick_cmd = ["nmap", "-sS",  "-Pn", "-p1-65535", "-oG", "-", target]
    quick_res = run_command(quick_cmd, timeout=300)
    
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
    
    # If no ports found, try common ports
    if not open_ports:
        open_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 27017]
    
    # Run detailed scan on open ports
    if open_ports:
        ports_str = ",".join(map(str, open_ports))
        detailed_cmd = ["nmap", "-sVC", "-T4", "-p", ports_str, "-oG", "-", target]
    else:
        detailed_cmd = ["nmap", "-sVC", "-T4", "-p", "1-1000", "-oG", "-", target]
    
    res = run_command(detailed_cmd, timeout=600)
    stdout = res.get("stdout", "") or ""
    parsed_ports = []
    host_info = {}
    
    for line in stdout.splitlines():
        # Parse host information
        if line.startswith("Host:"):
            host_match = re.search(r"Host:\s*(\S+)\s*\((\S+)\)", line)
            if host_match:
                host_info["ip"] = host_match.group(1)
                host_info["hostname"] = host_match.group(2)
        
        # Parse port information
        if "Ports:" in line:
            ports_field = re.search(r"Ports:\s*(.+)$", line)
            if ports_field:
                for port_info in ports_field.group(1).split(","):
                    parts = port_info.split("/")
                    if len(parts) >= 5:
                        try:
                            port_num = int(parts[0].strip())
                            state = parts[1].strip()
                            proto = parts[2].strip()
                            service = parts[4].strip()
                            version = parts[5].strip() if len(parts) > 5 else ""
                            
                            # Extract additional info
                            extra_info = ""
                            if len(parts) > 6:
                                extra_info = "/".join(parts[6:])
                            
                            parsed_ports.append({
                                "port": port_num,
                                "state": state,
                                "proto": proto,
                                "service": service,
                                "version": version,
                                "extra_info": extra_info,
                                "banner": extra_info if "banner" in extra_info.lower() else ""
                            })
                        except (ValueError, IndexError):
                            continue
    
    # Run OS detection if ports are open
    os_info = {}
    if parsed_ports:
        os_cmd = ["nmap", "-O", "-T4", target]
        os_res = run_command(os_cmd, timeout=300)
        os_stdout = os_res.get("stdout", "") or ""
        
        for line in os_stdout.splitlines():
            if "Running:" in line:
                os_info["os"] = line.split("Running:", 1)[1].strip()
            elif "OS details:" in line:
                os_info["os_details"] = line.split("OS details:", 1)[1].strip()
    
    return {
        "raw": stdout,
        "parsed_ports": parsed_ports,
        "host_info": host_info,
        "os_info": os_info,
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

    try:
        print("NMAPRUN")
        nmap_res = run_nmap(job.target)
        print("NMAPRUN END")
        
        print(nmap_res)
        print("WHOISRUN")
        whois_res = run_whois(job.target)
        print(whois_res)
        print("DNSENUMLUN")
        dns_res = run_dnsenum(job.target)
        print(dns_res)
        print("DNSENUMLUN END")
        
        combined = {
            "target": job.target,
            "nmap": nmap_res,
            "whois": whois_res,
            "dns": dns_res,
        }

        phase.data = combined
        phase.status = "success"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        return phase
    except Exception as e:
        phase.data = {"error": str(e)}
        phase.status = "failed"
        phase.updated_at = datetime.utcnow()
        db_session.add(phase)
        db_session.commit()
        db_session.refresh(phase)
        return phase
