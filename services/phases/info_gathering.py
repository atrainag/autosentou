# autosentou/services/phases/info_gathering.py
import re
import socket
from datetime import datetime
from typing import Dict, Any, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job
from autosentou.database import SessionLocal


def run_nmap(target: str) -> Dict[str, Any]:
    """Run nmap and parse grepable output into a small JSON summary."""
    cmd = ["nmap", "-sVC", "-Pn", "-p1-65535", "-oG", "-", target]
    res = run_command(cmd )
    stdout = res.get("stdout", "") or ""
    parsed_ports = []

    for line in stdout.splitlines():
        m = re.search(r"Ports:\s*(.+)$", line)
        if m:
            ports_field = m.group(1)
            for p in ports_field.split(","):
                parts = p.split("/")
                if len(parts) >= 5:
                    try:
                        port_num = int(parts[0].strip())
                    except Exception:
                        continue
                    state = parts[1]
                    proto = parts[2]
                    service = parts[4]
                    version = parts[5]
                    parsed_ports.append(
                        {
                            "port": port_num,
                            "state": state,
                            "proto": proto,
                            "version": version,
                        }
                    )
    return {
        "raw": stdout,
        "parsed_ports": parsed_ports,
        "meta": {"returncode": res.get("returncode"), "stderr": res.get("stderr")},
    }


def run_whois(target: str) -> Dict[str, Any]:
    cmd = ["whois", target]
    res = run_command(cmd, timeout=20)
    return {
        "raw": res.get("stdout", ""),
        "meta": {"returncode": res.get("returncode"), "stderr": res.get("stderr")},
    }


def run_dnsenum(target: str) -> Dict[str, Any]:
    # we use dnsenum instead and take its relevant information into our session local db
    cmd = ["dnsenum", target]
    res = run_command(cmd)
    return {
        "raw": res.get("stdout", ""),
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
