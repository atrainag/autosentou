# autosentou/services/phases/info_gathering.py
import re
import socket
from datetime import datetime
from typing import Dict, Any, Optional
from autosentou.services.utils.system import run_command
from autosentou.models import Phase, Job
from autosentou.database import SessionLocal


def run_nmap(target: str) -> Dict[str, Any]:
    
    # 初掃獲得開啓的端口（完整要加上-p1-65535）
    print("run_nmap // 1. find open port")
    cmd_1 = ["nmap", "-sS", "-Pn", target,"-oG", "-"]
    res_1 = run_command(cmd_1)
    print("A")
    stdout_1 = res_1.get("stdout", "") or ""
    parsed_ports_1 = []
    for line in stdout_1.splitlines():
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

                    if state.lower() == "open":
                        parsed_ports_1.append(
                            {"port": port_num, "state": state, "proto": proto}
                        )

    if not parsed_ports_1:
        return {
            "raw": stdout_1,
            "parsed_ports": [],
            "meta": {"returncode": res_1.get("returncode"), "stderr": res_1.get("stderr")},
        }

    open_ports = ",".join(str(p["port"]) for p in parsed_ports_1)
    print("open_ports: ", open_ports)
    
    # 複掃獲得端口版本
    print("run_nmap // 2. find port version")
    cmd_2 = ["nmap", "-sVC", "-Pn", target, "-p", open_ports, "-oG", "-"]
    res_2 = run_command(cmd_2)
    stdout_2 = res_2.get("stdout", "") or ""
    parsed_ports_2 = []

    for line in stdout_2.splitlines():
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
                    version = parts[6]

                    if state.lower() == "open":
                        print(f"Port {port_num} => Version: {version}")
                        parsed_ports_2.append(
                            {"port": port_num, "state": state, "proto": proto, "service": service, "version": version}
                        )
    return {
        "raw": stdout_2,
        "parsed_ports": parsed_ports_2,
        "meta": {"returncode": res_2.get("returncode"), "stderr": res_2.get("stderr")},
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
        nmap_res = run_nmap(job.target)
        print()
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
