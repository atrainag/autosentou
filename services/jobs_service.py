# autosentou/services/jobs_service.py
import threading
import uuid
import time
from datetime import datetime
from typing import Optional, Dict, Any, List

from autosentou.database import SessionLocal
from autosentou.models import Job, Phase, Report
from autosentou.services.utils.helpers import (
    job_to_dict,
    phase_to_dict,
    report_to_dict,
)
from autosentou.services.phases.info_gathering import run_info_gathering_phase
from autosentou.services.phases.vulnerability_analysis import run_vulnerability_analysis_phase
from autosentou.services.phases.web_enumeration import run_web_enumeration_phase
from autosentou.services.phases.sqli_testing import run_sqli_testing_phase
from autosentou.services.phases.brute_force_testing import run_brute_force_testing_phase
from autosentou.services.phases.report_generation import run_report_generation_phase


def _run_real_phases(db, job: Job, info_gathering_data: Dict[str, Any]):
    """Run all real pentesting phases in sequence."""
    phases_data = {
        'info_gathering': info_gathering_data
    }
    
    # Phase 2: Vulnerability Analysis
    job.phase = "Vulnerability Analysis"
    job.phase_desc = "Analyzing services for vulnerabilities and CVEs..."
    job.updated_at = datetime.utcnow()
    db.add(job)
    db.commit()
    db.refresh(job)
    
    vuln_phase = run_vulnerability_analysis_phase(db, job, info_gathering_data)
    if vuln_phase:
        phases_data['vulnerability_analysis'] = vuln_phase.data
    
    # Phase 3: Web Enumeration
    job.phase = "Web Enumeration"
    job.phase_desc = "Enumerating web directories and analyzing with AI..."
    job.updated_at = datetime.utcnow()
    db.add(job)
    db.commit()
    db.refresh(job)
    
    web_enum_phase = run_web_enumeration_phase(db, job, info_gathering_data)
    if web_enum_phase:
        phases_data['web_enumeration'] = web_enum_phase.data
    
    # Phase 4: SQL Injection Testing
    job.phase = "SQL Injection Testing"
    job.phase_desc = "Testing endpoints for SQL injection vulnerabilities..."
    job.updated_at = datetime.utcnow()
    db.add(job)
    db.commit()
    db.refresh(job)
    
    sqli_phase = run_sqli_testing_phase(db, job, phases_data.get('web_enumeration', {}))
    if sqli_phase:
        phases_data['sqli_testing'] = sqli_phase.data
    
    # Phase 5: Brute Force Testing
    job.phase = "Brute Force Testing"
    job.phase_desc = "Testing login endpoints with brute force attacks..."
    job.updated_at = datetime.utcnow()
    db.add(job)
    db.commit()
    db.refresh(job)
    
    bf_phase = run_brute_force_testing_phase(db, job, phases_data.get('web_enumeration', {}))
    if bf_phase:
        phases_data['brute_force_testing'] = bf_phase.data
    
    # Phase 6: Report Generation
    job.phase = "Report Generation"
    job.phase_desc = "Generating comprehensive markdown and PDF reports..."
    job.updated_at = datetime.utcnow()
    db.add(job)
    db.commit()
    db.refresh(job)
    
    report_phase = run_report_generation_phase(db, job, phases_data)
    if report_phase:
        phases_data['report_generation'] = report_phase.data
    
    return phases_data


def _background_scan_thread(job_id: str, target: str):
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return

        # Phase 1: Information Gathering
        job.phase = "Information Gathering"
        job.phase_desc = "Running nmap/whois/dns..."
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)

        info_gathering_phase = run_info_gathering_phase(db, job)
        if not info_gathering_phase:
            raise Exception("Information gathering phase failed")

        # Run all remaining phases
        phases_data = _run_real_phases(db, job, info_gathering_phase.data)

        # Finalize job
        job.status = "completed"
        job.phase = "All phases complete"
        job.phase_desc = "All done. Report ready."
        job.report_generated = True
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)

        # Create report record
        report_data = phases_data.get('report_generation', {})
        r = Report(
            job_id=job_id,
            report_path=report_data.get('pdf_path', f"/reports/{job_id}/report_{job_id}.pdf"),
            format="pdf",
            summary=f"Comprehensive penetration test report for {target}",
        )
        db.add(r)
        db.commit()
        db.refresh(r)

    except Exception as e:
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)
                job.updated_at = datetime.utcnow()
                db.add(job)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# Public API
def start_scan(target: str, description: Optional[str] = None, scan_config: Optional[Any] = None) -> str:
    db = SessionLocal()
    try:
        job_id = str(uuid.uuid4())
        job = Job(
            id=job_id,
            description=description or f"Scan for {target}",
            target=target,
            status="running",
            phase="Initializing",
            phase_desc="Starting scan...",
            report_generated=False,
            error_message=None,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        thread = threading.Thread(
            target=_background_scan_thread, args=(job_id, target), daemon=True
        )
        thread.start()

        return job_id
    finally:
        db.close()


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return None
        phases = (
            db.query(Phase)
            .filter(Phase.job_id == job_id)
            .order_by(Phase.created_at)
            .all()
        )
        report = db.query(Report).filter(Report.job_id == job_id).first()
        result = job_to_dict(job)
        result["phases"] = [phase_to_dict(p) for p in phases]
        result["report"] = report_to_dict(report) if report else None
        return result
    finally:
        db.close()


def get_all_jobs() -> List[Dict[str, Any]]:
    db = SessionLocal()
    try:
        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        return [job_to_dict(j) for j in jobs]
    finally:
        db.close()
