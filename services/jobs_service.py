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


def _fake_remaining_phases(db, job_id: str):
    """Create simulated phase rows to show progress for demo purposes."""
    remaining = [
        ("Vulnerability Analysis", "Mapping services to CVEs and preparing POCs..."),
        ("POC Execution", "Attempting safe PoCs or simulations..."),
        ("Web Enumeration", "Running dirsearch / crawler..."),
        ("Exploitation", "Testing non-destructive checks like banners..."),
        ("Report Generation", "Compiling markdown into PDF..."),
    ]
    for phase_name, phase_desc in remaining:
        p = Phase(
            job_id=job_id,
            phase_name=phase_name,
            data={"note": phase_desc},
            log_path=None,
            status="ongoing",
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        # update job status
        job = db.query(Job).filter(Job.id == job_id).first()
        job.phase = phase_name
        job.phase_desc = phase_desc
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)
        time.sleep(2)
        p.status = "success"
        p.updated_at = datetime.utcnow()
        db.add(p)
        db.commit()


def _background_scan_thread(job_id: str, target: str):
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return

        # Phase 1: information gathering (real)
        job.phase = "Information Gathering"
        job.phase_desc = "Running nmap/whois/dns..."
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)
        run_info_gathering_phase(db, job)

        # quickly update job to next phase
        job.phase = "Vulnerability Analysis"
        job.phase_desc = "Ready to map services to CVEs"
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)

        # simulated remaining phases so UI shows progress
        _fake_remaining_phases(db, job_id)

        # finalize
        job.status = "completed"
        job.phase = "All phases complete"
        job.phase_desc = "All done. Report ready."
        job.report_generated = True
        job.updated_at = datetime.utcnow()
        db.add(job)
        db.commit()
        db.refresh(job)

        r = Report(
            job_id=job_id,
            report_path=f"/reports/{job_id}.pdf",
            format="pdf",
            summary=f"Auto-generated report for {target}",
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
def start_scan(target: str, description: Optional[str] = None) -> str:
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
