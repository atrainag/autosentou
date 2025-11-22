"""
Phase Testing Controller
Allows testing individual phases with custom inputs for debugging/development
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from database import get_db
from models import Job, Phase
import uuid
from datetime import datetime

# Import phase functions
from services.phases.info_gathering import run_info_gathering_phase
from services.phases.web_enumeration import run_web_enumeration_phase
from services.phases.vulnerability_analysis import run_vulnerability_analysis_phase_enhanced
from services.phases.sqli_testing import run_sqli_testing_phase
from services.phases.authentication_testing import run_authentication_testing_phase
from services.phases.web_analysis import WebAnalysisPhase
from services.phases.report_generation.report_generator import run_report_generation_phase

router = APIRouter()


# ========== Request Models ==========

class Phase1Request(BaseModel):
    target: str


class Phase2Request(BaseModel):
    job_id: str
    custom_wordlist: Optional[str] = None


class Phase3Request(BaseModel):
    job_id: str


class Phase4Request(BaseModel):
    job_id: str


class Phase5Request(BaseModel):
    job_id: str


class Phase6Request(BaseModel):
    job_id: str
    max_pages: Optional[int] = 50


class ReportGenerationRequest(BaseModel):
    job_id: str


class RetryPhaseRequest(BaseModel):
    job_id: str
    phase_name: str  # e.g., "Information Gathering", "Web Enumeration", etc.
    custom_wordlist: Optional[str] = None  # For Web Enumeration
    max_pages: Optional[int] = 50  # For Web Analysis


# ========== Phase Testing Endpoints ==========

@router.post("/test-phase/info-gathering")
def test_info_gathering(request: Phase1Request, db: Session = Depends(get_db)):
    """
    Test Phase 1: Information Gathering
    Creates a temporary job and runs info gathering phase
    """
    try:
        # Create temporary test job
        job = Job(
            id=f"test-p1-{uuid.uuid4().hex[:8]}",
            target=request.target,
            description=f"Phase 1 Test - {request.target}",
            status="testing",
            created_at=datetime.now()
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Run phase
        phase = run_info_gathering_phase(db, job)

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/web-enumeration")
def test_web_enumeration(request: Phase2Request, db: Session = Depends(get_db)):
    """
    Test Phase 2: Web Enumeration
    Requires existing job with Phase 1 data
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get Phase 1 data
        phase1 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Information Gathering"
        ).first()

        if not phase1:
            raise HTTPException(status_code=404, detail="Phase 1 data not found. Run Phase 1 first.")

        # Run phase
        phase = run_web_enumeration_phase(
            db, job,
            phase1.data,
            custom_wordlist=request.custom_wordlist
        )

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/vulnerability-analysis")
def test_vulnerability_analysis(request: Phase3Request, db: Session = Depends(get_db)):
    """
    Test Phase 3: Vulnerability Analysis
    Requires existing job with Phase 1 and Phase 2 data
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get Phase 1 data
        phase1 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Information Gathering"
        ).first()
        if not phase1:
            raise HTTPException(status_code=404, detail="Phase 1 data not found")

        # Get Phase 2 data (optional)
        phase2 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Web Enumeration"
        ).first()

        # Run phase
        phase = run_vulnerability_analysis_phase_enhanced(
            db, job,
            phase1.data,
            web_enumeration_data=phase2.data if phase2 else None
        )

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/sqli-testing")
def test_sqli_testing(request: Phase4Request, db: Session = Depends(get_db)):
    """
    Test Phase 4: SQL Injection Testing
    Requires existing job with Phase 2 data
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get Phase 2 data
        phase2 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Web Enumeration"
        ).first()
        if not phase2:
            raise HTTPException(status_code=404, detail="Phase 2 data not found")

        # Run phase
        phase = run_sqli_testing_phase(db, job, phase2.data)

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/authentication-testing")
def test_authentication_testing(request: Phase5Request, db: Session = Depends(get_db)):
    """
    Test Phase 5: Authentication Testing
    Requires existing job with Phase 2 data
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get Phase 2 data
        phase2 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Web Enumeration"
        ).first()
        if not phase2:
            raise HTTPException(status_code=404, detail="Phase 2 data not found")

        # Run phase
        phase = run_authentication_testing_phase(db, job, phase2.data)

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/web-analysis")
def test_web_analysis(request: Phase6Request, db: Session = Depends(get_db)):
    """
    Test Phase 2.5: Web Analysis (NEW)
    Requires existing job with Phase 2 data
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Get Phase 2 data
        phase2 = db.query(Phase).filter(
            Phase.job_id == request.job_id,
            Phase.phase_name == "Web Enumeration"
        ).first()
        if not phase2:
            raise HTTPException(status_code=404, detail="Phase 2 data not found")

        # Run phase
        phase_executor = WebAnalysisPhase(db, job)
        phase = phase_executor.execute(phase2.data, max_pages=request.max_pages)

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-phase/report-generation")
def test_report_generation(request: ReportGenerationRequest, db: Session = Depends(get_db)):
    """
    Test Report Generation Phase
    Collects all phase data and generates the final report
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Collect all phase data
        all_phases_data = {}

        # Get all phases for this job
        phases = db.query(Phase).filter(Phase.job_id == request.job_id).all()

        # Map phase names to data keys
        phase_name_mapping = {
            "Information Gathering": "info_gathering",
            "Web Enumeration": "web_enumeration",
            "Web Analysis": "web_analysis",
            "Vulnerability Analysis": "vulnerability_analysis",
            "SQL Injection Testing": "sqli_testing",
            "Authentication Testing": "authentication_testing",
            "XSS Testing": "xss_testing"
        }

        # Collect phase data
        for phase in phases:
            if phase.phase_name in phase_name_mapping:
                data_key = phase_name_mapping[phase.phase_name]
                if phase.data:
                    all_phases_data[data_key] = phase.data

        # Check if we have at least Phase 1 data
        if not all_phases_data:
            raise HTTPException(
                status_code=400,
                detail="No phase data found. Run at least Phase 1 (Information Gathering) first."
            )

        # Run report generation
        phase = run_report_generation_phase(db, job, all_phases_data)

        if not phase:
            raise HTTPException(status_code=500, detail="Report generation failed")

        return {
            "success": True,
            "job_id": job.id,
            "phase_id": phase.id,
            "status": phase.status,
            "data": phase.data,
            "phases_used": list(all_phases_data.keys())
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/retry-phase")
def retry_phase(request: RetryPhaseRequest, db: Session = Depends(get_db)):
    """
    Retry a specific phase for an existing job.
    Useful when a phase fails and you want to retry without re-running the entire scan.
    """
    try:
        # Get existing job
        job = db.query(Job).filter(Job.id == request.job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Phase execution mapping
        phase_mapping = {
            "Information Gathering": {
                "func": run_info_gathering_phase,
                "args": lambda: [db, job]
            },
            "Web Enumeration": {
                "func": run_web_enumeration_phase,
                "args": lambda: _get_web_enum_args(db, job, request.custom_wordlist)
            },
            "Web Analysis": {
                "func": lambda db, job, phase2_data, max_pages: WebAnalysisPhase(db, job).execute(phase2_data, max_pages=max_pages),
                "args": lambda: _get_web_analysis_args(db, job, request.max_pages)
            },
            "Vulnerability Analysis": {
                "func": run_vulnerability_analysis_phase_enhanced,
                "args": lambda: _get_vuln_analysis_args(db, job)
            },
            "SQL Injection Testing": {
                "func": run_sqli_testing_phase,
                "args": lambda: _get_sqli_args(db, job)
            },
            "Authentication Testing": {
                "func": run_authentication_testing_phase,
                "args": lambda: _get_auth_testing_args(db, job)
            },
            "Report Generation": {
                "func": run_report_generation_phase,
                "args": lambda: _get_report_gen_args(db, job)
            }
        }

        if request.phase_name not in phase_mapping:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid phase name. Valid phases: {', '.join(phase_mapping.keys())}"
            )

        # Get phase function and args
        phase_info = phase_mapping[request.phase_name]
        phase_func = phase_info["func"]
        phase_args = phase_info["args"]()

        # Execute phase
        phase = phase_func(*phase_args)

        if not phase:
            raise HTTPException(status_code=500, detail=f"{request.phase_name} failed")

        return {
            "success": True,
            "job_id": job.id,
            "phase_name": request.phase_name,
            "phase_id": phase.id,
            "status": phase.status,
            "message": f"{request.phase_name} completed successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retry failed: {str(e)}")


def _get_web_enum_args(db, job, custom_wordlist):
    """Get Phase 1 data for Web Enumeration"""
    phase1 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Information Gathering"
    ).first()
    if not phase1:
        raise HTTPException(status_code=404, detail="Phase 1 data not found. Run Phase 1 first.")
    return [db, job, phase1.data, custom_wordlist]


def _get_web_analysis_args(db, job, max_pages):
    """Get Phase 2 data for Web Analysis"""
    phase2 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Web Enumeration"
    ).first()
    if not phase2:
        raise HTTPException(status_code=404, detail="Phase 2 data not found. Run Phase 2 first.")
    return [db, job, phase2.data, max_pages]


def _get_vuln_analysis_args(db, job):
    """Get Phase 1 and Phase 2 data for Vulnerability Analysis"""
    phase1 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Information Gathering"
    ).first()
    if not phase1:
        raise HTTPException(status_code=404, detail="Phase 1 data not found")

    phase2 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Web Enumeration"
    ).first()

    return [db, job, phase1.data, phase2.data if phase2 else None]


def _get_sqli_args(db, job):
    """Get Phase 2 data for SQL Injection Testing"""
    phase2 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Web Enumeration"
    ).first()
    if not phase2:
        raise HTTPException(status_code=404, detail="Phase 2 data not found")
    return [db, job, phase2.data]


def _get_auth_testing_args(db, job):
    """Get Phase 2 data for Authentication Testing"""
    phase2 = db.query(Phase).filter(
        Phase.job_id == job.id,
        Phase.phase_name == "Web Enumeration"
    ).first()
    if not phase2:
        raise HTTPException(status_code=404, detail="Phase 2 data not found")
    return [db, job, phase2.data]


def _get_report_gen_args(db, job):
    """Collect all phase data for Report Generation"""
    all_phases_data = {}
    phases = db.query(Phase).filter(Phase.job_id == job.id).all()

    phase_name_mapping = {
        "Information Gathering": "info_gathering",
        "Web Enumeration": "web_enumeration",
        "Web Analysis": "web_analysis",
        "Vulnerability Analysis": "vulnerability_analysis",
        "SQL Injection Testing": "sqli_testing",
        "Authentication Testing": "authentication_testing",
        "XSS Testing": "xss_testing"
    }

    for phase in phases:
        if phase.phase_name in phase_name_mapping:
            data_key = phase_name_mapping[phase.phase_name]
            if phase.data:
                all_phases_data[data_key] = phase.data

    if not all_phases_data:
        raise HTTPException(status_code=400, detail="No phase data found")

    return [db, job, all_phases_data]


@router.get("/test-jobs")
def get_test_jobs(db: Session = Depends(get_db)):
    """Get all test jobs for selection in phase testing"""
    jobs = db.query(Job).filter(
        (Job.status == "testing") | (Job.status == "completed")
    ).order_by(Job.created_at.desc()).limit(50).all()

    return {
        "jobs": [
            {
                "id": job.id,
                "target": job.target,
                "description": job.description,
                "status": job.status,
                "created_at": job.created_at.isoformat() if job.created_at else None
            }
            for job in jobs
        ]
    }


@router.get("/job/{job_id}/phases")
def get_job_phases(job_id: str, db: Session = Depends(get_db)):
    """Get all phases for a specific job"""
    phases = db.query(Phase).filter(Phase.job_id == job_id).all()

    return {
        "job_id": job_id,
        "phases": [
            {
                "id": phase.id,
                "name": phase.phase_name,
                "status": phase.status,
                "has_data": phase.data is not None and len(phase.data) > 0
            }
            for phase in phases
        ]
    }
