#  services/jobs_service.py
import threading
import uuid
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from  database import SessionLocal
from  models import Job, Phase, Report
from  services.utils.helpers import (
    job_to_dict,
    phase_to_dict,
    report_to_dict,
)
from  services.phases.info_gathering import run_info_gathering_phase
from  services.phases.vulnerability_analysis import run_vulnerability_analysis_phase_enhanced
from  services.phases.web_enumeration import run_web_enumeration_phase
from  services.phases.sqli_testing import run_sqli_testing_phase
from  services.phases.authentication_testing import run_authentication_testing_phase
from  services.phases.report_generation import run_report_generation_phase
from  services.phases.report_generation.vulnerability_utils import get_vulnerability_summary

logger = logging.getLogger(__name__)


def _run_real_phases(db, job: Job, info_gathering_data: Dict[str, Any]):
    """Run all real pentesting phases in sequence."""
    logger.info(f"[Job {job.id}] Starting pentesting phases execution")
    phases_data = {
        'information_gathering': info_gathering_data
    }

    # Phase 2: Web Enumeration V2 (with PathAnalyzer, AuthAnalyzer, RAG)
    logger.info(f"[Job {job.id}] ===== PHASE 2: Web Enumeration V2 =====")
    job.phase = "Web Enumeration"
    job.phase_desc = "Enumerating web directories with intelligent analysis (PathAnalyzer + RAG)..."
    job.updated_at = datetime.now()
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"[Job {job.id}] Running web enumeration phase V2...")

    # Get custom wordlist from job if specified
    custom_wordlist = job.custom_wordlist if hasattr(job, 'custom_wordlist') else None

    web_enum_phase = run_web_enumeration_phase(db, job, info_gathering_data, custom_wordlist)
    if web_enum_phase:
        phases_data['web_enumeration'] = web_enum_phase.data
        logger.info(f"[Job {job.id}] Web enumeration V2 completed - Status: {web_enum_phase.status}")
    else:
        logger.warning(f"[Job {job.id}] Web enumeration returned no data")

    # Phase 3: Enhanced Vulnerability Analysis (with web integration)
    logger.info(f"[Job {job.id}] ===== PHASE 3: Enhanced Vulnerability Analysis =====")
    job.phase = "Vulnerability Analysis"
    job.phase_desc = "Analyzing vulnerabilities with service + web correlation..."
    job.updated_at = datetime.now()
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"[Job {job.id}] Running enhanced vulnerability analysis phase...")

    vuln_phase = run_vulnerability_analysis_phase_enhanced(
        db,
        job,
        info_gathering_data,
        web_enumeration_data=phases_data.get('web_enumeration')
    )
    if vuln_phase:
        phases_data['vulnerability_analysis'] = vuln_phase.data
        logger.info(f"[Job {job.id}] Enhanced vulnerability analysis completed - Status: {vuln_phase.status}")
    else:
        logger.warning(f"[Job {job.id}] Vulnerability analysis returned no data")

    # Phase 4: SQL Injection Testing
    logger.info(f"[Job {job.id}] ===== PHASE 4: SQL Injection Testing =====")
    job.phase = "SQL Injection Testing"
    job.phase_desc = "Testing endpoints for SQL injection vulnerabilities..."
    job.updated_at = datetime.now()
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"[Job {job.id}] Running SQL injection testing phase...")

    sqli_phase = run_sqli_testing_phase(db, job, phases_data.get('web_enumeration', {}))
    if sqli_phase:
        phases_data['sqli_testing'] = sqli_phase.data
        logger.info(f"[Job {job.id}] SQL injection testing completed - Status: {sqli_phase.status}")
    else:
        logger.warning(f"[Job {job.id}] SQL injection testing returned no data")

    # Phase 5: Authentication Testing
    logger.info(f"[Job {job.id}] ===== PHASE 5: Authentication Testing =====")
    job.phase = "Authentication Testing"
    job.phase_desc = "Testing login pages for username enumeration vulnerabilities..."
    job.updated_at = datetime.now()
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"[Job {job.id}] Running authentication testing phase...")

    auth_phase = run_authentication_testing_phase(db, job, phases_data.get('web_enumeration', {}))
    if auth_phase:
        phases_data['authentication_testing'] = auth_phase.data
        logger.info(f"[Job {job.id}] Authentication testing completed - Status: {auth_phase.status}")
    else:
        logger.warning(f"[Job {job.id}] Authentication testing returned no data")

    # Phase 6: Report Generation
    logger.info(f"[Job {job.id}] ===== PHASE 6: Report Generation =====")
    job.phase = "Report Generation"
    job.phase_desc = "Generating comprehensive markdown and PDF reports..."
    job.updated_at = datetime.now()
    db.add(job)
    db.commit()
    db.refresh(job)
    logger.info(f"[Job {job.id}] Running report generation phase...")

    report_phase = run_report_generation_phase(db, job, phases_data)
    if report_phase:
        phases_data['report_generation'] = report_phase.data
        logger.info(f"[Job {job.id}] Report generation completed - Status: {report_phase.status}")
    else:
        logger.warning(f"[Job {job.id}] Report generation returned no data")

    logger.info(f"[Job {job.id}] All pentesting phases execution completed")
    return phases_data


def _background_scan_thread(job_id: str, target: str):
    logger.info("="*100)
    logger.info(f"[Job {job_id}] Background scan thread started for target: {target}")
    logger.info("="*100)

    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            logger.error(f"[Job {job_id}] Job not found in database!")
            return

        logger.info(f"[Job {job_id}] Job found - Starting pentesting scan")

        # Phase 1: Information Gathering
        logger.info(f"[Job {job_id}] ===== PHASE 1: Information Gathering =====")
        job.phase = "Information Gathering"
        job.phase_desc = "Running nmap/whois/dns..."
        job.updated_at = datetime.now()
        db.add(job)
        db.commit()
        db.refresh(job)
        logger.info(f"[Job {job_id}] Running information gathering phase...")

        info_gathering_phase = run_info_gathering_phase(db, job)
        if not info_gathering_phase:
            raise Exception("Information gathering phase failed")
        logger.info(f"[Job {job_id}] Information gathering completed - Status: {info_gathering_phase.status}")

        # Run all remaining phases
        phases_data = _run_real_phases(db, job, info_gathering_phase.data)

        # Finalize job
        logger.info(f"[Job {job_id}] ===== Finalizing Job =====")
        job.status = "completed"
        job.phase = "All phases complete"
        job.phase_desc = "All done. Report ready."
        job.report_generated = True
        job.updated_at = datetime.now()
        db.add(job)
        db.commit()
        db.refresh(job)
        logger.info(f"[Job {job_id}] Job marked as completed")

        # Create report record
        logger.info(f"[Job {job_id}] Creating report record in database...")
        report_data = phases_data.get('report_generation', {})

        # Get the PDF path from report data and make it relative to reports directory
        # Use detailed_findings_pdf which is the actual key set by report_generator
        pdf_full_path = report_data.get('detailed_findings_pdf', f"reports/{job_id}/pentest_report_detailed.pdf")
        # Remove 'reports/' prefix if present to store relative path
        if pdf_full_path.startswith('reports/'):
            pdf_relative_path = pdf_full_path[8:]  # Remove 'reports/' prefix
        elif pdf_full_path.startswith('/reports/'):
            pdf_relative_path = pdf_full_path[9:]  # Remove '/reports/' prefix
        else:
            # If path doesn't start with reports/, use job_id/pentest_report_detailed.pdf as fallback
            pdf_relative_path = f"{job_id}/pentest_report_detailed.pdf"

        r = Report(
            job_id=job_id,
            report_path=pdf_relative_path,
            format="pdf",
            summary=f"Comprehensive penetration test report for {target}",
        )
        db.add(r)
        db.commit()
        db.refresh(r)
        logger.info(f"[Job {job_id}] Report record created - Path: {r.report_path}")

        logger.info("="*100)
        logger.info(f"[Job {job_id}] SCAN COMPLETED SUCCESSFULLY")
        logger.info("="*100)

    except Exception as e:
        logger.error(f"[Job {job_id}] CRITICAL ERROR in background scan thread: {str(e)}", exc_info=True)
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)
                job.updated_at = datetime.now()
                db.add(job)
                db.commit()
                logger.error(f"[Job {job_id}] Job marked as failed - Error: {str(e)}")
        except Exception as inner_e:
            logger.error(f"[Job {job_id}] Failed to update job status: {str(inner_e)}", exc_info=True)
    finally:
        db.close()
        logger.info(f"[Job {job_id}] Background scan thread terminated")


# Public API
def start_scan(target: str, description: Optional[str] = None, scan_config: Optional[Any] = None, custom_wordlist: Optional[str] = None) -> str:
    logger.info(f"start_scan called - Target: {target}, Wordlist: {custom_wordlist or 'default'}")

    # Check for localhost
    if target.lower() in ['localhost', '127.0.0.1', '::1']:
        logger.info(f"Target {target} detected as localhost, normalizing to 127.0.0.1")
        target = '127.0.0.1'

    db = SessionLocal()
    try:
        job_id = str(uuid.uuid4())
        logger.info(f"Generated new job ID: {job_id}")

        job = Job(
            id=job_id,
            description=description or f"Scan for {target}",
            target=target,
            status="running",
            phase="Initializing",
            phase_desc="Starting scan...",
            report_generated=False,
            error_message=None,
            custom_wordlist=custom_wordlist  # Store wordlist path in job
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        logger.info(f"Job {job_id} created in database with status: {job.status}")

        logger.info(f"Starting background scan thread for job {job_id}")
        thread = threading.Thread(
            target=_background_scan_thread, args=(job_id, target), daemon=True
        )
        thread.start()
        logger.info(f"Background thread started for job {job_id}")

        return job_id
    except Exception as e:
        logger.error(f"Error creating scan job: {str(e)}", exc_info=True)
        raise
    finally:
        db.close()


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    logger.debug(f"get_job called - Job ID: {job_id}")
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            logger.warning(f"Job not found: {job_id}")
            return None

        logger.debug(f"Job found: {job_id} - Status: {job.status}, Phase: {job.phase}")

        phases = (
            db.query(Phase)
            .filter(Phase.job_id == job_id)
            .order_by(Phase.created_at)
            .all()
        )
        logger.debug(f"Found {len(phases)} phases for job {job_id}")

        report = db.query(Report).filter(Report.job_id == job_id).first()
        if report:
            logger.debug(f"Report found for job {job_id}: {report.report_path}")

        result = job_to_dict(job)
        result["phases"] = [phase_to_dict(p) for p in phases]
        result["report"] = report_to_dict(report) if report else None

        # Calculate vulnerability statistics using centralized utility
        # Build phases_data dictionary from phase records
        phases_data = {}
        for phase in phases:
            if phase.phase_name == "Information Gathering":
                phases_data['information_gathering'] = phase.data
            elif phase.phase_name == "Vulnerability Analysis":
                phases_data['vulnerability_analysis'] = phase.data
            elif phase.phase_name == "Web Enumeration":
                phases_data['web_enumeration'] = phase.data
            elif phase.phase_name == "SQL Injection Testing":
                phases_data['sqli_testing'] = phase.data
            elif phase.phase_name in ["Authentication Testing", "Brute Force Testing"]:
                phases_data['authentication_testing'] = phase.data
                phases_data['brute_force_testing'] = phase.data  # Backward compatibility

        # Calculate vulnerability statistics if phases have completed
        try:
            if phases_data:
                vuln_summary = get_vulnerability_summary(phases_data)
                result["vulnerability_statistics"] = vuln_summary['statistics']
                result["has_vulnerabilities"] = vuln_summary['has_vulnerabilities']
                logger.debug(f"Calculated vulnerability statistics for job {job_id}: {vuln_summary['statistics']['total_vulnerabilities']} total")
            else:
                # No phases data available yet
                result["vulnerability_statistics"] = {
                    'total_vulnerabilities': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'critical_high': 0,
                    'by_type': {'cve': 0, 'sqli': 0, 'authentication': 0, 'web_exposure': 0}
                }
                result["has_vulnerabilities"] = False
        except Exception as vuln_error:
            logger.warning(f"Error calculating vulnerability statistics for job {job_id}: {str(vuln_error)}")
            # Return zero stats on error
            result["vulnerability_statistics"] = {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'critical_high': 0,
                'by_type': {'cve': 0, 'sqli': 0, 'authentication': 0, 'web_exposure': 0}
            }
            result["has_vulnerabilities"] = False

        return result
    except Exception as e:
        logger.error(f"Error retrieving job {job_id}: {str(e)}", exc_info=True)
        raise
    finally:
        db.close()


def get_all_jobs() -> List[Dict[str, Any]]:
    logger.debug("get_all_jobs called")
    db = SessionLocal()
    try:
        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        logger.debug(f"Retrieved {len(jobs)} jobs from database")

        # Convert jobs to dict - NO vulnerability statistics for list view (too slow!)
        # Vulnerability stats are only calculated when fetching a specific job
        result = []
        for j in jobs:
            job_dict = job_to_dict(j)

            # Return empty stats for all jobs in list view
            # Frontend should fetch individual job for detailed stats
            job_dict["vulnerability_statistics"] = {
                'total_vulnerabilities': 0,
                'critical_high': 0,
                'by_type': {'cve': 0, 'sqli': 0, 'authentication': 0, 'web_exposure': 0}
            }
            job_dict["has_vulnerabilities"] = False

            result.append(job_dict)

        logger.debug(f"Returning {len(result)} jobs (without detailed vulnerability stats)")
        return result
    except Exception as e:
        logger.error(f"Error retrieving all jobs: {str(e)}", exc_info=True)
        raise
    finally:
        db.close()


def delete_job(job_id: str):
    """
    Delete a job, its related database entries, and all associated files.
    """
    import shutil
    import os
    from services.utils.output_manager import OutputManager
    from models import Finding, Report

    logger.info(f"Attempting to delete job {job_id}")
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            logger.warning(f"Job {job_id} not found for deletion. It might have been already deleted.")
            return

        # 1. Delete files from filesystem
        try:
            output_mgr = OutputManager(job_id)
            job_dir = output_mgr.job_dir
            if os.path.exists(job_dir):
                shutil.rmtree(job_dir)
                logger.info(f"Deleted job directory: {job_dir}")
        except Exception as e:
            logger.error(f"Error deleting job directory for job {job_id}: {e}", exc_info=True)
            # Proceed with DB deletion anyway

        # 2. Delete associated Findings
        db.query(Finding).filter(Finding.job_id == job_id).delete(synchronize_session='fetch')
        logger.info(f"Deleted findings for job {job_id}")

        # 3. Delete associated Report
        db.query(Report).filter(Report.job_id == job_id).delete(synchronize_session='fetch')
        logger.info(f"Deleted report for job {job_id}")

        # 4. Delete the Job itself (phases will be cascade-deleted)
        db.delete(job)
        logger.info(f"Deleted job record for job {job_id}")

        # 5. Commit transaction
        db.commit()
        logger.info(f"Job {job_id} deleted successfully from database.")

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting job {job_id} from database: {e}", exc_info=True)
        raise
    finally:
        db.close()



def run_all_phases(job_id: str):
    """Run all penetration testing phases sequentially."""
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            return
        
        # Phase 1: Information Gathering
        info_phase = run_info_gathering_phase(db, job)
        if info_phase.status != "success":
            job.status = "failed"
            db.commit()
            return
        
        # Phase 2: Web Enumeration V2 (pass wordlist)
        web_phase = run_web_enumeration_phase(
            db,
            job,
            info_phase.data,
            custom_wordlist=job.custom_wordlist  # Pass wordlist to web enumeration
        )
        if web_phase.status != "success":
            job.status = "failed"
            db.commit()
            return

        # Phase 3: Enhanced Vulnerability Analysis (with web integration)
        vuln_phase = run_vulnerability_analysis_phase_enhanced(
            db,
            job,
            info_phase.data,
            web_enumeration_data=web_phase.data
        )
        if vuln_phase.status != "success":
            job.status = "failed"
            db.commit()
            return
        
        # Phase 4: SQL Injection Testing
        sqli_phase = run_sqli_testing_phase(db, job, web_phase.data)
        if sqli_phase.status != "success":
            job.status = "failed"
            db.commit()
            return
        
        # Phase 5: Authentication Testing (replaced brute force)
        auth_phase = run_authentication_testing_phase(db, job, web_phase.data)
        if auth_phase.status != "success":
            job.status = "failed"
            db.commit()
            return
        
        # Phase 6: Report Generation
        phases_data = {
            'information_gathering': info_phase.data,
            'vulnerability_analysis': vuln_phase.data,
            'web_enumeration': web_phase.data,
            'sqli_testing': sqli_phase.data,
            'authentication_testing': auth_phase.data,
        }
        report_phase = run_report_generation_phase(db, job, phases_data)
        if report_phase.status != "success":
            job.status = "failed"
            db.commit()
            return
        
        job.status = "completed"
        db.commit()
    except Exception as e:
        logger.error(f"Error in run_all_phases: {e}", exc_info=True)
        job.status = "failed"
        db.commit()
    finally:
        db.close()
