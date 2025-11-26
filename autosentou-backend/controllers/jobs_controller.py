from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import logging
from database import get_db
from models import StartScanRequest, ExportRequest, Finding, FindingsSummaryResponse, FindingsListResponse, FindingResponse, Job
from services.jobs_service import start_scan, get_job, get_all_jobs, delete_job
import os
import shutil

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/start-scan")
def start_scan_endpoint(request: StartScanRequest, db: Session = Depends(get_db)):
    """
    Start a new penetration test scan.

    Args:
        request: Contains target and optional wordlist path
        db: Database session

    Returns:
        Job information with job_id
    """
    logger.info("="*80)
    logger.info(f"Received scan request for target: {request.target}")
    logger.info(f"Description: {request.description}")
    logger.info(f"Custom wordlist: {request.custom_wordlist or 'None (using default)'}")

    # Validate server connectivity before starting scan
    logger.info("Performing pre-scan connectivity check...")
    from services.utils.connectivity_check import is_server_responsive

    is_responsive, connectivity_message = is_server_responsive(request.target)

    if not is_responsive:
        logger.error(f"Connectivity check failed for {request.target}: {connectivity_message}")
        raise HTTPException(
            status_code=400,
            detail=f"Target server is not responding: {connectivity_message}"
        )

    logger.info(f"Connectivity check passed: {connectivity_message}")

    # Validate wordlist if provided
    if request.custom_wordlist:
        logger.info(f"Validating custom wordlist: {request.custom_wordlist}")
        if not os.path.exists(request.custom_wordlist):
            logger.error(f"Wordlist not found: {request.custom_wordlist}")
            raise HTTPException(
                status_code=400,
                detail=f"Wordlist not found: {request.custom_wordlist}"
            )
        if not os.path.isfile(request.custom_wordlist):
            logger.error(f"Wordlist path is not a file: {request.custom_wordlist}")
            raise HTTPException(
                status_code=400,
                detail=f"Wordlist path is not a file: {request.custom_wordlist}"
            )
        logger.info("Wordlist validation passed")

    try:
        # Fix: Pass target string, not db session
        logger.info("Starting scan job...")
        job_id = start_scan(
            target=request.target,
            description=request.description,
            custom_wordlist=request.custom_wordlist
        )
        logger.info(f"Scan job created successfully - Job ID: {job_id}")

        # Get the job to return details
        job_info = get_job(job_id)

        response = {
            "message": "Scan started",
            "job_id": job_id,
            "target": request.target,
            "status": job_info.get('status') if job_info else 'running',
            "wordlist": request.custom_wordlist or "default"
        }

        logger.info(f"Scan request completed successfully - Job ID: {job_id}")
        logger.info("="*80)
        return response

    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}", exc_info=True)
        raise


@router.post("/upload-wordlist")
async def upload_wordlist(file: UploadFile = File(...)):
    """
    Upload a custom wordlist file.

    Returns:
        Path to uploaded wordlist
    """
    logger.info(f"Received wordlist upload request - Filename: {file.filename}")

    # Create wordlists directory if it doesn't exist
    wordlists_dir = "wordlists/custom"
    os.makedirs(wordlists_dir, exist_ok=True)
    logger.debug(f"Wordlists directory ready: {wordlists_dir}")

    # Save the uploaded file
    file_path = os.path.join(wordlists_dir, file.filename)

    try:
        logger.info(f"Saving wordlist to: {file_path}")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info("Wordlist file saved successfully")

        # Count lines in wordlist
        logger.debug("Counting lines in wordlist...")
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)

        file_size = os.path.getsize(file_path)
        logger.info(f"Wordlist uploaded: {file.filename} ({file_size} bytes, {line_count} lines)")

        return {
            "message": "Wordlist uploaded successfully",
            "path": file_path,
            "filename": file.filename,
            "size": file_size,
            "line_count": line_count
        }
    except Exception as e:
        logger.error(f"Failed to upload wordlist: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload wordlist: {str(e)}"
        )


@router.get("/wordlists")
def list_wordlists():
    """
    List available wordlists.

    Returns:
        List of wordlist objects, each containing:
        - name: filename
        - path: absolute file path
        - size: file size in bytes
        - line_count: number of lines
        - type: 'default' or 'custom'
    """
    logger.info("Received request to list available wordlists")
    wordlists = []

    # Check default wordlist
    default_wordlist = "wordlists/common.txt"
    if os.path.exists(default_wordlist):
        logger.debug(f"Found default wordlist: {default_wordlist}")
        with open(default_wordlist, "r", encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)

        wordlists.append({
            "name": "common.txt",
            "path": default_wordlist,
            "size": os.path.getsize(default_wordlist),
            "line_count": line_count,
            "type": "default"
        })
    else:
        logger.warning(f"Default wordlist not found: {default_wordlist}")

    # Check custom wordlists
    custom_dir = "wordlists/custom"
    if os.path.exists(custom_dir):
        logger.debug(f"Scanning custom wordlists directory: {custom_dir}")
        for filename in os.listdir(custom_dir):
            file_path = os.path.join(custom_dir, filename)
            if os.path.isfile(file_path):
                try:
                    with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)

                    wordlists.append({
                        "name": filename,
                        "path": file_path,
                        "size": os.path.getsize(file_path),
                        "line_count": line_count,
                        "type": "custom"
                    })
                    logger.debug(f"Found custom wordlist: {filename}")
                except Exception as e:
                    logger.warning(f"Failed to process wordlist {filename}: {str(e)}")
                    continue
    else:
        logger.info(f"Custom wordlists directory not found: {custom_dir}")

    logger.info(f"Found {len(wordlists)} wordlists total")

    return wordlists


@router.get("/wordlists/{filename}")
def get_wordlist_content(filename: str, limit: int = Query(default=1000, ge=1, le=10000)):
    """
    Retrieve the content of a specific wordlist file.

    Args:
        filename: Name of the wordlist file
        limit: Maximum number of lines to return (default: 1000, max: 10000)

    Returns:
        Dictionary containing:
        - filename: Name of the wordlist
        - content: List of lines from the file
        - line_count: Total number of lines in file
        - size: File size in bytes
        - type: 'custom' or 'default'

    Raises:
        HTTPException: 400 for invalid filename, 404 if not found, 500 for other errors
    """
    logger.info("="*80)
    logger.info(f"Received request to get wordlist content - Filename: {filename}")
    logger.info(f"Line limit: {limit}")

    # Security: Prevent path traversal attacks
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.error(f"Invalid filename (path traversal attempt detected): {filename}")
        raise HTTPException(
            status_code=400,
            detail="Invalid filename: Path traversal characters not allowed"
        )

    # Search for file in custom directory first, then default directory
    custom_path = os.path.join("wordlists/custom", filename)
    default_path = os.path.join("wordlists", filename)

    file_path = None
    wordlist_type = None

    if os.path.exists(custom_path) and os.path.isfile(custom_path):
        file_path = custom_path
        wordlist_type = "custom"
        logger.info(f"Found wordlist in custom directory: {custom_path}")
    elif os.path.exists(default_path) and os.path.isfile(default_path):
        file_path = default_path
        wordlist_type = "default"
        logger.info(f"Found wordlist in default directory: {default_path}")
    else:
        logger.warning(f"Wordlist not found: {filename}")
        raise HTTPException(
            status_code=404,
            detail=f"Wordlist not found: {filename}"
        )

    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        logger.debug(f"File size: {file_size} bytes")

        # Read file content
        logger.debug(f"Reading wordlist content (limit: {limit} lines)...")
        content = []
        total_lines = 0

        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                total_lines += 1
                if len(content) < limit:
                    # Strip newline characters and add to content
                    content.append(line.rstrip('\n\r'))

        logger.info(f"Wordlist content retrieved successfully - Total lines: {total_lines}, Returned: {len(content)}")
        logger.info("="*80)

        return {
            "filename": filename,
            "content": content,
            "line_count": total_lines,
            "size": file_size,
            "type": wordlist_type
        }

    except Exception as e:
        logger.error(f"Failed to read wordlist {filename}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read wordlist: {str(e)}"
        )


@router.delete("/wordlist/{wordlistName}")
def delete_wordlist(wordlistName: str):
    """
    Delete a custom wordlist file.

    Args:
        wordlistName: Name of the wordlist file to delete

    Returns:
        Dictionary containing:
        - message: Success message
        - filename: Name of the deleted wordlist

    Raises:
        HTTPException: 400 for invalid filename (path traversal)
                      403 for attempting to delete default wordlists
                      404 if file not found
                      500 for other errors
    """
    logger.info("="*80)
    logger.info(f"Received request to delete wordlist - Filename: {wordlistName}")

    # Security: Prevent path traversal attacks
    if ".." in wordlistName or "/" in wordlistName or "\\" in wordlistName:
        logger.error(f"Invalid filename (path traversal attempt detected): {wordlistName}")
        raise HTTPException(
            status_code=400,
            detail="Invalid filename: Path traversal characters not allowed"
        )

    # Only allow deleting custom wordlists (security feature)
    custom_path = os.path.join("wordlists/custom", wordlistName)
    logger.debug(f"Checking for wordlist at: {custom_path}")

    # Check if file exists
    if not os.path.exists(custom_path):
        logger.warning(f"Wordlist not found: {wordlistName}")
        raise HTTPException(
            status_code=404,
            detail=f"Wordlist not found: {wordlistName}"
        )

    # Verify it's a file (not a directory)
    if not os.path.isfile(custom_path):
        logger.error(f"Path is not a file: {custom_path}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid path: Not a file"
        )

    try:
        # Delete the file
        logger.info(f"Deleting wordlist: {custom_path}")
        os.remove(custom_path)
        logger.info(f"Wordlist deleted successfully: {wordlistName}")
        logger.info("="*80)

        return {
            "message": "Wordlist deleted successfully",
            "filename": wordlistName
        }

    except Exception as e:
        logger.error(f"Failed to delete wordlist {wordlistName}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete wordlist: {str(e)}"
        )


@router.get("/job/{job_id}")
def get_job_endpoint(job_id: str, db: Session = Depends(get_db)):
    logger.info(f"Received request to get job details - Job ID: {job_id}")
    try:
        job = get_job(job_id)
        if not job:
            logger.warning(f"Job not found: {job_id}")
            raise HTTPException(status_code=404, detail="Job not found")

        logger.info(f"Job retrieved successfully - Job ID: {job_id}, Status: {job.get('status')}")
        return job
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving job: {str(e)}")


@router.get("/jobs")
def get_all_jobs_endpoint(db: Session = Depends(get_db)):
    logger.info("Received request to list all jobs")
    try:
        jobs = get_all_jobs()
        logger.info(f"Retrieved {len(jobs)} jobs")
        return jobs
    except Exception as e:
        logger.error(f"Error retrieving all jobs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving jobs: {str(e)}")


@router.get("/findings/total-count")
def get_total_findings_count(db: Session = Depends(get_db)):
    """
    Get total count of all findings across all jobs.

    Returns:
        Dictionary with total_findings count
    """
    logger.info("Received request to get total findings count")
    try:
        from sqlalchemy import func

        total = db.query(func.count(Finding.id)).scalar() or 0
        logger.info(f"Total findings count: {total}")

        return {"total_findings": total}
    except Exception as e:
        logger.error(f"Error getting total findings count: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error getting total findings count: {str(e)}")


@router.post("/job/{job_id}/cancel")
def cancel_scan_endpoint(job_id: str, db: Session = Depends(get_db)):
    """
    Request cancellation of a running scan.

    This sets a cancellation flag that the scan workflow checks between phases.
    The scan will stop gracefully at the next phase boundary.

    Args:
        job_id: ID of the job to cancel
        db: Database session

    Returns:
        Success message with job status
    """
    logger.info(f"Received request to cancel scan - Job ID: {job_id}")

    try:
        # Get the job
        job = db.query(Job).filter(Job.id == job_id).first()

        if not job:
            logger.error(f"Job not found: {job_id}")
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

        # Check if job is already completed or failed
        if job.status in ['completed', 'failed', 'cancelled']:
            logger.warning(f"Cannot cancel job {job_id} - already {job.status}")
            return {
                "message": f"Job is already {job.status}",
                "job_id": job_id,
                "status": job.status
            }

        # Set cancellation flag
        job.cancellation_requested = True
        job.phase_desc = "Cancellation requested - stopping at next phase..."
        db.commit()

        logger.info(f"Cancellation requested for job {job_id} - current phase: {job.phase}")

        return {
            "message": "Cancellation requested - scan will stop gracefully at next phase",
            "job_id": job_id,
            "current_phase": job.phase,
            "status": job.status
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error cancelling job: {str(e)}")


@router.post("/job/{job_id}/resume")
def resume_scan_endpoint(job_id: str, db: Session = Depends(get_db)):
    """
    Resume a suspended scan job.

    When a scan is suspended due to AI rate limiting, this endpoint can be used
    to resume the scan from where it left off.

    Args:
        job_id: ID of the suspended job to resume
        db: Database session

    Returns:
        Success message with job status and resume information
    """
    logger.info(f"Received request to resume scan - Job ID: {job_id}")

    try:
        # Import here to avoid circular import
        from services.jobs_service import resume_suspended_job

        # Attempt to resume
        result = resume_suspended_job(job_id)

        if result.get('success'):
            logger.info(f"Job {job_id} resumed successfully - {result.get('message')}")
            return {
                "message": result.get('message', 'Job resumed'),
                "job_id": job_id,
                "status": "running",
                "retry_count": result.get('retry_count', 0)
            }
        else:
            error_msg = result.get('error', 'Unknown error')
            logger.warning(f"Cannot resume job {job_id}: {error_msg}")

            # Check if it's a timing issue
            if 'resume_after' in result:
                return {
                    "message": error_msg,
                    "job_id": job_id,
                    "status": "suspended",
                    "resume_after": result.get('resume_after')
                }

            raise HTTPException(status_code=400, detail=error_msg)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resuming job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error resuming job: {str(e)}")


@router.delete("/job/{job_id}")
def delete_job_endpoint(job_id: str):
    logger.info(f"Received request to delete job - Job ID: {job_id}")
    try:
        delete_job(job_id)
        logger.info(f"Job deleted successfully - Job ID: {job_id}")
        return {"message": "Job deleted successfully", "job_id": job_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error deleting job: {str(e)}")


@router.get("/report/{reportPath:path}")
def download_report(reportPath: str, format: Optional[str] = Query(None)):
    """
    Download a report file (PDF or DOCX).

    Args:
        reportPath: Path to the report file relative to reports directory (e.g., "job_id/report.pdf")
        format: Optional format parameter (for compatibility, not used as path already includes extension)

    Returns:
        FileResponse with the report file

    Raises:
        HTTPException: 400 for invalid path (path traversal)
                      404 if file not found
                      500 for other errors
    """
    logger.info("="*80)
    logger.info(f"Received request to download report - Path: {reportPath}")
    if format:
        logger.info(f"Format parameter: {format}")

    # Security: Prevent path traversal attacks
    if ".." in reportPath or reportPath.startswith("/") or reportPath.startswith("\\"):
        logger.error(f"Invalid report path (path traversal attempt detected): {reportPath}")
        raise HTTPException(
            status_code=400,
            detail="Invalid report path: Path traversal characters not allowed"
        )

    # Construct full file path
    reports_base_dir = "reports"
    file_path = os.path.join(reports_base_dir, reportPath)
    logger.debug(f"Full file path: {file_path}")

    # Check if file exists
    if not os.path.exists(file_path):
        logger.warning(f"Report file not found: {file_path}")
        raise HTTPException(
            status_code=404,
            detail=f"Report not found: {reportPath}"
        )

    # Verify it's a file (not a directory)
    if not os.path.isfile(file_path):
        logger.error(f"Path is not a file: {file_path}")
        raise HTTPException(
            status_code=400,
            detail="Invalid path: Not a file"
        )

    # Verify file extension is allowed (security check)
    allowed_extensions = ['.pdf', '.docx', '.md']
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in allowed_extensions:
        logger.error(f"Invalid file extension: {file_extension}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed types: {', '.join(allowed_extensions)}"
        )

    try:
        # Determine media type based on file extension
        media_type_mapping = {
            '.pdf': 'application/pdf',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.md': 'text/markdown'
        }
        media_type = media_type_mapping.get(file_extension, 'application/octet-stream')

        # Extract filename for Content-Disposition header
        filename = os.path.basename(file_path)

        logger.info(f"Serving report file: {filename} (type: {media_type})")
        logger.info("="*80)

        return FileResponse(
            path=file_path,
            media_type=media_type,
            filename=filename
        )

    except Exception as e:
        logger.error(f"Failed to serve report {reportPath}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to serve report: {str(e)}"
        )


@router.get("/job/{job_id}/summary")
def get_job_summary(job_id: str, db: Session = Depends(get_db)):
    """
    Get aggregated summary of findings for a job.
    Returns counts by severity and OWASP category.

    Args:
        job_id: Job ID

    Returns:
        FindingsSummaryResponse with aggregated statistics
    """
    from sqlalchemy import func

    logger.info(f"Fetching summary for job: {job_id}")

    try:
        # Get total findings count
        total_findings = db.query(func.count(Finding.id)).filter(Finding.job_id == job_id).scalar() or 0

        # Get counts by severity
        severity_counts = db.query(
            Finding.severity,
            func.count(Finding.id)
        ).filter(Finding.job_id == job_id).group_by(Finding.severity).all()

        by_severity = {severity: count for severity, count in severity_counts}

        # Get counts by OWASP category
        owasp_counts = db.query(
            Finding.owasp_category,
            func.count(Finding.id)
        ).filter(Finding.job_id == job_id).group_by(Finding.owasp_category).all()

        by_owasp_category = {category: count for category, count in owasp_counts if category}

        # Get counts by finding type
        type_counts = db.query(
            Finding.finding_type,
            func.count(Finding.id)
        ).filter(Finding.job_id == job_id).group_by(Finding.finding_type).all()

        by_finding_type = {ftype: count for ftype, count in type_counts}

        summary = FindingsSummaryResponse(
            total_findings=total_findings,
            by_severity=by_severity,
            by_owasp_category=by_owasp_category,
            by_finding_type=by_finding_type,
            critical_findings=by_severity.get('Critical', 0),
            high_findings=by_severity.get('High', 0),
            medium_findings=by_severity.get('Medium', 0),
            low_findings=by_severity.get('Low', 0)
        )

        logger.info(f"Summary generated: {total_findings} total findings")
        return summary

    except Exception as e:
        logger.error(f"Error generating summary for job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error generating summary: {str(e)}")


@router.get("/job/{job_id}/findings")
def get_job_findings(
    job_id: str,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=500),
    search: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    owasp_category: Optional[str] = Query(default=None),
    finding_type: Optional[str] = Query(default=None),
    sort_by: Optional[str] = Query(default="created_at"),
    sort_order: Optional[str] = Query(default="desc"),
    db: Session = Depends(get_db)
):
    """
    Get paginated, filtered, and sorted findings for a job.

    Args:
        job_id: Job ID
        page: Page number (1-indexed)
        limit: Items per page
        search: Text search across title, description, cve_id
        severity: Filter by severity (Critical, High, Medium, Low)
        owasp_category: Filter by OWASP category
        finding_type: Filter by finding type
        sort_by: Field to sort by (severity, created_at, title)
        sort_order: Sort order (asc, desc)

    Returns:
        FindingsListResponse with paginated findings
    """
    import math

    logger.info(f"Fetching findings for job {job_id}: page={page}, limit={limit}, "
               f"search={search}, severity={severity}, owasp_category={owasp_category}")

    try:
        # Build query
        query = db.query(Finding).filter(Finding.job_id == job_id)

        # Apply filters
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                (Finding.title.ilike(search_filter)) |
                (Finding.description.ilike(search_filter)) |
                (Finding.cve_id.ilike(search_filter))
            )

        if severity:
            query = query.filter(Finding.severity == severity)

        if owasp_category:
            query = query.filter(Finding.owasp_category == owasp_category)

        if finding_type:
            query = query.filter(Finding.finding_type == finding_type)

        # Get total count before pagination
        total = query.count()

        # Apply sorting
        if sort_by == "severity":
            # Custom severity ordering: Critical > High > Medium > Low
            severity_order = {
                'Critical': 1,
                'High': 2,
                'Medium': 3,
                'Low': 4
            }
            # Note: This is a simplified approach. For production, use CASE statement
            query = query.order_by(Finding.severity.desc() if sort_order == "desc" else Finding.severity.asc())
        elif sort_by == "title":
            query = query.order_by(Finding.title.desc() if sort_order == "desc" else Finding.title.asc())
        else:  # default to created_at
            query = query.order_by(Finding.created_at.desc() if sort_order == "desc" else Finding.created_at.asc())

        # Apply pagination
        offset = (page - 1) * limit
        findings = query.offset(offset).limit(limit).all()

        # Convert to response models
        finding_responses = [FindingResponse.from_orm(f) for f in findings]

        total_pages = math.ceil(total / limit) if total > 0 else 0

        response = FindingsListResponse(
            findings=finding_responses,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages
        )

        logger.info(f"Returning {len(findings)} findings (page {page}/{total_pages}, total={total})")
        return response

    except Exception as e:
        logger.error(f"Error fetching findings for job {job_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching findings: {str(e)}")


@router.post("/job/{job_id}/export")
def export_job_findings(job_id: str, export_request: ExportRequest, db: Session = Depends(get_db)):
    """
    Export filtered findings to PDF, CSV, or JSON.

    Args:
        job_id: Job ID
        export_request: Export parameters including format and filters

    Returns:
        FileResponse with the exported file
    """
    import csv
    import json as json_module
    from datetime import datetime

    logger.info(f"Export request for job {job_id}: format={export_request.format}, "
               f"filters={export_request.search}, {export_request.severity}")

    try:
        # Get job
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        # Build query with filters
        query = db.query(Finding).filter(Finding.job_id == job_id)

        if export_request.search:
            search_filter = f"%{export_request.search}%"
            query = query.filter(
                (Finding.title.ilike(search_filter)) |
                (Finding.description.ilike(search_filter)) |
                (Finding.cve_id.ilike(search_filter))
            )

        if export_request.severity:
            query = query.filter(Finding.severity == export_request.severity)

        if export_request.owasp_category:
            query = query.filter(Finding.owasp_category == export_request.owasp_category)

        if export_request.finding_type:
            query = query.filter(Finding.finding_type == export_request.finding_type)

        # Get findings
        findings = query.all()

        # Create export directory
        export_dir = f"reports/{job_id}/exports"
        os.makedirs(export_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename_base = f"findings_export_{timestamp}"

        # Export based on format
        if export_request.format == "csv":
            filepath = os.path.join(export_dir, f"{filename_base}.csv")
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Title', 'Severity', 'OWASP Category', 'Type', 'Description',
                             'Service', 'Port', 'URL', 'CVE ID', 'Remediation']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for finding in findings:
                    writer.writerow({
                        'Title': finding.title,
                        'Severity': finding.severity,
                        'OWASP Category': finding.owasp_category or '',
                        'Type': finding.finding_type,
                        'Description': finding.description or '',
                        'Service': finding.service or '',
                        'Port': finding.port or '',
                        'URL': finding.url or '',
                        'CVE ID': finding.cve_id or '',
                        'Remediation': finding.remediation or ''
                    })

            logger.info(f"CSV export created: {filepath}")
            return FileResponse(
                path=filepath,
                media_type='text/csv',
                filename=f"{filename_base}.csv"
            )

        elif export_request.format == "json":
            filepath = os.path.join(export_dir, f"{filename_base}.json")
            export_data = {
                'job_id': job_id,
                'target': job.target,
                'export_date': datetime.now().isoformat(),
                'filters': {
                    'search': export_request.search,
                    'severity': export_request.severity,
                    'owasp_category': export_request.owasp_category,
                    'finding_type': export_request.finding_type
                },
                'findings': [
                    {
                        'id': f.id,
                        'title': f.title,
                        'description': f.description,
                        'severity': f.severity,
                        'owasp_category': f.owasp_category,
                        'finding_type': f.finding_type,
                        'service': f.service,
                        'port': f.port,
                        'url': f.url,
                        'cve_id': f.cve_id,
                        'cvss_score': f.cvss_score,
                        'remediation': f.remediation,
                        'poc': f.poc,
                        'evidence': f.evidence,
                        'created_at': f.created_at.isoformat()
                    }
                    for f in findings
                ]
            }

            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json_module.dump(export_data, jsonfile, indent=2)

            logger.info(f"JSON export created: {filepath}")
            return FileResponse(
                path=filepath,
                media_type='application/json',
                filename=f"{filename_base}.json"
            )

        elif export_request.format == "pdf":
            # Generate a simple PDF report with filtered findings
            from services.phases.report_generation.converters import convert_html_to_pdf

            # Generate HTML content
            html_lines = []
            html_lines.append("<html><head><style>")
            html_lines.append("body { font-family: Arial, sans-serif; margin: 40px; }")
            html_lines.append("h1 { color: #333; }")
            html_lines.append(".finding { margin: 20px 0; padding: 15px; border-left: 4px solid #ddd; background: #f9f9f9; }")
            html_lines.append(".critical { border-left-color: #dc2626; }")
            html_lines.append(".high { border-left-color: #ea580c; }")
            html_lines.append(".medium { border-left-color: #ca8a04; }")
            html_lines.append(".low { border-left-color: #2563eb; }")
            html_lines.append(".badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }")
            html_lines.append("</style></head><body>")

            html_lines.append(f"<h1>Security Findings Report</h1>")
            html_lines.append(f"<p><strong>Target:</strong> {job.target}</p>")
            html_lines.append(f"<p><strong>Export Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
            html_lines.append(f"<p><strong>Total Findings:</strong> {len(findings)}</p>")
            html_lines.append("<hr/>")

            for finding in findings:
                severity_class = finding.severity.lower() if finding.severity else 'low'
                html_lines.append(f"<div class='finding {severity_class}'>")
                html_lines.append(f"<h3>{finding.title}</h3>")
                html_lines.append(f"<p><span class='badge'>{finding.severity}</span> "
                                f"<span class='badge'>{finding.owasp_category or 'N/A'}</span></p>")
                if finding.description:
                    html_lines.append(f"<p><strong>Description:</strong> {finding.description}</p>")
                if finding.service:
                    html_lines.append(f"<p><strong>Service:</strong> {finding.service}:{finding.port}</p>")
                if finding.url:
                    html_lines.append(f"<p><strong>URL:</strong> {finding.url}</p>")
                if finding.cve_id:
                    html_lines.append(f"<p><strong>CVE:</strong> {finding.cve_id}</p>")
                if finding.remediation:
                    html_lines.append(f"<p><strong>Remediation:</strong> {finding.remediation}</p>")
                html_lines.append("</div>")

            html_lines.append("</body></html>")
            html_content = "\n".join(html_lines)

            filepath = os.path.join(export_dir, f"{filename_base}.pdf")

            try:
                convert_html_to_pdf(html_content, filepath)
                logger.info(f"PDF export created: {filepath}")
                return FileResponse(
                    path=filepath,
                    media_type='application/pdf',
                    filename=f"{filename_base}.pdf"
                )
            except Exception as pdf_error:
                logger.error(f"PDF generation failed: {pdf_error}")
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(pdf_error)}")

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported export format: {export_request.format}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting findings: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error exporting findings: {str(e)}")
