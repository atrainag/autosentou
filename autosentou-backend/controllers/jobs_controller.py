from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import logging
from database import get_db
from models import StartScanRequest
from services.jobs_service import start_scan, get_job, get_all_jobs
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
