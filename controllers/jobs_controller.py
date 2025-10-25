from fastapi import APIRouter, HTTPException, BackgroundTasks
from autosentou.services.jobs_service import start_scan, get_job, get_all_jobs
from autosentou.services.phases.info_gathering import run_dnsenum
from autosentou.services.config import config_manager
from autosentou.models import StartScanRequest
from typing import Dict, Any

router = APIRouter(prefix="/api", tags=["jobs"])

@router.post("/start-scan")
def api_start_scan(payload: StartScanRequest):
    """Start a new penetration test scan with the given configuration."""
    target = payload.target
    description = payload.description
    
    # Validate target
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Create scan configuration
    scan_config = config_manager.create_scan_config(
        target=target,
        description=description,
        scan_type=payload.scan_type,
        include_brute_force=payload.include_brute_force,
        include_sqli_testing=payload.include_sqli_testing,
        include_web_enumeration=payload.include_web_enumeration,
        custom_wordlist=payload.custom_wordlist,
        max_threads=payload.max_threads,
        timeout=payload.timeout,
    )
    
    print(f"Starting {scan_config.scan_type} scan for {target} with description: {description}")
    job_id = start_scan(target, description, scan_config)
    return {
        "message": "Scan started successfully", 
        "job_id": job_id,
        "scan_type": scan_config.scan_type,
        "phases": config_manager.get_scan_phases(scan_config)
    }


@router.get("/scan-status/{job_id}")
def api_get_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@router.get("/scans")
def api_list():
    """Get a list of all scans."""
    return get_all_jobs()


@router.get("/tools/status")
def api_get_tools_status():
    """Get the status of all required tools."""
    tool_status = config_manager.validate_tools()
    return {
        "tools": tool_status,
        "all_available": all(tool_status.values()),
        "missing_tools": [tool for tool, available in tool_status.items() if not available]
    }


@router.get("/scan-config/{job_id}")
def api_get_scan_config(job_id: str):
    """Get the configuration used for a specific scan."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Extract configuration from job data
    # This would need to be stored in the job record
    return {
        "job_id": job_id,
        "target": job.get("target"),
        "scan_type": "comprehensive",  # Would be stored in job
        "phases": job.get("phases", [])
    }

