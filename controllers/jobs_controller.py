from fastapi import APIRouter, HTTPException
from autosentou.services.jobs_service import start_scan, get_job, get_all_jobs
from autosentou.services.phases.info_gathering import run_dnsenum
from autosentou.models import StartScanRequest
router = APIRouter(prefix="/api", tags=["jobs"])

@router.post("/start-scan12")
def api_start_scan(payload: StartScanRequest):
    target = payload.target
    job_id = start_scan(target)
    return {"message": "Scan started", "job_id": job_id}


@router.get("/scan-status/{job_id}")
def api_get_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@router.get("/scans")
def api_list():
    return get_all_jobs()

@router.get("/dnsenum/{target}")
def api_run_dnsenum(target: str):
    res = run_dnsenum(target)
    return res


