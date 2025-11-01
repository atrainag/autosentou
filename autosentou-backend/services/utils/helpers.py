from  models import Job, Phase, Report


def job_to_dict(job: Job):
    return {
        "id": job.id,
        "description": job.description,
        "target": job.target,
        "status": job.status,
        "phase": job.phase,
        "phase_desc": job.phase_desc,
        "report_generated": job.report_generated,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
    }


def phase_to_dict(phase: Phase):
    return {
        "id": phase.id,
        "job_id": phase.job_id,
        "phase_name": phase.phase_name,
        "data": phase.data,
        "log_path": phase.log_path,
        "status": phase.status,
        "created_at": phase.created_at.isoformat() if phase.created_at else None,
        "updated_at": phase.updated_at.isoformat() if phase.updated_at else None,
    }


def report_to_dict(r: Report):
    return {
        "id": r.id,
        "job_id": r.job_id,
        "report_path": r.report_path,
        "format": r.format,
        "summary": r.summary,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
    }
