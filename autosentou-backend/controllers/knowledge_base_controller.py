"""
Knowledge Base API Controller
Provides REST API endpoints for vulnerability knowledge base management
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import Response, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional, List
import logging
import math

from database import get_db
from models import KnowledgeBaseVulnerability, Finding
from schemas.knowledge_base import (
    KnowledgeBaseVulnerabilityCreate,
    KnowledgeBaseVulnerabilityUpdate,
    KnowledgeBaseVulnerability as KBVulnSchema,
    KnowledgeBaseVulnerabilityList,
    KnowledgeBaseSearchRequest,
    KnowledgeBaseMatchRequest,
    KnowledgeBaseMatchResult,
    ConfigurationSchema,
    ConfigurationUpdate,
    BulkImportRequest,
    BulkImportResponse
)
import services.knowledge_base_service as kb_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/knowledge-base", tags=["Knowledge Base"])


# ============================================================================
# CRUD Endpoints
# ============================================================================

@router.post("/vulnerabilities/", response_model=KBVulnSchema, status_code=201)
def create_vulnerability(
    vuln_data: KnowledgeBaseVulnerabilityCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new vulnerability in the knowledge base.

    - **name**: Unique vulnerability name
    - **description**: Detailed description
    - **severity**: Severity level (e.g., Critical, High, Medium, Low)
    - **remediation**: Remediation advice (optional)
    - **cve_id**: CVE identifier (optional)
    - **cwe_id**: CWE identifier (optional)
    - **category**: Category (e.g., Web, Network, Auth) (optional)
    - **priority**: Priority for matching (0-100)
    """
    try:
        logger.info(f"Creating KB vulnerability: {vuln_data.name}")
        vulnerability = kb_service.create_vulnerability(db, vuln_data)
        return vulnerability
    except ValueError as e:
        logger.warning(f"Validation error creating vulnerability: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/vulnerabilities/", response_model=KnowledgeBaseVulnerabilityList)
def list_vulnerabilities(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    is_active: Optional[bool] = Query(True, description="Filter by active status"),
    db: Session = Depends(get_db)
):
    """
    Get a paginated list of vulnerabilities with optional filtering.

    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 20, max: 100)
    - **search**: Search in name, description, CVE, CWE
    - **category**: Filter by category
    - **severity**: Filter by severity
    - **is_active**: Show only active vulnerabilities (default: True)
    """
    try:
        skip = (page - 1) * limit
        vulnerabilities, total = kb_service.get_vulnerabilities(
            db=db,
            skip=skip,
            limit=limit,
            search=search,
            category=category,
            severity=severity,
            is_active=is_active
        )

        total_pages = math.ceil(total / limit) if total > 0 else 0

        return KnowledgeBaseVulnerabilityList(
            vulnerabilities=vulnerabilities,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages
        )
    except Exception as e:
        logger.error(f"Error listing vulnerabilities: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/vulnerabilities/{vulnerability_id}", response_model=KBVulnSchema)
def get_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a single vulnerability by ID.

    - **vulnerability_id**: The vulnerability ID
    """
    try:
        vulnerability = kb_service.get_vulnerability(db, vulnerability_id)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting vulnerability: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/vulnerabilities/{vulnerability_id}", response_model=KBVulnSchema)
def update_vulnerability(
    vulnerability_id: int,
    vuln_data: KnowledgeBaseVulnerabilityUpdate,
    db: Session = Depends(get_db)
):
    """
    Update an existing vulnerability.

    - **vulnerability_id**: The vulnerability ID
    - All fields are optional; only provided fields will be updated
    """
    try:
        logger.info(f"Updating KB vulnerability: {vulnerability_id}")
        vulnerability = kb_service.update_vulnerability(db, vulnerability_id, vuln_data)
        if not vulnerability:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return vulnerability
    except ValueError as e:
        logger.warning(f"Validation error updating vulnerability: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating vulnerability: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/vulnerabilities/{vulnerability_id}", status_code=204)
def delete_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete (deactivate) a vulnerability.

    - **vulnerability_id**: The vulnerability ID
    """
    try:
        logger.info(f"Deleting KB vulnerability: {vulnerability_id}")
        success = kb_service.delete_vulnerability(db, vulnerability_id)
        if not success:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return Response(status_code=204)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting vulnerability: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Advanced Search & Matching
# ============================================================================

@router.post("/vulnerabilities/search", response_model=KnowledgeBaseVulnerabilityList)
def search_vulnerabilities(
    search_request: KnowledgeBaseSearchRequest,
    db: Session = Depends(get_db)
):
    """
    Advanced search for vulnerabilities.

    - **query**: Search query
    - **category**: Filter by category
    - **severity**: Filter by severity
    - **is_active**: Filter by active status
    - **page**: Page number
    - **limit**: Items per page
    """
    try:
        skip = (search_request.page - 1) * search_request.limit
        vulnerabilities, total = kb_service.get_vulnerabilities(
            db=db,
            skip=skip,
            limit=search_request.limit,
            search=search_request.query,
            category=search_request.category,
            severity=search_request.severity,
            is_active=search_request.is_active
        )

        total_pages = math.ceil(total / search_request.limit) if total > 0 else 0

        return KnowledgeBaseVulnerabilityList(
            vulnerabilities=vulnerabilities,
            total=total,
            page=search_request.page,
            limit=search_request.limit,
            total_pages=total_pages
        )
    except Exception as e:
        logger.error(f"Error searching vulnerabilities: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/vulnerabilities/match", response_model=KnowledgeBaseMatchResult)
def match_vulnerability(
    match_request: KnowledgeBaseMatchRequest,
    db: Session = Depends(get_db)
):
    """
    Test matching a finding description to knowledge base entries using RAG.

    - **finding_description**: The finding description to match
    - **finding_title**: Optional finding title
    - **threshold**: Similarity threshold (0.0-1.0, default: 0.85)
    """
    try:
        logger.info("Testing KB matching with RAG")
        result = kb_service.match_finding_to_kb(
            db=db,
            finding_description=match_request.finding_description,
            finding_title=match_request.finding_title,
            threshold=match_request.threshold
        )

        if not result:
            return KnowledgeBaseMatchResult(
                matched=False,
                kb_entry=None,
                similarity_score=0.0,
                matches=[]
            )

        return KnowledgeBaseMatchResult(
            matched=result['matched'],
            kb_entry=result['kb_entry'],
            similarity_score=result['similarity_score'],
            matches=result['all_matches']
        )
    except Exception as e:
        logger.error(f"Error matching vulnerability: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Bulk Operations
# ============================================================================

@router.post("/vulnerabilities/import", response_model=BulkImportResponse)
def import_vulnerabilities(
    import_request: BulkImportRequest,
    db: Session = Depends(get_db)
):
    """
    Bulk import vulnerabilities from a list.

    - **vulnerabilities**: List of vulnerabilities to import
    - **overwrite_existing**: Whether to overwrite existing entries with same name
    """
    try:
        logger.info(f"Importing {len(import_request.vulnerabilities)} vulnerabilities")
        result = kb_service.import_vulnerabilities(db, import_request)
        return result
    except Exception as e:
        logger.error(f"Error importing vulnerabilities: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/vulnerabilities/export")
def export_vulnerabilities(
    format: str = Query("json", regex="^(json|csv)$"),
    category: Optional[str] = Query(None),
    is_active: bool = Query(True),
    db: Session = Depends(get_db)
):
    """
    Export vulnerabilities to JSON or CSV format.

    - **format**: Export format (json or csv)
    - **category**: Filter by category
    - **is_active**: Export only active vulnerabilities
    """
    try:
        logger.info(f"Exporting vulnerabilities in {format} format")
        export_data = kb_service.export_vulnerabilities(
            db=db,
            format=format,
            category=category,
            is_active=is_active
        )

        media_type = "application/json" if format == "json" else "text/csv"
        filename = f"knowledge_base_vulnerabilities.{format}"

        return Response(
            content=export_data,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"Error exporting vulnerabilities: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Finding-KB Linking
# ============================================================================

@router.post("/link-finding/{finding_id}")
def link_finding(
    finding_id: int,
    kb_id: int = Query(..., description="Knowledge base vulnerability ID"),
    similarity_score: Optional[float] = Query(None, description="Similarity score"),
    db: Session = Depends(get_db)
):
    """
    Link a finding to a knowledge base entry.
    This will update the finding's severity and remediation from the KB entry.

    - **finding_id**: The finding ID
    - **kb_id**: The knowledge base vulnerability ID
    - **similarity_score**: Optional similarity score
    """
    try:
        logger.info(f"Linking Finding {finding_id} to KB {kb_id}")
        success = kb_service.link_finding_to_kb(
            db=db,
            finding_id=finding_id,
            kb_id=kb_id,
            similarity_score=similarity_score
        )

        if not success:
            raise HTTPException(status_code=404, detail="Finding or KB entry not found")

        return {"message": "Finding linked successfully", "finding_id": finding_id, "kb_id": kb_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error linking finding to KB: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Configuration Management
# ============================================================================

@router.get("/config/{key}", response_model=ConfigurationSchema)
def get_configuration(
    key: str,
    db: Session = Depends(get_db)
):
    """
    Get a configuration value.

    - **key**: Configuration key (e.g., 'rag_similarity_threshold')
    """
    try:
        config = kb_service.get_configuration(db, key)
        if not config:
            raise HTTPException(status_code=404, detail="Configuration not found")
        return config
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting configuration: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/config/{key}", response_model=ConfigurationSchema)
def update_configuration(
    key: str,
    config_data: ConfigurationUpdate,
    db: Session = Depends(get_db)
):
    """
    Update a configuration value.

    - **key**: Configuration key
    - **value**: New value
    """
    try:
        logger.info(f"Updating configuration: {key} = {config_data.value}")
        config = kb_service.set_configuration(db, key, config_data.value)
        return config
    except Exception as e:
        logger.error(f"Error updating configuration: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/config/similarity-threshold/value")
def get_similarity_threshold(db: Session = Depends(get_db)):
    """
    Get the current RAG similarity threshold value.
    """
    try:
        threshold = kb_service.get_similarity_threshold(db)
        return {"key": "rag_similarity_threshold", "value": threshold}
    except Exception as e:
        logger.error(f"Error getting similarity threshold: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Uncategorized Findings Management
# ============================================================================

@router.get("/uncategorized-findings")
def get_uncategorized_findings(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    job_id: Optional[str] = Query(None, description="Filter by job ID"),
    sort_by: Optional[str] = Query("created_at", description="Sort by field"),
    sort_order: Optional[str] = Query("desc", description="Sort order (asc/desc)"),
    db: Session = Depends(get_db)
):
    """
    Get a paginated list of uncategorized findings.

    - **page**: Page number (default: 1)
    - **limit**: Items per page (default: 20, max: 100)
    - **search**: Search in title, description, cve_id
    - **severity**: Filter by severity
    - **finding_type**: Filter by finding type
    - **job_id**: Filter by job ID
    - **sort_by**: Field to sort by (created_at, severity, title)
    - **sort_order**: Sort order (asc, desc)
    """
    try:
        from models import FindingResponse

        # Build base query for uncategorized findings
        query = db.query(Finding).filter(Finding.is_categorized == False)

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

        if finding_type:
            query = query.filter(Finding.finding_type == finding_type)

        if job_id:
            query = query.filter(Finding.job_id == job_id)

        # Get total count before pagination
        total = query.count()

        # Apply sorting
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}

        if sort_by == "severity":
            # Custom severity sorting
            findings = query.all()
            findings = sorted(
                findings,
                key=lambda f: severity_order.get(f.severity or 'Informational', 999),
                reverse=(sort_order == "desc")
            )
            # Apply pagination on sorted list
            skip = (page - 1) * limit
            findings = findings[skip:skip + limit]
        else:
            # Database sorting for other fields
            sort_field = getattr(Finding, sort_by, Finding.created_at)
            if sort_order == "desc":
                query = query.order_by(sort_field.desc())
            else:
                query = query.order_by(sort_field.asc())

            # Apply pagination
            skip = (page - 1) * limit
            findings = query.offset(skip).limit(limit).all()

        # Convert to response schema
        findings_list = [
            FindingResponse(
                id=f.id,
                job_id=f.job_id,
                title=f.title,
                description=f.description,
                finding_type=f.finding_type,
                severity=f.severity,
                owasp_category=f.owasp_category,
                service=f.service,
                port=f.port,
                url=f.url,
                cve_id=f.cve_id,
                cvss_score=f.cvss_score,
                remediation=f.remediation,
                poc=f.poc,
                evidence=f.evidence,
                is_categorized=f.is_categorized,
                created_at=f.created_at
            )
            for f in findings
        ]

        total_pages = math.ceil(total / limit) if total > 0 else 0

        return {
            "findings": findings_list,
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": total_pages
        }
    except Exception as e:
        logger.error(f"Error getting uncategorized findings: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# Global cancellation flag for re-categorization
_recategorization_cancelled = False

@router.post("/recategorize-uncategorized")
def recategorize_uncategorized_findings(
    limit: Optional[int] = Query(None, description="Max number of findings to process (default: all)"),
    db: Session = Depends(get_db)
):
    """
    Bulk re-categorize all uncategorized findings using AI.

    This is useful for retrying findings that failed categorization due to API rate limits or errors.
    Uses rate limiting to avoid hitting the Gemini API limit (10 req/min).

    - **limit**: Maximum number of findings to process (optional, default: all uncategorized)
    """
    import time
    from services.ai.ai_categorizer import ai_categorize_finding

    global _recategorization_cancelled
    _recategorization_cancelled = False  # Reset cancellation flag

    try:
        # Get uncategorized findings
        query = db.query(Finding).filter(Finding.is_categorized == False)

        if limit:
            findings = query.limit(limit).all()
        else:
            findings = query.all()

        total_findings = len(findings)

        if total_findings == 0:
            return {
                "message": "No uncategorized findings to process",
                "total": 0,
                "successful": 0,
                "failed": 0
            }

        logger.info(f"Starting bulk re-categorization of {total_findings} uncategorized findings")

        successful = 0
        failed = 0
        last_ai_call_time = 0

        for idx, finding in enumerate(findings, 1):
            # Check for cancellation
            if _recategorization_cancelled:
                logger.warning(f"Re-categorization cancelled by user at {idx}/{total_findings}")
                db.commit()  # Commit progress so far
                return {
                    "message": f"Re-categorization cancelled by user",
                    "total": total_findings,
                    "successful": successful,
                    "failed": failed,
                    "cancelled_at": idx - 1
                }

            try:
                logger.info(f"[{idx}/{total_findings}] Processing: {finding.title}")

                # Rate limiting: Wait 6 seconds between AI calls
                time_since_last_call = time.time() - last_ai_call_time
                if time_since_last_call < 6 and idx > 1:  # Skip first iteration
                    sleep_time = 6 - time_since_last_call
                    logger.info(f"  ⏱ Rate limit: waiting {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

                # Prepare finding data for AI categorization
                finding_data = {
                    'title': finding.title,
                    'description': finding.description,
                    'finding_type': finding.finding_type,
                    'url': finding.url,
                    'service': finding.service,
                    'port': finding.port,
                    'cve_id': finding.cve_id,
                    'evidence': finding.evidence
                }

                last_ai_call_time = time.time()
                ai_result = ai_categorize_finding(finding_data)

                if ai_result:
                    # Update finding with AI categorization
                    finding.severity = ai_result.get('severity', finding.severity or 'Medium')
                    finding.owasp_category = ai_result.get('owasp_category', finding.owasp_category)
                    if ai_result.get('remediation') and not finding.remediation:
                        finding.remediation = ai_result['remediation']
                    finding.is_categorized = True

                    # Try to create KB entry for future matches
                    try:
                        kb_entry = kb_service.create_kb_from_finding(
                            db=db,
                            finding_data=finding_data,
                            ai_categorization=ai_result
                        )
                        if kb_entry:
                            kb_service.link_finding_to_kb(
                                db=db,
                                finding_id=finding.id,
                                kb_id=kb_entry.id,
                                similarity_score=1.0
                            )
                    except Exception as kb_error:
                        logger.warning(f"  ⚠ KB creation failed: {kb_error}")

                    successful += 1
                    logger.info(f"  ✓ Categorized: {ai_result['severity']} / {ai_result.get('owasp_category', 'N/A')}")
                else:
                    failed += 1
                    logger.warning(f"  ✗ AI categorization failed")

            except Exception as e:
                failed += 1
                logger.error(f"  ✗ Error processing finding {finding.id}: {e}")
                continue

        # Commit all changes
        db.commit()

        logger.info(f"✓ Bulk re-categorization complete: {successful} successful, {failed} failed")

        return {
            "message": f"Processed {total_findings} uncategorized findings",
            "total": total_findings,
            "successful": successful,
            "failed": failed
        }

    except Exception as e:
        logger.error(f"Error in bulk re-categorization: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/cancel-recategorization")
def cancel_recategorization():
    """
    Cancel the ongoing re-categorization process.

    This sets a flag that the re-categorization loop checks between each finding.
    Progress will be saved up to the point of cancellation.
    """
    global _recategorization_cancelled
    _recategorization_cancelled = True

    logger.info("Re-categorization cancellation requested")

    return {
        "message": "Cancellation requested - process will stop after current finding",
        "cancelled": True
    }


# ============================================================================
# Statistics
# ============================================================================

@router.get("/stats")
def get_kb_statistics(db: Session = Depends(get_db)):
    """
    Get statistics about the knowledge base.
    """
    try:
        total_vulns = db.query(KnowledgeBaseVulnerability).filter(
            KnowledgeBaseVulnerability.is_active == True
        ).count()

        total_inactive = db.query(KnowledgeBaseVulnerability).filter(
            KnowledgeBaseVulnerability.is_active == False
        ).count()

        # Count by severity
        severity_counts = {}
        active_vulns = db.query(KnowledgeBaseVulnerability).filter(
            KnowledgeBaseVulnerability.is_active == True
        ).all()

        for vuln in active_vulns:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        # Count by category
        category_counts = {}
        for vuln in active_vulns:
            if vuln.category:
                category_counts[vuln.category] = category_counts.get(vuln.category, 0) + 1

        # Count linked findings
        linked_findings = db.query(Finding).filter(
            Finding.is_categorized == True
        ).count()

        uncategorized_findings = db.query(Finding).filter(
            Finding.is_categorized == False
        ).count()

        return {
            "total_active_vulnerabilities": total_vulns,
            "total_inactive_vulnerabilities": total_inactive,
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "linked_findings": linked_findings,
            "uncategorized_findings": uncategorized_findings
        }
    except Exception as e:
        logger.error(f"Error getting KB statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
