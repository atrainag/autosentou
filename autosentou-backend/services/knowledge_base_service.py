"""
Knowledge Base Service Layer
Handles CRUD operations for vulnerability knowledge base with RAG integration
"""
import logging
import json
import csv
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from datetime import datetime

from models import (
    KnowledgeBaseVulnerability,
    Configuration,
    Finding,
    finding_knowledge_base_link
)
from schemas.knowledge_base import (
    KnowledgeBaseVulnerabilityCreate,
    KnowledgeBaseVulnerabilityUpdate,
    KnowledgeBaseSearchRequest,
    BulkImportRequest
)

logger = logging.getLogger(__name__)


# ============================================================================
# CRUD Operations for Knowledge Base Vulnerabilities
# ============================================================================

def create_vulnerability(
    db: Session,
    vuln_data: KnowledgeBaseVulnerabilityCreate
) -> KnowledgeBaseVulnerability:
    """
    Create a new vulnerability in the knowledge base.
    Also adds it to the RAG system for intelligent matching.
    """
    try:
        # Check for duplicate name (case-insensitive)
        existing = db.query(KnowledgeBaseVulnerability).filter(
            func.lower(KnowledgeBaseVulnerability.name) == func.lower(vuln_data.name)
        ).first()

        if existing:
            raise ValueError(f"Vulnerability with name '{vuln_data.name}' already exists")

        # Create new vulnerability
        db_vuln = KnowledgeBaseVulnerability(
            name=vuln_data.name,
            description=vuln_data.description,
            severity=vuln_data.severity,
            remediation=vuln_data.remediation,
            cve_id=vuln_data.cve_id,
            cwe_id=vuln_data.cwe_id,
            category=vuln_data.category,
            priority=vuln_data.priority,
            is_active=True,
            version=1
        )

        db.add(db_vuln)
        db.commit()
        db.refresh(db_vuln)

        logger.info(f"Created vulnerability in KB: {db_vuln.name} (ID: {db_vuln.id})")

        # Add to RAG system
        try:
            from services.ai.rag_service import add_kb_vulnerability_to_rag
            add_kb_vulnerability_to_rag(db_vuln)
        except Exception as e:
            logger.warning(f"Failed to add KB entry to RAG: {e}")

        return db_vuln

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating vulnerability: {e}")
        raise


def get_vulnerability(db: Session, vuln_id: int) -> Optional[KnowledgeBaseVulnerability]:
    """Get a single vulnerability by ID."""
    return db.query(KnowledgeBaseVulnerability).filter(
        KnowledgeBaseVulnerability.id == vuln_id
    ).first()


def get_vulnerabilities(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    search: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    is_active: Optional[bool] = True
) -> Tuple[List[KnowledgeBaseVulnerability], int]:
    """
    Get a list of vulnerabilities with pagination and filtering.
    Returns (vulnerabilities, total_count)
    """
    query = db.query(KnowledgeBaseVulnerability)

    # Apply filters
    if is_active is not None:
        query = query.filter(KnowledgeBaseVulnerability.is_active == is_active)

    if category:
        query = query.filter(KnowledgeBaseVulnerability.category == category)

    if severity:
        query = query.filter(KnowledgeBaseVulnerability.severity == severity)

    if search:
        search_filter = or_(
            KnowledgeBaseVulnerability.name.ilike(f"%{search}%"),
            KnowledgeBaseVulnerability.description.ilike(f"%{search}%"),
            KnowledgeBaseVulnerability.cve_id.ilike(f"%{search}%"),
            KnowledgeBaseVulnerability.cwe_id.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)

    # Get total count
    total = query.count()

    # Apply pagination and ordering
    vulnerabilities = query.order_by(
        KnowledgeBaseVulnerability.priority.desc(),
        KnowledgeBaseVulnerability.created_at.desc()
    ).offset(skip).limit(limit).all()

    return vulnerabilities, total


def update_vulnerability(
    db: Session,
    vuln_id: int,
    vuln_data: KnowledgeBaseVulnerabilityUpdate
) -> Optional[KnowledgeBaseVulnerability]:
    """
    Update an existing vulnerability.
    Creates a new version and updates the RAG system.
    """
    try:
        db_vuln = get_vulnerability(db, vuln_id)
        if not db_vuln:
            return None

        # Check for duplicate name if name is being updated
        if vuln_data.name and vuln_data.name != db_vuln.name:
            existing = db.query(KnowledgeBaseVulnerability).filter(
                func.lower(KnowledgeBaseVulnerability.name) == func.lower(vuln_data.name),
                KnowledgeBaseVulnerability.id != vuln_id
            ).first()

            if existing:
                raise ValueError(f"Vulnerability with name '{vuln_data.name}' already exists")

        # Update fields
        update_data = vuln_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_vuln, field, value)

        # Increment version
        db_vuln.version += 1
        db_vuln.updated_at = datetime.now()

        db.commit()
        db.refresh(db_vuln)

        logger.info(f"Updated vulnerability in KB: {db_vuln.name} (ID: {db_vuln.id}, v{db_vuln.version})")

        # Update in RAG system
        try:
            from services.ai.rag_service import update_kb_vulnerability_in_rag
            update_kb_vulnerability_in_rag(db_vuln)
        except Exception as e:
            logger.warning(f"Failed to update KB entry in RAG: {e}")

        return db_vuln

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating vulnerability: {e}")
        raise


def delete_vulnerability(db: Session, vuln_id: int) -> bool:
    """
    Soft delete a vulnerability by setting is_active=False.
    Removes it from the RAG system.
    """
    try:
        db_vuln = get_vulnerability(db, vuln_id)
        if not db_vuln:
            return False

        db_vuln.is_active = False
        db_vuln.updated_at = datetime.now()

        db.commit()
        logger.info(f"Deactivated vulnerability in KB: {db_vuln.name} (ID: {db_vuln.id})")

        # Remove from RAG system
        try:
            from services.ai.rag_service import remove_kb_vulnerability_from_rag
            remove_kb_vulnerability_from_rag(db_vuln.id)
        except Exception as e:
            logger.warning(f"Failed to remove KB entry from RAG: {e}")

        return True

    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting vulnerability: {e}")
        raise


# ============================================================================
# RAG-Based Matching
# ============================================================================

def match_finding_to_kb(
    db: Session,
    finding_description: str,
    finding_title: Optional[str] = None,
    threshold: float = 0.85
) -> Optional[Dict[str, Any]]:
    """
    Use RAG to find the best matching KB entry for a finding.
    Returns match info including the KB entry and similarity score.
    """
    try:
        from services.ai.rag_service import search_similar_vulnerabilities

        # Combine title and description for better matching
        search_text = f"{finding_title or ''} {finding_description}".strip()

        # Search for similar vulnerabilities
        matches = search_similar_vulnerabilities(search_text, top_k=5)

        if not matches:
            return None

        # Get the best match
        best_match = matches[0]

        if best_match['similarity_score'] >= threshold:
            # Get the full KB entry from database
            kb_entry = get_vulnerability(db, best_match['kb_id'])

            if kb_entry and kb_entry.is_active:
                return {
                    'matched': True,
                    'kb_entry': kb_entry,
                    'similarity_score': best_match['similarity_score'],
                    'all_matches': matches
                }

        return {
            'matched': False,
            'kb_entry': None,
            'similarity_score': best_match['similarity_score'] if matches else 0.0,
            'all_matches': matches
        }

    except Exception as e:
        logger.error(f"Error matching finding to KB: {e}")
        return None


def link_finding_to_kb(
    db: Session,
    finding_id: int,
    kb_id: int,
    similarity_score: Optional[float] = None
) -> bool:
    """
    Create a link between a finding and a KB entry.
    Also updates the finding's severity and remediation from the KB entry.
    """
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        kb_entry = get_vulnerability(db, kb_id)

        if not finding or not kb_entry:
            return False

        # Create the link
        stmt = finding_knowledge_base_link.insert().values(
            finding_id=finding_id,
            knowledge_base_id=kb_id,
            similarity_score=similarity_score,
            linked_at=datetime.now()
        )
        db.execute(stmt)

        # Update finding with KB data
        finding.severity = kb_entry.severity
        finding.remediation = kb_entry.remediation
        finding.is_categorized = True

        db.commit()
        logger.info(f"Linked Finding {finding_id} to KB {kb_id} (score: {similarity_score})")

        return True

    except Exception as e:
        db.rollback()
        logger.error(f"Error linking finding to KB: {e}")
        raise


# ============================================================================
# Bulk Operations
# ============================================================================

def import_vulnerabilities(
    db: Session,
    import_data: BulkImportRequest
) -> Dict[str, Any]:
    """
    Bulk import vulnerabilities.
    Returns statistics about the import.
    """
    total_imported = 0
    total_failed = 0
    failed_entries = []

    for vuln_data in import_data.vulnerabilities:
        try:
            # Check if exists
            existing = db.query(KnowledgeBaseVulnerability).filter(
                func.lower(KnowledgeBaseVulnerability.name) == func.lower(vuln_data.name)
            ).first()

            if existing and not import_data.overwrite_existing:
                failed_entries.append({
                    'name': vuln_data.name,
                    'reason': 'Already exists'
                })
                total_failed += 1
                continue

            if existing and import_data.overwrite_existing:
                # Update existing
                for field, value in vuln_data.model_dump().items():
                    setattr(existing, field, value)
                existing.version += 1
                existing.updated_at = datetime.now()
            else:
                # Create new
                db_vuln = KnowledgeBaseVulnerability(**vuln_data.model_dump())
                db.add(db_vuln)

            total_imported += 1

        except Exception as e:
            logger.warning(f"Failed to import vulnerability '{vuln_data.name}': {e}")
            failed_entries.append({
                'name': vuln_data.name,
                'reason': str(e)
            })
            total_failed += 1

    db.commit()

    return {
        'total_imported': total_imported,
        'total_failed': total_failed,
        'failed_entries': failed_entries
    }


def export_vulnerabilities(
    db: Session,
    category: Optional[str] = None,
    is_active: bool = True
) -> str:
    """
    Export vulnerabilities to JSON format.
    Returns JSON string.
    """
    query = db.query(KnowledgeBaseVulnerability)

    if is_active is not None:
        query = query.filter(KnowledgeBaseVulnerability.is_active == is_active)

    if category:
        query = query.filter(KnowledgeBaseVulnerability.category == category)

    vulnerabilities = query.all()

    # Export as JSON
    data = []
    for vuln in vulnerabilities:
        data.append({
            'name': vuln.name,
            'description': vuln.description,
            'severity': vuln.severity,
            'remediation': vuln.remediation,
            'cve_id': vuln.cve_id,
            'cwe_id': vuln.cwe_id,
            'category': vuln.category,
            'priority': vuln.priority
        })
    return json.dumps(data, indent=2)


# ============================================================================
# AI-Powered KB Entry Creation
# ============================================================================

def create_kb_from_finding(
    db: Session,
    finding_data: Dict[str, Any],
    ai_categorization: Dict[str, Any]
) -> Optional[KnowledgeBaseVulnerability]:
    """
    Create a new KB entry from a finding and its AI categorization.
    This allows the system to learn from new findings.

    Args:
        db: Database session
        finding_data: Dictionary with finding details (title, description, etc.)
        ai_categorization: AI categorization result with severity, category, remediation, etc.

    Returns:
        Created KnowledgeBaseVulnerability or None if creation failed
    """
    try:
        # Build a descriptive name from the finding
        name = finding_data.get('title', 'Unknown Vulnerability')

        # Check if similar entry already exists (to avoid duplicates)
        existing = db.query(KnowledgeBaseVulnerability).filter(
            func.lower(KnowledgeBaseVulnerability.name) == func.lower(name)
        ).first()

        if existing:
            logger.info(f"KB entry already exists: {name}")
            return existing

        # Create new KB entry
        kb_entry = KnowledgeBaseVulnerability(
            name=name,
            description=finding_data.get('description', ''),
            severity=ai_categorization.get('severity', 'Medium'),
            remediation=ai_categorization.get('remediation', ''),
            cve_id=finding_data.get('cve_id'),
            cwe_id=ai_categorization.get('cwe_id'),
            category=ai_categorization.get('category', 'Uncategorized'),
            priority=_calculate_priority(ai_categorization.get('severity', 'Medium')),
            is_active=True,
            version=1
        )

        db.add(kb_entry)
        db.commit()
        db.refresh(kb_entry)

        logger.info(f"✓ Created new KB entry from finding: {name} (ID: {kb_entry.id})")

        # Add to RAG system
        try:
            from services.ai.rag_service import add_kb_vulnerability_to_rag
            add_kb_vulnerability_to_rag(kb_entry)
        except Exception as e:
            logger.warning(f"Failed to add new KB entry to RAG: {e}")

        return kb_entry

    except Exception as e:
        db.rollback()
        logger.error(f"Error creating KB entry from finding: {e}")
        return None


def _calculate_priority(severity: str) -> int:
    """Calculate priority value from severity."""
    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    return severity_map.get(severity, 2)


# ============================================================================
# Configuration Management
# ============================================================================

def get_configuration(db: Session, key: str) -> Optional[Configuration]:
    """Get a configuration value by key."""
    return db.query(Configuration).filter(Configuration.key == key).first()


def set_configuration(db: Session, key: str, value: str, description: Optional[str] = None) -> Configuration:
    """Set or update a configuration value."""
    config = get_configuration(db, key)

    if config:
        config.value = value
        if description:
            config.description = description
        config.updated_at = datetime.now()
    else:
        config = Configuration(key=key, value=value, description=description)
        db.add(config)

    db.commit()
    db.refresh(config)
    return config


def get_similarity_threshold(db: Session) -> float:
    """Get the RAG similarity threshold from configuration."""
    config = get_configuration(db, 'rag_similarity_threshold')
    if config:
        try:
            return float(config.value)
        except ValueError:
            pass
    return 0.85  # Default threshold
