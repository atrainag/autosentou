from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Boolean,
    Integer,
    Float,
    ForeignKey,
    JSON,
    Table,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
from  database import Base
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from pydantic import Field


# Association table for many-to-many relationship between Finding and KnowledgeBaseVulnerability
finding_knowledge_base_link = Table(
    'finding_knowledge_base_link',
    Base.metadata,
    Column('finding_id', Integer, ForeignKey('findings.id'), primary_key=True),
    Column('knowledge_base_id', Integer, ForeignKey('knowledge_base_vulnerability.id'), primary_key=True),
    Column('similarity_score', Float, nullable=True),  # RAG similarity score
    Column('linked_at', DateTime, default=datetime.now)
)


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, index=True)
    description = Column(String)
    target = Column(Text)  # IP address used for scanning (resolved from original_target)
    original_target = Column(Text, nullable=True)  # Original input (domain/URL) for display
    status = Column(String)  # running, completed, failed, cancelled, suspended
    phase = Column(String)
    phase_desc = Column(String)
    report_generated = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    cancellation_requested = Column(Boolean, default=False)  # For graceful scan cancellation
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    custom_wordlist = Column(String, nullable=True)  # Path to wordlist file

    # Suspension/Resume fields for rate limit handling
    suspension_reason = Column(String, nullable=True)  # Why the job was suspended
    last_completed_phase = Column(String, nullable=True)  # Phase completed before suspension
    suspended_at = Column(DateTime, nullable=True)  # When job was suspended
    resume_after = Column(DateTime, nullable=True)  # When to auto-resume (based on rate limit)
    retry_count = Column(Integer, default=0)  # Number of resume attempts

    # Relationships
    phases = relationship("Phase", back_populates="job", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="job", uselist=False)


class Phase(Base):
    __tablename__ = "phases"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, ForeignKey("jobs.id"))
    phase_name = Column(String)
    data = Column(JSON)
    log_path = Column(Text, nullable=True)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    job = relationship("Job", back_populates="phases")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, ForeignKey("jobs.id"))
    report_path = Column(Text)
    format = Column(String, default="pdf")
    summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=datetime.now)

    job = relationship("Job", back_populates="report")


class KnowledgeBaseVulnerability(Base):
    """
    Knowledge base for vulnerability management.
    Allows users to define custom severities, remediation advice, and categorization.
    Integrated with RAG for intelligent matching to scan findings.
    """
    __tablename__ = 'knowledge_base_vulnerability'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # Free-text for flexibility
    remediation = Column(Text, nullable=True)

    # Enhanced fields for better matching and categorization
    cve_id = Column(String, nullable=True, index=True)
    cwe_id = Column(String, nullable=True, index=True)
    owasp_category = Column(String, nullable=True, index=True)  # e.g., "A03:2021 - Injection"
    category = Column(String, nullable=True, index=True)  # e.g., "Web", "Network", "Auth"
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=0)  # Higher = preferred when multiple matches

    # Versioning support
    version = Column(Integer, default=1)
    previous_version_id = Column(Integer, ForeignKey('knowledge_base_vulnerability.id'), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    # Relationships
    findings = relationship(
        "Finding",
        secondary=finding_knowledge_base_link,
        back_populates="knowledge_base_entries"
    )


class Configuration(Base):
    """
    Application configuration storage.
    Stores settings like RAG similarity threshold and other user preferences.
    """
    __tablename__ = 'configuration'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, unique=True, nullable=False, index=True)
    value = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class Finding(Base):
    """
    Unified table for all vulnerability findings across different scan phases.
    Supports filtering, searching, and categorization for the interactive dashboard.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, ForeignKey("jobs.id"), index=True)

    # Finding details
    title = Column(String, nullable=False)
    description = Column(Text)
    finding_type = Column(String, index=True)  # 'cve', 'sqli', 'auth', 'web_exposure', etc.

    # Categorization (AI-powered)
    severity = Column(String, index=True)  # 'Low', 'Medium', 'High', 'Critical'
    owasp_category = Column(String, index=True)  # e.g., 'A03:2021 - Injection'

    # Technical details
    service = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    url = Column(Text, nullable=True)

    # CVE-specific
    cve_id = Column(String, nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)

    # Additional metadata
    remediation = Column(Text, nullable=True)
    poc = Column(Text, nullable=True)  # Proof of concept
    evidence = Column(JSON, nullable=True)  # Additional evidence/metadata

    # Knowledge Base integration
    is_categorized = Column(Boolean, default=False)  # Track if linked to KB

    # Timestamps
    created_at = Column(DateTime, default=datetime.now)

    # Relationships
    job = relationship("Job")
    knowledge_base_entries = relationship(
        "KnowledgeBaseVulnerability",
        secondary=finding_knowledge_base_link,
        back_populates="findings"
    )


class StartScanRequest(BaseModel):
    target: str
    description: Optional[str] = None
    custom_wordlist: Optional[str] = None


class Vulnerability(BaseModel):
    id: Optional[int] = None
    job_id: str
    service: str
    port: int
    vulnerability_type: str
    severity: str
    description: str
    cve_references: List[str] = []
    cvss_score: Optional[float] = None
    poc_available: bool = False
    poc_successful: Optional[bool] = None
    exploit_difficulty: Optional[str] = None
    remediation: Optional[str] = None
    created_at: Optional[datetime] = None


class WebEndpoint(BaseModel):
    id: Optional[int] = None
    job_id: str
    url: str
    status_code: int
    content_length: int
    risk_level: str
    matched_patterns: List[str] = []
    ai_recommendation: Optional[str] = None
    confidence_score: Optional[float] = None
    created_at: Optional[datetime] = None


class BruteForceResult(BaseModel):
    id: Optional[int] = None
    job_id: str
    endpoint_url: str
    tool_used: str
    successful_logins: List[Dict[str, str]] = []
    failed_attempts: int = 0
    test_duration: Optional[float] = None
    created_at: Optional[datetime] = None


class SQLInjectionResult(BaseModel):
    id: Optional[int] = None
    job_id: str
    endpoint_url: str
    vulnerable: bool
    injection_type: Optional[str] = None
    payloads: List[str] = []
    database_info: Dict[str, Any] = {}
    confidence: str = "Unknown"
    created_at: Optional[datetime] = None


class FindingResponse(BaseModel):
    """Pydantic model for Finding API responses."""
    id: int
    job_id: str
    title: str
    description: Optional[str] = None
    finding_type: str
    severity: str
    owasp_category: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    poc: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    is_categorized: Optional[bool] = False
    created_at: datetime

    class Config:
        from_attributes = True


class FindingsSummaryResponse(BaseModel):
    """Response model for findings summary endpoint."""
    total_findings: int
    by_severity: Dict[str, int]
    by_owasp_category: Dict[str, int]
    by_finding_type: Dict[str, int]
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


class FindingsListResponse(BaseModel):
    """Response model for paginated findings list."""
    findings: List[FindingResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class ExportRequest(BaseModel):
    """Request model for exporting filtered findings."""
    format: str = "pdf"  # pdf, csv, json
    search: Optional[str] = None
    severity: Optional[str] = None
    owasp_category: Optional[str] = None
    finding_type: Optional[str] = None
