from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Boolean,
    Integer,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship
from datetime import datetime
from  database import Base
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from pydantic import Field

class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, index=True)
    description = Column(String)
    target = Column(Text)
    status = Column(String)
    phase = Column(String)
    phase_desc = Column(String)
    report_generated = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    custom_wordlist = Column(String, nullable=True)  # Path to wordlist file

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


class StartScanRequest(BaseModel):
    target: str 
    description: Optional[str] = None
    scan_type: Optional[str] = "comprehensive"  # comprehensive, quick, web_only, network_only
    include_brute_force: Optional[bool] = True
    include_sqli_testing: Optional[bool] = True
    include_web_enumeration: Optional[bool] = True
    custom_wordlist: Optional[str] = None
    max_threads: Optional[int] = 10
    timeout: Optional[int] = 300


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
