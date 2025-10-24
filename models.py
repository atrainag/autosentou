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
from autosentou.database import Base
from pydantic import BaseModel
from typing import Optional, Dict, Any
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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    job = relationship("Job", back_populates="phases")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, ForeignKey("jobs.id"))
    report_path = Column(Text)
    format = Column(String, default="pdf")
    summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("Job", back_populates="report")


class StartScanRequest(BaseModel):
    target:str 
    description: Optional[str] = None
