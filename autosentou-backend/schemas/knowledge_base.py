"""
Pydantic schemas for Knowledge Base Vulnerability management
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class KnowledgeBaseVulnerabilityBase(BaseModel):
    """Base schema with common fields"""
    name: str = Field(..., min_length=1, max_length=500, description="Vulnerability name")
    description: str = Field(..., min_length=1, description="Detailed description")
    severity: str = Field(..., description="Severity level (e.g., Critical, High, Medium, Low)")
    remediation: Optional[str] = Field(None, description="Remediation advice")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    category: Optional[str] = Field(None, description="Category (e.g., Web, Network, Auth)")
    priority: int = Field(default=0, ge=0, le=100, description="Priority for matching (0-100)")


class KnowledgeBaseVulnerabilityCreate(KnowledgeBaseVulnerabilityBase):
    """Schema for creating a new vulnerability"""
    pass


class KnowledgeBaseVulnerabilityUpdate(BaseModel):
    """Schema for updating an existing vulnerability (all fields optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = Field(None, min_length=1)
    severity: Optional[str] = None
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=0, le=100)


class KnowledgeBaseVulnerability(KnowledgeBaseVulnerabilityBase):
    """Schema for vulnerability responses"""
    id: int
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class KnowledgeBaseVulnerabilityList(BaseModel):
    """Schema for paginated list of vulnerabilities"""
    vulnerabilities: List[KnowledgeBaseVulnerability]
    total: int
    page: int
    limit: int
    total_pages: int


class KnowledgeBaseSearchRequest(BaseModel):
    """Schema for advanced search"""
    query: Optional[str] = Field(None, description="Search query")
    category: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = True
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=20, ge=1, le=100)


class KnowledgeBaseMatchRequest(BaseModel):
    """Schema for testing finding-to-KB matching"""
    finding_description: str = Field(..., description="Finding description to match")
    finding_title: Optional[str] = Field(None, description="Finding title")
    threshold: Optional[float] = Field(0.85, ge=0.0, le=1.0, description="Similarity threshold")


class KnowledgeBaseMatchResult(BaseModel):
    """Schema for match results"""
    matched: bool
    kb_entry: Optional[KnowledgeBaseVulnerability] = None
    similarity_score: Optional[float] = None
    matches: List[dict] = []  # List of all potential matches with scores


class ConfigurationSchema(BaseModel):
    """Schema for configuration settings"""
    key: str
    value: str
    description: Optional[str] = None

    class Config:
        from_attributes = True


class ConfigurationUpdate(BaseModel):
    """Schema for updating configuration"""
    value: str


class BulkImportRequest(BaseModel):
    """Schema for bulk importing vulnerabilities"""
    vulnerabilities: List[KnowledgeBaseVulnerabilityCreate]
    overwrite_existing: bool = Field(default=False, description="Overwrite if name exists")


class BulkImportResponse(BaseModel):
    """Schema for bulk import response"""
    total_imported: int
    total_failed: int
    failed_entries: List[dict] = []
