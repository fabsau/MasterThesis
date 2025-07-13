"""
Pydantic models for ETL → DB payload validation.
All shapes and constraints live here so downstream code
(Feast feature pipelines, CatBoost/IsolationForest trainers,
FastAPI, etc.) can trust the data.
"""

from pydantic import BaseModel, Field, validator, field_validator, ValidationInfo
from typing import Any, List, Optional
from datetime import datetime, timezone
from uuid import UUID


def utcnow():
    return datetime.now(timezone.utc)


class TenantModel(BaseModel):
    tenant_id: int = Field(..., gt=0, description="Primary key from S1 accountId")
    name: str = Field(..., min_length=1, description="Tenant/display name")


class EndpointModel(BaseModel):
    endpoint_id: int = Field(..., gt=0)
    tenant_id: int = Field(..., gt=0)
    agent_uuid: UUID
    computer_name: Optional[str] = None
    os_name: Optional[str] = None
    os_type: Optional[str] = None
    os_revision: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    # insert validator to pick first IP if comma-separated
    @validator("ip_v4", "ip_v6", pre=True)
    def normalize_ip(cls, v):
        if v and isinstance(v, str) and "," in v:
            return v.split(",")[0].strip()
        return v

    group_id: Optional[int] = Field(None, ge=0)
    site_id: Optional[int] = Field(None, ge=0)
    agent_version: Optional[str] = None
    scan_started_at: Optional[datetime] = None
    scan_finished_at: Optional[datetime] = None
    ingested_at: Optional[datetime] = Field(default_factory=utcnow)

    @validator("scan_finished_at")
    def scan_finished_after_start(cls, v: Optional[datetime], values: dict) -> Optional[datetime]:
        start = values.get("scan_started_at")
        if start and v and v < start:
            raise ValueError("scan_finished_at must be >= scan_started_at")
        return v


class ThreatModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    storyline: Optional[str] = None
    tenant_id: int = Field(..., gt=0, description="Tenant identifier")
    endpoint_id: Optional[int] = None
    md5: Optional[bytes] = None
    sha1: Optional[bytes] = None
    sha256: Optional[bytes] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = Field(None, ge=0)
    threat_name: Optional[str] = None
    publisher_name: Optional[str] = None
    certificate_id: Optional[str] = None
    initiated_by: Optional[str] = None
    incident_status: Optional[str] = None
    analyst_verdict: Optional[str] = None
    detection_type: Optional[str] = None
    confidence_level: Optional[str] = None
    classification: Optional[str] = None
    classification_source: Optional[str] = None
    identified_at: datetime = Field(..., description="When S1 first saw it")
    created_at: datetime = Field(..., description="When S1 created it")
    last_updated_at: Optional[datetime] = None

    @field_validator("md5", "sha1", "sha256", mode="before")
    def _hex_to_bytes(cls, v: Any, info: ValidationInfo) -> Optional[bytes]:
        if v is None:
            return None
        if isinstance(v, str):
            try:
                return bytes.fromhex(v)
            except ValueError:
                raise ValueError(f"Invalid hex for field {info.field_name!r}: {v!r}")
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        raise TypeError(f"Field {info.field_name!r} expected str|bytes, got {type(v)}")


class NoteModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    note: str = Field(..., min_length=1)

class TacticModel(BaseModel):
    name: str
    source: str
    techniques: Optional[List["TechniqueModel"]] = None


class TechniqueModel(BaseModel):
    name: str
    link: str

class LabelModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    verdict: Optional[str] = None
    detection_type: Optional[str] = None
    incident_status: Optional[str] = None
    confidence_level: Optional[str] = None
    classification: Optional[str] = None
    classificationSource: Optional[str] = None
    initiated_by: Optional[str] = None
    ingested_at: Optional[datetime] = Field(default_factory=utcnow)


class IndicatorModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    category: Optional[str] = None
    description: Optional[str] = None
    ids: Optional[List[int]] = None
    tactics: Optional[List[TacticModel]] = None 

# Resolve forward references for TacticModel (and any other models if necessary)
TacticModel.model_rebuild()
