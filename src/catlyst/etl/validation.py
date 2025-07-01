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


class TenantModel(BaseModel):
    tenant_id: int = Field(..., gt=0, description="Primary key from S1 accountId")
    name: str = Field(..., min_length=1, description="Tenant/display name")


class EndpointModel(BaseModel):
    endpoint_id: int = Field(..., gt=0)
    tenant_id: int = Field(..., gt=0)
    agent_uuid: UUID
    computer_name: Optional[str] = Field(None)
    os_name: Optional[str] = Field(None)
    os_type: Optional[str] = Field(None)
    os_revision: Optional[str] = Field(None)
    ip_v4: Optional[str] = Field(None)
    ip_v6: Optional[str] = Field(None)
    group_id: Optional[int] = Field(None, ge=0)
    site_id: Optional[int] = Field(None, ge=0)
    agent_version: Optional[str] = Field(None)
    scan_started_at: Optional[datetime] = Field(None)
    scan_finished_at: Optional[datetime] = Field(None)
    ingested_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))

    @validator("scan_finished_at")
    def scan_finished_after_start(cls, v: Optional[datetime], values: dict) -> Optional[datetime]:
        start = values.get("scan_started_at")
        if start and v and v < start:
            raise ValueError("scan_finished_at must be >= scan_started_at")
        return v


class ThreatModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    storyline: Optional[str] = Field(None)
    tenant_id: int = Field(..., gt=0)
    endpoint_id: Optional[int] = Field(None, ge=0)

    md5: Optional[bytes] = Field(None)
    sha1: Optional[bytes] = Field(None)
    sha256: Optional[bytes] = Field(None)
    file_path: Optional[str] = Field(None)
    file_size: Optional[int] = Field(None, ge=0)
    threat_name: Optional[str] = Field(None)
    publisher_name: Optional[str] = Field(None)
    certificate_id: Optional[str] = Field(None)
    identified_at: datetime = Field(..., description="When S1 first saw it")
    created_at: datetime = Field(..., description="When S1 created it")

    @field_validator("md5", "sha1", "sha256", mode="before")
    def _hex_to_bytes(cls, v: Any, info: ValidationInfo) -> Optional[bytes]:
        """
        If S1 gives us a hex string, decode it into raw bytes.
        If it’s already bytes/bytearray, pass through. Otherwise error.
        """
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


class LabelModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    verdict: Optional[str] = Field(None)
    detection_type: Optional[str] = Field(None)
    incident_status: Optional[str] = Field(None)
    confidence_level: Optional[str] = Field(None)
    classification: Optional[str] = Field(None)
    classification_src: Optional[str] = Field(None)
    initiated_by: Optional[str] = Field(None)
    ingested_at: Optional[datetime] = Field(None)


class IndicatorModel(BaseModel):
    threat_id: int = Field(..., gt=0)
    category: Optional[str] = Field(None)
    description: Optional[str] = Field(None)
    ids: Optional[List[int]] = Field(None)
    tactics: Optional[List[str]] = Field(None)
    techniques: Optional[Any] = Field(None)  # JSONB‐like

