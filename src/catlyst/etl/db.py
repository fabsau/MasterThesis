"""
ETL → Postgres upserts/inserts with full Pydantic validation.
"""

import logging
from typing import Any, Dict, List

from pydantic import ValidationError
from sqlalchemy import insert
from sqlalchemy.orm import Session

from catlyst.db.schema import (
    tenants,
    endpoints,
    threats,
    threat_notes,
    threat_labels,
    threat_indicators,
)
from catlyst.etl.validation import (
    TenantModel,
    EndpointModel,
    ThreatModel,
    NoteModel,
    LabelModel,
    IndicatorModel,
)

log = logging.getLogger(__name__)


def upsert_tenant(db: Session, account_id: int, account_name: str) -> None:
    try:
        tenant = TenantModel(tenant_id=account_id, name=account_name)
        stmt = (
            insert(tenants)
            .values(**tenant.dict())
            .on_conflict_do_nothing()
        )
        db.execute(stmt)
    except ValidationError as exc:
        log.error("TenantModel validation failed: %s", exc)


def upsert_endpoint(
    db: Session,
    endpoint_id: int,
    tenant_id: int,
    agent_uuid: str,
    **attrs: Any
) -> None:
    payload: Dict[str, Any] = {
        "endpoint_id": endpoint_id,
        "tenant_id": tenant_id,
        "agent_uuid": agent_uuid,
        **attrs,
    }
    try:
        endpoint = EndpointModel(**payload)
        stmt = (
            insert(endpoints)
            .values(**endpoint.dict())
            .on_conflict_do_update(index_elements=["endpoint_id"], set_=attrs)
        )
        db.execute(stmt)
    except ValidationError as exc:
        log.error("EndpointModel validation failed: %s", exc)


def upsert_threat(db: Session, t: Dict[str, Any]) -> None:
    ti = t.get("threatInfo", {}) or {}
    det = t.get("agentDetectionInfo", {}) or {}
    rt = t.get("agentRealtimeInfo", {}) or {}

    payload: Dict[str, Any] = {
        "threat_id": int(ti.get("threatId") or 0),
        "tenant_id": int(det.get("accountId") or 0),
        "endpoint_id": int(rt.get("agentId") or 0) or None,
        "md5": ti.get("md5"),
        "sha1": ti.get("sha1"),
        "sha256": ti.get("sha256"),
        "file_path": ti.get("filePath"),
        "file_size": ti.get("fileSize"),
        "threat_name": ti.get("threatName"),
        "publisher_name": ti.get("publisherName"),
        "certificate_id": ti.get("certificateId"),
        "detection_type": ti.get("detectionType"),
        "confidence_level": ti.get("confidenceLevel"),
        "incident_status": ti.get("incidentStatus"),
        "analyst_verdict": ti.get("analystVerdict"),
        "classification_src": ti.get("classificationSource"),
        "initiated_by": ti.get("initiatedBy"),
        "identified_at": ti.get("identifiedAt"),
        "created_at": ti.get("createdAt"),
    }

    try:
        val = ThreatModel(**payload)
        stmt = (
            insert(threats)
            .values(**val.dict())
            .on_conflict_do_update(
                index_elements=["threat_id"],
                set_={
                    "last_updated_at": insert(threats).excluded.created_at,
                    "incident_status": insert(threats).excluded.incident_status,
                    "analyst_verdict": insert(threats).excluded.analyst_verdict,
                },
            )
        )
        db.execute(stmt)
    except ValidationError as exc:
        log.error(
            "ThreatModel validation failed for threat_id=%s: %s",
            payload.get("threat_id"),
            exc,
        )


def insert_notes(db: Session, threat_id: int, notes: List[str]) -> None:
    for text in notes or []:
        try:
            note = NoteModel(threat_id=threat_id, note=text)
            stmt = (
                insert(threat_notes)
                .values(**note.dict())
                .on_conflict_do_nothing()
            )
            db.execute(stmt)
        except ValidationError as exc:
            log.warning("Skipping invalid note (threat=%s): %s", threat_id, exc)


def insert_labels(db: Session, threat_id: int, verdict: str) -> None:
    if not verdict:
        return
    try:
        label = LabelModel(
            threat_id=threat_id,
            verdict=verdict,
            source="initial_fetch",
            labeled_by="system",
        )
        stmt = (
            insert(threat_labels)
            .values(**label.dict())
            .on_conflict_do_nothing()
        )
        db.execute(stmt)
    except ValidationError as exc:
        log.warning("Skipping invalid label (threat=%s): %s", threat_id, exc)


def insert_indicators(
    db: Session, threat_id: int, indicators: List[Dict[str, Any]]
) -> None:
    for ind in indicators or []:
        payload: Dict[str, Any] = {
            "threat_id": threat_id,
            "category": ind.get("category"),
            "description": ind.get("description"),
            "ids": ind.get("ids"),
            "tactics": ind.get("tactics"),
            "techniques": ind.get("techniques"),
        }
        try:
            indicator = IndicatorModel(**payload)
            stmt = (
                insert(threat_indicators)
                .values(**indicator.dict())
                .on_conflict_do_nothing()
            )
            db.execute(stmt)
        except ValidationError as exc:
            log.warning(
                "Skipping invalid indicator (threat=%s): %s", threat_id, exc
            )