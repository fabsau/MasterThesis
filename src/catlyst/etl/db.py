"""
ETL → Batch upsert/inserts with full Pydantic validation.
This module assumes you have the complete list of threat payloads already
loaded in memory. It first extracts unique core objects (tenants, endpoints,
threats) and performs bulk upserts (with commit). Then, it processes and
inserts dependent objects (labels, indicators, notes, and deepvis events).
All data is validated using our Pydantic models from catlyst/etl/validation.py.
"""

import logging
from typing import Any, Dict, List, Callable
from pydantic import ValidationError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy import insert
from sqlalchemy.orm import Session
from tqdm import tqdm

from catlyst.db.schema import (
    tenants,
    endpoints,
    threats,
    threat_labels,
    threat_indicators,
    threat_notes,
    deepvis_events,
)
from catlyst.etl.validation import (
    TenantModel,
    EndpointModel,
    ThreatModel,
    LabelModel,
    IndicatorModel,
    NoteModel,
)

logger = logging.getLogger(__name__)

def _bulk_upsert_with_fallback(
    db: Session,
    table,
    payloads: List[Dict[str, Any]],
    stmt_builder: Callable[[List[Dict[str, Any]]], Any],
    chunk_size: int = 100,
) -> None:
    try:
        db.execute(stmt_builder(payloads))
        db.commit()
    except Exception as bulk_exc:
        logger.error("Bulk upsert failed for %s: %s", table.name, str(bulk_exc)[:200])
        db.rollback()
        # Fallback: Try chunked upsert
        for start in range(0, len(payloads), chunk_size):
            chunk = payloads[start : start + chunk_size]
            try:
                db.execute(stmt_builder(chunk))
                db.commit()
            except Exception as chunk_exc:
                db.rollback()
                logger.error("Chunk upsert failed for table %s records %d-%d: %s", table.name, start, start + len(chunk) - 1, str(chunk_exc)[:200])
                # Final fallback: per-record upsert
                pk = list(table.primary_key.columns)[0].name
                for rec in chunk:
                    try:
                        stmt = insert(table).values(**rec)
                        db.execute(stmt)
                        db.commit()
                    except Exception as rec_exc:
                        db.rollback()
                        logger.error("Record upsert failed for %s id=%s payload=%s: %s", table.name, rec.get(pk), rec, str(rec_exc)[:200])
    # Final commit to ensure changes are saved
    db.commit()

def upsert_tenant(db: Session, account_id: int, account_name: str) -> None:
    try:
        tenant = TenantModel(tenant_id=account_id, name=account_name)
        stmt = insert(tenants).values(**tenant.dict()).on_conflict_do_nothing()
        db.execute(stmt)
        db.commit()
    except ValidationError as exc:
        logger.error("TenantModel validation failed: %s", exc)

def upsert_endpoint(
    db: Session,
    endpoint_id: int,
    tenant_id: int,
    agent_uuid: str,
    **attrs: Any,
) -> None:
    payload = {
        "endpoint_id": endpoint_id,
        "tenant_id": tenant_id,
        "agent_uuid": agent_uuid,
        **attrs,
    }
    try:
        endpoint = EndpointModel(**payload)
        stmt = insert(endpoints).values(**endpoint.dict()).on_conflict_do_update(
            index_elements=["endpoint_id"],
            set_=attrs
        )
        db.execute(stmt)
        db.commit()
    except ValidationError as exc:
        logger.error("EndpointModel validation failed: %s", exc)

def upsert_threat(db: Session, t: Dict[str, Any]) -> None:
    ti = t.get("threatInfo", {}) or {}
    det = t.get("agentDetectionInfo", {}) or {}
    rt = t.get("agentRealtimeInfo", {}) or {}
    payload = {
        "threat_id": int(ti.get("threatId") or 0),
        "tenant_id": int(det.get("accountId") or 0),
        "endpoint_id": int(rt.get("agentId") or 0) if rt.get("agentId") else None,
        "md5": ti.get("md5"),
        "sha1": ti.get("sha1"),
        "sha256": ti.get("sha256"),
        "file_path": ti.get("filePath"),
        "file_size": ti.get("fileSize"),
        "threat_name": ti.get("threatName"),
        "publisher_name": ti.get("publisherName"),
        "certificate_id": ti.get("certificateId"),
        "initiated_by": ti.get("initiatedBy"),
        "identified_at": ti.get("identifiedAt"),
        "created_at": ti.get("createdAt"),
    }
    try:
        threat = ThreatModel(**payload)
        stmt = insert(threats).values(**threat.dict()).on_conflict_do_update(
            index_elements=["threat_id"],
            set_={
                "incident_status": insert(threats).excluded.incident_status,
                "analyst_verdict": insert(threats).excluded.analyst_verdict,
                "last_updated_at": insert(threats).excluded.created_at,
            }
        )
        db.execute(stmt)
        db.commit()
    except ValidationError as exc:
        logger.error("ThreatModel validation failed for threat_id=%s: %s", payload.get("threat_id"), exc)
    except Exception as e:
        db.rollback()
        logger.error("Error upserting threat: %s", e)

def insert_notes(db: Session, threat_id: int, notes: List[str]) -> None:
    for text in notes or []:
        try:
            note = NoteModel(threat_id=threat_id, note=text)
            stmt = insert(threat_notes).values(**note.dict()).on_conflict_do_nothing()
            db.execute(stmt)
        except ValidationError as exc:
            logger.warning("Skipping invalid note (threat=%s): %s", threat_id, exc)
        except Exception as e:
            logger.error("Error inserting note for threat %s: %s", threat_id, e)
    db.commit()

def insert_labels(db: Session, threat_id: int, verdict: str) -> None:
    if not verdict:
        return
    try:
        label = LabelModel(threat_id=threat_id, verdict=verdict)
        stmt = insert(threat_labels).values(**label.dict()).on_conflict_do_nothing()
        db.execute(stmt)
        db.commit()
    except ValidationError as exc:
        logger.warning("Skipping invalid label (threat=%s): %s", threat_id, exc)
    except Exception as e:
        db.rollback()
        logger.error("Error inserting label for threat %s: %s", threat_id, e)

def insert_indicators(db: Session, threat_id: int, indicators: List[Dict[str, Any]]) -> None:
    for ind in indicators or []:
        payload = {
            "threat_id": threat_id,
            "category": ind.get("category"),
            "description": ind.get("description"),
            "ids": ind.get("ids"),
            "tactics": ind.get("tactics"),
            "techniques": ind.get("techniques"),
        }
        try:
            indicator = IndicatorModel(**payload)
            stmt = insert(threat_indicators).values(**indicator.dict()).on_conflict_do_nothing()
            db.execute(stmt)
        except ValidationError as exc:
            logger.warning("Skipping invalid indicator (threat=%s): %s", threat_id, exc)
        except Exception as e:
            logger.error("Error inserting indicator for threat %s: %s", threat_id, e)
    db.commit()

def batch_upsert_core(db: Session, all_threats: List[Dict[str, Any]], show_progress: bool = True) -> None:
    """
    Process all payloads to bulk upsert tenants, endpoints, and threats.
    """
    tenants_payload: Dict[int, Dict[str, Any]] = {}
    endpoints_payload: Dict[int, Dict[str, Any]] = {}
    threats_payload: Dict[int, Dict[str, Any]] = {}
    iter_fn = tqdm if show_progress else lambda x, **kw: x

    for t in iter_fn(all_threats, desc="Processing core objects", unit="record"):
        ti = t.get("threatInfo", {}) or {}
        det = t.get("agentDetectionInfo", {}) or {}
        rt = t.get("agentRealtimeInfo", {}) or {}
        # Tenant processing
        tenant_id = int(det.get("accountId") or 0)
        tenant_name = (det.get("accountName") or "").strip()
        if tenant_id and tenant_name:
            try:
                tenant = TenantModel(tenant_id=tenant_id, name=tenant_name)
                tenants_payload[tenant_id] = tenant.dict()
            except ValidationError as exc:
                logger.error("TenantModel validation failed for %s: %s", tenant_id, exc)
        # Endpoint processing
        endpoint_id = int(rt.get("agentId") or 0) if rt.get("agentId") else None
        if endpoint_id:
            try:
                endpoint = EndpointModel(
                    endpoint_id=endpoint_id,
                    tenant_id=tenant_id,
                    agent_uuid=rt.get("agentUuid") or "",
                    computer_name=rt.get("agentComputerName"),
                    os_name=rt.get("agentOsName"),
                    os_type=rt.get("agentOsType"),
                    os_revision=rt.get("agentOsRevision"),
                    ip_v4=det.get("agentIpV4") or rt.get("agentLocalIpV4"),
                    ip_v6=det.get("agentIpV6") or rt.get("agentLocalIpV6"),
                    group_id=int(rt.get("groupId") or det.get("groupId") or 0),
                    site_id=int(rt.get("siteId") or det.get("siteId") or 0),
                    agent_version=rt.get("agentVersion"),
                    scan_started_at=rt.get("scanStartedAt"),
                    scan_finished_at=rt.get("scanFinishedAt"),
                )
                endpoints_payload[endpoint_id] = endpoint.dict()
            except ValidationError as exc:
                logger.error("EndpointModel validation failed for %s: %s", endpoint_id, exc)
        # Threat processing
        try:
            threat = ThreatModel(
                threat_id=int(ti.get("threatId") or 0),
                tenant_id=tenant_id,
                endpoint_id=endpoint_id,
                md5=ti.get("md5"),
                sha1=ti.get("sha1"),
                sha256=ti.get("sha256"),
                file_path=ti.get("filePath"),
                file_size=ti.get("fileSize"),
                threat_name=ti.get("threatName"),
                publisher_name=ti.get("publisherName"),
                certificate_id=ti.get("certificateId"),
                identified_at=ti.get("identifiedAt"),
                created_at=ti.get("createdAt"),
            )
            threats_payload[int(ti.get("threatId") or 0)] = threat.dict()
        except ValidationError as exc:
            logger.error("ThreatModel validation failed for threat_id=%s: %s", ti.get("threatId"), exc)

    # Bulk upsert tenants
    if tenants_payload:
        _bulk_upsert_with_fallback(
            db,
            tenants,
            list(tenants_payload.values()),
            lambda p: pg_insert(tenants).values(p).on_conflict_do_nothing()
        )
    # Bulk upsert endpoints
    if endpoints_payload:
        sample = next(iter(endpoints_payload.values()))
        upd = {k: pg_insert(endpoints).excluded[k] for k in sample if k != "endpoint_id"}
        _bulk_upsert_with_fallback(
            db,
            endpoints,
            list(endpoints_payload.values()),
            lambda p: pg_insert(endpoints).values(p).on_conflict_do_update(
                index_elements=["endpoint_id"], set_=upd
            )
        )
    # Bulk upsert threats
    if threats_payload:
        sample = next(iter(threats_payload.values()))
        upd = {k: pg_insert(threats).excluded[k] for k in sample if k != "threat_id"}
        upd.update({
            "last_updated_at": pg_insert(threats).excluded.created_at,
        })
        _bulk_upsert_with_fallback(
            db,
            threats,
            list(threats_payload.values()),
            lambda p: pg_insert(threats).values(p).on_conflict_do_update(
                index_elements=["threat_id"], set_=upd
            )
        )

def batch_upsert_dependents(db: Session, all_threats: List[Dict[str, Any]], show_progress: bool = True) -> None:
    """
    Processes and bulk inserts labels, indicators, notes, and deepvis events.
    """
    labels: List[Dict[str, Any]] = []
    indicators: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    deepvis: List[Dict[str, Any]] = []
    iter_fn = tqdm if show_progress else lambda x, **kw: x

    for t in iter_fn(all_threats, desc="Processing dependent objects", unit="record"):
        ti = t.get("threatInfo", {}) or {}
        threat_id = int(ti.get("threatId") or 0)
        if not threat_id:
            continue
        # Process label from analyst verdict
        verdict = (ti.get("analystVerdict") or "").strip()
        if verdict:
            try:
                label = LabelModel(threat_id=threat_id, verdict=verdict)
                labels.append(label.dict())
            except ValidationError as exc:
                logger.warning("Skipping invalid label (threat=%s): %s", threat_id, exc)
        # Process indicators
        for ind in t.get("indicators", []):
            payload = {
                "threat_id": threat_id,
                "category": ind.get("category"),
                "description": ind.get("description"),
                "ids": ind.get("ids"),
                "tactics": ind.get("tactics"),
                "techniques": ind.get("techniques"),
            }
            try:
                obj = IndicatorModel(**payload)
                indicators.append(obj.dict())
            except ValidationError as exc:
                logger.warning("IndicatorModel failed for %s: %s", threat_id, exc)
        # Process notes
        for note in t.get("notes", []):
            try:
                obj = NoteModel(threat_id=threat_id, note=note)
                notes.append(obj.dict())
            except ValidationError as exc:
                logger.warning("NoteModel failed for %s: %s", threat_id, exc)
        # Process deepvis events
        for ev in t.get("deepvis", []):
            deepvis.append({
                "threat_id": threat_id,
                "event_time": ev.get("eventTime"),
                "event_type": ev.get("eventType"),
                "event_cat": ev.get("eventCategory"),
                "severity": ev.get("severity"),
            })

    if labels:
        _bulk_upsert_with_fallback(
            db, threat_labels, labels,
            lambda p: pg_insert(threat_labels).values(p).on_conflict_do_nothing()
        )
    if indicators:
        _bulk_upsert_with_fallback(
            db, threat_indicators, indicators,
            lambda p: pg_insert(threat_indicators).values(p).on_conflict_do_nothing()
        )
    if notes:
        _bulk_upsert_with_fallback(
            db, threat_notes, notes,
            lambda p: pg_insert(threat_notes).values(p).on_conflict_do_nothing()
        )
    if deepvis:
        _bulk_upsert_with_fallback(
            db, deepvis_events, deepvis,
            lambda p: pg_insert(deepvis_events).values(p).on_conflict_do_nothing()
        )
    logger.info("Dependent bulk insert complete: %d labels, %d indicators, %d notes, %d deepvis",
                len(labels), len(indicators), len(notes), len(deepvis))