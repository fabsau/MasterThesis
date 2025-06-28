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

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from tqdm import tqdm

from catlyst.db.schema import (
    tenants, endpoints, threats,
    threat_labels, threat_indicators,
    threat_notes, deepvis_events
)
from catlyst.etl.validation import (
    TenantModel, EndpointModel, ThreatModel,
    LabelModel, IndicatorModel, NoteModel
)

log = logging.getLogger(__name__)


def _bulk_upsert_with_fallback(
    db: Session,
    table,
    payloads: List[Dict[str, Any]],
    stmt_builder: Callable[[List[Dict[str, Any]]], Any],
    chunk_size: int = 100,
) -> None:
    """
    Try bulk upsert, then fallback to chunked upsert, then per-record.
    Logs any record that still fails.
    """
    # Attempt one big bulk upsert
    try:
        db.execute(stmt_builder(payloads))
        db.commit()
        return
    except Exception as bulk_exc:
        db.rollback()
        log.error("Bulk upsert failed for %s: %s", table.name, str(bulk_exc)[:200])

    # Retry in chunks
    for start in range(0, len(payloads), chunk_size):
        chunk = payloads[start : start + chunk_size]
        try:
            db.execute(stmt_builder(chunk))
            db.commit()
            continue
        except Exception as chunk_exc:
            db.rollback()
            log.error(
                "Chunk upsert failed for %s records %d-%d: %s",
                table.name, start, start + len(chunk) - 1, str(chunk_exc)[:200]
            )
        # Fallback to per-record
        pk = list(table.primary_key.columns)[0].name
        for rec in chunk:
            try:
                db.execute(stmt_builder([rec]))
                db.commit()
            except Exception as rec_exc:
                db.rollback()
                log.error(
                    "Record upsert failed for %s id=%s payload=%s: %s",
                    table.name,
                    rec.get(pk),
                    rec,
                    str(rec_exc)[:200]
                )
    # Final commit to ensure any remaining
    db.commit()


def batch_upsert_core(db: Session, all_threats: List[Dict[str, Any]]) -> None:
    """
    Process all payloads to bulk upsert tenants, endpoints, and threats.
    """
    tenants_payload: Dict[int, Dict[str, Any]] = {}
    endpoints_payload: Dict[int, Dict[str, Any]] = {}
    threats_payload: Dict[int, Dict[str, Any]] = {}

    for t in tqdm(all_threats, desc="Processing core objects", unit="record"):
        ti = t.get("threatInfo", {}) or {}
        det = t.get("agentDetectionInfo", {}) or {}
        rt = t.get("agentRealtimeInfo", {}) or {}

        # Tenant
        try:
            tenant_id = int(det.get("accountId") or 0)
        except Exception:
            continue
        tenant_name = (det.get("accountName") or "").strip()
        if tenant_id and tenant_name:
            try:
                obj = TenantModel(tenant_id=tenant_id, name=tenant_name)
                tenants_payload[tenant_id] = obj.dict()
            except Exception as e:
                log.error("TenantModel validation failed for %s: %s", tenant_id, e)

        # Endpoint
        try:
            endpoint_id = int(rt.get("agentId") or 0) or None
        except Exception:
            endpoint_id = None
        if endpoint_id:
            try:
                obj = EndpointModel(
                    endpoint_id=endpoint_id,
                    tenant_id=tenant_id,
                    agent_uuid=rt.get("agentUuid") or "",
                    computer_name=rt.get("agentComputerName"),
                    os_name=rt.get("agentOsName"),
                    os_type=rt.get("agentOsType"),
                    ip_v4=rt.get("agentLocalIpV4"),
                    ip_v6=rt.get("agentLocalIpV6"),
                    agent_version=rt.get("agentVersion"),
                    scan_started_at=rt.get("scanStartedAt"),
                    scan_finished_at=rt.get("scanFinishedAt"),
                )
                endpoints_payload[endpoint_id] = obj.dict()
            except Exception as e:
                log.error("EndpointModel validation failed for %s: %s", endpoint_id, e)

        # Threat
        try:
            threat_id = int(ti.get("threatId") or 0)
        except Exception:
            continue
        if threat_id:
            try:
                obj = ThreatModel(
                    threat_id=threat_id,
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
                    detection_type=ti.get("detectionType"),
                    confidence_level=ti.get("confidenceLevel"),
                    incident_status=ti.get("incidentStatus"),
                    analyst_verdict=ti.get("analystVerdict"),
                    classification_src=ti.get("classificationSource"),
                    initiated_by=ti.get("initiatedBy"),
                    identified_at=ti.get("identifiedAt"),
                    created_at=ti.get("createdAt"),
                )
                threats_payload[threat_id] = obj.dict()
            except Exception as e:
                log.error("ThreatModel validation failed for %s: %s", threat_id, e)

    # Upsert tenants
    if tenants_payload:
        _bulk_upsert_with_fallback(
            db,
            tenants,
            list(tenants_payload.values()),
            lambda p: pg_insert(tenants).values(p).on_conflict_do_nothing()
        )

    # Upsert endpoints
    if endpoints_payload:
        sample = next(iter(endpoints_payload.values()))
        upd = {k: pg_insert(endpoints).excluded[k] for k in sample if k != "endpoint_id"}
        _bulk_upsert_with_fallback(
            db,
            endpoints,
            list(endpoints_payload.values()),
            lambda p: pg_insert(endpoints).values(p)
                         .on_conflict_do_update(index_elements=["endpoint_id"], set_=upd)
        )

    # Upsert threats
    if threats_payload:
        sample = next(iter(threats_payload.values()))
        upd = {k: pg_insert(threats).excluded[k] for k in sample if k != "threat_id"}
        upd.update({
            "incident_status": pg_insert(threats).excluded.incident_status,
            "analyst_verdict": pg_insert(threats).excluded.analyst_verdict,
            "last_updated_at": pg_insert(threats).excluded.created_at,
        })
        _bulk_upsert_with_fallback(
            db,
            threats,
            list(threats_payload.values()),
            lambda p: pg_insert(threats).values(p)
                         .on_conflict_do_update(index_elements=["threat_id"], set_=upd)
        )

    log.info(
        "Core bulk upsert complete: %d tenants, %d endpoints, %d threats",
        len(tenants_payload), len(endpoints_payload), len(threats_payload),
    )


def batch_upsert_dependents(db: Session, all_threats: List[Dict[str, Any]]) -> None:
    """
    Processes and bulk inserts labels, indicators, notes, and deepvis events.
    """
    labels: List[Dict[str, Any]] = []
    indicators: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    deepvis: List[Dict[str, Any]] = []

    for t in tqdm(all_threats, desc="Processing dependent objects", unit="record"):
        ti = t.get("threatInfo", {}) or {}
        try:
            tid = int(ti.get("threatId") or 0)
        except Exception:
            continue
        if not tid:
            continue

        verdict = (ti.get("analystVerdict") or "").strip()
        if verdict:
            try:
                obj = LabelModel(threat_id=tid, verdict=verdict,
                                 source="initial_fetch", labeled_by="system")
                labels.append(obj.dict())
            except Exception as e:
                log.warning("LabelModel failed for %s: %s", tid, e)

        for ind in t.get("indicators", []):
            payload = {
                "threat_id": tid,
                "category": ind.get("category"),
                "description": ind.get("description"),
                "ids": ind.get("ids"),
                "tactics": ind.get("tactics"),
                "techniques": ind.get("techniques"),
            }
            try:
                obj = IndicatorModel(**payload)
                indicators.append(obj.dict())
            except Exception as e:
                log.warning("IndicatorModel failed for %s: %s", tid, e)

        for note in t.get("notes", []):
            try:
                obj = NoteModel(threat_id=tid, note=note)
                notes.append(obj.dict())
            except Exception as e:
                log.warning("NoteModel failed for %s: %s", tid, e)

        for ev in t.get("deepvis", []):
            deepvis.append({
                "threat_id": tid,
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

    log.info(
        "Dependent bulk insert complete: %d labels, %d indicators, %d notes, %d deepvis",
        len(labels), len(indicators), len(notes), len(deepvis),
    )