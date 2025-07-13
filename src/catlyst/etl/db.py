# src/catlyst/etl/db.py

"""
ETL → Batch upsert/inserts with full Pydantic validation.
This module assumes you have the complete list of threat payloads already
loaded in memory. It first extracts unique core objects (tenants, endpoints,
threats) and performs bulk upserts (with commit). Then, it processes and
inserts dependent objects (labels, normalized indicators, notes, and deepvis events).
All data is validated using our Pydantic models from catlyst/etl/validation.py.
"""

import logging
from typing import Any, Dict, List
from pydantic import ValidationError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy import insert as sql_insert
from sqlalchemy.orm import Session
from tqdm import tqdm

from catlyst.db.schema import (
    tenants,
    endpoints,
    threats,
    threat_indicators,
    threat_notes,
    deepvis_events,
    indicator_tactics,
    tactic_techniques,
)
from catlyst.etl.validation import (
    TenantModel,
    EndpointModel,
    ThreatModel,
    NoteModel,
    # IndicatorModel, # "IndicatorModel" is not accessedPylance
    TacticModel,
    TechniqueModel,
)

logger = logging.getLogger(__name__)

def _bulk_upsert_with_fallback(
    db: Session,
    table,
    payloads: List[Dict[str, Any]],
    stmt_builder: Any,
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
                        stmt = sql_insert(table).values(**rec)
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
        stmt = pg_insert(tenants).values(**tenant.dict()).on_conflict_do_nothing()
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
        # Create an update payload (excluding unique constraint columns) using model_dump()
        update_payload = {k: v for k, v in endpoint.model_dump().items() if k not in ("tenant_id", "agent_uuid")}
        # Use the unique constraint (tenant_id, agent_uuid) as the conflict target.
        stmt = pg_insert(endpoints).values(**endpoint.model_dump()).on_conflict_do_update(
            index_elements=["tenant_id", "agent_uuid"],
            set_=update_payload
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
        "storyline": ti.get("storyline"),
        "tenant_id": int(det.get("accountId") or 0),
        "incident_status": ti.get("incidentStatus"),
        "analyst_verdict": ti.get("analystVerdict"),
        "detection_type": ti.get("detectionType"),
        "confidence_level": ti.get("confidenceLevel"),
        "classification": ti.get("classification"),
        "classification_source": ti.get("classificationSource"),
        "created_at": ti.get("createdAt"),
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
        "last_updated_at": ti.get("updatedAt"),
    }
    try:
        threat = ThreatModel(**payload)
        stmt = pg_insert(threats).values(**threat.dict()).on_conflict_do_update(
            index_elements=["threat_id"],
            set_={
                "incident_status": pg_insert(threats).excluded.incident_status,
                "analyst_verdict": pg_insert(threats).excluded.analyst_verdict,
                "detection_type": pg_insert(threats).excluded.detection_type,
                "confidence_level": pg_insert(threats).excluded.confidence_level,
                "classification": pg_insert(threats).excluded.classification,
                "classification_source": pg_insert(threats).excluded.classification_source,
                "initiated_by": pg_insert(threats).excluded.initiated_by,
                "last_updated_at": pg_insert(threats).excluded.last_updated_at,
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
            stmt = pg_insert(threat_notes).values(**note.dict()).on_conflict_do_nothing()
            db.execute(stmt)
        except ValidationError as exc:
            logger.warning("Skipping invalid note (threat=%s): %s", threat_id, exc)
        except Exception as e:
            logger.error("Error inserting note for threat %s: %s", threat_id, e)
    db.commit()

# Removed label insertion; labels now merged into threats table

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
                storyline=ti.get("storyline"),
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
                last_updated_at=ti.get("updatedAt"),
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

def insert_indicators_normalized(
    db: Session, threat_id: int, indicators: List[Dict[str, Any]]
) -> None:
    """
    Fully normalized insert of each indicator → tactics → techniques.
    """
    for ind in indicators or []:
        # 1) Upsert base indicator
        payload = {
            "threat_id": threat_id,
            "category": ind.get("category"),
            "description": ind.get("description"),
            "ids": ind.get("ids"),
        }
        try:
            res = db.execute(
                pg_insert(threat_indicators)
                .values(**payload)
                .on_conflict_do_nothing()
                .returning(threat_indicators.c.indicator_id)
            )
            row = res.fetchone()
            db.commit()
            if not row:
                # already existed; skip inserting tactics/techniques for this indicator
                continue
            indicator_id = row.indicator_id
        except Exception as e:
            db.rollback()
            logger.error("Error upserting indicator %s: %s", payload, e)
            continue

        # 2) Insert each tactic for this indicator
        for t in ind.get("tactics", []):
            try:
                tac = TacticModel(**t)
            except ValidationError as exc:
                logger.warning("Skipping invalid tactic for indicator=%s: %s", indicator_id, exc)
                continue

            try:
                res2 = db.execute(
                sql_insert(indicator_tactics)
                    .values(
                        indicator_id=indicator_id,
                        name=tac.name,
                        source=tac.source
                    )
                    .returning(indicator_tactics.c.tactic_id)
                )
                tactic_id = res2.scalar_one()
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error("Error inserting tactic %s for indicator_id=%s: %s", tac, indicator_id, e)
                continue

            # 3) Insert each technique under that tactic
            for tech in t.get("techniques", []):
                try:
                    techm = TechniqueModel(**tech)
                except ValidationError as exc:
                    logger.warning("Skipping invalid technique for tactic=%s: %s", tactic_id, exc)
                    continue
                try:
                    db.execute(
                        sql_insert(tactic_techniques)
                        .values(
                            tactic_id=tactic_id,
                            name=techm.name,
                            link=techm.link
                        )
                    )
                except Exception as e:
                    logger.error("Error inserting technique %s for tactic_id=%s: %s", techm, tactic_id, e)
            db.commit()

def batch_upsert_dependents(db: Session, all_threats: List[Dict[str, Any]], show_progress: bool = True) -> None:
    """
    Processes and inserts labels, notes, normalized indicators, and deepvis events.
    """
    iter_fn = tqdm if show_progress else lambda x, **kw: x

    for t in iter_fn(all_threats, desc="Processing dependent objects", unit="record"):
        ti = t.get("threatInfo", {}) or {}
        threat_id = int(ti.get("threatId") or 0)
        if not threat_id:
            continue
        upsert_threat(db, t)

        # Labels are merged into threats table; no separate insert_labels call

        # Process notes
        insert_notes(db, threat_id, t.get("notes", []))

        # Process indicators (normalized)
        insert_indicators_normalized(db, threat_id, t.get("indicators", []))

        # Process deepvis events
        for ev in t.get("deepvis", []):
            try:
                db.execute(
                    pg_insert(deepvis_events)
                    .values(
                        threat_id=threat_id,
                        event_time=ev.get("eventTime"),
                        event_type=ev.get("eventType"),
                        event_cat=ev.get("eventCategory"),
                        severity=ev.get("severity"),
                    )
                    .on_conflict_do_nothing(
                        index_elements=["threat_id", "event_time", "event_type"]
                    )
                )
            except Exception as e:
                logger.error("Error inserting deepvis event for threat %s: %s", threat_id, e)
        db.commit()

    logger.info("Dependent insert (normalized) complete.")
