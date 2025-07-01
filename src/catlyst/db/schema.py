# src/catlyst/db/schema.py

from sqlalchemy import (
    MetaData, Table, Column,
    BigInteger, Integer, Text, TIMESTAMP,
    ForeignKey, UniqueConstraint, Index,
    text, func
)
from sqlalchemy.dialects.postgresql import UUID, REAL, JSONB, BYTEA, INET, ENUM, ARRAY
metadata = MetaData()

#
# ========== ENUM TYPES ==========
#
detection_type_enum = ENUM(
    'static', 'dynamic', name='detection_type', metadata=metadata
)
incident_status_enum = ENUM(
    'unresolved', 'in_progress', 'resolved',
    name='incident_status', metadata=metadata
)
analyst_verdict_enum = ENUM(
    'undefined', 'true_positive', 'false_positive',
    name='analyst_verdict', metadata=metadata
)

#
#  CORE TABLES
#
tenants = Table(
    "tenants", metadata,
    Column("tenant_id", BigInteger, primary_key=True),
    Column("name",      Text,       nullable=False),
    Column("ingested_at", TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
)

endpoints = Table(
    "endpoints", metadata,
    Column("endpoint_id",   BigInteger, primary_key=True, autoincrement=True),
    Column("tenant_id",     BigInteger,
           ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
           nullable=False),
    Column("agent_uuid",    UUID,    nullable=False),
    Column("computer_name", Text),
    Column("os_name",       Text),
    Column("os_type",       Text),
    Column("os_revision",   Text),
    Column("ip_v4",         INET),
    Column("ip_v6",         INET),
    Column("group_id",      BigInteger),
    Column("site_id",       BigInteger),
    Column("agent_version", Text),
    Column("scan_started_at",   TIMESTAMP(timezone=True)),
    Column("scan_finished_at",  TIMESTAMP(timezone=True)),
    # The ingested_at column replaces created_at as per suggested changes.
    Column("ingested_at", TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    UniqueConstraint("tenant_id", "agent_uuid", name="uq_endpoint_tenant_uuid"),
    Index("ix_endpoints_tenant", "tenant_id"),
)

threats = Table(
    "threats", metadata,
    Column("threat_id",           BigInteger, primary_key=True),
    Column("storyline",           Text),
    Column("tenant_id",           BigInteger,
           ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
           nullable=False),
    Column("endpoint_id",         BigInteger,
           ForeignKey("endpoints.endpoint_id", ondelete="SET NULL")),
    Column("md5",                 BYTEA),
    Column("sha1",                BYTEA),
    Column("sha256",              BYTEA),
    Column("file_path",           Text),
    Column("file_size",           BigInteger),
    Column("threat_name",         Text),
    Column("publisher_name",      Text),
    Column("certificate_id",      Text),
    Column("identified_at",       TIMESTAMP(timezone=True), nullable=False),
    Column("created_at",          TIMESTAMP(timezone=True), nullable=False),
    Column("ingested_at",         TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Column("last_updated_at",     TIMESTAMP(timezone=True),
           nullable=False, server_default=func.now()),
    UniqueConstraint("tenant_id", "sha256", "identified_at",
                     name="uq_threat_unique"),
    Index("ix_threats_sha256",     "sha256"),
    # Indexes for removed columns dropped
    Index("ix_threats_tenant_date", "tenant_id", "identified_at"),
)


threat_notes = Table(
    "threat_notes", metadata,
    Column("note_id",   BigInteger, primary_key=True, autoincrement=True),
    Column("threat_id", BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("note",      Text, nullable=False),
    Column("ingested_at", TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Index("ix_notes_threat", "threat_id"),
)

threat_labels = Table(
    "threat_labels", metadata,
    Column("label_id",    BigInteger, primary_key=True, autoincrement=True),
    Column("threat_id",   BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("verdict",             analyst_verdict_enum, nullable=False, server_default=text("'undefined'")),

    Column("incident_status",     incident_status_enum),
    Column("detection_type",      detection_type_enum),
    Column("confidence_level",    Text),
    Column("classification",      Text),
    Column("classification_src",  Text),
    Column("initiated_by",        Text),
    Column("ingested_at", TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Index("ix_labels_threat", "threat_id"),
    Index("ix_labels_verdict", "verdict"),
)


#
#  DEDUPLICATION MATCHES
#
threat_matches = Table(
    "threat_matches", metadata,
    Column("id",                BigInteger, primary_key=True, autoincrement=True),
    Column("threat_id",         BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("matched_threat_id", BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("similarity_score",  REAL,    nullable=False),
    Column("matched_at",        TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    UniqueConstraint("threat_id", "matched_threat_id",
                     name="uq_threat_match_pair"),
    Index("ix_threat_matches_threat", "threat_id"),
)

#
#  THREAT INDICATORS (flattened + raw)
#
threat_indicators = Table(
    "threat_indicators", metadata,
    Column("indicator_id", BigInteger, primary_key=True, autoincrement=True),
    Column("threat_id",    BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("category",     Text),
    Column("description",  Text),
    Column("ids",          ARRAY(Integer)),
    Column("tactics",      ARRAY(Text)),
    Column("techniques",   JSONB),
    # Column("raw",          JSONB, nullable=False),
    Column("ingested_at",   TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Index("ix_indicators_threat", "threat_id"),
    Index("ix_indicators_ids",     "ids",      postgresql_using="gin"),
    Index("ix_indicators_tactics", "tactics",  postgresql_using="gin"),
)

#
#  DEEP-VIS EVENTS (one flat table, partition by event_time)
#
deepvis_events = Table(
    "deepvis_events", metadata,
    Column("dvevent_id",  BigInteger, primary_key=True, autoincrement=True),
    Column("threat_id",   BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           nullable=False),
    Column("event_time",  TIMESTAMP(timezone=True), nullable=False),
    Column("event_type",  Text, nullable=False),
    Column("event_cat",   Text),
    Column("severity",    Integer),
    # Column("raw",         JSONB, nullable=False),
    Column("ingested_at", TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Index("ix_dv_threat_time", "threat_id", "event_time"),
    Index("ix_dv_event_type",  "event_type"),
    # Index("ix_dv_raw_gin",      "raw", postgresql_using="gin"),
)

#
#  MODEL RUNS & PROVENANCE
#
model_runs = Table(
    "model_runs", metadata,
    Column("model_run_id", BigInteger, primary_key=True, autoincrement=True),
    Column("name",         Text, nullable=False),
    Column("description",  Text),
    Column("featureset",   Text),
    Column("trained_at",   TIMESTAMP(timezone=True),
           nullable=False, server_default="now()"),
    Column("metrics",      JSONB),
)
model_run_rows = Table(
    "model_run_rows", metadata,
    Column("model_run_id", BigInteger,
           ForeignKey("model_runs.model_run_id", ondelete="CASCADE"),
           primary_key=True),
    Column("threat_id",    BigInteger,
           ForeignKey("threats.threat_id", ondelete="CASCADE"),
           primary_key=True),
)
model_run_columns = Table(
    "model_run_columns", metadata,
    Column("model_run_id",  BigInteger,
           ForeignKey("model_runs.model_run_id", ondelete="CASCADE"),
           primary_key=True),
    Column("column_name",   Text, primary_key=True),
)

#
#  TRIGGER FOR last_updated_at
#
from sqlalchemy import DDL, event

ddl_last_updated = DDL("""
CREATE OR REPLACE FUNCTION trg_set_last_updated()
RETURNS TRIGGER AS $$
BEGIN
  NEW.last_updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_threats_last_update ON threats;
CREATE TRIGGER trg_threats_last_update
  BEFORE INSERT OR UPDATE ON threats
  FOR EACH ROW EXECUTE PROCEDURE trg_set_last_updated();
""")

event.listen(metadata, "after_create", ddl_last_updated)

#
#  EXPORT
#
__all__ = [
    "metadata",
    # enums
    "detection_type_enum", "incident_status_enum", "analyst_verdict_enum",
    # core tables
    "tenants", "endpoints", "threats",
    # child tables
    "threat_notes", "threat_labels",
    "threat_matches",
    # ML metadata
    "model_runs", "model_run_rows", "model_run_columns",
    # indicators & events
    "threat_indicators", "deepvis_events",
]