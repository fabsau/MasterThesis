"""Initial schema

Revision ID: 1
Revises: 
Create Date: 2025-07-02 22:54:03.496301

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ENUM types
    analyst_verdict_enum = sa.Enum('undefined', 'true_positive', 'false_positive', name='analyst_verdict', create_type=True)
    incident_status_enum = sa.Enum('unresolved', 'in_progress', 'resolved', name='incident_status', create_type=True)
    detection_type_enum = sa.Enum('static', 'dynamic', name='detection_type', create_type=True)

    analyst_verdict_enum.create(op.get_bind(), checkfirst=True)
    incident_status_enum.create(op.get_bind(), checkfirst=True)
    detection_type_enum.create(op.get_bind(), checkfirst=True)

    # tenants table
    op.create_table(
        'tenants',
        sa.Column('tenant_id', sa.BigInteger(), primary_key=True),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # endpoints table
    op.create_table(
        'endpoints',
        sa.Column('endpoint_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.BigInteger(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column('agent_uuid', postgresql.UUID(), nullable=False),
        sa.Column('computer_name', sa.Text(), nullable=True),
        sa.Column('os_name', sa.Text(), nullable=True),
        sa.Column('os_type', sa.Text(), nullable=True),
        sa.Column('os_revision', sa.Text(), nullable=True),
        sa.Column('ip_v4', sa.dialects.postgresql.INET(), nullable=True),
        sa.Column('ip_v6', sa.dialects.postgresql.INET(), nullable=True),
        sa.Column('group_id', sa.BigInteger(), nullable=True),
        sa.Column('site_id', sa.BigInteger(), nullable=True),
        sa.Column('agent_version', sa.Text(), nullable=True),
        sa.Column('scan_started_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('scan_finished_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('tenant_id', 'agent_uuid', name='uq_endpoint_tenant_uuid'),
    )
    op.create_index('ix_endpoints_tenant', 'endpoints', ['tenant_id'], unique=False)

    # threats table
    op.create_table(
        'threats',
        sa.Column('threat_id', sa.BigInteger(), primary_key=True),
        sa.Column('storyline', sa.Text(), nullable=True),
        sa.Column('tenant_id', sa.BigInteger(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column('incident_status', incident_status_enum, nullable=True),
        sa.Column('analyst_verdict', analyst_verdict_enum, nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('endpoint_id', sa.BigInteger(), sa.ForeignKey("endpoints.endpoint_id", ondelete="SET NULL"), nullable=True),
        sa.Column('md5', sa.LargeBinary(), nullable=True),
        sa.Column('sha1', sa.LargeBinary(), nullable=True),
        sa.Column('sha256', sa.LargeBinary(), nullable=True),
        sa.Column('file_path', sa.Text(), nullable=True),
        sa.Column('file_size', sa.BigInteger(), nullable=True),
        sa.Column('threat_name', sa.Text(), nullable=True),
        sa.Column('publisher_name', sa.Text(), nullable=True),
        sa.Column('certificate_id', sa.Text(), nullable=True),
        sa.Column('initiated_by', sa.Text(), nullable=True),
        sa.Column('identified_at', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_updated_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('tenant_id', 'sha256', 'identified_at', name='uq_threat_unique'),
    )
    op.create_index('ix_threats_sha256', 'threats', ['sha256'], unique=False)
    op.create_index('ix_threats_sha1', 'threats', ['sha1'], unique=False)
    op.create_index('ix_threats_md5', 'threats', ['md5'], unique=False)
    op.create_index('ix_threats_tenant_date', 'threats', ['tenant_id', 'identified_at'], unique=False)

    # Create trigger function and trigger to update last_updated_at on threats
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trg_set_last_updated()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.last_updated_at = now();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_threats_last_update ON threats;
        CREATE TRIGGER trg_threats_last_update
            BEFORE INSERT OR UPDATE ON threats
            FOR EACH ROW EXECUTE PROCEDURE trg_set_last_updated();
        """
    )

    # threat_notes table
    op.create_table(
        'threat_notes',
        sa.Column('note_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('threat_id', sa.BigInteger(), sa.ForeignKey("threats.threat_id", ondelete="CASCADE"), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_notes_threat', 'threat_notes', ['threat_id'], unique=False)

    # threat_labels table
    op.create_table(
        'threat_labels',
        sa.Column('label_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('threat_id', sa.BigInteger(), sa.ForeignKey("threats.threat_id", ondelete="CASCADE"), nullable=False),
        sa.Column('verdict', analyst_verdict_enum, nullable=False, server_default=sa.text("'undefined'")),
        sa.Column('incident_status', incident_status_enum, nullable=True),
        sa.Column('detection_type', detection_type_enum, nullable=True),
        sa.Column('confidence_level', sa.Text(), nullable=True),
        sa.Column('classification', sa.Text(), nullable=True),
        sa.Column('classificationSource', sa.Text(), nullable=True),
        sa.Column('initiated_by', sa.Text(), nullable=True),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_labels_threat', 'threat_labels', ['threat_id'], unique=False)
    op.create_index('ix_labels_verdict', 'threat_labels', ['verdict'], unique=False)

    # threat_indicators table
    op.create_table(
        'threat_indicators',
        sa.Column('indicator_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('threat_id', sa.BigInteger(), sa.ForeignKey("threats.threat_id", ondelete="CASCADE"), nullable=False),
        sa.Column('category', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('ids', postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_indicators_threat', 'threat_indicators', ['threat_id'], unique=False)
    op.create_index('ix_indicators_ids', 'threat_indicators', ['ids'], unique=False, postgresql_using='gin')

    # indicator_tactics table
    op.create_table(
        'indicator_tactics',
        sa.Column('tactic_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('indicator_id', sa.BigInteger(), sa.ForeignKey("threat_indicators.indicator_id", ondelete="CASCADE"), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('source', sa.Text(), nullable=False),
    )
    op.create_index('ix_tactics_indicator', 'indicator_tactics', ['indicator_id'], unique=False)

    # tactic_techniques table
    op.create_table(
        'tactic_techniques',
        sa.Column('technique_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('tactic_id', sa.BigInteger(), sa.ForeignKey("indicator_tactics.tactic_id", ondelete="CASCADE"), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('link', sa.Text(), nullable=False),
    )
    op.create_index('ix_techniques_tactic', 'tactic_techniques', ['tactic_id'], unique=False)

    # deepvis_events table
    op.create_table(
        'deepvis_events',
        sa.Column('dvevent_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('threat_id', sa.BigInteger(), sa.ForeignKey("threats.threat_id", ondelete="CASCADE"), nullable=False),
        sa.Column('event_time', sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('event_cat', sa.Text(), nullable=True),
        sa.Column('severity', sa.Integer(), nullable=True),
        sa.Column('ingested_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint('threat_id', 'event_time', 'event_type', name='uq_deepvis_event')
    )
    op.create_index('ix_dv_threat_time', 'deepvis_events', ['threat_id', 'event_time'], unique=False)
    op.create_index('ix_dv_event_type', 'deepvis_events', ['event_type'], unique=False)

    # model_runs table
    op.create_table(
        'model_runs',
        sa.Column('model_run_id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('featureset', sa.Text(), nullable=True),
        sa.Column('trained_at', sa.TIMESTAMP(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('metrics', postgresql.JSONB(), nullable=True),
    )

    # model_run_rows table
    op.create_table(
        'model_run_rows',
        sa.Column('model_run_id', sa.BigInteger(), sa.ForeignKey("model_runs.model_run_id", ondelete="CASCADE"), primary_key=True),
        sa.Column('threat_id', sa.BigInteger(), sa.ForeignKey("threats.threat_id", ondelete="CASCADE"), primary_key=True),
    )

    # model_run_columns table
    op.create_table(
        'model_run_columns',
        sa.Column('model_run_id', sa.BigInteger(), sa.ForeignKey("model_runs.model_run_id", ondelete="CASCADE"), primary_key=True),
        sa.Column('column_name', sa.Text(), primary_key=True),
    )


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.drop_table('model_run_columns')
    op.drop_table('model_run_rows')
    op.drop_table('model_runs')
    op.drop_index('ix_dv_event_type', table_name='deepvis_events')
    op.drop_index('ix_dv_threat_time', table_name='deepvis_events')
    op.drop_table('deepvis_events')
    op.drop_index('ix_techniques_tactic', table_name='tactic_techniques')
    op.drop_table('tactic_techniques')
    op.drop_index('ix_tactics_indicator', table_name='indicator_tactics')
    op.drop_table('indicator_tactics')
    op.drop_index('ix_indicators_ids', table_name='threat_indicators')
    op.drop_index('ix_indicators_threat', table_name='threat_indicators')
    op.drop_table('threat_indicators')
    op.drop_index('ix_labels_verdict', table_name='threat_labels')
    op.drop_index('ix_labels_threat', table_name='threat_labels')
    op.drop_table('threat_labels')
    op.drop_index('ix_notes_threat', table_name='threat_notes')
    op.drop_table('threat_notes')
    op.drop_index('ix_threats_tenant_date', table_name='threats')
    op.drop_index('ix_threats_md5', table_name='threats')
    op.drop_index('ix_threats_sha1', table_name='threats')
    op.drop_index('ix_threats_sha256', table_name='threats')
    op.drop_table('threats')
    op.drop_index('ix_endpoints_tenant', table_name='endpoints')
    op.drop_table('endpoints')
    op.drop_table('tenants')

    # Drop ENUM types
    analyst_verdict_enum = sa.Enum('undefined', 'true_positive', 'false_positive', name='analyst_verdict')
    incident_status_enum = sa.Enum('unresolved', 'in_progress', 'resolved', name='incident_status')
    detection_type_enum = sa.Enum('static', 'dynamic', name='detection_type')
    analyst_verdict_enum.drop(op.get_bind(), checkfirst=True)
    incident_status_enum.drop(op.get_bind(), checkfirst=True)
    detection_type_enum.drop(op.get_bind(), checkfirst=True)