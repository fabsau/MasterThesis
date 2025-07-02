"""Add classification & storyline, enrich endpoints, unify created→ingested timestamps

Revision ID: 20250701_story_class_and_endpoint_updates
Revises: 20250629_statupd
Create Date: 2025-07-01

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "v0.5.0_cleanup"
down_revision = "20250629_statupd"
branch_labels = None
depends_on = None


def upgrade():
    # tenants: drop region, rename created_at → ingested_at
    op.drop_column("tenants", "region")
    op.alter_column("tenants", "created_at", new_column_name="ingested_at")

    # threats: add classification & storyline
    op.add_column("threats", sa.Column("classification", sa.Text(), nullable=True))
    op.add_column("threats", sa.Column("storyline", sa.Text(), nullable=True))

    # endpoints: add missing columns, rename created_at → ingested_at
    op.alter_column("endpoints", "created_at", new_column_name="ingested_at")

    # threat_labels: drop source & labeled_by, rename labeled_at → ingested_at
    op.drop_column("threat_labels", "source")
    op.drop_column("threat_labels", "labeled_by")
    op.alter_column("threat_labels", "labeled_at", new_column_name="ingested_at")

    # threat_notes: rename created_at → ingested_at
    op.alter_column("threat_notes", "created_at", new_column_name="ingested_at")

    # threat_indicators: rename created_at → ingested_at
    op.add_column(
        "threat_indicators",
        sa.Column(
            "ingested_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()")
        )
    )


def downgrade():
    raise NotImplementedError("Downgrade not supported")