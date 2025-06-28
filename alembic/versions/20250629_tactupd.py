"""Add tactics and techniques columns.

Revision ID: 20250629_tactupd
Revises: 20250629_add_ids_to_threat_indicators
Create Date: 2025-06-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250629_tactupd'
down_revision = '20250629_add_ids_column'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column(
        'threat_indicators',
        sa.Column('tactics', postgresql.ARRAY(sa.Text), nullable=True)
    )
    op.add_column(
        'threat_indicators',
        sa.Column('techniques', postgresql.JSONB, nullable=True)
    )

def downgrade():
    op.drop_column('threat_indicators', 'techniques')
    op.drop_column('threat_indicators', 'tactics')