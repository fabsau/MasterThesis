"""Add ids column to threat_indicators table.

Revision ID: 20250629_add_ids_to_threat_indicators
Revises: 20250628_hashes_nullable
Create Date: 2025-06-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250629_add_ids_column'
down_revision = '20250628_hashes_nullable'
branch_labels = None
depends_on = None

def upgrade():
    # Add the missing "ids" column to the threat_indicators table.
    op.add_column(
        'threat_indicators',
        sa.Column('ids', postgresql.ARRAY(sa.Integer), nullable=True)
    )

def downgrade():
    # Remove the "ids" column from the threat_indicators table.
    op.drop_column('threat_indicators', 'ids')