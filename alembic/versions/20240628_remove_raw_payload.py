"""remove raw_payload column from threats table

Revision ID: 20240628_remove_raw_payload
Revises: a6566bab7e7c
Create Date: 2025-06-28

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20240628_remove_raw_payload'
down_revision = 'a6566bab7e7c'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.drop_column('threats', 'raw_payload')

def downgrade() -> None:
    from sqlalchemy.dialects import postgresql
    op.add_column('threats', sa.Column('raw_payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False))
