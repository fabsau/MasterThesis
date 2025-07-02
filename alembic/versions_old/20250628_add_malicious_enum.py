"""add 'malicious' to confidence_level_t ENUM

Revision ID: 20250628_add_malicious_enum
Revises: 20240628_remove_raw_payload
Create Date: 2025-06-28

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '20250628_add_malicious_enum'
down_revision = '20240628_remove_raw_payload'
branch_labels = None
depends_on = None

def upgrade():
    op.execute("ALTER TYPE confidence_level_t ADD VALUE IF NOT EXISTS 'malicious';")

def downgrade():
    pass  # It is not straightforward to remove a value from a Postgres ENUM