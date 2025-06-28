"""Make md5, sha1, sha256 nullable in threats table.

Revision ID: 20250628_make_threat_sha_nullable
Revises: 20250628_add_malicious_enum
Create Date: 2025-06-28

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250628_hashes_nullable'
down_revision = '20250628_add_malicious_enum'
branch_labels = None
depends_on = None

def upgrade():
    op.alter_column('threats', 'sha256', nullable=True)
    op.alter_column('threats', 'sha1', nullable=True)
    op.alter_column('threats', 'md5', nullable=True)

def downgrade():
    op.alter_column('threats', 'sha256', nullable=False)
    op.alter_column('threats', 'sha1', nullable=False)
    op.alter_column('threats', 'md5', nullable=False)
