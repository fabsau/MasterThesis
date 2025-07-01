"""remove analyst_verdict column from threats table

Revision ID: 20250701_remove_analyst_verdict
Revises: v0.5.0_cleanup  # Adjust this to the current latest revision ID if needed
Create Date: 2025-07-01

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250701_remove_analyst_verdict'
down_revision = 'v0.5.0_cleanup'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.drop_column('threats', 'analyst_verdict')

def downgrade() -> None:
    op.add_column('threats', sa.Column('analyst_verdict', sa.Text(), nullable=True))