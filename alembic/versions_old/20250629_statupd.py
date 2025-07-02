"""Update incident_status_t enum to include resolved, in_progress, unresolved.

Revision ID: 20250629_statupd
Revises: 20250629_statfix
Create Date: 2025-06-29

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '20250629_statupd'
down_revision = '20250629_tactupd'
branch_labels = None
depends_on = None

def upgrade():
    # Add the missing enum values.
    op.execute("ALTER TYPE incident_status_t ADD VALUE 'in_progress'")
    op.execute("ALTER TYPE incident_status_t ADD VALUE 'unresolved'")

def downgrade():
    # Downgrade not supported because PostgreSQL cannot remove enum values easily.
    pass