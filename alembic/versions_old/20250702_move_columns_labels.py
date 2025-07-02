"""Move analyst/label columns from threats to threat_labels

Revision ID: 20250702_move_columns_labels
Revises: 20250701_remove_analyst_verdict
Create Date: 2024-07-02 12:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250702_move_columns_labels'
down_revision = '20250701_remove_analyst_verdict'  # Set to your last revision
branch_labels = None
depends_on = None

def upgrade():
    # 1. Add columns to threat_labels
    op.add_column('threat_labels', sa.Column('detection_type', postgresql.ENUM('static', 'dynamic', name='detection_type'), nullable=True))
    op.add_column('threat_labels', sa.Column('confidence_level', sa.Text(), nullable=True))
    op.add_column('threat_labels', sa.Column('incident_status', postgresql.ENUM('unresolved', 'in_progress', 'resolved', name='incident_status'), nullable=True))
    op.add_column('threat_labels', sa.Column('verdict', postgresql.ENUM('undefined', 'true_positive', 'false_positive', name='analyst_verdict'), nullable=False, server_default='undefined'))
    op.add_column('threat_labels', sa.Column('classification', sa.Text(), nullable=True))
    op.add_column('threat_labels', sa.Column('classification_src', sa.Text(), nullable=True))
    op.add_column('threat_labels', sa.Column('initiated_by', sa.Text(), nullable=True))
    # Remove old 'comment' column if present
    with op.batch_alter_table('threat_labels') as batch_op:
        batch_op.drop_column('comment')


    # 3. Drop columns from threats
    with op.batch_alter_table('threats') as batch_op:
        batch_op.drop_column('detection_type')
        batch_op.drop_column('confidence_level')
        batch_op.drop_column('incident_status')
        batch_op.drop_column('analyst_verdict')
        batch_op.drop_column('classification')
        batch_op.drop_column('classification_src')
        batch_op.drop_column('initiated_by')
        # Drop related indexes if any
        batch_op.drop_index('ix_threats_verdict', if_exists=True)
        batch_op.drop_index('ix_threats_confidence', if_exists=True)
        batch_op.drop_index('ix_threats_status', if_exists=True)

def downgrade():
    # 1. Add columns back to threats
    with op.batch_alter_table('threats') as batch_op:
        batch_op.add_column(sa.Column('detection_type', postgresql.ENUM('static', 'dynamic', name='detection_type'), nullable=True))
        batch_op.add_column(sa.Column('confidence_level', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('incident_status', postgresql.ENUM('unresolved', 'in_progress', 'resolved', name='incident_status'), nullable=True))
        batch_op.add_column(sa.Column('analyst_verdict', postgresql.ENUM('undefined', 'true_positive', 'false_positive', name='analyst_verdict'), nullable=False, server_default='undefined'))
        batch_op.add_column(sa.Column('classification', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('classification_src', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('initiated_by', sa.Text(), nullable=True))
        # Restore indexes as needed
        batch_op.create_index('ix_threats_verdict', ['analyst_verdict'])
        batch_op.create_index('ix_threats_confidence', ['confidence_level'])
        batch_op.create_index('ix_threats_status', ['incident_status'])

    # 2. Drop new columns from threat_labels
    with op.batch_alter_table('threat_labels') as batch_op:
        batch_op.drop_column('detection_type')
        batch_op.drop_column('confidence_level')
        batch_op.drop_column('incident_status')
        batch_op.drop_column('verdict')
        batch_op.drop_column('classification')
        batch_op.drop_column('classification_src')
        batch_op.drop_column('initiated_by')
        batch_op.add_column(sa.Column('comment', sa.Text(), nullable=True))