"""Organization Enhancement: Add defensive state and domain fields

Revision ID: 004_organization_enhancement
Revises: 003_remediation_persistence
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa

revision = '004_organization_enhancement'
down_revision = '003_remediation_persistence'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('description', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('defensive_state', sa.String(), nullable=False, server_default='INITIAL'))
        batch_op.add_column(sa.Column('assets', sa.JSON(), nullable=True, server_default='{}'))
        batch_op.add_column(sa.Column('security_controls', sa.JSON(), nullable=True, server_default='{}'))
        batch_op.add_column(sa.Column('detection_rules', sa.JSON(), nullable=True, server_default='{}'))
        batch_op.add_column(sa.Column('experiment_summary', sa.JSON(), nullable=True, server_default='{}'))
        batch_op.add_column(sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')))
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')))


def downgrade() -> None:
    with op.batch_alter_table('organizations', schema=None) as batch_op:
        batch_op.drop_column('updated_at')
        batch_op.drop_column('created_at')
        batch_op.drop_column('experiment_summary')
        batch_op.drop_column('detection_rules')
        batch_op.drop_column('security_controls')
        batch_op.drop_column('assets')
        batch_op.drop_column('defensive_state')
        batch_op.drop_column('description')