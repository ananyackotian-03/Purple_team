"""Reconciliation Schema Update: RetestResult scenario_id alignment & DetectionGapRecord persistent table

Revision ID: 001_reconciliation
Revises: None
Create Date: 2026-08-14

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001_reconciliation'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create detection_gaps table
    op.create_table(
        'detection_gaps',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('scenario_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('technique_id', sa.String(), nullable=False),
        sa.Column('original_outcome', sa.String(), nullable=False),
        sa.Column('evidence_event_ids', sa.Text(), nullable=True),
        sa.Column('matched_rule_ids', sa.Text(), nullable=True),
        sa.Column('root_cause', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('remediation_status', sa.String(), nullable=False, server_default='OPEN'),
        sa.Column('retest_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # 2. Add alignment columns to retest_results
    with op.batch_alter_table('retest_results') as batch_op:
        batch_op.add_column(sa.Column('scenario_id', postgresql.UUID(as_uuid=True), nullable=True))
        batch_op.add_column(sa.Column('before_outcome', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('after_outcome', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('validated_rule_ids', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('evaluated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')))
        batch_op.alter_column('exercise_id', existing_type=postgresql.UUID(as_uuid=True), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table('retest_results') as batch_op:
        batch_op.drop_column('evaluated_at')
        batch_op.drop_column('validated_rule_ids')
        batch_op.drop_column('after_outcome')
        batch_op.drop_column('before_outcome')
        batch_op.drop_column('scenario_id')

    op.drop_table('detection_gaps')
