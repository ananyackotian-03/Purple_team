"""Remediation Persistence Schema: proposal status, attempt lifecycle, verification, audit events

Revision ID: 003_remediation_persistence
Revises: 002_application_remediation
Create Date: 2026-08-19

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '003_remediation_persistence'
down_revision: Union[str, None] = '002_application_remediation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add target_id, status to remediation_proposals
    with op.batch_alter_table('remediation_proposals') as batch_op:
        batch_op.add_column(sa.Column('target_id', postgresql.UUID(as_uuid=True),
                                       sa.ForeignKey('application_targets.id'), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(), nullable=False, server_default='CREATED'))

    # 2. Add organization_id, status, start_time, end_time, failure_reason, rollback_status to remediation_attempts
    with op.batch_alter_table('remediation_attempts') as batch_op:
        batch_op.add_column(sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                                       sa.ForeignKey('organizations.id'), nullable=True))
        batch_op.add_column(sa.Column('status', sa.String(), nullable=False, server_default='PROPOSED'))
        batch_op.add_column(sa.Column('start_time', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('end_time', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('failure_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('rollback_status', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('files_changed', sa.Text(), nullable=True))

    # 3. Create remediation_verifications table
    op.create_table(
        'remediation_verifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('vulnerability_findings.id'), nullable=False),
        sa.Column('remediation_attempt_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('remediation_attempts.id'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('original_attack_blocked', sa.Boolean(), nullable=False),
        sa.Column('original_attack_evidence', sa.Text(), nullable=True),
        sa.Column('retest_outcome', sa.String(), nullable=False),
        sa.Column('retest_evidence', sa.Text(), nullable=True),
        sa.Column('regression_tests_passed', sa.Boolean(), nullable=True),
        sa.Column('application_functional', sa.Boolean(), nullable=True),
        sa.Column('verification_decision', sa.String(), nullable=False),
        sa.Column('verification_reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # 4. Create remediation_audit_events table
    op.create_table(
        'remediation_audit_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                   sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('exercise_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('entity_type', sa.String(), nullable=False),
        sa.Column('entity_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('actor', sa.String(), nullable=False, server_default='system'),
        sa.Column('correlation_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=True),
    )

    # 5. Indexes for efficient tenant filtering
    op.create_index('ix_findings_org', 'vulnerability_findings', ['organization_id'])
    op.create_index('ix_findings_target', 'vulnerability_findings', ['target_id'])
    op.create_index('ix_findings_status', 'vulnerability_findings', ['organization_id', 'status'])
    op.create_index('ix_proposals_org', 'remediation_proposals', ['organization_id'])
    op.create_index('ix_proposals_finding', 'remediation_proposals', ['finding_id'])
    op.create_index('ix_attempts_org', 'remediation_attempts', ['organization_id'])
    op.create_index('ix_attempts_finding', 'remediation_attempts', ['finding_id'])
    op.create_index('ix_attempts_status', 'remediation_attempts', ['organization_id', 'status'])
    op.create_index('ix_verifications_org', 'remediation_verifications', ['organization_id'])
    op.create_index('ix_verifications_finding', 'remediation_verifications', ['finding_id'])
    op.create_index('ix_audit_org', 'remediation_audit_events', ['organization_id'])
    op.create_index('ix_audit_entity', 'remediation_audit_events', ['entity_type', 'entity_id'])
    op.create_index('ix_audit_correlation', 'remediation_audit_events', ['correlation_id'])
    op.create_index('ix_audit_timestamp', 'remediation_audit_events', ['organization_id', 'timestamp'])


def downgrade() -> None:
    op.drop_table('remediation_audit_events')
    op.drop_table('remediation_verifications')

    with op.batch_alter_table('remediation_attempts') as batch_op:
        batch_op.drop_column('files_changed')
        batch_op.drop_column('rollback_status')
        batch_op.drop_column('failure_reason')
        batch_op.drop_column('end_time')
        batch_op.drop_column('start_time')
        batch_op.drop_column('status')
        batch_op.drop_column('organization_id')

    with op.batch_alter_table('remediation_proposals') as batch_op:
        batch_op.drop_column('status')
        batch_op.drop_column('target_id')
