"""Application Remediation Schema: Branch 2 tables for vulnerability remediation pipeline

Revision ID: 002_application_remediation
Revises: 001_reconciliation
Create Date: 2026-08-19

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '002_application_remediation'
down_revision: Union[str, None] = '001_reconciliation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. application_targets table
    op.create_table(
        'application_targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('target_type', sa.String(), nullable=False, server_default='dockerized'),
        sa.Column('environment', sa.String(), nullable=False, server_default='lab'),
        sa.Column('repository_url', sa.String(), nullable=True),
        sa.Column('commit_sha', sa.String(), nullable=True),
        sa.Column('docker_image', sa.String(), nullable=True),
        sa.Column('docker_compose_path', sa.String(), nullable=True),
        sa.Column('local_path', sa.String(), nullable=True),
        sa.Column('owner_user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('authorized_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('authorization_expiry', sa.DateTime(), nullable=False),
        sa.Column('allowed_technique_ids', sa.Text(), nullable=True),
        sa.Column('max_risk_level', sa.String(), nullable=False, server_default='HIGH'),
        sa.Column('network_isolated', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # 2. target_clones table
    op.create_table(
        'target_clones',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('source_target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('application_targets.id'), nullable=False),
        sa.Column('source_revision', sa.String(), nullable=False),
        sa.Column('clone_type', sa.String(), nullable=False, server_default='dockerized'),
        sa.Column('docker_container_name', sa.String(), nullable=True),
        sa.Column('docker_network', sa.String(), nullable=True),
        sa.Column('filesystem_path', sa.String(), nullable=True),
        sa.Column('network_isolated', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('max_cpu_seconds', sa.Integer(), nullable=False, server_default=sa.text('120')),
        sa.Column('max_memory_mb', sa.Integer(), nullable=False, server_default=sa.text('512')),
        sa.Column('max_disk_mb', sa.Integer(), nullable=False, server_default=sa.text('1024')),
        sa.Column('secrets_injected', sa.Text(), nullable=True),
        sa.Column('original_secrets_excluded', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('current_version', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.Column('snapshot_ids', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='CREATING'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('cleanup_status', sa.String(), nullable=False, server_default='PENDING'),
    )

    # 3. clone_snapshots table
    op.create_table(
        'clone_snapshots',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('clone_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('target_clones.id'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.Column('snapshot_type', sa.String(), nullable=False),
        sa.Column('file_hashes', sa.Text(), nullable=False, server_default='{}'),
        sa.Column('container_snapshot_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
    )

    # 4. vulnerability_findings table
    op.create_table(
        'vulnerability_findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('application_targets.id'), nullable=False),
        sa.Column('exercise_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('exercises.id'), nullable=True),
        sa.Column('scenario_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('attack_technique_id', sa.String(), nullable=False),
        sa.Column('vulnerability_category', sa.String(), nullable=False),
        sa.Column('affected_component', sa.String(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False, server_default='MEDIUM'),
        sa.Column('confidence', sa.String(), nullable=False, server_default='SUSPECTED'),
        sa.Column('root_cause_hypothesis', sa.Text(), nullable=True),
        sa.Column('reproduction_info', sa.Text(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='OPEN'),
        sa.Column('remediation_status', sa.String(), nullable=False, server_default='OPEN'),
        sa.Column('iteration_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('max_iterations', sa.Integer(), nullable=False, server_default=sa.text('3')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('provenance', sa.Text(), nullable=True),
    )

    # 5. remediation_proposals table
    op.create_table(
        'remediation_proposals',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('vulnerability_findings.id'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('root_cause', sa.Text(), nullable=False),
        sa.Column('proposed_remediation', sa.Text(), nullable=False),
        sa.Column('affected_files', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('patches', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('expected_security_effect', sa.Text(), nullable=False),
        sa.Column('expected_behavior', sa.Text(), nullable=False),
        sa.Column('test_plan', sa.Text(), nullable=False),
        sa.Column('rollback_plan', sa.Text(), nullable=False),
        sa.Column('risk_assessment', sa.Text(), nullable=False),
        sa.Column('schema_validated', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('policy_validated', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('clone_validated', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('provenance', sa.Text(), nullable=True),
    )

    # 6. remediation_attempts table
    op.create_table(
        'remediation_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('vulnerability_findings.id'), nullable=False),
        sa.Column('proposal_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_proposals.id'), nullable=False),
        sa.Column('clone_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('target_clones.id'), nullable=False),
        sa.Column('snapshot_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('changes_applied', sa.Boolean(), nullable=True),
        sa.Column('build_passed', sa.Boolean(), nullable=True),
        sa.Column('tests_passed', sa.Boolean(), nullable=True),
        sa.Column('behavior_preserved', sa.Boolean(), nullable=True),
        sa.Column('build_output', sa.Text(), nullable=True),
        sa.Column('test_output', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('provenance', sa.Text(), nullable=True),
    )

    # 7. remediation_retest_results table
    op.create_table(
        'remediation_retest_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('vulnerability_findings.id'), nullable=False),
        sa.Column('proposal_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_proposals.id'), nullable=False),
        sa.Column('clone_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('target_clones.id'), nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('original_attack_blocked', sa.Boolean(), nullable=False),
        sa.Column('original_attack_evidence', sa.Text(), nullable=True),
        sa.Column('variants_tested', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('variants_blocked', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('variant_details', sa.Text(), nullable=True),
        sa.Column('regression_tests_passed', sa.Boolean(), nullable=True),
        sa.Column('application_functional', sa.Boolean(), nullable=True),
        sa.Column('vulnerability_eliminated', sa.Boolean(), nullable=False),
        sa.Column('retest_outcome', sa.String(), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('provenance', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('remediation_retest_results')
    op.drop_table('remediation_attempts')
    op.drop_table('remediation_proposals')
    op.drop_table('vulnerability_findings')
    op.drop_table('clone_snapshots')
    op.drop_table('target_clones')
    op.drop_table('application_targets')
