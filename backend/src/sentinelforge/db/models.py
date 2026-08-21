from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Integer, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

Base = declarative_base()

class Organization(Base):
    __tablename__ = 'organizations'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)

class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    username = Column(String, nullable=False)

class Environment(Base):
    __tablename__ = 'environments'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    name = Column(String, nullable=False)

class Exercise(Base):
    __tablename__ = 'exercises'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    environment_id = Column(UUID(as_uuid=True), ForeignKey('environments.id'), nullable=True)
    state = Column(String, nullable=False, default="CREATED")

class SecurityObjectiveRecord(Base):
    __tablename__ = 'security_objectives'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    target_category = Column(String, nullable=False, default="linux_host")
    default_risk_level = Column(String, nullable=False, default="MEDIUM")
    created_at = Column(DateTime, default=datetime.utcnow)

class AdversarialScenarioRecord(Base):
    __tablename__ = 'adversarial_scenarios'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    objective_id = Column(UUID(as_uuid=True), ForeignKey('security_objectives.id'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    title = Column(String, nullable=False)
    strategy_description = Column(Text, nullable=False)
    proposed_risk_level = Column(String, nullable=False, default="MEDIUM")
    created_by = Column(String, nullable=False, default="red_agent")
    created_at = Column(DateTime, default=datetime.utcnow)

class ExecutionPlanRecord(Base):
    __tablename__ = 'execution_plans'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario_id = Column(UUID(as_uuid=True), ForeignKey('adversarial_scenarios.id'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    steps_description = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="DRAFT")
    created_at = Column(DateTime, default=datetime.utcnow)

class PolicyDecisionRecord(Base):
    __tablename__ = 'policy_decisions'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    scenario_id = Column(UUID(as_uuid=True), ForeignKey('adversarial_scenarios.id'), nullable=True)
    blueprint_id = Column(UUID(as_uuid=True), nullable=True)
    status = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    evaluated_at = Column(DateTime, default=datetime.utcnow)

class SimulationResult(Base):
    __tablename__ = 'simulation_results'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    blueprint_id = Column(UUID(as_uuid=True), unique=True, nullable=False)
    action_id = Column(UUID(as_uuid=True), nullable=False)
    status = Column(String, nullable=False)

class RetestResult(Base):
    __tablename__ = 'retest_results'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    exercise_id = Column(UUID(as_uuid=True), ForeignKey('exercises.id'), nullable=True)
    scenario_id = Column(UUID(as_uuid=True), nullable=True)
    before_outcome = Column(String, nullable=True)
    after_outcome = Column(String, nullable=True)
    detection_improved = Column(String, nullable=False)
    validated_rule_ids = Column(Text, nullable=True)
    evaluated_at = Column(DateTime, default=datetime.utcnow)

class DetectionGapRecord(Base):
    __tablename__ = 'detection_gaps'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    scenario_id = Column(UUID(as_uuid=True), nullable=False)
    action_id = Column(UUID(as_uuid=True), nullable=False)
    technique_id = Column(String, nullable=False)
    original_outcome = Column(String, nullable=False)
    evidence_event_ids = Column(Text, nullable=True)
    matched_rule_ids = Column(Text, nullable=True)
    root_cause = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    remediation_status = Column(String, nullable=False, default="OPEN")
    retest_id = Column(UUID(as_uuid=True), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    action = Column(String, nullable=False)
    blueprint_id = Column(UUID(as_uuid=True), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class NormalizedEvent(Base):
    __tablename__ = 'normalized_events'
    # event_id acts as primary key for idempotency guarantee
    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    correlation_id = Column(UUID(as_uuid=True), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    process_name = Column(String, nullable=False)
    executable = Column(String, nullable=True)
    command_line = Column(String, nullable=False)
    user_name = Column(String, nullable=False)
    user_uid = Column(Integer, nullable=False)
    target_file = Column(String, nullable=True)
    container_name = Column(String, nullable=False)
    raw_event_hash = Column(String, nullable=False)

class DetectionResult(Base):
    __tablename__ = 'detection_results'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detection_id = Column(UUID(as_uuid=True), unique=True, nullable=False)
    correlation_id = Column(UUID(as_uuid=True), nullable=True)
    simulation_id = Column(UUID(as_uuid=True), nullable=True)
    action_id = Column(UUID(as_uuid=True), nullable=True)
    exercise_id = Column(UUID(as_uuid=True), nullable=True)
    technique_id = Column(String, nullable=False)
    rule_id = Column(String, nullable=False)
    matched = Column(Boolean, nullable=False)
    outcome = Column(String, nullable=False) # DETECTED, NOT_DETECTED, DETECTION_GAP, EVENT_NO_MATCH
    timestamp = Column(DateTime, nullable=False)
    source = Column(String, nullable=False)

class RedAgentStrategyRecord(Base):
    """Strategic memory record for Red Agent strategy fingerprint tracking.

    Tenant isolation is enforced by the mandatory `organization_id` column.
    The `fingerprint_hash` is the deterministic composite hash produced by
    StrategyFingerprint.create(); it is used by NoveltyEvaluator to skip
    DUPLICATE/SIMILAR proposals before they reach the safety boundary.
    """
    __tablename__ = 'red_agent_strategies'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    objective_id = Column(UUID(as_uuid=True), nullable=False)
    scenario_id = Column(UUID(as_uuid=True), nullable=False)
    technique_id = Column(String, nullable=False)
    fingerprint_hash = Column(String, nullable=False, index=True)
    command_pattern = Column(Text, nullable=False)
    outcome = Column(String, nullable=True)  # ALLOWED, DENIED, EXECUTED, DETECTED, DETECTION_GAP, NOT_DETECTED
    created_at = Column(DateTime, default=datetime.utcnow)

class PurpleEvaluationRecord(Base):
    """Persistent Purple Evaluation record — one per experiment/scenario.

    Tenant isolation is enforced by the mandatory `organization_id` column.
    Stores the deterministic detection verdict produced by PurpleEvaluator.
    """
    __tablename__ = 'purple_evaluations'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    experiment_id = Column(UUID(as_uuid=True), nullable=False)
    execution_id = Column(UUID(as_uuid=True), nullable=True)
    technique_id = Column(String, nullable=False)
    detection_status = Column(String, nullable=False)  # DETECTED, NOT_DETECTED, DETECTION_GAP
    matched_rule_ids = Column(Text, nullable=True)     # JSON list
    evidence_event_ids = Column(Text, nullable=True)   # JSON list
    expected_detection = Column(Boolean, nullable=False, default=False)
    gap_reason = Column(Text, nullable=True)
    detection_latency_ms = Column(Integer, nullable=True)
    evaluated_at = Column(DateTime, default=datetime.utcnow)

