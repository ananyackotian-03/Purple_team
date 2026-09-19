"""Digital Twin Database Models.

Lightweight security Digital Twin foundation representing an organization's
current known security state. All entities are tenant-scoped via organization_id.

SECURITY INVARIANTS:
- Every entity has organization_id FK for tenant isolation
- LLM cannot directly mutate these tables (only service layer can)
- State is derived from persisted evidence, not LLM claims
- All mutations go through the service layer with validation
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Integer, Text, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

from sentinelforge.db.models import Base


class DigitalTwinAsset(Base):
    """Represents a physical or logical asset in the organization's Digital Twin.
    
    Assets are the foundational elements - hosts, containers, services, etc.
    Each asset is tenant-scoped and cannot be accessed across organizations.
    """
    __tablename__ = 'digital_twin_assets'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    
    # Asset identity
    name = Column(String, nullable=False)
    asset_type = Column(String, nullable=False)  # host, container, service, database, network, application
    description = Column(Text, nullable=True)
    
    # Asset configuration
    operating_system = Column(String, nullable=True)
    software_version = Column(String, nullable=True)
    network_segment = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    
    # Security-relevant state
    risk_level = Column(String, nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    is_active = Column(Boolean, nullable=False, default=True)
    last_scanned_at = Column(DateTime, nullable=True)
    
    # Metadata
    tags = Column(JSON, nullable=True, default=list)  # List of string tags
    metadata_json = Column(JSON, nullable=True, default=dict)
    
    # Audit
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    services = relationship("DigitalTwinService", back_populates="asset", cascade="all, delete-orphan")
    security_controls = relationship("DigitalTwinAssetControl", back_populates="asset", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<DigitalTwinAsset {self.name} ({self.asset_type})>"


class DigitalTwinService(Base):
    """Represents a service or application running on an asset.
    
    Services represent the logical workloads running in the environment.
    Each service is linked to exactly one asset via asset_id.
    """
    __tablename__ = 'digital_twin_services'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_assets.id'), nullable=False, index=True)
    
    # Service identity
    name = Column(String, nullable=False)
    service_type = Column(String, nullable=False)  # web_app, api, database, worker, cron, etc.
    description = Column(Text, nullable=True)
    
    # Service configuration
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)  # http, https, tcp, udp
    version = Column(String, nullable=True)
    technology_stack = Column(JSON, nullable=True, default=list)  # List of technologies
    
    # Security-relevant state
    risk_level = Column(String, nullable=False, default="MEDIUM")
    is_internet_facing = Column(Boolean, nullable=False, default=False)
    has_authentication = Column(Boolean, nullable=False, default=True)
    has_encryption = Column(Boolean, nullable=False, default=True)
    last_tested_at = Column(DateTime, nullable=True)
    
    # Detection coverage
    detection_rules_count = Column(Integer, nullable=False, default=0)
    coverage_pct = Column(Float, nullable=False, default=0.0)
    
    # Metadata
    metadata_json = Column(JSON, nullable=True, default=dict)
    
    # Audit
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset = relationship("DigitalTwinAsset", back_populates="services")
    security_controls = relationship("DigitalTwinServiceControl", back_populates="service", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<DigitalTwinService {self.name} ({self.service_type})>"


class DigitalTwinSecurityControl(Base):
    """Represents a security control in the organization's Digital Twin.
    
    Security controls are standalone entities that can be associated with
    assets and services. They represent firewalls, IDS, SIEM, etc.
    """
    __tablename__ = 'digital_twin_security_controls'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    
    # Control identity
    name = Column(String, nullable=False)
    control_type = Column(String, nullable=False)  # firewall, ids, siem, edr, waf, etc.
    description = Column(Text, nullable=True)
    
    # Control configuration
    enabled = Column(Boolean, nullable=False, default=True)
    version = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    
    # Coverage
    technique_ids = Column(JSON, nullable=True, default=list)  # MITRE ATT&CK techniques covered
    coverage_description = Column(Text, nullable=True)
    
    # Validation state
    last_validated_at = Column(DateTime, nullable=True)
    validation_status = Column(String, nullable=False, default="UNTESTED")  # UNTESTED, PASSED, FAILED
    
    # Metadata
    metadata_json = Column(JSON, nullable=True, default=dict)
    
    # Audit
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset_controls = relationship("DigitalTwinAssetControl", back_populates="control", cascade="all, delete-orphan")
    service_controls = relationship("DigitalTwinServiceControl", back_populates="control", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<DigitalTwinSecurityControl {self.name} ({self.control_type})>"


class DigitalTwinAssetControl(Base):
    """Association between assets and security controls.
    
    This is a many-to-many relationship with additional metadata about
    when the control was applied to the asset.
    """
    __tablename__ = 'digital_twin_asset_controls'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_assets.id'), nullable=False, index=True)
    control_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_security_controls.id'), nullable=False, index=True)
    
    # Association metadata
    applied_at = Column(DateTime, default=datetime.utcnow)
    applied_by = Column(String, nullable=True)  # System, user, or process
    configuration_json = Column(JSON, nullable=True, default=dict)
    
    # Validation
    last_tested_at = Column(DateTime, nullable=True)
    test_result = Column(String, nullable=True)  # PASSED, FAILED, SKIPPED
    
    # Relationships
    asset = relationship("DigitalTwinAsset", back_populates="security_controls")
    control = relationship("DigitalTwinSecurityControl", back_populates="asset_controls")
    
    def __repr__(self):
        return f"<DigitalTwinAssetControl asset={self.asset_id} control={self.control_id}>"


class DigitalTwinServiceControl(Base):
    """Association between services and security controls.
    
    This is a many-to-many relationship with additional metadata about
    how the control protects the service.
    """
    __tablename__ = 'digital_twin_service_controls'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    service_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_services.id'), nullable=False, index=True)
    control_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_security_controls.id'), nullable=False, index=True)
    
    # Association metadata
    applied_at = Column(DateTime, default=datetime.utcnow)
    protection_level = Column(String, nullable=True)  # full, partial, monitoring
    
    # Validation
    last_tested_at = Column(DateTime, nullable=True)
    test_result = Column(String, nullable=True)  # PASSED, FAILED, SKIPPED
    
    # Relationships
    service = relationship("DigitalTwinService", back_populates="security_controls")
    control = relationship("DigitalTwinSecurityControl", back_populates="service_controls")
    
    def __repr__(self):
        return f"<DigitalTwinServiceControl service={self.service_id} control={self.control_id}>"


class DigitalTwinDetectionCoverage(Base):
    """Tracks detection coverage for specific techniques on assets/services.
    
    This represents the organization's belief about what is detected,
    derived from actual experiment results (not LLM claims).
    """
    __tablename__ = 'digital_twin_detection_coverage'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    
    # What is being covered
    asset_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_assets.id'), nullable=True, index=True)
    service_id = Column(UUID(as_uuid=True), ForeignKey('digital_twin_services.id'), nullable=True, index=True)
    technique_id = Column(String, nullable=False, index=True)
    
    # Coverage state
    is_detected = Column(Boolean, nullable=False, default=False)
    detection_method = Column(String, nullable=True)  # sigma, yara, custom, etc.
    rule_ids = Column(JSON, nullable=True, default=list)  # Detection rule IDs
    
    # Evidence
    last_experiment_id = Column(UUID(as_uuid=True), nullable=True)
    last_detected_at = Column(DateTime, nullable=True)
    confidence_score = Column(Float, nullable=False, default=0.0)  # 0.0 to 1.0
    
    # Metadata
    metadata_json = Column(JSON, nullable=True, default=dict)
    
    # Audit
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<DigitalTwinDetectionCoverage technique={self.technique_id} detected={self.is_detected}>"


class DigitalTwinSecurityPosture(Base):
    """Periodic snapshot of the organization's security posture.
    
    This provides time-series data for tracking security posture trends.
    Each record is a point-in-time snapshot derived from actual evidence.
    """
    __tablename__ = 'digital_twin_security_posture'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False, index=True)
    
    # Posture metrics
    total_assets = Column(Integer, nullable=False, default=0)
    active_assets = Column(Integer, nullable=False, default=0)
    total_services = Column(Integer, nullable=False, default=0)
    internet_facing_services = Column(Integer, nullable=False, default=0)
    total_security_controls = Column(Integer, nullable=False, default=0)
    enabled_controls = Column(Integer, nullable=False, default=0)
    
    # Coverage metrics
    total_techniques_tested = Column(Integer, nullable=False, default=0)
    techniques_detected = Column(Integer, nullable=False, default=0)
    detection_coverage_pct = Column(Float, nullable=False, default=0.0)
    
    # Risk metrics
    high_risk_assets = Column(Integer, nullable=False, default=0)
    critical_risk_assets = Column(Integer, nullable=False, default=0)
    unresolved_gaps = Column(Integer, nullable=False, default=0)
    
    # Experiment metrics
    total_experiments = Column(Integer, nullable=False, default=0)
    successful_experiments = Column(Integer, nullable=False, default=0)
    failed_experiments = Column(Integer, nullable=False, default=0)
    
    # Snapshot metadata
    snapshot_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    computed_from_evidence = Column(Boolean, nullable=False, default=True)
    
    def __repr__(self):
        return f"<DigitalTwinSecurityPosture {self.snapshot_date} coverage={self.detection_coverage_pct}%>"
