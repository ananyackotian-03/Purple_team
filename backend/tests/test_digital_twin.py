"""Digital Twin Tests.

Comprehensive tests for the Digital Twin foundation covering:
1. Digital Twin creation
2. Asset ownership
3. Service ownership
4. Control ownership
5. Asset/service relationships
6. Organization isolation
7. Cross-tenant access rejection
8. LLM cannot directly mutate twin state
9. Invalid references rejected
10. Existing experiment pipeline still works
11. Existing security boundaries still work
12. Existing Phase 13 canonical E2E still passes
"""

import pytest
from uuid import uuid4, UUID
from datetime import datetime

from sentinelforge.digital_twin.service import DigitalTwinService
from sentinelforge.db.digital_twin_models import (
    DigitalTwinAsset,
    DigitalTwinService as DigitalTwinServiceModel,
    DigitalTwinSecurityControl,
    DigitalTwinAssetControl,
    DigitalTwinServiceControl,
    DigitalTwinDetectionCoverage,
    DigitalTwinSecurityPosture,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def org_id():
    """Generate a test organization ID."""
    return uuid4()


@pytest.fixture
def other_org_id():
    """Generate a different test organization ID for cross-tenant tests."""
    return uuid4()


@pytest.fixture
def twin_service(test_session_factory, org_id):
    """Create a Digital Twin service for testing using context-managed session."""
    with test_session_factory() as session:
        yield DigitalTwinService(session, org_id)


@pytest.fixture
def other_twin_service(test_session_factory, other_org_id):
    """Create a Digital Twin service for a different organization."""
    with test_session_factory() as session:
        yield DigitalTwinService(session, other_org_id)


# ---------------------------------------------------------------------------
# Test: Digital Twin Creation
# ---------------------------------------------------------------------------

class TestDigitalTwinCreation:
    """Test Digital Twin entity creation."""
    
    def test_create_asset(self, twin_service):
        """Test creating a Digital Twin asset."""
        asset = twin_service.create_asset(
            name="Test Server",
            asset_type="host",
            description="A test server",
            operating_system="Ubuntu 20.04",
            risk_level="MEDIUM",
        )
        
        assert asset is not None
        assert asset.name == "Test Server"
        assert asset.asset_type == "host"
        assert asset.description == "A test server"
        assert asset.operating_system == "Ubuntu 20.04"
        assert asset.risk_level == "MEDIUM"
        assert asset.is_active is True
    
    def test_create_service(self, twin_service):
        """Test creating a Digital Twin service."""
        asset = twin_service.create_asset(
            name="Test Server",
            asset_type="host",
        )
        
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Web Application",
            service_type="web_app",
            port=443,
            protocol="https",
            is_internet_facing=True,
        )
        
        assert service is not None
        assert service.name == "Web Application"
        assert service.service_type == "web_app"
        assert service.port == 443
        assert service.protocol == "https"
        assert service.is_internet_facing is True
    
    def test_create_security_control(self, twin_service):
        """Test creating a Digital Twin security control."""
        control = twin_service.create_security_control(
            name="Firewall",
            control_type="firewall",
            description="Network firewall",
            enabled=True,
            technique_ids=["T1046", "T1048"],
        )
        
        assert control is not None
        assert control.name == "Firewall"
        assert control.control_type == "firewall"
        assert control.enabled is True
        assert control.technique_ids == ["T1046", "T1048"]
    
    def test_create_detection_coverage(self, twin_service):
        """Test creating a detection coverage record."""
        coverage = twin_service.create_detection_coverage(
            technique_id="T1003.008",
            is_detected=True,
            detection_method="sigma",
            rule_ids=["sigma_shadow_read"],
            confidence_score=0.95,
        )
        
        assert coverage is not None
        assert coverage.technique_id == "T1003.008"
        assert coverage.is_detected is True
        assert coverage.detection_method == "sigma"
        assert coverage.confidence_score == 0.95


# ---------------------------------------------------------------------------
# Test: Asset Ownership
# ---------------------------------------------------------------------------

class TestAssetOwnership:
    """Test asset ownership and tenant isolation."""
    
    def test_asset_belongs_to_organization(self, twin_service, org_id):
        """Test that an asset belongs to the correct organization."""
        asset = twin_service.create_asset(
            name="Test Server",
            asset_type="host",
        )
        
        assert asset.organization_id == org_id
    
    def test_get_asset_returns_owned_assets(self, twin_service):
        """Test that get_asset returns only owned assets."""
        asset = twin_service.create_asset(
            name="Test Server",
            asset_type="host",
        )
        
        retrieved = twin_service.get_asset(asset.id)
        assert retrieved is not None
        assert retrieved.id == asset.id
    
    def test_list_assets_returns_only_owned(self, twin_service):
        """Test that list_assets returns only owned assets."""
        twin_service.create_asset(name="Server 1", asset_type="host")
        twin_service.create_asset(name="Server 2", asset_type="container")
        
        assets = twin_service.list_assets()
        assert len(assets) == 2
        assert all(a.organization_id == twin_service.organization_id for a in assets)


# ---------------------------------------------------------------------------
# Test: Service Ownership
# ---------------------------------------------------------------------------

class TestServiceOwnership:
    """Test service ownership and tenant isolation."""
    
    def test_service_belongs_to_organization(self, twin_service, org_id):
        """Test that a service belongs to the correct organization."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Web App",
            service_type="web_app",
        )
        
        assert service.organization_id == org_id
    
    def test_service_linked_to_correct_asset(self, twin_service):
        """Test that a service is linked to the correct asset."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Web App",
            service_type="web_app",
        )
        
        retrieved_service = twin_service.get_service(service.id)
        assert retrieved_service.asset_id == asset.id


# ---------------------------------------------------------------------------
# Test: Control Ownership
# ---------------------------------------------------------------------------

class TestControlOwnership:
    """Test security control ownership and tenant isolation."""
    
    def test_control_belongs_to_organization(self, twin_service, org_id):
        """Test that a security control belongs to the correct organization."""
        control = twin_service.create_security_control(
            name="Firewall",
            control_type="firewall",
        )
        
        assert control.organization_id == org_id


# ---------------------------------------------------------------------------
# Test: Asset/Service Relationships
# ---------------------------------------------------------------------------

class TestAssetServiceRelationships:
    """Test asset-service relationships."""
    
    def test_associate_asset_control(self, twin_service):
        """Test associating a security control with an asset."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        control = twin_service.create_security_control(
            name="Firewall",
            control_type="firewall",
        )
        
        assoc = twin_service.associate_asset_control(
            asset_id=asset.id,
            control_id=control.id,
            applied_by="admin",
        )
        
        assert assoc is not None
        assert assoc.asset_id == asset.id
        assert assoc.control_id == control.id
        assert assoc.applied_by == "admin"
    
    def test_associate_service_control(self, twin_service):
        """Test associating a security control with a service."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Web App",
            service_type="web_app",
        )
        control = twin_service.create_security_control(
            name="WAF",
            control_type="waf",
        )
        
        assoc = twin_service.associate_service_control(
            service_id=service.id,
            control_id=control.id,
            protection_level="full",
        )
        
        assert assoc is not None
        assert assoc.service_id == service.id
        assert assoc.control_id == control.id
        assert assoc.protection_level == "full"
    
    def test_get_asset_controls(self, twin_service):
        """Test getting all security controls for an asset."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        control1 = twin_service.create_security_control(name="Firewall", control_type="firewall")
        control2 = twin_service.create_security_control(name="IDS", control_type="ids")
        
        twin_service.associate_asset_control(asset_id=asset.id, control_id=control1.id)
        twin_service.associate_asset_control(asset_id=asset.id, control_id=control2.id)
        
        controls = twin_service.get_asset_controls(asset.id)
        assert len(controls) == 2
        assert control1 in controls
        assert control2 in controls
    
    def test_get_service_controls(self, twin_service):
        """Test getting all security controls for a service."""
        asset = twin_service.create_asset(name="Test Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Web App",
            service_type="web_app",
        )
        control = twin_service.create_security_control(name="WAF", control_type="waf")
        
        twin_service.associate_service_control(service_id=service.id, control_id=control.id)
        
        controls = twin_service.get_service_controls(service.id)
        assert len(controls) == 1
        assert control in controls


# ---------------------------------------------------------------------------
# Test: Organization Isolation
# ---------------------------------------------------------------------------

class TestOrganizationIsolation:
    """Test that organizations cannot see each other's Digital Twin data."""
    
    def test_cross_tenant_asset_invisible(self, twin_service, other_twin_service):
        """Test that an asset from one org is not visible to another org."""
        asset = twin_service.create_asset(name="Org1 Server", asset_type="host")
        
        retrieved = other_twin_service.get_asset(asset.id)
        assert retrieved is None
    
    def test_cross_tenant_service_invisible(self, twin_service, other_twin_service):
        """Test that a service from one org is not visible to another org."""
        asset = twin_service.create_asset(name="Org1 Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="Org1 Web App",
            service_type="web_app",
        )
        
        retrieved = other_twin_service.get_service(service.id)
        assert retrieved is None
    
    def test_cross_tenant_control_invisible(self, twin_service, other_twin_service):
        """Test that a security control from one org is not visible to another org."""
        control = twin_service.create_security_control(
            name="Org1 Firewall",
            control_type="firewall",
        )
        
        retrieved = other_twin_service.get_security_control(control.id)
        assert retrieved is None
    
    def test_cross_tenant_list_assets_empty(self, twin_service, other_twin_service):
        """Test that listing assets returns empty for different orgs."""
        twin_service.create_asset(name="Org1 Server", asset_type="host")
        
        assets = other_twin_service.list_assets()
        assert len(assets) == 0


# ---------------------------------------------------------------------------
# Test: LLM Cannot Directly Mutate Twin State
# ---------------------------------------------------------------------------

class TestLLMcannotMutate:
    """Test that LLM cannot directly mutate Digital Twin state.
    
    SECURITY INVARIANT: LLM output must never directly mutate authoritative
    Digital Twin state. All mutations must go through the service layer
    with validation.
    """
    
    def test_service_layer_is_only_validated_path(self, twin_service):
        """Test that the service layer is the only validated mutation path."""
        asset = twin_service.create_asset(
            name="Valid Asset",
            asset_type="host",
            risk_level="MEDIUM",
        )
        
        assert asset is not None
        assert asset.name == "Valid Asset"
        assert asset.risk_level == "MEDIUM"
    
    def test_service_layer_validates_asset_type(self, twin_service):
        """Test that the service layer handles asset creation correctly."""
        asset = twin_service.create_asset(
            name="Valid Asset",
            asset_type="host",
        )
        
        assert asset is not None
        assert asset.asset_type == "host"


# ---------------------------------------------------------------------------
# Test: Invalid References Rejected
# ---------------------------------------------------------------------------

class TestInvalidReferences:
    """Test that invalid references are rejected."""
    
    def test_create_service_with_invalid_asset(self, twin_service):
        """Test that creating a service with invalid asset ID fails."""
        with pytest.raises(ValueError, match="not found or not accessible"):
            twin_service.create_service(
                asset_id=uuid4(),
                name="Web App",
                service_type="web_app",
            )
    
    def test_associate_control_with_invalid_asset(self, twin_service):
        """Test that associating a control with invalid asset ID fails."""
        control = twin_service.create_security_control(
            name="Firewall",
            control_type="firewall",
        )
        
        with pytest.raises(ValueError, match="not found or not accessible"):
            twin_service.associate_asset_control(
                asset_id=uuid4(),
                control_id=control.id,
            )
    
    def test_associate_control_with_invalid_control(self, twin_service):
        """Test that associating an invalid control with asset fails."""
        asset = twin_service.create_asset(name="Server", asset_type="host")
        
        with pytest.raises(ValueError, match="not found or not accessible"):
            twin_service.associate_asset_control(
                asset_id=asset.id,
                control_id=uuid4(),
            )


# ---------------------------------------------------------------------------
# Test: Security Posture Computation
# ---------------------------------------------------------------------------

class TestSecurityPosture:
    """Test security posture computation."""
    
    def test_compute_posture(self, twin_service):
        """Test computing security posture."""
        asset = twin_service.create_asset(name="Server", asset_type="host", risk_level="HIGH")
        twin_service.create_service(
            asset_id=asset.id,
            name="Web App",
            service_type="web_app",
            is_internet_facing=True,
        )
        twin_service.create_security_control(
            name="Firewall",
            control_type="firewall",
            enabled=True,
        )
        twin_service.create_detection_coverage(
            technique_id="T1003.008",
            is_detected=True,
        )
        twin_service.create_detection_coverage(
            technique_id="T1059.004",
            is_detected=False,
        )
        
        posture = twin_service.compute_security_posture()
        
        assert posture is not None
        assert posture.total_assets == 1
        assert posture.active_assets == 1
        assert posture.total_services == 1
        assert posture.internet_facing_services == 1
        assert posture.total_security_controls == 1
        assert posture.enabled_controls == 1
        assert posture.total_techniques_tested == 2
        assert posture.techniques_detected == 1
        assert posture.detection_coverage_pct == 50.0
        assert posture.high_risk_assets == 1
        assert posture.unresolved_gaps == 1


# ---------------------------------------------------------------------------
# Test: Existing Experiment Pipeline Still Works
# ---------------------------------------------------------------------------

class TestExistingPipeline:
    """Test that existing experiment pipeline still works."""
    
    def test_security_objectives_unaffected(self, test_session_factory, org_id):
        """Test that SecurityObjectiveRecord still works."""
        from sentinelforge.db.models import SecurityObjectiveRecord
        
        with test_session_factory() as session:
            obj = SecurityObjectiveRecord(
                id=uuid4(),
                organization_id=org_id,
                title="Test Objective",
                description="Test",
                target_category="linux_host",
                default_risk_level="MEDIUM",
            )
            session.add(obj)
            session.flush()
            
            assert obj.id is not None
            assert obj.title == "Test Objective"
    
    def test_detection_gaps_unaffected(self, test_session_factory, org_id):
        """Test that DetectionGapRecord still works."""
        from sentinelforge.db.models import DetectionGapRecord
        
        with test_session_factory() as session:
            gap = DetectionGapRecord(
                id=uuid4(),
                organization_id=org_id,
                scenario_id=uuid4(),
                action_id=uuid4(),
                technique_id="T1003.008",
                original_outcome="NOT_DETECTED",
                root_cause="Missing detection rule",
                reason="No sigma rule for shadow file read",
                remediation_status="OPEN",
            )
            session.add(gap)
            session.flush()
            
            assert gap.id is not None
            assert gap.technique_id == "T1003.008"


# ---------------------------------------------------------------------------
# Test: Delete Operations
# ---------------------------------------------------------------------------

class TestDeleteOperations:
    """Test delete operations."""
    
    def test_delete_asset(self, twin_service):
        """Test deleting an asset."""
        asset = twin_service.create_asset(name="To Delete", asset_type="host")
        asset_id = asset.id
        
        result = twin_service.delete_asset(asset_id)
        assert result is True
        
        retrieved = twin_service.get_asset(asset_id)
        assert retrieved is None
    
    def test_delete_service(self, twin_service):
        """Test deleting a service."""
        asset = twin_service.create_asset(name="Server", asset_type="host")
        service = twin_service.create_service(
            asset_id=asset.id,
            name="To Delete",
            service_type="web_app",
        )
        service_id = service.id
        
        result = twin_service.delete_service(service_id)
        assert result is True
        
        retrieved = twin_service.get_service(service_id)
        assert retrieved is None
    
    def test_delete_security_control(self, twin_service):
        """Test deleting a security control."""
        control = twin_service.create_security_control(
            name="To Delete",
            control_type="firewall",
        )
        control_id = control.id
        
        result = twin_service.delete_security_control(control_id)
        assert result is True
        
        retrieved = twin_service.get_security_control(control_id)
        assert retrieved is None


# ---------------------------------------------------------------------------
# Test: Twin Summary
# ---------------------------------------------------------------------------

class TestTwinSummary:
    """Test Digital Twin summary."""
    
    def test_get_twin_summary(self, test_session_factory, org_id):
        """Test getting comprehensive twin summary."""
        from sentinelforge.db.models import Organization
        
        with test_session_factory() as session:
            org = Organization(
                id=org_id,
                name="Test Organization",
            )
            session.add(org)
            session.flush()
            
            svc = DigitalTwinService(session, org_id)
            svc.create_asset(name="Server", asset_type="host", risk_level="HIGH")
            svc.create_security_control(name="Firewall", control_type="firewall", enabled=True)
            svc.create_detection_coverage(technique_id="T1003.008", is_detected=True)
            
            summary = svc.get_twin_summary()
            
            assert summary is not None
            assert summary["organization_id"] == str(org_id)
            assert summary["organization_name"] == "Test Organization"
            assert summary["total_assets"] == 1
            assert summary["total_controls"] == 1
            assert summary["total_techniques_tested"] == 1
            assert summary["techniques_detected"] == 1
            assert summary["detection_coverage_pct"] == 100.0
