"""Digital Twin Service Layer.

Provides CRUD operations and business logic for Digital Twin entities.
All operations are tenant-scoped via organization_id.

SECURITY INVARIANTS:
- All queries are filtered by organization_id
- LLM cannot directly call service methods (only API layer can)
- State derivation uses persisted evidence, not LLM claims
- All mutations are validated before persistence
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from sqlalchemy import func

from sentinelforge.db.digital_twin_models import (
    DigitalTwinAsset,
    DigitalTwinService as DigitalTwinServiceDB,
    DigitalTwinSecurityControl,
    DigitalTwinAssetControl,
    DigitalTwinServiceControl,
    DigitalTwinDetectionCoverage,
    DigitalTwinSecurityPosture,
)


class DigitalTwinService:
    """Service layer for Digital Twin operations.
    
    All methods are tenant-scoped via organization_id.
    No method accepts raw LLM output for state mutation.
    """
    
    def __init__(self, db_session: Session, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id
    
    # ------------------------------------------------------------------
    # Asset Operations
    # ------------------------------------------------------------------
    
    def create_asset(
        self,
        name: str,
        asset_type: str,
        description: str = "",
        operating_system: Optional[str] = None,
        software_version: Optional[str] = None,
        network_segment: Optional[str] = None,
        ip_address: Optional[str] = None,
        risk_level: str = "MEDIUM",
        tags: List[str] = None,
        metadata_json: Dict[str, Any] = None,
    ) -> DigitalTwinAsset:
        """Create a new Digital Twin asset."""
        asset = DigitalTwinAsset(
            id=uuid4(),
            organization_id=self.organization_id,
            name=name,
            asset_type=asset_type,
            description=description,
            operating_system=operating_system,
            software_version=software_version,
            network_segment=network_segment,
            ip_address=ip_address,
            risk_level=risk_level,
            tags=tags or [],
            metadata_json=metadata_json or {},
        )
        self.db_session.add(asset)
        self.db_session.flush()
        return asset
    
    def get_asset(self, asset_id: UUID) -> Optional[DigitalTwinAsset]:
        """Get a Digital Twin asset by ID (tenant-scoped)."""
        return self.db_session.query(DigitalTwinAsset).filter(
            DigitalTwinAsset.id == asset_id,
            DigitalTwinAsset.organization_id == self.organization_id,
        ).first()
    
    def list_assets(
        self,
        asset_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[DigitalTwinAsset]:
        """List all Digital Twin assets for this organization."""
        query = self.db_session.query(DigitalTwinAsset).filter(
            DigitalTwinAsset.organization_id == self.organization_id
        )
        if asset_type:
            query = query.filter(DigitalTwinAsset.asset_type == asset_type)
        if risk_level:
            query = query.filter(DigitalTwinAsset.risk_level == risk_level)
        if is_active is not None:
            query = query.filter(DigitalTwinAsset.is_active == is_active)
        return query.all()
    
    def update_asset(
        self,
        asset_id: UUID,
        **kwargs,
    ) -> Optional[DigitalTwinAsset]:
        """Update a Digital Twin asset."""
        asset = self.get_asset(asset_id)
        if not asset:
            return None
        for key, value in kwargs.items():
            if hasattr(asset, key) and value is not None:
                setattr(asset, key, value)
        asset.updated_at = datetime.utcnow()
        self.db_session.flush()
        return asset
    
    def delete_asset(self, asset_id: UUID) -> bool:
        """Delete a Digital Twin asset and its associations."""
        asset = self.get_asset(asset_id)
        if not asset:
            return False
        self.db_session.delete(asset)
        self.db_session.flush()
        return True
    
    # ------------------------------------------------------------------
    # Service Operations
    # ------------------------------------------------------------------
    
    def create_service(
        self,
        asset_id: UUID,
        name: str,
        service_type: str,
        description: str = "",
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        version: Optional[str] = None,
        technology_stack: List[str] = None,
        risk_level: str = "MEDIUM",
        is_internet_facing: bool = False,
        has_authentication: bool = True,
        has_encryption: bool = True,
        metadata_json: Dict[str, Any] = None,
    ) -> DigitalTwinServiceDB:
        """Create a new Digital Twin service."""
        # Validate asset exists and is tenant-scoped
        asset = self.get_asset(asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} not found or not accessible")
        
        service = DigitalTwinServiceDB(
            id=uuid4(),
            organization_id=self.organization_id,
            asset_id=asset_id,
            name=name,
            service_type=service_type,
            description=description,
            port=port,
            protocol=protocol,
            version=version,
            technology_stack=technology_stack or [],
            risk_level=risk_level,
            is_internet_facing=is_internet_facing,
            has_authentication=has_authentication,
            has_encryption=has_encryption,
            metadata_json=metadata_json or {},
        )
        self.db_session.add(service)
        self.db_session.flush()
        return service
    
    def get_service(self, service_id: UUID) -> Optional[DigitalTwinServiceDB]:
        """Get a Digital Twin service by ID (tenant-scoped)."""
        return self.db_session.query(DigitalTwinServiceDB).filter(
            DigitalTwinServiceDB.id == service_id,
            DigitalTwinServiceDB.organization_id == self.organization_id,
        ).first()
    
    def list_services(
        self,
        asset_id: Optional[UUID] = None,
        service_type: Optional[str] = None,
        is_internet_facing: Optional[bool] = None,
    ) -> List[DigitalTwinServiceDB]:
        """List all Digital Twin services for this organization."""
        query = self.db_session.query(DigitalTwinServiceDB).filter(
            DigitalTwinServiceDB.organization_id == self.organization_id
        )
        if asset_id:
            query = query.filter(DigitalTwinServiceDB.asset_id == asset_id)
        if service_type:
            query = query.filter(DigitalTwinServiceDB.service_type == service_type)
        if is_internet_facing is not None:
            query = query.filter(DigitalTwinServiceDB.is_internet_facing == is_internet_facing)
        return query.all()
    
    def update_service(
        self,
        service_id: UUID,
        **kwargs,
    ) -> Optional[DigitalTwinServiceDB]:
        """Update a Digital Twin service."""
        service = self.get_service(service_id)
        if not service:
            return None
        for key, value in kwargs.items():
            if hasattr(service, key) and value is not None:
                setattr(service, key, value)
        service.updated_at = datetime.utcnow()
        self.db_session.flush()
        return service
    
    def delete_service(self, service_id: UUID) -> bool:
        """Delete a Digital Twin service and its associations."""
        service = self.get_service(service_id)
        if not service:
            return False
        self.db_session.delete(service)
        self.db_session.flush()
        return True
    
    # ------------------------------------------------------------------
    # Security Control Operations
    # ------------------------------------------------------------------
    
    def create_security_control(
        self,
        name: str,
        control_type: str,
        description: str = "",
        enabled: bool = True,
        version: Optional[str] = None,
        vendor: Optional[str] = None,
        technique_ids: List[str] = None,
        coverage_description: str = "",
        metadata_json: Dict[str, Any] = None,
    ) -> DigitalTwinSecurityControl:
        """Create a new Digital Twin security control."""
        control = DigitalTwinSecurityControl(
            id=uuid4(),
            organization_id=self.organization_id,
            name=name,
            control_type=control_type,
            description=description,
            enabled=enabled,
            version=version,
            vendor=vendor,
            technique_ids=technique_ids or [],
            coverage_description=coverage_description,
            metadata_json=metadata_json or {},
        )
        self.db_session.add(control)
        self.db_session.flush()
        return control
    
    def get_security_control(self, control_id: UUID) -> Optional[DigitalTwinSecurityControl]:
        """Get a Digital Twin security control by ID (tenant-scoped)."""
        return self.db_session.query(DigitalTwinSecurityControl).filter(
            DigitalTwinSecurityControl.id == control_id,
            DigitalTwinSecurityControl.organization_id == self.organization_id,
        ).first()
    
    def list_security_controls(
        self,
        control_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[DigitalTwinSecurityControl]:
        """List all Digital Twin security controls for this organization."""
        query = self.db_session.query(DigitalTwinSecurityControl).filter(
            DigitalTwinSecurityControl.organization_id == self.organization_id
        )
        if control_type:
            query = query.filter(DigitalTwinSecurityControl.control_type == control_type)
        if enabled is not None:
            query = query.filter(DigitalTwinSecurityControl.enabled == enabled)
        return query.all()
    
    def update_security_control(
        self,
        control_id: UUID,
        **kwargs,
    ) -> Optional[DigitalTwinSecurityControl]:
        """Update a Digital Twin security control."""
        control = self.get_security_control(control_id)
        if not control:
            return None
        for key, value in kwargs.items():
            if hasattr(control, key) and value is not None:
                setattr(control, key, value)
        control.updated_at = datetime.utcnow()
        self.db_session.flush()
        return control
    
    def delete_security_control(self, control_id: UUID) -> bool:
        """Delete a Digital Twin security control and its associations."""
        control = self.get_security_control(control_id)
        if not control:
            return False
        self.db_session.delete(control)
        self.db_session.flush()
        return True
    
    # ------------------------------------------------------------------
    # Asset-Control Association Operations
    # ------------------------------------------------------------------
    
    def associate_asset_control(
        self,
        asset_id: UUID,
        control_id: UUID,
        applied_by: Optional[str] = None,
        configuration_json: Dict[str, Any] = None,
    ) -> DigitalTwinAssetControl:
        """Associate a security control with an asset."""
        # Validate both entities exist and are tenant-scoped
        asset = self.get_asset(asset_id)
        if not asset:
            raise ValueError(f"Asset {asset_id} not found or not accessible")
        control = self.get_security_control(control_id)
        if not control:
            raise ValueError(f"Security control {control_id} not found or not accessible")
        
        # Check for existing association
        existing = self.db_session.query(DigitalTwinAssetControl).filter(
            DigitalTwinAssetControl.asset_id == asset_id,
            DigitalTwinAssetControl.control_id == control_id,
            DigitalTwinAssetControl.organization_id == self.organization_id,
        ).first()
        if existing:
            return existing
        
        association = DigitalTwinAssetControl(
            id=uuid4(),
            organization_id=self.organization_id,
            asset_id=asset_id,
            control_id=control_id,
            applied_by=applied_by,
            configuration_json=configuration_json or {},
        )
        self.db_session.add(association)
        self.db_session.flush()
        return association
    
    def get_asset_controls(self, asset_id: UUID) -> List[DigitalTwinSecurityControl]:
        """Get all security controls associated with an asset."""
        associations = self.db_session.query(DigitalTwinAssetControl).filter(
            DigitalTwinAssetControl.asset_id == asset_id,
            DigitalTwinAssetControl.organization_id == self.organization_id,
        ).all()
        control_ids = [assoc.control_id for assoc in associations]
        if not control_ids:
            return []
        return self.db_session.query(DigitalTwinSecurityControl).filter(
            DigitalTwinSecurityControl.id.in_(control_ids),
            DigitalTwinSecurityControl.organization_id == self.organization_id,
        ).all()
    
    def remove_asset_control(self, asset_id: UUID, control_id: UUID) -> bool:
        """Remove an association between an asset and a security control."""
        association = self.db_session.query(DigitalTwinAssetControl).filter(
            DigitalTwinAssetControl.asset_id == asset_id,
            DigitalTwinAssetControl.control_id == control_id,
            DigitalTwinAssetControl.organization_id == self.organization_id,
        ).first()
        if not association:
            return False
        self.db_session.delete(association)
        self.db_session.flush()
        return True
    
    # ------------------------------------------------------------------
    # Service-Control Association Operations
    # ------------------------------------------------------------------
    
    def associate_service_control(
        self,
        service_id: UUID,
        control_id: UUID,
        protection_level: Optional[str] = None,
    ) -> DigitalTwinServiceControl:
        """Associate a security control with a service."""
        # Validate both entities exist and are tenant-scoped
        service = self.get_service(service_id)
        if not service:
            raise ValueError(f"Service {service_id} not found or not accessible")
        control = self.get_security_control(control_id)
        if not control:
            raise ValueError(f"Security control {control_id} not found or not accessible")
        
        # Check for existing association
        existing = self.db_session.query(DigitalTwinServiceControl).filter(
            DigitalTwinServiceControl.service_id == service_id,
            DigitalTwinServiceControl.control_id == control_id,
            DigitalTwinServiceControl.organization_id == self.organization_id,
        ).first()
        if existing:
            return existing
        
        association = DigitalTwinServiceControl(
            id=uuid4(),
            organization_id=self.organization_id,
            service_id=service_id,
            control_id=control_id,
            protection_level=protection_level,
        )
        self.db_session.add(association)
        self.db_session.flush()
        return association
    
    def get_service_controls(self, service_id: UUID) -> List[DigitalTwinSecurityControl]:
        """Get all security controls associated with a service."""
        associations = self.db_session.query(DigitalTwinServiceControl).filter(
            DigitalTwinServiceControl.service_id == service_id,
            DigitalTwinServiceControl.organization_id == self.organization_id,
        ).all()
        control_ids = [assoc.control_id for assoc in associations]
        if not control_ids:
            return []
        return self.db_session.query(DigitalTwinSecurityControl).filter(
            DigitalTwinSecurityControl.id.in_(control_ids),
            DigitalTwinSecurityControl.organization_id == self.organization_id,
        ).all()
    
    def remove_service_control(self, service_id: UUID, control_id: UUID) -> bool:
        """Remove an association between a service and a security control."""
        association = self.db_session.query(DigitalTwinServiceControl).filter(
            DigitalTwinServiceControl.service_id == service_id,
            DigitalTwinServiceControl.control_id == control_id,
            DigitalTwinServiceControl.organization_id == self.organization_id,
        ).first()
        if not association:
            return False
        self.db_session.delete(association)
        self.db_session.flush()
        return True
    
    # ------------------------------------------------------------------
    # Detection Coverage Operations
    # ------------------------------------------------------------------
    
    def create_detection_coverage(
        self,
        technique_id: str,
        asset_id: Optional[UUID] = None,
        service_id: Optional[UUID] = None,
        is_detected: bool = False,
        detection_method: Optional[str] = None,
        rule_ids: List[str] = None,
        confidence_score: float = 0.0,
        metadata_json: Dict[str, Any] = None,
    ) -> DigitalTwinDetectionCoverage:
        """Create a detection coverage record."""
        # Validate references if provided
        if asset_id:
            asset = self.get_asset(asset_id)
            if not asset:
                raise ValueError(f"Asset {asset_id} not found or not accessible")
        if service_id:
            service = self.get_service(service_id)
            if not service:
                raise ValueError(f"Service {service_id} not found or not accessible")
        
        coverage = DigitalTwinDetectionCoverage(
            id=uuid4(),
            organization_id=self.organization_id,
            asset_id=asset_id,
            service_id=service_id,
            technique_id=technique_id,
            is_detected=is_detected,
            detection_method=detection_method,
            rule_ids=rule_ids or [],
            confidence_score=confidence_score,
            metadata_json=metadata_json or {},
        )
        self.db_session.add(coverage)
        self.db_session.flush()
        return coverage
    
    def get_detection_coverage(
        self,
        asset_id: Optional[UUID] = None,
        service_id: Optional[UUID] = None,
        technique_id: Optional[str] = None,
    ) -> List[DigitalTwinDetectionCoverage]:
        """Get detection coverage records."""
        query = self.db_session.query(DigitalTwinDetectionCoverage).filter(
            DigitalTwinDetectionCoverage.organization_id == self.organization_id
        )
        if asset_id:
            query = query.filter(DigitalTwinDetectionCoverage.asset_id == asset_id)
        if service_id:
            query = query.filter(DigitalTwinDetectionCoverage.service_id == service_id)
        if technique_id:
            query = query.filter(DigitalTwinDetectionCoverage.technique_id == technique_id)
        return query.all()
    
    def update_detection_coverage(
        self,
        coverage_id: UUID,
        **kwargs,
    ) -> Optional[DigitalTwinDetectionCoverage]:
        """Update a detection coverage record."""
        coverage = self.db_session.query(DigitalTwinDetectionCoverage).filter(
            DigitalTwinDetectionCoverage.id == coverage_id,
            DigitalTwinDetectionCoverage.organization_id == self.organization_id,
        ).first()
        if not coverage:
            return None
        for key, value in kwargs.items():
            if hasattr(coverage, key) and value is not None:
                setattr(coverage, key, value)
        coverage.updated_at = datetime.utcnow()
        self.db_session.flush()
        return coverage
    
    # ------------------------------------------------------------------
    # Security Posture Operations
    # ------------------------------------------------------------------
    
    def compute_security_posture(self) -> DigitalTwinSecurityPosture:
        """Compute current security posture from Digital Twin entities.
        
        This is a deterministic computation from persisted entities.
        No LLM input influences the result.
        """
        # Asset metrics
        total_assets = self.db_session.query(func.count(DigitalTwinAsset.id)).filter(
            DigitalTwinAsset.organization_id == self.organization_id
        ).scalar() or 0
        
        active_assets = self.db_session.query(func.count(DigitalTwinAsset.id)).filter(
            DigitalTwinAsset.organization_id == self.organization_id,
            DigitalTwinAsset.is_active == True,
        ).scalar() or 0
        
        high_risk_assets = self.db_session.query(func.count(DigitalTwinAsset.id)).filter(
            DigitalTwinAsset.organization_id == self.organization_id,
            DigitalTwinAsset.risk_level == "HIGH",
        ).scalar() or 0
        
        critical_risk_assets = self.db_session.query(func.count(DigitalTwinAsset.id)).filter(
            DigitalTwinAsset.organization_id == self.organization_id,
            DigitalTwinAsset.risk_level == "CRITICAL",
        ).scalar() or 0
        
        # Service metrics
        total_services = self.db_session.query(func.count(DigitalTwinServiceDB.id)).filter(
            DigitalTwinServiceDB.organization_id == self.organization_id
        ).scalar() or 0
        
        internet_facing_services = self.db_session.query(func.count(DigitalTwinServiceDB.id)).filter(
            DigitalTwinServiceDB.organization_id == self.organization_id,
            DigitalTwinServiceDB.is_internet_facing == True,
        ).scalar() or 0
        
        # Security control metrics
        total_controls = self.db_session.query(func.count(DigitalTwinSecurityControl.id)).filter(
            DigitalTwinSecurityControl.organization_id == self.organization_id
        ).scalar() or 0
        
        enabled_controls = self.db_session.query(func.count(DigitalTwinSecurityControl.id)).filter(
            DigitalTwinSecurityControl.organization_id == self.organization_id,
            DigitalTwinSecurityControl.enabled == True,
        ).scalar() or 0
        
        # Detection coverage metrics
        total_techniques = self.db_session.query(
            func.count(func.distinct(DigitalTwinDetectionCoverage.technique_id))
        ).filter(
            DigitalTwinDetectionCoverage.organization_id == self.organization_id
        ).scalar() or 0
        
        techniques_detected = self.db_session.query(
            func.count(func.distinct(DigitalTwinDetectionCoverage.technique_id))
        ).filter(
            DigitalTwinDetectionCoverage.organization_id == self.organization_id,
            DigitalTwinDetectionCoverage.is_detected == True,
        ).scalar() or 0
        
        detection_coverage_pct = (techniques_detected / total_techniques * 100) if total_techniques > 0 else 0.0
        
        # Create posture snapshot
        posture = DigitalTwinSecurityPosture(
            id=uuid4(),
            organization_id=self.organization_id,
            total_assets=total_assets,
            active_assets=active_assets,
            total_services=total_services,
            internet_facing_services=internet_facing_services,
            total_security_controls=total_controls,
            enabled_controls=enabled_controls,
            total_techniques_tested=total_techniques,
            techniques_detected=techniques_detected,
            detection_coverage_pct=detection_coverage_pct,
            high_risk_assets=high_risk_assets,
            critical_risk_assets=critical_risk_assets,
            unresolved_gaps=total_techniques - techniques_detected,
            snapshot_date=datetime.utcnow(),
            computed_from_evidence=True,
        )
        self.db_session.add(posture)
        self.db_session.flush()
        return posture
    
    def get_posture_history(
        self,
        limit: int = 30,
    ) -> List[DigitalTwinSecurityPosture]:
        """Get security posture history."""
        return self.db_session.query(DigitalTwinSecurityPosture).filter(
            DigitalTwinSecurityPosture.organization_id == self.organization_id
        ).order_by(
            DigitalTwinSecurityPosture.snapshot_date.desc()
        ).limit(limit).all()
    
    # ------------------------------------------------------------------
    # Summary Operations
    # ------------------------------------------------------------------
    
    def get_twin_summary(self) -> Dict[str, Any]:
        """Get comprehensive Digital Twin summary for an organization."""
        from sentinelforge.db.models import Organization
        
        # Get organization
        org = self.db_session.query(Organization).filter(
            Organization.id == self.organization_id
        ).first()
        if not org:
            raise ValueError(f"Organization {self.organization_id} not found")
        
        # Asset summary
        assets = self.list_assets()
        assets_by_type = {}
        for asset in assets:
            assets_by_type[asset.asset_type] = assets_by_type.get(asset.asset_type, 0) + 1
        
        # Service summary
        services = self.list_services()
        services_by_type = {}
        internet_facing = 0
        for svc in services:
            services_by_type[svc.service_type] = services_by_type.get(svc.service_type, 0) + 1
            if svc.is_internet_facing:
                internet_facing += 1
        
        # Control summary
        controls = self.list_security_controls()
        controls_by_type = {}
        enabled_count = 0
        for ctrl in controls:
            controls_by_type[ctrl.control_type] = controls_by_type.get(ctrl.control_type, 0) + 1
            if ctrl.enabled:
                enabled_count += 1
        
        # Coverage summary
        coverage_records = self.get_detection_coverage()
        techniques_tested = set()
        techniques_detected = set()
        for cov in coverage_records:
            techniques_tested.add(cov.technique_id)
            if cov.is_detected:
                techniques_detected.add(cov.technique_id)
        
        coverage_pct = (len(techniques_detected) / len(techniques_tested) * 100) if techniques_tested else 0.0
        
        # Risk summary
        high_risk = sum(1 for a in assets if a.risk_level == "HIGH")
        critical_risk = sum(1 for a in assets if a.risk_level == "CRITICAL")
        
        return {
            "organization_id": str(self.organization_id),
            "organization_name": org.name,
            "total_assets": len(assets),
            "assets_by_type": assets_by_type,
            "total_services": len(services),
            "services_by_type": services_by_type,
            "internet_facing_services": internet_facing,
            "total_controls": len(controls),
            "enabled_controls": enabled_count,
            "controls_by_type": controls_by_type,
            "total_techniques_tested": len(techniques_tested),
            "techniques_detected": len(techniques_detected),
            "detection_coverage_pct": coverage_pct,
            "high_risk_assets": high_risk,
            "critical_risk_assets": critical_risk,
            "unresolved_gaps": len(techniques_tested) - len(techniques_detected),
            "computed_at": datetime.utcnow().isoformat(),
        }
