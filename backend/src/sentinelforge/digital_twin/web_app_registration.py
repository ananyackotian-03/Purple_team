"""SentinelForge — Vulnerable Web Application Registration.

Registers the controlled vulnerable Flask web application in the Digital Twin
as an asset/service with associated security controls and detection coverage.

This module is used by integration tests and the canonical E2E demo.
It does NOT modify the Digital Twin directly — all mutations go through the
DigitalTwinService layer.

SECURITY:
- The web application runs ONLY inside the Docker lab.
- All mutations are tenant-scoped via organization_id.
- LLM cannot call these functions directly.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID

logger = logging.getLogger(__name__)

# Web application constants
WEB_APP_NAME = "sentinelforge-vulnerable-app"
WEB_APP_DESCRIPTION = (
    "Controlled deliberately vulnerable Flask web application for "
    "Cyber Immune security experimentation. Contains intentional SQL injection, "
    "command injection, and path traversal vulnerabilities. "
    "Runs ONLY inside the Docker laboratory."
)
WEB_APP_SERVICE_NAME = "flask-web-service"
WEB_APP_PORT = 5000
WEB_APP_PROTOCOL = "http"
WEB_APP_TECHNOLOGY = ["python", "flask", "sqlite"]

# Security controls
CONTROLS = [
    {
        "name": "Network Isolation",
        "control_type": "firewall",
        "description": "Docker network isolation prevents external access to the vulnerable application.",
        "technique_ids": ["T1090"],  # Proxy
    },
    {
        "name": "Container Hardening",
        "control_type": "container_security",
        "description": "Non-root user, read-only filesystem, dropped capabilities, no-new-privileges.",
        "technique_ids": ["T1611"],  # Escape to Host
    },
    {
        "name": "Sigma Detection Rules",
        "control_type": "ids",
        "description": "Sigma rules detect SQL injection, command injection, and path traversal attempts.",
        "technique_ids": ["T1190", "T1059", "T1083"],
    },
]

# Detection coverage for each vulnerability
DETECTION_COVERAGE = [
    {"technique_id": "T1190", "is_detected": True, "detection_method": "sigma", "rule_ids": ["sentinelforge-web-sqli-login"]},
    {"technique_id": "T1059", "is_detected": True, "detection_method": "sigma", "rule_ids": ["sentinelforge-web-cmd-injection"]},
    {"technique_id": "T1083", "is_detected": True, "detection_method": "sigma", "rule_ids": ["sentinelforge-web-path-traversal"]},
]


def register_vulnerable_web_app(digital_twin_service) -> Dict:
    """Register the vulnerable web application in the Digital Twin.

    Args:
        digital_twin_service: DigitalTwinService instance (tenant-scoped).

    Returns:
        Dict with created asset, service, controls, and coverage IDs.
    """
    # 1. Create asset
    asset = digital_twin_service.create_asset(
        name=WEB_APP_NAME,
        asset_type="application",
        description=WEB_APP_DESCRIPTION,
        operating_system="linux",
        software_version="1.0.0",
        network_segment="isolated-lab",
        risk_level="HIGH",
        tags=["vulnerable", "lab", "web-application", "sentinelforge-target"],
        metadata_json={
            "docker_image": "vulnerable-app",
            "docker_compose_path": "backend/tests/integration/vulnerable_app/",
            "port": WEB_APP_PORT,
            "purpose": "Cyber Immune security experimentation",
        },
    )
    logger.info("Registered Digital Twin asset: %s", asset.id)

    # 2. Create service
    service = digital_twin_service.create_service(
        asset_id=asset.id,
        name=WEB_APP_SERVICE_NAME,
        service_type="web_app",
        description="Flask web service with intentional vulnerabilities for security testing.",
        port=WEB_APP_PORT,
        protocol=WEB_APP_PROTOCOL,
        version="1.0.0",
        technology_stack=WEB_APP_TECHNOLOGY,
        risk_level="HIGH",
        is_internet_facing=False,
        has_authentication=True,
        has_encryption=False,
        metadata_json={
            "vulnerabilities": ["sql_injection", "command_injection", "path_traversal"],
            "intentionally_vulnerable": True,
        },
    )
    logger.info("Registered Digital Twin service: %s", service.id)

    # 3. Create security controls
    control_ids = []
    for ctrl_spec in CONTROLS:
        ctrl = digital_twin_service.create_security_control(
            name=ctrl_spec["name"],
            control_type=ctrl_spec["control_type"],
            description=ctrl_spec["description"],
            technique_ids=ctrl_spec["technique_ids"],
        )
        control_ids.append(ctrl.id)

        # Associate control with service
        digital_twin_service.associate_service_control(
            service_id=service.id,
            control_id=ctrl.id,
            protection_level="full",
        )
        logger.info("Registered security control: %s (%s)", ctrl.name, ctrl.id)

    # 4. Create detection coverage
    coverage_ids = []
    for cov_spec in DETECTION_COVERAGE:
        cov = digital_twin_service.create_detection_coverage(
            technique_id=cov_spec["technique_id"],
            service_id=service.id,
            is_detected=cov_spec["is_detected"],
            detection_method=cov_spec["detection_method"],
            rule_ids=cov_spec["rule_ids"],
            confidence_score=0.8,
        )
        coverage_ids.append(cov.id)
        logger.info(
            "Registered detection coverage: technique=%s detected=%s",
            cov_spec["technique_id"],
            cov_spec["is_detected"],
        )

    return {
        "asset_id": asset.id,
        "service_id": service.id,
        "control_ids": control_ids,
        "coverage_ids": coverage_ids,
    }
