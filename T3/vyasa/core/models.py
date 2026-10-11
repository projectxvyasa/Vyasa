"""
VYASA Domain Data Models
Defines structured schemas for Assets, Findings, Attack Paths, and Audit Reports.
"""

from __future__ import annotations
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ValidationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Asset(BaseModel):
    """Represents a discovered host, IP, or network entity."""
    asset_id: str
    host: str
    ip: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=_utc_now)


class Finding(BaseModel):
    """Represents an identified weakness, vulnerability, or misconfiguration."""
    finding_id: str
    title: str
    description: str
    severity: Severity = Severity.LOW
    asset_id: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    validation_status: ValidationStatus = ValidationStatus.UNVERIFIED
    created_at: datetime = Field(default_factory=_utc_now)


class AttackStep(BaseModel):
    """An individual hop/phase within an attack path."""
    step_order: int
    title: str
    action_taken: str
    source_finding_id: Optional[str] = None
    technique: str
    target_asset_id: str
    impact: str


class AttackPath(BaseModel):
    """
    A correlated chain of findings forming a realistic attack trajectory.
    Example: Recon Exposure -> Weak Auth -> Privilege Escalation -> Critical Data Access
    """
    path_id: str
    title: str
    narrative: str
    steps: List[AttackStep]
    composite_severity: Severity
    likelihood: str = "Medium"
    business_impact: str
    created_at: datetime = Field(default_factory=_utc_now)


class RemediationItem(BaseModel):
    """Actionable remediation recommendation with priority."""
    priority: int
    title: str
    target_finding_ids: List[str]
    technical_action: str
    strategic_recommendation: str


class InvestigationTelemetry(BaseModel):
    """Telemetry capturing what was attempted, what was returned, and how it was analyzed."""
    probe_id: str
    title: str
    category: str
    endpoint: str
    method: str = "GET"
    request_summary: str
    response_summary: str
    verdict: str  # "VULNERABLE", "SECURE", "INCONCLUSIVE"
    evidence_details: Optional[str] = None
    duration_ms: Optional[float] = None
    timestamp: datetime = Field(default_factory=_utc_now)


class ReportPreferences(BaseModel):
    """User-selected preferences for report generation."""
    include_executive_summary: bool = True
    include_investigation_telemetry: bool = True  # "What the model tried & what it got"
    include_attack_paths: bool = True
    include_vulnerability_catalog: bool = True
    include_full_test_matrix: bool = True
    include_raw_evidence: bool = True
    include_remediation_roadmap: bool = True


class AuditReport(BaseModel):
    """The final comprehensive executive and technical security report."""
    report_id: str
    target_scope: str
    executive_summary: str
    assets: List[Asset]
    findings: List[Finding]
    attack_paths: List[AttackPath]
    remediation_roadmap: List[RemediationItem]
    investigation_telemetry: List[InvestigationTelemetry] = Field(default_factory=list)
    preferences: Optional[ReportPreferences] = None
    generated_at: datetime = Field(default_factory=_utc_now)
