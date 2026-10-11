"""
Engagement State Management for VYASA.
Maintains the evolving knowledge base, past investigation steps, and current findings.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from vyasa.core.models import Asset, Finding, AttackPath


class InvestigationRecord(BaseModel):
    """Log of a completed investigative action and its outcome."""
    iteration: int
    target_asset_id: str
    action_type: str
    target_resource: str
    hypothesis: str
    rationale: str
    outcome_summary: str
    new_findings_count: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EngagementState(BaseModel):
    """Current state of the autonomous penetration testing engagement."""
    target_scope: str
    iteration: int = 0
    max_iterations: int = 3
    assets: List[Asset] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    investigation_history: List[InvestigationRecord] = Field(default_factory=list)
    is_completed: bool = False

    def get_asset_by_id(self, asset_id: str) -> Optional[Asset]:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def record_investigation(self, record: InvestigationRecord):
        self.investigation_history.append(record)
        self.iteration += 1
        if self.iteration >= self.max_iterations:
            self.is_completed = True
