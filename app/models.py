from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


TestOutcome = Literal["PASS", "FAIL", "NOT TESTED", "SKIPPED"]
ControlStatus = Literal["PASS", "PARTIAL", "FAIL", "NOT TESTED", "SKIPPED"]


class Control(BaseModel):
    requirement_title: str
    mandatory_optional: str
    full_requirement: str
    control_application: str
    control_id: str
    evidence_title: str
    typical_evidence: str
    category: str
    typical_location: str
    capabilities: str
    control_status: str
    internal_note: str
    recommended_priority_controls: str


class PromptResult(BaseModel):
    prompt: str
    response: str
    result: TestOutcome
    reason: str
    error_types: Optional[List[str]] = None  # OWASP/AILuminate-aligned error taxonomy
    audit_log: Optional[Dict[str, str]] = None  # Structured audit trail (e.g., matched rule, context)
    verification_result: Optional[TestOutcome] = None
    verification_reason: Optional[str] = None


class ControlResult(BaseModel):
    control_id: str
    category: str
    tested: bool
    tested_by_definition: Optional[str] = None
    crosswalk_root_id: Optional[str] = None
    overlap_tags: List[str] = Field(default_factory=list)
    overlap_control_ids: List[str] = Field(default_factory=list)
    execution_group_id: Optional[str] = None
    score: Optional[float] = None
    status: ControlStatus
    not_tested_reason: Optional[str] = None
    skipped_reason: Optional[str] = None  # Reason if SKIPPED (e.g., "not applicable to agent category")
    blocked_prompt_count: int = 0
    indeterminate_prompt_count: int = 0
    failure_classification: Optional[Literal["model_behavior", "control_enforcement"]] = None
    results: List[PromptResult] = Field(default_factory=list)


class ControlReliabilityMetrics(BaseModel):
    kill_switch_success_rate: Optional[float] = None
    unauthorized_action_block_rate: Optional[float] = None
    containment_timing_success_rate: Optional[float] = None
    delayed_compliance_success_rate: Optional[float] = None
    thresholds: Dict[str, float] = Field(default_factory=dict)
    sample_sizes: Dict[str, int] = Field(default_factory=dict)
    passed: bool = True
    fail_reasons: List[str] = Field(default_factory=list)
    model_behavior_failures: int = 0
    control_enforcement_failures: int = 0


class AssessmentSummary(BaseModel):
    vendor_endpoint: str
    overall_score: Optional[float]
    control_results: List[ControlResult]
    generated_at: datetime
    verification_agent_enabled: bool = False
    control_reliability: Optional[ControlReliabilityMetrics] = None
    report_path: Optional[str] = None


class AssessmentRequest(BaseModel):
    vendor_endpoint: str
    include_optional: bool = True
    control_ids: Optional[List[str]] = None
    agent_category: Optional[str] = None  # Optional override; falls back to env default
    allow_sensitive_probes: Optional[bool] = None  # If False, sensitive tests must be skipped
    use_verification_agent: Optional[bool] = None  # Opt-in only; defaults to disabled unless explicitly set


class AssessmentResponse(BaseModel):
    summary: AssessmentSummary
    controls_by_status: Dict[str, int]
    failed_tests: List[Dict[str, str]]
    coverage: Dict[str, object]
