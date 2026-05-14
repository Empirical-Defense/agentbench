from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import HTTPException

from app.main import _resolve_agent_category, _validate_url, assess, coverage_preview
from app.models import AssessmentRequest
from app.models import AssessmentSummary, Control, ControlResult


def _make_control(control_id: str, category: str = "Technical Implementation") -> Control:
    return Control(
        requirement_title="Requirement",
        mandatory_optional="Mandatory",
        full_requirement="Full requirement",
        control_application="Core",
        control_id=control_id,
        evidence_title="Evidence",
        typical_evidence="Typical evidence",
        category=category,
        typical_location="Repo",
        capabilities="Universal",
        control_status="",
        internal_note="",
        recommended_priority_controls="",
    )


def test_validate_url_rejects_invalid_vendor_url() -> None:
    assert _validate_url("not-a-url") is False


def test_resolve_agent_category_rejects_invalid_value() -> None:
    try:
        _resolve_agent_category("not-real")
        assert False, "Expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 400


def test_coverage_uses_category_prompt_resolver() -> None:
    controls = [_make_control("B002.1")]

    with patch("app.main.load_controls", return_value=controls), patch(
        "app.main.get_prompts_for_agent", return_value=["p1", "p2", "p3"]
    ):
        payload = coverage_preview(include_optional=True, control_ids=["B002.1"], agent_category="chat_only")

    assert payload["controls"][0]["prompt_count"] == 3


def test_assess_returns_summary_with_blocked_annotation_fields() -> None:
    summary = AssessmentSummary(
        vendor_endpoint="redacted",
        overall_score=1.0,
        generated_at=datetime.now(timezone.utc),
        control_results=[
            ControlResult(
                control_id="C003.1",
                category="Technical Implementation",
                tested=True,
                status="PASS",
                score=1.0,
                blocked_prompt_count=0,
                indeterminate_prompt_count=0,
                results=[],
            )
        ],
    )

    with patch("app.main.ComplianceOrchestrator") as mocked_orchestrator:
        mocked_orchestrator.return_value.run.return_value = summary
        response = assess(
            AssessmentRequest(
                vendor_endpoint="http://127.0.0.1:9010/infer",
                include_optional=True,
                agent_category="chat_only",
            )
        )

    assert response.summary.control_results[0].blocked_prompt_count == 0
    assert response.summary.control_results[0].indeterminate_prompt_count == 0
