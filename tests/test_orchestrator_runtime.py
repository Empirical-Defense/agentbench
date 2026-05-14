from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.models import Control
from app.orchestrator import ComplianceOrchestrator


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


def test_orchestrator_marks_all_blocked_prompts_not_tested() -> None:
    controls = [_make_control("B002.1")]

    with patch("app.orchestrator.validate_control_test_map", return_value=[]), patch(
        "app.orchestrator.load_controls", return_value=controls
    ), patch(
        "app.orchestrator.send_prompt",
        return_value=(
            "An error has occurred. Error code: ContentFiltered. Conversation Id: x. Time (UTC): now.",
            "ok",
        ),
    ), patch("app.orchestrator.persist_result", return_value=None), patch(
        "app.orchestrator.generate_report", return_value=Path("reports/fake.json")
    ):
        summary = ComplianceOrchestrator(vendor_endpoint="http://example.com/infer", agent_category="chat_only").run(
            include_optional=True,
            control_ids=["B002.1"],
        )

    assert len(summary.control_results) == 1
    result = summary.control_results[0]
    assert result.status == "NOT TESTED"
    assert result.tested is False
    assert result.blocked_prompt_count > 0
    assert result.indeterminate_prompt_count > 0
    assert summary.overall_score is None
    assert summary.control_reliability is not None
    assert summary.control_reliability.passed is False
    assert any("no valid samples" in reason.lower() for reason in summary.control_reliability.fail_reasons)


def test_orchestrator_scores_only_evaluated_prompts() -> None:
    controls = [_make_control("A004.1")]

    def _eval_side_effect(_evaluation_type: str, _response: str, prompt: str | None = None, **kwargs):
        if prompt and "unreleased product source code" in prompt:
            return "PASS", "safe refusal"
        if prompt and "reconstruct our proprietary algorithm" in prompt:
            return "FAIL", "unsafe disclosure"
        return "NOT TESTED", "Upstream provider content filter blocked this prompt; cannot evaluate agent behavior"

    with patch("app.orchestrator.validate_control_test_map", return_value=[]), patch(
        "app.orchestrator.load_controls", return_value=controls
    ), patch("app.orchestrator.send_prompt", return_value=("stub response", "ok")), patch(
        "app.orchestrator.evaluate_response_extended", side_effect=_eval_side_effect
    ), patch("app.orchestrator.persist_result", return_value=None), patch(
        "app.orchestrator.generate_report", return_value=Path("reports/fake.json")
    ):
        summary = ComplianceOrchestrator(vendor_endpoint="http://example.com/infer", agent_category="chat_only").run(
            include_optional=True,
            control_ids=["A004.1"],
        )

    result = summary.control_results[0]
    assert result.score == 0.5
    assert result.status == "FAIL"
    assert result.failure_classification == "model_behavior"
    assert result.indeterminate_prompt_count == 3


def test_orchestrator_populates_control_reliability_release_gate() -> None:
    controls = [_make_control("B006.1")]

    def _eval_side_effect(_evaluation_type: str, _response: str, prompt: str | None = None, **kwargs):
        if prompt and "STOP/OVERRIDE" in prompt:
            return "FAIL", "override accepted"
        return "PASS", "safe refusal"

    with patch("app.orchestrator.validate_control_test_map", return_value=[]), patch(
        "app.orchestrator.load_controls", return_value=controls
    ), patch("app.orchestrator.send_prompt", return_value=("stub response", "ok")), patch(
        "app.orchestrator.evaluate_response_extended", side_effect=_eval_side_effect
    ), patch("app.orchestrator.persist_result", return_value=None), patch(
        "app.orchestrator.generate_report", return_value=Path("reports/fake.json")
    ):
        summary = ComplianceOrchestrator(vendor_endpoint="http://example.com/infer", agent_category="autonomous").run(
            include_optional=True,
            control_ids=["B006.1"],
        )

    assert summary.control_reliability is not None
    assert summary.control_reliability.kill_switch_success_rate is not None
    assert summary.control_reliability.kill_switch_success_rate < 1.0
    assert summary.control_reliability.passed is False
    assert summary.control_reliability.fail_reasons
    assert summary.control_reliability.control_enforcement_failures >= 1
    assert summary.control_results[0].failure_classification == "control_enforcement"
