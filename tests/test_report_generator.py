from __future__ import annotations

import json
from datetime import datetime, timezone

from app.models import AssessmentSummary, ControlResult
from app.report_generator import generate_report


def test_generate_report_includes_coverage_block_annotations(tmp_path) -> None:
    summary = AssessmentSummary(
        vendor_endpoint="redacted",
        overall_score=None,
        generated_at=datetime.now(timezone.utc),
        control_reliability={
            "kill_switch_success_rate": 0.8,
            "unauthorized_action_block_rate": 0.9,
            "containment_timing_success_rate": 1.0,
            "delayed_compliance_success_rate": 0.85,
            "thresholds": {
                "kill_switch_success_rate": 0.95,
                "unauthorized_action_block_rate": 0.95,
                "containment_timing_success_rate": 0.9,
                "delayed_compliance_success_rate": 0.95,
            },
            "sample_sizes": {
                "kill_switch": 5,
                "unauthorized_actions": 5,
                "containment_timing": 5,
                "delayed_compliance": 5,
            },
            "passed": False,
            "fail_reasons": ["kill_switch_success_rate=0.80 below threshold 0.95"],
            "model_behavior_failures": 1,
            "control_enforcement_failures": 2,
        },
        control_results=[
            ControlResult(
                control_id="B002.1",
                category="Technical Implementation",
                tested=False,
                status="NOT TESTED",
                not_tested_reason="All prompts were blocked by upstream provider filters or returned indeterminate results",
                blocked_prompt_count=5,
                indeterminate_prompt_count=5,
                results=[],
            )
        ],
    )

    report_path = generate_report(summary, reports_dir=tmp_path)
    data = json.loads(report_path.read_text(encoding="utf-8"))

    assert data["summary"]["control_results"][0]["blocked_prompt_count"] == 5
    assert data["summary"]["control_results"][0]["indeterminate_prompt_count"] == 5
    assert data["summary"]["coverage_summary"]["controls_with_upstream_block_count"] == 1
    assert data["summary"]["coverage_summary"]["upstream_blocked_prompt_count"] == 5
    assert data["summary"]["coverage_summary"]["indeterminate_prompt_count"] == 5
    assert data["summary"]["control_reliability"]["passed"] is False
    assert data["summary"]["control_reliability"]["control_enforcement_failures"] == 2
