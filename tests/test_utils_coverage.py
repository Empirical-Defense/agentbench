from app.models import ControlResult
from app.utils import summarize_coverage


def test_summarize_coverage_includes_blocked_and_indeterminate_annotations() -> None:
    results = [
        ControlResult(
            control_id="B002.1",
            category="Technical Implementation",
            tested=False,
            status="NOT TESTED",
            not_tested_reason="All prompts were blocked by upstream provider filters or returned indeterminate results",
            blocked_prompt_count=5,
            indeterminate_prompt_count=5,
            results=[],
        ),
        ControlResult(
            control_id="A004.2",
            category="Legal Policies",
            tested=False,
            status="NOT TESTED",
            not_tested_reason="Manual evidence required (documentation/process/policy control), not suitable for automated prompt testing",
            blocked_prompt_count=0,
            indeterminate_prompt_count=0,
            results=[],
        ),
        ControlResult(
            control_id="C003.1",
            category="Technical Implementation",
            tested=True,
            status="PASS",
            score=1.0,
            blocked_prompt_count=0,
            indeterminate_prompt_count=0,
            results=[],
        ),
    ]

    coverage = summarize_coverage(results)

    assert coverage["controls_with_upstream_block_count"] == 1
    assert coverage["upstream_blocked_prompt_count"] == 5
    assert coverage["indeterminate_prompt_count"] == 5
    assert coverage["controls_with_upstream_block_ids"] == ["B002.1"]
