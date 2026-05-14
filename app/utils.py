from __future__ import annotations

import logging
from collections import Counter
from typing import Dict, Iterable, List

from app.models import ControlResult

logger = logging.getLogger(__name__)


def summarize_statuses(control_results: Iterable[ControlResult]) -> Dict[str, int]:
    """Count controls by status."""
    counts = Counter(result.status for result in control_results)
    return {
        "PASS": counts.get("PASS", 0),
        "PARTIAL": counts.get("PARTIAL", 0),
        "FAIL": counts.get("FAIL", 0),
        "NOT TESTED": counts.get("NOT TESTED", 0),
        "SKIPPED": counts.get("SKIPPED", 0),
    }


def collect_failed_tests(control_results: Iterable[ControlResult]) -> List[Dict[str, str]]:
    """Collect all failed test results from control assessments."""
    failures: List[Dict[str, str]] = []
    for control_result in control_results:
        for prompt_result in control_result.results:
            if prompt_result.result == "FAIL":
                failures.append(
                    {
                        "control_id": control_result.control_id,
                        "prompt": prompt_result.prompt,
                        "response": prompt_result.response,
                        "reason": prompt_result.reason,
                    }
                )
    logger.debug(f"Collected {len(failures)} failed tests")
    return failures


def summarize_coverage(control_results: Iterable[ControlResult]) -> Dict[str, object]:
    """Summarize assessment coverage by automation status."""
    results = list(control_results)
    tested_ids = [result.control_id for result in results if result.tested]
    skipped_ids = [result.control_id for result in results if result.status == "SKIPPED"]
    manual_only_ids = [
        result.control_id
        for result in results
        if not result.tested and result.not_tested_reason and "manual evidence" in result.not_tested_reason.lower()
    ]
    unimplemented_ids = [
        result.control_id
        for result in results
        if not result.tested and result.control_id not in manual_only_ids and result.control_id not in skipped_ids
    ]
    blocked_control_ids = [result.control_id for result in results if result.blocked_prompt_count > 0]
    upstream_blocked_prompt_count = sum(result.blocked_prompt_count for result in results)
    indeterminate_prompt_count = sum(result.indeterminate_prompt_count for result in results)

    return {
        "total_controls_in_scope": len(results),
        "automated_tested_count": len(tested_ids),
        "skipped_agent_category_count": len(skipped_ids),
        "manual_evidence_only_count": len(manual_only_ids),
        "unimplemented_automation_count": len(unimplemented_ids),
        "controls_with_upstream_block_count": len(blocked_control_ids),
        "upstream_blocked_prompt_count": upstream_blocked_prompt_count,
        "indeterminate_prompt_count": indeterminate_prompt_count,
        "automated_tested_control_ids": tested_ids,
        "skipped_agent_category_control_ids": skipped_ids,
        "manual_evidence_only_control_ids": manual_only_ids,
        "unimplemented_automation_control_ids": unimplemented_ids,
        "controls_with_upstream_block_ids": blocked_control_ids,
    }
