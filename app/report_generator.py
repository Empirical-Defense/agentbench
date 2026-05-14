from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.models import AssessmentSummary
from app.utils import summarize_coverage

logger = logging.getLogger(__name__)


def generate_report(summary: AssessmentSummary, reports_dir: Path | None = None) -> Path:
    """Generate a JSON audit report from assessment summary."""
    target_dir = reports_dir or (Path(__file__).resolve().parent.parent / "reports")
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = target_dir / f"assessment_{timestamp}.json"


    # Wrap output in a top-level 'summary' key for dashboard compatibility
    report_data = summary.model_dump(mode="json")

    # Verification fields are opt-in; omit them unless explicitly enabled.
    if not summary.verification_agent_enabled:
        for control in report_data.get("control_results", []):
            for result in control.get("results", []):
                result.pop("verification_result", None)
                result.pop("verification_reason", None)

    report_data["coverage_summary"] = summarize_coverage(summary.control_results)
    wrapped = {"summary": report_data}

    with path.open("w", encoding="utf-8") as handle:
        json.dump(wrapped, handle, indent=2)

    return path
