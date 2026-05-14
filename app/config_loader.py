from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Dict, List

from app.models import Control

logger = logging.getLogger(__name__)


CSV_COLUMNS = {
    "Requirement title": "requirement_title",
    "Mandatory / Optional": "mandatory_optional",
    "Full requirement": "full_requirement",
    "Control application": "control_application",
    "Control": "control_id",
    "Evidence title": "evidence_title",
    "Typical evidence": "typical_evidence",
    "Category": "category",
    "Typical Location": "typical_location",
    "Capabilities": "capabilities",
    "Control status": "control_status",
    "Internal note": "internal_note",
    "Recommended priority controls": "recommended_priority_controls",
}

CONTROL_ID_PATTERN = re.compile(r"\b([A-Z]{1,5}\d{2,3}(?:\.\d+)?)\b")
NIST_HEADER_PATTERN = re.compile(r"^([A-Z]+)\s+(\d+(?:\.\d+)?)$")


def _project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).resolve().parent.parent



def get_controls_csv_paths() -> list[Path]:
    """Get paths to active controls CSV files."""
    root = _project_root() / "data"
    return [
        root / "aiuc_controls.csv",
        root / "owasp_llm_controls.csv",
        root / "nist_ai_rmf_playbook.csv",
    ]


def _extract_control_id(row: Dict[str, str]) -> str:
    """Extract control ID from CSV row, checking multiple columns."""
    # Prefer explicit control IDs from the Control column, but gracefully
    # handle newer CSV variants where IDs live in Evidence title.
    for column in ("Control", "Evidence title", "Requirement title"):
        value = (row.get(column, "") or "").strip()
        match = CONTROL_ID_PATTERN.search(value)
        if match:
            return match.group(1)
    return ""


def _load_nist_playbook_controls(path: Path) -> List[Control]:
    """Load controls from NIST AI RMF playbook wide CSV format.

    This file stores controls as columns like `MAP 1.1`, `GOVERN 2.3`.
    """
    controls: List[Control] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))

    if not rows:
        return controls

    headers = rows[0]
    detail_row = rows[1] if len(rows) > 1 else []

    for idx, raw_header in enumerate(headers[1:], start=1):
        header = (raw_header or "").strip()
        if not header:
            continue
        match = NIST_HEADER_PATTERN.match(header)
        if not match:
            continue

        family, number = match.groups()
        control_id = f"{family}{number}"
        if control_id in seen:
            continue

        full_requirement = ""
        if idx < len(detail_row):
            full_requirement = (detail_row[idx] or "").strip()

        controls.append(
            Control(
                requirement_title=header,
                mandatory_optional="Optional",
                full_requirement=full_requirement,
                control_application="NIST AI RMF Playbook",
                control_id=control_id,
                evidence_title=f"{control_id} - {header}",
                typical_evidence="NIST AI RMF playbook artifact",
                category="NIST AI RMF Playbook",
                typical_location="NIST AI RMF Playbook",
                capabilities="Govern, Map, Measure, Manage",
                control_status="",
                internal_note="",
                recommended_priority_controls="",
            )
        )
        seen.add(control_id)

    return controls



def load_controls() -> List[Control]:
    """Load and merge controls from all configured CSV files."""
    controls: List[Control] = []
    for path in get_controls_csv_paths():
        if not path.exists():
            logger.warning(f"Control file not found: {path}")
            continue

        if path.name == "nist_ai_rmf_playbook.csv":
            nist_controls = _load_nist_playbook_controls(path)
            controls.extend(nist_controls)
            logger.info(f"Loaded {len(nist_controls)} controls from {path}")
            continue

        loaded_for_file = 0
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            missing_id_sources = [col for col in ("Control", "Evidence title", "Requirement title") if col not in fieldnames]
            if len(missing_id_sources) == 3:
                logger.warning(
                    f"CSV {path} missing all control ID source columns: ('Control', 'Evidence title', 'Requirement title')"
                )
                continue
            missing_optional = [col for col in CSV_COLUMNS if col not in fieldnames]
            if missing_optional:
                logger.info(f"CSV {path} missing optional columns (will default to ''): {missing_optional}")
            for row in reader:
                mapped: Dict[str, str] = {
                    internal_name: (row.get(csv_name, "") or "").strip()
                    for csv_name, internal_name in CSV_COLUMNS.items()
                }
                control_id = _extract_control_id(row)
                if not control_id:
                    continue
                mapped["control_id"] = control_id
                controls.append(Control(**mapped))
                loaded_for_file += 1
        logger.info(f"Loaded {loaded_for_file} controls from {path}")
    logger.info(f"Total controls loaded: {len(controls)}")
    return controls


def group_controls_by_category(controls: List[Control]) -> Dict[str, List[Control]]:
    """Group controls by category."""
    grouped: Dict[str, List[Control]] = {}
    for control in controls:
        grouped.setdefault(control.category or "Uncategorized", []).append(control)
    return grouped
