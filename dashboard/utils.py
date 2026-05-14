import re
from typing import Any, Dict

def friendly_classification(control: Dict[str, Any]) -> str:
    tested = bool(control.get("tested"))
    status = (control.get("status") or "").upper()
    reason = (control.get("not_tested_reason") or "").lower()
    if tested:
        return "Automated"
    if status == "SKIPPED":
        return "Skipped (Agent Type)"
    if "manual evidence" in reason:
        return "Manual Evidence"
    return "Missing Automation"

def clean_evidence_label(control_id: str, evidence_title: str, fallback_title: str) -> str:
    text = (evidence_title or "").strip()
    if text:
        text = re.sub(r"^[A-Z]\d{3}(?:\.\d+)?\s*[:\-]?\s*", "", text)
        if text:
            return text
    return (fallback_title or "No title available").strip()

def clean_family_title(title: str) -> str:
    text = (title or "").strip()
    if not text:
        return "No title available"
    text = re.sub(r"^[A-Z]\d{3}\s*[:\-]\s*", "", text)
    return text or "No title available"

def control_family(control_id: str) -> str:
    if not control_id:
        return "UNKNOWN"
    return control_id.split(".")[0]

def control_sort_key(control_id: str) -> tuple[str, int, int, str]:
    text = (control_id or "").strip().upper()
    match = re.match(r"^([A-Z]+)(\d+)(?:\.(\d+))?$", text)
    if not match:
        return ("ZZZ", 999999, 999999, text)
    alpha = match.group(1)
    major = int(match.group(2))
    minor = int(match.group(3) or 0)
    return (alpha, major, minor, text)

def family_outcome_bucket(control: Dict[str, Any]) -> str:
    status = (control.get("status") or "").upper()
    if status == "PASS":
        return "Pass"
    if status in {"FAIL", "PARTIAL"}:
        return "Fail / Partial"
    return "Not Assessed"


def rollup_nist_family(family_id: str) -> str:
    """Collapse NIST control subfamilies into top-level families for charts.

    Examples:
    - MAP1, MAP2, MAP4 -> MAP
    - GOVERN1, GOVERN6 -> GOVERN
    - MANAGE1, MANAGE4 -> MANAGE
    - MEASURE1, MEASURE4 -> MEASURE
    """
    text = (family_id or "").strip().upper()
    for prefix in ("MAP", "GOVERN", "MANAGE", "MEASURE"):
        if re.match(rf"^{prefix}\d+$", text):
            return prefix
    return text or "UNKNOWN"
