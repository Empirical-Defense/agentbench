import json
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd
import requests
from dashboard.utils import control_sort_key

def findings_histogram_from_summary(summary_data: Dict[str, Any]) -> pd.DataFrame:
    rows = []
    for control in summary_data.get("control_results", []):
        control_id = control.get("control_id")
        if not control_id:
            continue
        findings_count = 0
        for result in control.get("results", []):
            result_value = (result.get("result") or "").upper()
            if result_value in {"FAIL", "PARTIAL"}:
                findings_count += 1
        rows.append({"Control": control_id, "Findings": findings_count})
    if not rows:
        return pd.DataFrame()
    return (
        pd.DataFrame(rows)
        .sort_values("Control", key=lambda s: s.map(control_sort_key))
        .head(20)
    )

def load_latest_findings_histogram() -> pd.DataFrame:
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    report_files = sorted(reports_dir.glob("assessment_*.json"), reverse=True)
    for report_path in report_files:
        try:
            with report_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            summary = data.get("summary")
            if summary and isinstance(summary, dict):
                df = findings_histogram_from_summary(summary)
                if not df.empty:
                    return df
        except Exception:
            continue  # Skip unreadable or malformed files
    return pd.DataFrame()

def fetch_controls_catalog(api_base_url: str) -> List[Dict[str, Any]]:
    # Keep this request short so dashboard interactions (like report upload) do not feel hung
    # when the API is offline or slow.
    response = requests.get(f"{api_base_url.rstrip('/')}/controls", timeout=3)
    response.raise_for_status()
    payload = response.json()
    rows: List[Dict[str, Any]] = []
    categories = payload.get("categories", {})
    for category_name, controls in categories.items():
        for control in controls:
            rows.append(
                {
                    "control_id": control.get("control_id", ""),
                    "title": control.get("requirement_title", ""),
                    "evidence_title": control.get("evidence_title", ""),
                    "category": category_name,
                    "mandatory_optional": control.get("mandatory_optional", ""),
                }
            )
    rows.sort(key=lambda item: control_sort_key(item.get("control_id", "")))
    return rows
