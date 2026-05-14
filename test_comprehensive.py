#!/usr/bin/env python3
import requests
import json

endpoint = "https://[REDACTED_HOST].0b.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/524b7fb9a31a457e99fbf1b97bbaaad8/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=[REDACTED_TOKEN]"

# Test with multiple controls
payload = {
    "vendor_endpoint": endpoint,
    "include_optional": False,
    "control_ids": ["A006", "B001", "C003", "D001"]
}

try:
    resp = requests.post(
        "http://127.0.0.1:8000/assess",
        json=payload,
        timeout=600
    )
    if resp.status_code != 200:
        print("Status:", resp.status_code)
        print("Body:", resp.text)
        raise SystemExit(1)

    result = resp.json()
    print("Status:", resp.status_code)
    print(f"\nTotal Controls Tested: {len(result['summary']['control_results'])}")
    for ctrl in result['summary']['control_results']:
        score = ctrl.get("score")
        score_text = f"{score:.2f}" if isinstance(score, (int, float)) else "n/a"
        print(f"  {ctrl['control_id']}: {ctrl['status']} (score: {score_text})")

    overall = result["summary"].get("overall_score")
    overall_text = f"{overall:.2f}" if isinstance(overall, (int, float)) else "n/a"
    print(f"\nOverall Score: {overall_text}")
    print(f"Status Summary: {result['controls_by_status']}")
    if "coverage" in result:
        coverage = result["coverage"]
        print("\nCoverage Summary:")
        print(f"  Automated Tested: {coverage.get('automated_tested_count', 0)}")
        print(f"  Manual Evidence Only: {coverage.get('manual_evidence_only_count', 0)}")
        print(f"  Missing Automation: {coverage.get('unimplemented_automation_count', 0)}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
