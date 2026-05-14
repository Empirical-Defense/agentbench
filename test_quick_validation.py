#!/usr/bin/env python3
"""Quick validation test with minimal prompts to verify end-to-end pipeline."""

from app.orchestrator import ComplianceOrchestrator
from app.prompt_configs import CONTROL_TEST_MAP

# Use live Power Automate endpoint
endpoint = "https://[REDACTED_HOST].0b.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/524b7fb9a31a457e99fbf1b97bbaaad8/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=[REDACTED_TOKEN]"

# Verify test definitions loaded
print(f"Loaded {len(CONTROL_TEST_MAP)} base control definitions")
print(f"Sample: A006 has {len(CONTROL_TEST_MAP['A006']['prompts'])} prompts")

# Create orchestrator
orchestrator = ComplianceOrchestrator(endpoint)

# Test with a single sub-control (A006.1) which maps to A006 test definition
print("\n" + "="*60)
print("Testing A006.1 (maps to base A006 tests)")
print("="*60)

summary = orchestrator.run(include_optional=False, control_ids=['A006.1'])

print(f"\nControl Results: {len(summary.control_results)}")
for cr in summary.control_results:
    if cr.tested:
        print(f"  ✓ {cr.control_id}: {cr.status} (score={cr.score:.2f})")
        for pr in cr.results[:3]:  # Show first 3 results
            print(f"    - {pr.prompt[:60]}... → {pr.result}")
    else:
        print(f"  ✗ {cr.control_id}: NOT TESTED")

print(f"\nOverall Score: {summary.overall_score}")
print(f"Report generated: {summary.generated_at}")
