# AIUC to OWASP LLM Top 10 Crosswalk

This folder stores versioned crosswalks from AIUC controls to OWASP LLM Top 10 risks.

## Structure

- Versioned mappings: `frameworks/crosswalks/owasp_llm_top10/<version_dir>/aiuc_to_owasp_llm_top10.csv`
- Active version pointer: `frameworks/crosswalks/active_versions.env`
- Source OWASP docs: `frameworks/owas_top_10_llm/<version_dir>/`

`<version_dir>` uses underscore format, for example:
- `1.1` -> `1_1`
- `1.2` -> `1_2`

## Mapping Fields

- `aiuc_control_id`: AIUC control (base ID or sub-control)
- `aiuc_control_family`: AIUC family prefix (A, B, C, ...)
- `owasp_llm_risk_id`: OWASP risk identifier (`LLM01` ... `LLM10`)
- `owasp_llm_risk_title`: OWASP risk title for readability
- `owasp_llm_version`: OWASP LLM Top 10 version this mapping is tied to
- `mapping_strength`: `high`, `medium`, `low`
- `mapping_rationale`: short rationale for auditability

## Version Upgrades

Use:

```bash
./scripts/set_owasp_llm_top10_version.sh 1.2
```

What it does:
1. Validates `frameworks/owas_top_10_llm/1_2` exists.
2. Updates `frameworks/crosswalks/active_versions.env`.
3. Creates `frameworks/crosswalks/owasp_llm_top10/1_2/aiuc_to_owasp_llm_top10.csv` from the previously active version if it does not yet exist.
4. Rewrites the `owasp_llm_version` column in the new file to match the target version.

After switching, review and adjust mappings for any OWASP taxonomy changes.
