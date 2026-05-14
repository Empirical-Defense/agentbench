import streamlit as st

def render_assessment_metrics(summary_data, payload_data):
    if summary_data is not None:
        st.subheader("Assessment Outcome")
        statuses = (payload_data or {}).get("controls_by_status", {})
        not_assessed = sum(1 for c in summary_data.get("control_results", []) if not c.get("tested"))
        skipped = statuses.get("SKIPPED", 0)
        eligible = len(summary_data.get("control_results", [])) - skipped
        tested = sum(1 for c in summary_data.get("control_results", []) if c.get("tested"))
        # Calculate prompt-level Test Pass Rate
        total_prompts = 0
        prompt_score_sum = 0.0
        for control in summary_data.get("control_results", []):
            for result in control.get("results", []):
                val = (result.get("result") or "").upper()
                total_prompts += 1
                if val == "PASS":
                    prompt_score_sum += 1.0
                elif val == "PARTIAL":
                    prompt_score_sum += 0.5
        test_pass_rate = (prompt_score_sum / total_prompts) if total_prompts else None

        # Calculate control-level Control Pass Rate
        controls = summary_data.get("control_results", [])
        total_controls = len(controls)
        pass_controls = sum(1 for c in controls if (c.get("status") or "").upper() == "PASS")
        control_pass_rate = (pass_controls / total_controls) if total_controls else None

        r1, r2, r3, r4, r5 = st.columns(5)
        r1.metric("Control Pass Rate (Main Score)", "N/A" if control_pass_rate is None else f"{control_pass_rate * 100:.1f}%", help="Percentage of controls with status = PASS (recommended for overall assessment)")
        r2.metric("Test Pass Rate (Prompt Avg)", "N/A" if test_pass_rate is None else f"{test_pass_rate * 100:.1f}%", help="Weighted average of all prompt results (PASS=1.0, PARTIAL=0.5, FAIL=0.0)")
        r3.metric("Green (Pass)", statuses.get("PASS", 0))
        r4.metric("Red (Fail/Partial)", statuses.get("FAIL", 0) + statuses.get("PARTIAL", 0))
        r5.metric("Gray (Not Assessed)", not_assessed)
        st.caption(f"Coverage: {tested}/{eligible if eligible >= 0 else 0} tested ({skipped} skipped for agent type)")
