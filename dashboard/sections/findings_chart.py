import streamlit as st
import pandas as pd
import altair as alt
from dashboard.utils import control_family, control_sort_key
from dashboard.data import findings_histogram_from_summary

def render_findings_chart(summary_data):
    st.subheader("Findings Per Control")
    if summary_data is None:
        st.info("No prior assessment report found yet. Run an assessment to populate this bar graph.")
    else:
        findings_df = findings_histogram_from_summary(summary_data)
        if findings_df.empty:
            st.info("No findings data available for the current assessment.")
        else:
            findings_df["Family"] = findings_df["Control"].apply(control_family)
            families = sorted(findings_df["Family"].unique(), key=control_sort_key)
            selected_family = st.selectbox("Select Control Family", options=families)
            family_findings = findings_df[findings_df["Family"] == selected_family]
            if family_findings.empty:
                st.info(f"No findings data for family {selected_family}.")
            else:
                control_order = sorted(family_findings["Control"].unique(), key=control_sort_key)
                family_findings = family_findings.copy()
                family_findings.loc[:, "Control"] = pd.Categorical(
                    family_findings["Control"],
                    categories=control_order,
                    ordered=True,
                )
                chart = (
                    alt.Chart(family_findings)
                    .mark_bar(color="#EF6C00")
                    .encode(
                        x="Findings:Q",
                        y=alt.Y("Control:N", sort=control_order),
                        tooltip=["Control", "Findings"],
                    )
                    .properties(height=400)
                )
                st.altair_chart(chart, width='stretch')
