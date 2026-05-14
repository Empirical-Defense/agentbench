import streamlit as st
import pandas as pd
import altair as alt
from dashboard.utils import control_family, control_sort_key, family_outcome_bucket, rollup_nist_family

def render_family_chart(catalog_df, summary_data):
    outcome_color_scale = alt.Scale(
        domain=["Pass", "Fail / Partial", "Not Assessed"],
        range=["#2E7D32", "#C62828", "#757575"],
    )
    st.subheader("Control By Family")
    if summary_data is None:
        if catalog_df.empty:
            st.info("No control family data available.")
        else:
            chart_df = catalog_df.copy()
            chart_df["family_rollup"] = chart_df["family"].apply(rollup_nist_family)
            family_counts = (
                chart_df.groupby("family_rollup", as_index=False)
                .size()
                .rename(columns={"family_rollup": "Family", "size": "Count"})
                .sort_values("Count", ascending=False)
            )
            family_order = sorted(family_counts["Family"].unique(), key=control_sort_key)
            chart = (
                alt.Chart(family_counts)
                .mark_bar(color="#1565C0")
                .encode(
                    x=alt.X("Family:N", sort=family_order),
                    y="Count:Q",
                    tooltip=["Family", "Count"],
                )
                .properties(height=500)
            )
            st.altair_chart(chart, width='stretch')
    else:
        family_rows = [
            {
                "Family": rollup_nist_family(control_family(c.get("control_id") or "")),
                "Outcome": family_outcome_bucket(c),
            }
            for c in summary_data.get("control_results", [])
        ]
        family_df = pd.DataFrame(family_rows)
        if family_df.empty:
            st.info("No control family data available.")
        else:
            grouped = (
                family_df.groupby(["Family", "Outcome"], as_index=False)
                .size()
                .rename(columns={"size": "Count"})
            )
            family_order = sorted(grouped["Family"].unique(), key=control_sort_key)
            chart = (
                alt.Chart(grouped)
                .mark_bar()
                .encode(
                    x=alt.X("Family:N", sort=family_order),
                    y="Count:Q",
                    color=alt.Color("Outcome:N", scale=outcome_color_scale),
                    tooltip=["Family", "Outcome", "Count"],
                )
                .properties(height=500)
            )
            st.altair_chart(chart, width='stretch')
