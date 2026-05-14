def render_assessment_metrics(summary_data, payload_data):
    if summary_data is not None:
        st.subheader("Assessment Outcome")
        statuses = (payload_data or {}).get("controls_by_status", {})
        not_assessed = sum(1 for c in summary_data.get("control_results", []) if not c.get("tested"))
        skipped = statuses.get("SKIPPED", 0)
        eligible = len(summary_data.get("control_results", [])) - skipped
        tested = sum(1 for c in summary_data.get("control_results", []) if c.get("tested"))
        from dashboard.components.metric_row import metric_row
        overall = summary_data.get("overall_score")
        metric_row([
            ("Overall Score", "N/A" if overall is None else f"{overall * 100:.1f}%"),
            ("Green (Pass)", statuses.get("PASS", 0)),
            ("Red (Fail/Partial)", statuses.get("FAIL", 0) + statuses.get("PARTIAL", 0)),
            ("Gray (Not Assessed)", not_assessed),
            ("Skipped", skipped),
        ])
        st.caption(f"Coverage: {tested}/{eligible if eligible >= 0 else 0} tested ({skipped} skipped for agent type)")

def render_catalog_summary(catalog_df):
    if not catalog_df.empty:
        aiuc_df = catalog_df[catalog_df["control_id"].str.match(r"^[A-Z]\d{3}(?:\.\d+)?$", na=False)]
        owasp_df = catalog_df[catalog_df["control_id"].str.match(r"^LLM\d{2}(?:\.\d+)?$", na=False)]
        nist_df = catalog_df[catalog_df["control_id"].str.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", na=False)]
        st.subheader("Catalog Summary")
        st.caption(
            f"AIUC: {len(aiuc_df)} | OWASP LLM: {len(owasp_df)} | NIST AI RMF: {len(nist_df)}"
        )
        total_controls = len(catalog_df)
        family_count = catalog_df['family'].nunique()
        mandatory_count = (catalog_df['mandatory_optional'].str.lower() == 'mandatory').sum()
        optional_count = (catalog_df['mandatory_optional'].str.lower() == 'optional').sum()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Controls", total_controls)
        m2.metric("Control Families", family_count)
        m3.metric("Mandatory", mandatory_count)
        m4.metric("Optional", optional_count)

def render_family_chart(catalog_df, summary_data):
    outcome_color_scale = alt.Scale(
        domain=["Pass", "Fail / Partial", "Not Assessed"],
        range=["#2E7D32", "#C62828", "#757575"],
    )
    st.subheader("Control By Family")
    from dashboard.components.altair_chart_block import altair_chart_block
    if summary_data is None:
        if catalog_df.empty:
            st.info("No control family data available.")
        else:
            family_counts = (
                catalog_df.groupby("family", as_index=False)
                .size()
                .rename(columns={"family": "Family", "size": "Count"})
                .sort_values("Count", ascending=False)
            )
            family_order = sorted(family_counts["Family"].unique(), key=_control_sort_key)
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
            altair_chart_block(chart, title="Control By Family")
    else:
        family_rows = [
            {
                "Family": _control_family(c.get("control_id") or ""),
                "Outcome": _family_outcome_bucket(c),
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
            family_order = sorted(grouped["Family"].unique(), key=_control_sort_key)
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
            altair_chart_block(chart, title="Control By Family")

def render_findings_chart(summary_data):
    from dashboard.components.altair_chart_block import altair_chart_block
    st.subheader("Findings Per Control")
    if summary_data is None:
        st.info("No prior assessment report found yet. Run an assessment to populate this bar graph.")
    else:
        findings_df = _findings_histogram_from_summary(summary_data)
        if findings_df.empty:
            st.info("No findings data available for the current assessment.")
        else:
            findings_df["Family"] = findings_df["Control"].str.extract(r"^([A-Z]\d{3})")
            families = sorted(findings_df["Family"].unique(), key=_control_sort_key)
            selected_family = st.selectbox("Select Control Family", options=families)
            family_findings = findings_df[findings_df["Family"] == selected_family]
            if family_findings.empty:
                st.info(f"No findings data for family {selected_family}.")
            else:
                control_order = sorted(family_findings["Control"].unique(), key=_control_sort_key)
                family_findings["Control"] = pd.Categorical(
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
                altair_chart_block(chart, title=f"Findings for {selected_family}")

def render_control_tables(catalog_df):
    if not catalog_df.empty:
        from dashboard.components.table_block import table_block
        aiuc_df = catalog_df[catalog_df["control_id"].str.match(r"^[A-Z]\d{3}(?:\.\d+)?$", na=False)]
        owasp_df = catalog_df[catalog_df["control_id"].str.match(r"^LLM\d{2}(?:\.\d+)?$", na=False)]
        nist_df = catalog_df[catalog_df["control_id"].str.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", na=False)]
        preview_cols = ["control_id", "title", "evidence_title", "category", "mandatory_optional"]
        aiuc_table = aiuc_df[preview_cols].rename(
            columns={
                "control_id": "Control",
                "title": "Requirement",
                "evidence_title": "Evidence",
                "category": "Category",
                "mandatory_optional": "Priority",
            }
        )
        owasp_table = owasp_df[preview_cols].rename(
            columns={
                "control_id": "Control",
                "title": "Requirement",
                "evidence_title": "Evidence",
                "category": "Category",
                "mandatory_optional": "Priority",
            }
        )
        nist_table = nist_df[preview_cols].rename(
            columns={
                "control_id": "Control",
                "title": "Requirement",
                "evidence_title": "Evidence",
                "category": "Category",
                "mandatory_optional": "Priority",
            }
        )
        table_block(aiuc_table, title="AIUC-1 Controls", expander={"label": "Show Full AIUC-1 Control Catalog", "expanded": False})
        table_block(owasp_table, title="OWASP LLM Controls", expander={"label": "Show Full OWASP LLM Control Catalog", "expanded": False})
        table_block(nist_table, title="NIST AI RMF Controls", expander={"label": "Show Full NIST AI RMF Control Catalog", "expanded": False})

"""
Dashboard rendering functions for AgentBench AI Compliance Dashboard.
"""

from typing import Any, Dict, List
import pandas as pd
from dashboard.sections.assessment_metrics import render_assessment_metrics
from dashboard.sections.catalog_summary import render_catalog_summary
from dashboard.sections.family_chart import render_family_chart
from dashboard.sections.findings_chart import render_findings_chart
from dashboard.sections.control_tables import render_control_tables

def render_homepage(
    controls_catalog: List[Dict[str, Any]],
    summary_data: Dict[str, Any] | None = None,
    payload_data: Dict[str, Any] | None = None,
) -> None:

    catalog_df = pd.DataFrame(controls_catalog) if controls_catalog else pd.DataFrame()
    if not catalog_df.empty:
        # Add family column for downstream use
        catalog_df["family"] = catalog_df["control_id"].apply(lambda cid: cid.split(".")[0] if isinstance(cid, str) else "")
    render_assessment_metrics(summary_data, payload_data)
    render_catalog_summary(catalog_df)
    render_family_chart(catalog_df, summary_data)
    render_findings_chart(summary_data)
    render_control_tables(catalog_df)
    if catalog_df.empty:
        import streamlit as st
        st.warning("Control catalog is unavailable. Check API URL in the sidebar and try again.")