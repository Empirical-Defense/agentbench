

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from typing import Any, Dict, List

from dashboard.views import render_homepage
from dashboard.utils import (
    friendly_classification as _friendly_classification,
    clean_evidence_label as _clean_evidence_label,
    clean_family_title as _clean_family_title,
    control_family as _control_family,
    control_sort_key as _control_sort_key,
    family_outcome_bucket as _family_outcome_bucket,
)
from dashboard.data import (
    findings_histogram_from_summary as _findings_histogram_from_summary,
    load_latest_findings_histogram as _load_latest_findings_histogram,
    fetch_controls_catalog,
)

import altair as alt
import pandas as pd
import requests
import streamlit as st


def _matches_control_set(control_id: str, control_set_option: str) -> bool:
    if not control_id:
        return False
    if control_set_option == "AIUC":
        return bool(re.match(r"^[A-Z]\d{3}(?:\.\d+)?$", control_id))
    if control_set_option == "OWASP LLM":
        return bool(re.match(r"^LLM\d{2}(?:\.\d+)?$", control_id))
    if control_set_option == "NIST AI RMF":
        return bool(re.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", control_id))
    return True


def _compact_list_display(values: list[str], head: int = 4) -> str:
    """Render long mapping lists compactly for table display."""
    cleaned = [str(value).strip() for value in (values or []) if str(value).strip()]
    if not cleaned:
        return ""
    if len(cleaned) <= head:
        return ", ".join(cleaned)
    return f"{', '.join(cleaned[:head])} (+{len(cleaned) - head} more)"


def _compact_execution_group_display(execution_group_id: str, max_len: int = 140) -> str:
    """Keep execution-group summaries readable in the findings selector table."""
    if not execution_group_id:
        return ""
    text = str(execution_group_id).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "..."


def _framework_sort_rank(framework: str, framework_lens: str) -> tuple[int, str]:
    """Return sort rank for frameworks under the active lens."""
    normalized = (framework or "").strip().upper()
    if normalized == "OWASP":
        normalized = "OWASP LLM"
    if normalized == "NIST":
        normalized = "NIST AI RMF"

    if framework_lens == "AIUC":
        order = ["AIUC", "OWASP LLM", "NIST AI RMF"]
    elif framework_lens == "OWASP LLM":
        order = ["OWASP LLM", "NIST AI RMF", "AIUC"]
    elif framework_lens == "NIST AI RMF":
        order = ["NIST AI RMF", "OWASP LLM", "AIUC"]
    else:
        order = ["AIUC", "OWASP LLM", "NIST AI RMF"]

    if normalized in order:
        return (order.index(normalized), normalized)
    return (len(order), normalized)


def _order_framework_tags(tags: list[str], framework_lens: str) -> list[str]:
    """Order framework tags based on chosen lens for display consistency."""
    unique_tags = sorted({(tag or "").strip() for tag in (tags or []) if (tag or "").strip()})
    return sorted(unique_tags, key=lambda tag: _framework_sort_rank(tag, framework_lens))


def _format_framework_tags(tags: list[str], framework_lens: str) -> str:
    """Format framework tags ordered by lens."""
    ordered = _order_framework_tags(tags, framework_lens)
    return ", ".join(ordered)


def _format_execution_group(execution_group_id: str, framework_lens: str, compact: bool = True) -> str:
    """Reorder execution-group framework segments using the active framework lens."""
    text = (execution_group_id or "").strip()
    if not text:
        return ""

    parts = [part.strip() for part in text.split("|") if part.strip()]
    parsed = []
    for part in parts:
        framework = part.split(":", 1)[0].strip()
        parsed.append((framework, part))

    ordered_parts = [
        part
        for _, part in sorted(
            parsed,
            key=lambda item: _framework_sort_rank(item[0], framework_lens),
        )
    ]
    ordered_text = " | ".join(ordered_parts)
    if compact:
        return _compact_execution_group_display(ordered_text)
    return ordered_text


def _control_framework(control_id: str) -> str:
    """Infer framework family for display and neutral summary counts."""
    cid = (control_id or "").strip().upper()
    if re.match(r"^LLM\d{2}(?:\.\d+)?$", cid):
        return "OWASP LLM"
    if re.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", cid):
        return "NIST AI RMF"
    if re.match(r"^[A-Z]\d{3}(?:\.\d+)?$", cid):
        return "AIUC"
    return "Other"


def _format_rate(value: Any) -> str:
    if value is None:
        return "N/A"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"



st.set_page_config(page_title="AgentBench", page_icon="images/icon.png", layout="wide")
st.title("AgentBench — Control Validation")
st.caption("Evaluate whether AI agent controls hold under test conditions")






with st.sidebar:
    st.header("Run Settings")
    api_base_url = st.text_input("API URL", value="http://127.0.0.1:8000", key="api_url_input")
    vendor_endpoint = st.text_input("Agent Endpoint", value="http://127.0.0.1:9010/infer", key="agent_endpoint_input")
    agent_category = st.selectbox(
        "Agent Category",
        options=["chat_only", "rag_based", "code_generation", "autonomous", "domain_specific", "offline"],
        index=0,
        help="Tests are filtered to controls applicable to this agent type.",
        key="agent_category_select"
    )
    include_optional = st.checkbox("Include Optional Controls", value=True)

    controls_catalog: List[Dict[str, Any]] = []
    catalog_error = None
    has_loaded_assessment = "last_assessment" in st.session_state
    cached_catalog = st.session_state.get("controls_catalog_cache")
    if has_loaded_assessment and isinstance(cached_catalog, list):
        controls_catalog = cached_catalog
        if not controls_catalog:
            try:
                controls_catalog = fetch_controls_catalog(api_base_url)
                st.session_state["controls_catalog_cache"] = controls_catalog
            except requests.RequestException as exc:
                catalog_error = str(exc)
    elif not has_loaded_assessment:
        try:
            controls_catalog = fetch_controls_catalog(api_base_url)
            st.session_state["controls_catalog_cache"] = controls_catalog
        except requests.RequestException as exc:
            catalog_error = str(exc)

    if catalog_error:
        st.warning("Unable to load control catalog from API. You can still run all controls.")
        st.caption(catalog_error)

    control_set_option = st.selectbox(
        "Control Set",
        options=["All", "AIUC", "OWASP LLM", "NIST AI RMF"],
        index=0,
        help="Filter dashboard views by framework control set.",
        key="control_set_filter",
    )

    framework_lens = st.selectbox(
        "Primary Framework Lens",
        options=["Neutral", "AIUC", "OWASP LLM", "NIST AI RMF"],
        index=0,
        help="Controls ordering and display emphasis across mappings.",
        key="framework_lens_filter",
    )

    if control_set_option == "AIUC":
        control_set_controls = [
            item for item in controls_catalog
            if re.match(r"^[A-Z]\d{3}(?:\.\d+)?$", item.get("control_id", ""))
        ]
    elif control_set_option == "OWASP LLM":
        control_set_controls = [
            item for item in controls_catalog
            if re.match(r"^LLM\d{2}(?:\.\d+)?$", item.get("control_id", ""))
        ]
    elif control_set_option == "NIST AI RMF":
        control_set_controls = [
            item for item in controls_catalog
            if re.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", item.get("control_id", ""))
        ]
    else:
        control_set_controls = controls_catalog

    dashboard_controls_catalog = control_set_controls

    category_options = sorted({item["category"] for item in control_set_controls if item.get("category")})
    chosen_categories = st.multiselect("Categories", options=category_options, default=category_options)
    control_search = st.text_input("Find Controls", value="", placeholder="Type control ID, requirement, or evidence title", key="find_controls_input")

    visible_controls = control_set_controls
    if chosen_categories:
        visible_controls = [item for item in visible_controls if item.get("category") in chosen_categories]
    if control_search.strip():
        search_lower = control_search.lower().strip()
        visible_controls = [
            item
            for item in visible_controls
            if search_lower in item.get("control_id", "").lower()
            or search_lower in item.get("title", "").lower()
            or search_lower in item.get("evidence_title", "").lower()
        ]

    family_map: Dict[str, Dict[str, str]] = {}
    for item in visible_controls:
        control_id = item.get("control_id", "")
        if not control_id:
            continue
        family_id = control_id.split(".")[0]
        if family_id not in family_map:
            title = _clean_family_title(item.get("title", ""))
            if family_id.startswith("LLM"):
                label = f"OWASP LLM - {title}"
            else:
                label = f"{family_id} - {title}"
            family_map[family_id] = {
                "family_id": family_id,
                "label": label,
            }

    family_ids = sorted(family_map.keys(), key=_control_sort_key)
    selected_family_ids = st.multiselect(
        "Control Families",
        options=family_ids,
        format_func=lambda fid: family_map.get(fid, {}).get("label", fid),
        help="Select a family like A001 to include all sub-controls under that family.",
    )

    control_ids = [item["control_id"] for item in visible_controls if item.get("control_id")]
    control_labels = {
        item["control_id"]: (
            f"{item.get('control_id')} - "
            f"{_clean_evidence_label(item.get('control_id', ''), item.get('evidence_title', ''), item.get('title', ''))}"
        )
        for item in visible_controls
        if item.get("control_id")
    }


    selected_control_ids = st.multiselect(
        "Specific Sub-Controls",
        options=control_ids,
        format_func=lambda cid: control_labels.get(cid, cid),
        help="Select specific checks like A001.1, A001.2, A001.3.",
    )

    selected_scope_ids = sorted(set(selected_family_ids + selected_control_ids))
    if selected_scope_ids:
        st.caption(f"Selected scope: {', '.join(selected_scope_ids)}")
    else:
        st.caption("Selected scope: all controls in current filters")

    # Preview panel: show summary table of selected controls
    if selected_control_ids:
        st.markdown("**Preview: Selected Controls**")
        preview_rows = []
        for cid in selected_control_ids:
            ctrl = next((item for item in visible_controls if item.get("control_id") == cid), None)
            if ctrl:
                desc = ctrl.get("title") or "No description available."
                preview_rows.append({
                    "Control ID": cid,
                    "Description": desc
                })
        if preview_rows:
            import pandas as pd
            st.dataframe(pd.DataFrame(preview_rows), width='stretch', hide_index=True)
        else:
            st.info("No details available for selected controls.")


    allow_sensitive_probes = st.checkbox(
        "Allow sensitive data probes",
        value=False,
        help="Enable this to allow tests that may attempt to elicit or probe for sensitive data (e.g., SSNs, passwords)."
    )


    # User Settings Summary
    st.markdown("---")
    st.subheader("Current Settings")
    st.markdown(f"- **Sensitive probes:** {'ON' if allow_sensitive_probes else 'OFF'}")
    st.markdown(f"- **Optional controls:** {'ON' if include_optional else 'OFF'}")
    st.markdown(f"- **Agent category:** `{agent_category}`")
    st.markdown(f"- **Control set:** `{control_set_option}`")
    st.markdown(f"- **Framework lens:** `{framework_lens}`")
    if selected_scope_ids:
        st.markdown(f"- **Selected controls:** {', '.join(selected_scope_ids)}")
    else:
        st.markdown("- **Selected controls:** All in current filters")

    run_clicked = st.button("Run Assessment", width='stretch')

    st.markdown("---")
    st.subheader("Load Assessment Report")
    uploaded_report = st.file_uploader(
        "Upload JSON report",
        type=["json"],
        help="Upload a report file to view it in the dashboard."
    )
    if uploaded_report is not None:
        try:
            uploaded_bytes = uploaded_report.getvalue()
            upload_digest = hashlib.sha256(uploaded_bytes).hexdigest()
            if st.session_state.get("last_uploaded_digest") == upload_digest:
                uploaded_json = None
            else:
                uploaded_json = json.loads(uploaded_bytes)
                st.session_state["last_uploaded_digest"] = upload_digest

            if uploaded_json is None:
                pass
            elif not isinstance(uploaded_json, dict):
                st.error("Uploaded file is not a JSON object. Please upload a valid assessment report.")
            elif "summary" not in uploaded_json:
                st.error("Uploaded file is missing a top-level 'summary' key. Please ensure your report matches the expected format: { 'summary': { 'control_results': [...] } }")
            elif not isinstance(uploaded_json["summary"], dict):
                st.error("The 'summary' key must map to a JSON object. Please check your report format.")
            elif "control_results" not in uploaded_json["summary"]:
                st.error("The 'summary' object is missing the 'control_results' key. Please check your report format.")
            else:
                st.session_state["last_assessment"] = uploaded_json
                st.session_state["active_dashboard_view"] = "Overview"
                st.success("Uploaded report loaded successfully.")
                st.rerun()
        except Exception as e:
            st.error(f"Failed to load uploaded report: {e}")

summary: Dict[str, Any] | None = None

if run_clicked:
    try:
        with st.spinner("Running assessment..."):
            response = requests.post(
                f"{api_base_url.rstrip('/')}/assess",
                json={
                    "vendor_endpoint": vendor_endpoint,
                    "include_optional": include_optional,
                    "control_ids": selected_scope_ids or None,
                    "agent_category": agent_category,
                    "allow_sensitive_probes": allow_sensitive_probes,
                },
                timeout=600,
            )
            response.raise_for_status()
            payload = response.json()
            summary = payload["summary"]
            st.session_state["last_assessment"] = payload
            st.rerun()
            st.session_state["active_dashboard_view"] = "Overview"
    except requests.RequestException as exc:
        st.error(f"API request failed: {exc}")


# Always set payload and summary from session state if available
payload = None
summary = None
if "last_assessment" in st.session_state:
    payload = st.session_state["last_assessment"]
    if isinstance(payload, dict) and "summary" in payload:
        summary = payload["summary"]


def _render_homepage(
    controls_catalog: List[Dict[str, Any]],
    summary_data: Dict[str, Any] | None = None,
    payload_data: Dict[str, Any] | None = None,
) -> None:
    if controls_catalog:
        catalog_df = pd.DataFrame(controls_catalog)
        catalog_df["family"] = catalog_df["control_id"].apply(_control_family)
        catalog_df["framework"] = catalog_df["control_id"].apply(_control_framework)

        total_controls = str(len(catalog_df))
        family_count = str(catalog_df["family"].nunique())
        mandatory_count = str((catalog_df["mandatory_optional"].str.lower() == "mandatory").sum())
        optional_count = str((catalog_df["mandatory_optional"].str.lower() == "optional").sum())

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Controls", total_controls)
        m2.metric("Control Families", family_count)
        m3.metric("Mandatory", mandatory_count)
        m4.metric("Optional", optional_count)

        framework_counts = (
            catalog_df.groupby("framework", as_index=False)
            .size()
            .rename(columns={"size": "count"})
        )
        framework_counts = framework_counts.assign(
            _rank=framework_counts["framework"].map(lambda value: _framework_sort_rank(str(value), framework_lens))
        ).sort_values("_rank")
        framework_summary = ", ".join(
            f"{row['framework']}: {int(row['count'])}"
            for _, row in framework_counts.iterrows()
        )
        if framework_summary:
            st.caption(f"Framework mix: {framework_summary}")
    else:
        st.warning("Control catalog is unavailable. Check API URL in the sidebar and try again.")



    if summary_data is not None:
        st.subheader("Assessment Outcome")
        r1, r2, r3, r4, r5 = st.columns(5)
        statuses = (payload_data or {}).get("controls_by_status", {})
        assessed_controls = len(summary_data.get("control_results", []))
        catalog_controls = len(controls_catalog)
        skipped = int(statuses.get("SKIPPED", 0) or 0)
        payload_not_tested = int(statuses.get("NOT TESTED", 0) or 0)
        out_of_scope = max(catalog_controls - assessed_controls, 0)
        not_assessed = payload_not_tested + out_of_scope
        eligible = assessed_controls - skipped
        tested = sum(1 for c in summary_data.get("control_results", []) if c.get("tested"))

        # --- Prompt-level Test Pass Rate ---
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

        # --- Control-level Control Pass Rate ---
        controls = summary_data.get("control_results", [])
        total_controls = len(controls)
        pass_controls = sum(1 for c in controls if (c.get("status") or "").upper() == "PASS")
        control_pass_rate = (pass_controls / total_controls) if total_controls else None

        # Show Control Pass Rate as the main score
        r1.metric("Control Pass Rate (Main Score)", "N/A" if control_pass_rate is None else f"{control_pass_rate * 100:.1f}%", help="Percentage of controls with status = PASS (recommended for overall assessment)")
        r2.metric("Test Pass Rate (Prompt Avg)", "N/A" if test_pass_rate is None else f"{test_pass_rate * 100:.1f}%", help="Weighted average of all prompt results (PASS=1.0, PARTIAL=0.5, FAIL=0.0)")
        r3.metric("Green (Pass)", statuses.get("PASS", 0))
        r4.metric("Red (Fail/Partial)", statuses.get("FAIL", 0) + statuses.get("PARTIAL", 0))
        r5.metric("Gray (Not Assessed/Out of Scope)", not_assessed)
        st.caption(
            f"Coverage: {tested}/{eligible if eligible >= 0 else 0} tested ({skipped} skipped) | "
            f"Assessment scope: {assessed_controls}/{catalog_controls} controls"
        )
        st.info("Control Pass Rate is now the main score (recommended for reporting). Test Pass Rate reflects performance across all individual test cases. A control may fail even if most of its tests pass.")

        reliability = summary_data.get("control_reliability") or {}
        if reliability:
            st.subheader("Control Reliability")
            rel1, rel2, rel3, rel4 = st.columns(4)
            rel1.metric("Kill-Switch Success", _format_rate(reliability.get("kill_switch_success_rate")))
            rel2.metric("Unauthorized Actions Blocked", _format_rate(reliability.get("unauthorized_action_block_rate")))
            rel3.metric("Containment Timing", _format_rate(reliability.get("containment_timing_success_rate")))
            rel4.metric("Delayed Compliance Blocked", _format_rate(reliability.get("delayed_compliance_success_rate")))

            gate_state = "PASS" if reliability.get("passed") else "FAIL"
            st.write(f"Release Gate: **{gate_state}**")
            st.write(
                "Failure classes: "
                f"model behavior={int(reliability.get('model_behavior_failures', 0))}, "
                f"control enforcement={int(reliability.get('control_enforcement_failures', 0))}"
            )
            reasons = reliability.get("fail_reasons") or []
            if reasons:
                st.warning("Release gate failed for the following reasons:")
                for reason in reasons:
                    st.write(f"- {reason}")

    outcome_color_scale = alt.Scale(
        domain=["Pass", "Fail / Partial", "Not Assessed"],
        range=["#2E7D32", "#C62828", "#757575"],
    )

    st.subheader("Control By Family")
    if summary_data is None:
        if not controls_catalog:
            st.info("No control family data available.")
        else:
            catalog_df = pd.DataFrame(controls_catalog)
            if not catalog_df.empty:
                catalog_df["family"] = catalog_df["control_id"].apply(_control_family)
                family_counts = (
                    catalog_df.groupby("family", as_index=False)
                    .size()
                    .rename(columns={"family": "Family", "size": "Count"})
                    .sort_values("Count", ascending=False)
                )
                family_order = sorted(family_counts["Family"].unique(), key=_control_sort_key)

                family_chart = (
                    alt.Chart(family_counts)
                    .mark_bar(color="#1565C0")
                    .encode(
                        x=alt.X("Family:N", sort=family_order, title="Control Family"),
                        y=alt.Y("Count:Q", title="Number of Controls", axis=alt.Axis(format="d")),
                        tooltip=["Family", "Count"],
                    )
                    .properties(height=500)
                )
                st.altair_chart(family_chart, width='stretch')
            else:
                st.info("No control family data available.")
    else:
        family_rows = []
        for control in summary_data.get("control_results", []):
            control_id = control.get("control_id") or ""
            family = _control_family(control_id)
            family_rows.append(
                {
                    "Family": family,
                    "Outcome": _family_outcome_bucket(control),
                }
            )

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

            family_chart = (
                alt.Chart(grouped)
                .mark_bar()
                .encode(
                    x=alt.X("Family:N", sort=family_order, title="Control Family"),
                    y=alt.Y("Count:Q", title="Number of Controls", axis=alt.Axis(format="d")),
                    color=alt.Color("Outcome:N", scale=outcome_color_scale, legend=alt.Legend(title="Outcome")),
                    tooltip=["Family", "Outcome", "Count"],
                )
                .properties(height=500)
            )
            st.altair_chart(family_chart, width='stretch')

    st.subheader("Findings Per Control")
    if summary_data is None:
        findings_hist_df = _load_latest_findings_histogram()
        chart_label = "Fail/Partial Prompt Findings"
        empty_msg = "No prior assessment report found yet. Run an assessment to populate this bar graph."
        # Only show the empty message, do not show selectbox or chart
        st.info(empty_msg)
    else:
        findings_hist_df = _findings_histogram_from_summary(summary_data)
        chart_label = "Fail/Partial Prompt Findings"
        empty_msg = "No findings data available for the current assessment."
        if findings_hist_df.empty:
            st.info(empty_msg)
        else:
            # Extract family from control ID
            findings_hist_df["Family"] = findings_hist_df["Control"].apply(_control_family)
            # Get list of families and allow user to select
            families = sorted(findings_hist_df["Family"].unique(), key=_control_sort_key)
            selected_family = st.selectbox("Select Control Family", options=families, key="findings_family_select")
            # Filter by selected family
            family_findings = findings_hist_df[
                findings_hist_df["Family"] == selected_family
            ].sort_values("Control", key=lambda s: s.map(_control_sort_key))
            if family_findings.empty:
                st.info(f"No findings data for family {selected_family}.")
            else:
                # Convert Control to categorical to preserve order
                family_findings = family_findings.copy()
                control_order = sorted(family_findings["Control"].unique(), key=_control_sort_key)
                family_findings["Control"] = pd.Categorical(
                    family_findings["Control"],
                    categories=control_order,
                    ordered=True,
                )
                findings_chart = (
                    alt.Chart(family_findings)
                    .mark_bar(color="#EF6C00")
                    .encode(
                        x=alt.X("Findings:Q", title="Findings Count", axis=alt.Axis(format="d")),
                        y=alt.Y("Control:N", title="Control", sort=control_order),
                        tooltip=["Control", "Findings"],
                    )
                    .properties(height=400)
                )
                st.altair_chart(findings_chart, width='stretch')

    # --- Control Coverage Map ---
    if summary_data is not None:
        st.subheader("Control Coverage Map")
        coverage_rows = []
        for control in summary_data.get("control_results", []):
            coverage_rows.append({
                "Control": control.get("control_id"),
                "Category": control.get("category"),
                "Status": control.get("status"),
                "Reason": control.get("skipped_reason") or control.get("not_tested_reason") or "",
            })
        if coverage_rows:
            coverage_df = pd.DataFrame(coverage_rows)
            # Color map for status
            status_color = {
                "PASS": "#2E7D32",
                "FAIL": "#C62828",
                "PARTIAL": "#FFB300",
                "NOT TESTED": "#757575",
                "SKIPPED": "#90A4AE",
            }
            def highlight_status(row):
                color = status_color.get(str(row["Status"]).upper(), "#FFFFFF")
                return [f"background-color: {color}; color: #fff;" if col == "Status" else "" for col in row.index]
            st.dataframe(
                coverage_df.style.apply(highlight_status, axis=1),
                width='stretch',
            )
        else:
            st.info("No control coverage data available.")

    if controls_catalog:
        catalog_df = pd.DataFrame(controls_catalog)
        catalog_df["framework"] = catalog_df["control_id"].apply(_control_framework)
        preview_cols = ["control_id", "title", "evidence_title", "category", "mandatory_optional"]

        st.subheader("Control Catalog")
        with st.expander("Show Full Cross-Framework Control Catalog", expanded=False):
            catalog_preview_rows = [
                {
                    "Control": row.get("control_id", ""),
                    "Requirement": row.get("title", ""),
                    "Evidence": row.get("evidence_title", ""),
                    "Category": row.get("category", ""),
                    "Priority": row.get("mandatory_optional", ""),
                    "Framework": row.get("framework", ""),
                }
                for row in catalog_df.to_dict("records")
            ]
            catalog_preview_df = pd.DataFrame(catalog_preview_rows)
            st.dataframe(catalog_preview_df, width='stretch')

if summary is None:
    render_homepage(dashboard_controls_catalog)

if summary is not None:
    payload = st.session_state["last_assessment"]
    summary_data = summary

    nav_options = ["Overview", "Findings", "Controls", "JSON Output"]
    selected_view = st.radio(
        "Page",
        options=nav_options,
        key="active_dashboard_view",
        horizontal=True,
        label_visibility="collapsed",
    )

    if selected_view == "Overview":
        render_homepage(dashboard_controls_catalog, summary_data=summary_data, payload_data=payload)

    if selected_view == "Findings":
        st.subheader("Prompt-Level Findings")
        control_results = [
            control
            for control in summary_data.get("control_results", [])
            if _matches_control_set(control.get("control_id", ""), control_set_option)
        ]
        if not control_results:
            st.info(f"No controls available for findings view with control set '{control_set_option}'.")
        else:
            control_map = {
                control.get("control_id", ""): control
                for control in control_results
                if control.get("control_id")
            }
            all_control_ids = sorted(control_map.keys())
            failed_control_ids = sorted(
                [
                    cid
                    for cid, control in control_map.items()
                    if control.get("status") in {"FAIL", "PARTIAL"}
                ]
            )
            shutdown_failure_ids = sorted(
                [
                    cid
                    for cid, control in control_map.items()
                    if control.get("status") in {"FAIL", "PARTIAL"}
                    and str(control.get("control_id", "")).upper().startswith(("B006", "D003"))
                ]
            )
            automated_control_ids = sorted(
                [cid for cid, control in control_map.items() if control.get("tested")]
            )

            selection_key = "findings_selected_controls"
            if selection_key not in st.session_state:
                st.session_state[selection_key] = all_control_ids

            a1, a2, a3, a4, a5 = st.columns(5)
            if a1.button("All", width='stretch'):
                st.session_state[selection_key] = all_control_ids
            if a2.button("Automated", width='stretch'):
                st.session_state[selection_key] = automated_control_ids
            if a3.button("Failed/Partial", width='stretch'):
                st.session_state[selection_key] = failed_control_ids
            if a4.button("Shutdown Failures", width='stretch'):
                st.session_state[selection_key] = shutdown_failure_ids
            if a5.button("Clear", width='stretch'):
                st.session_state[selection_key] = []

            selection_df = pd.DataFrame(
                [
                    {
                        "Selected": cid in st.session_state[selection_key],
                        "Control": cid,
                        "Crosswalk Root": control_map[cid].get("crosswalk_root_id") or "",
                        "Frameworks": _format_framework_tags(control_map[cid].get("overlap_tags") or [], framework_lens),
                        "Mapped Controls": _compact_list_display(control_map[cid].get("overlap_control_ids") or []),
                        "Execution Group": _format_execution_group(control_map[cid].get("execution_group_id") or "", framework_lens, compact=True),
                        "Category": control_map[cid].get("category"),
                        "Status": control_map[cid].get("status"),
                        "Type": _friendly_classification(control_map[cid]),
                        "Failure Class": control_map[cid].get("failure_classification") or "",
                    }
                    for cid in all_control_ids
                ]
            )

            edited_df = st.data_editor(
                selection_df,
                width='stretch',
                hide_index=True,
                disabled=["Control", "Crosswalk Root", "Frameworks", "Mapped Controls", "Execution Group", "Category", "Status", "Type", "Failure Class"],
                column_config={"Selected": st.column_config.CheckboxColumn("Select")},
                key="findings_selector_table",
            )

            selected_ids = edited_df.loc[edited_df["Selected"], "Control"].tolist()
            st.session_state[selection_key] = selected_ids

            if not selected_ids:
                st.info("Select one or more controls to view detailed findings.")
            else:
                for cid in selected_ids:
                    selected = control_map[cid]
                    st.markdown(f"### {cid} - {selected.get('category', 'Uncategorized')}")
                    st.write(f"Status: **{selected.get('status', 'Unknown')}**")
                    st.write(f"Score: **{selected.get('score', 'n/a')}**")
                    st.write(f"Crosswalk Root: **{selected.get('crosswalk_root_id') or 'N/A'}**")
                    st.write(f"Framework Tags: **{_format_framework_tags(selected.get('overlap_tags') or [], framework_lens) or 'N/A'}**")
                    st.write(f"Mapped Controls: **{', '.join(selected.get('overlap_control_ids') or []) or 'N/A'}**")
                    st.write(f"Execution Group: **{_format_execution_group(selected.get('execution_group_id') or '', framework_lens, compact=False) or 'N/A'}**")
                    st.write(f"Failure Class: **{selected.get('failure_classification') or 'N/A'}**")

                    if not selected.get("tested"):
                        skipped_reason = selected.get("skipped_reason")
                        not_tested_reason = selected.get("not_tested_reason")
                        if skipped_reason and "sensitive data probe disabled" in skipped_reason.lower():
                            st.warning("This control was skipped because 'Allow sensitive data probes' was not enabled in the settings.")
                        elif skipped_reason:
                            st.info(skipped_reason)
                        elif not_tested_reason:
                            st.info(not_tested_reason)
                        else:
                            st.info("This control was not tested.")
                        continue

                    for idx, result in enumerate(selected.get("results", []), start=1):
                        prompt = result.get("prompt", "")
                        outcome = result.get("result", "")
                        reason = result.get("reason", "")
                        response_text = result.get("response", "")
                        error_types = result.get("error_types", None)
                        audit_log = result.get("audit_log", None)
                        verification_result = result.get("verification_result", None)
                        verification_reason = result.get("verification_reason", None)
                        with st.expander(f"{idx}. {outcome} - {prompt[:100]}"):
                            st.markdown("**Prompt**")
                            st.write(prompt)
                            st.markdown("**Why It Passed Or Failed**")
                            st.write(reason)
                            if error_types:
                                st.markdown("**Error Types (Taxonomy):**")
                                if isinstance(error_types, list) and error_types:
                                    cleaned_error_types = []
                                    for et in error_types:
                                        normalized = str(et).replace("\r", "").replace("\n", " ").strip()
                                        if normalized:
                                            cleaned_error_types.append(normalized)

                                    if cleaned_error_types:
                                        st.write(", ".join(cleaned_error_types))
                                    else:
                                        st.markdown("_None_")
                                else:
                                    st.markdown("_None_")
                            if audit_log:
                                # Only show audit log if at least one field is non-blank
                                mr = audit_log.get("matched_rule", "") if isinstance(audit_log, dict) else ""
                                mt = audit_log.get("matched_text", "") if isinstance(audit_log, dict) else ""
                                if mr or mt:
                                    st.markdown("**Audit Log:**")
                                    audit_lines = []
                                    if mr:
                                        audit_lines.append(f"- **Matched Rule:** {mr}")
                                    if mt:
                                        audit_lines.append(f"- **Matched Text:** {mt}")
                                    st.markdown("\n".join(audit_lines))
                                # else:  # Optionally show a placeholder
                                #     st.markdown("**Audit Log:** _N/A_")
                            st.markdown("**Agent Response**")
                            st.write(response_text)
                            if verification_result or verification_reason:
                                st.markdown(f"**Verification Agent Result:** {verification_result or 'N/A'}")
                                st.markdown(f"**Verification Agent Reason:** {verification_reason or 'N/A'}")

    if selected_view == "Controls":
        st.subheader("Control Results")
        filtered_control_results = [
            control
            for control in summary_data.get("control_results", [])
            if _matches_control_set(control.get("control_id", ""), control_set_option)
        ]
        flat_rows = []
        for control in filtered_control_results:
            overlap_tags = control.get("overlap_tags") or []
            mapped_controls = control.get("overlap_control_ids") or []
            execution_group = control.get("execution_group_id") or ""
            flat_rows.append(
                {
                    "Control": control.get("control_id"),
                    "Crosswalk Root": control.get("crosswalk_root_id") or "",
                    "Frameworks": _format_framework_tags(overlap_tags, framework_lens),
                    "Mapped Controls": _compact_list_display(mapped_controls),
                    "Execution Group": _format_execution_group(execution_group, framework_lens, compact=True),
                    "Category": control.get("category"),
                    "Type": _friendly_classification(control),
                    "Status": control.get("status"),
                    "Failure Class": control.get("failure_classification") or "",
                    "Score": control.get("score"),
                    "Test Suite": control.get("tested_by_definition"),
                    "Not Tested Reason": control.get("not_tested_reason"),
                }
            )

        controls_df = pd.DataFrame(flat_rows)
        if controls_df.empty:
            st.info(f"No control results available for control set '{control_set_option}'.")
        else:
            framework_values = sorted(
                {
                    tag
                    for control in filtered_control_results
                    for tag in (control.get("overlap_tags") or [])
                }
            )

            f1, f2, f3, f4, f5 = st.columns(5)
            status_choices = sorted([value for value in controls_df["Status"].dropna().unique()])
            type_choices = sorted([value for value in controls_df["Type"].dropna().unique()])
            category_choices = sorted([value for value in controls_df["Category"].dropna().unique()])
            failure_class_choices = sorted([value for value in controls_df["Failure Class"].dropna().unique() if value])

            selected_status = f1.multiselect("Status Filter", options=status_choices, default=status_choices)
            selected_types = f2.multiselect("Type Filter", options=type_choices, default=type_choices)
            selected_categories = f3.multiselect("Category Filter", options=category_choices, default=category_choices)
            selected_frameworks = f4.multiselect("Framework Filter", options=framework_values, default=framework_values)
            selected_failure_classes = f5.multiselect("Failure Class", options=failure_class_choices, default=failure_class_choices)

            framework_filtered_results = [
                control
                for control in filtered_control_results
                if not selected_frameworks
                or bool(set(control.get("overlap_tags") or []).intersection(selected_frameworks))
            ]
            framework_filtered_ids = {control.get("control_id") for control in framework_filtered_results if control.get("control_id")}

            filtered_df = controls_df[
                controls_df["Status"].isin(selected_status)
                & controls_df["Type"].isin(selected_types)
                & controls_df["Category"].isin(selected_categories)
                & controls_df["Control"].isin(framework_filtered_ids)
            ]

            if selected_failure_classes:
                filtered_df = filtered_df[
                    filtered_df["Failure Class"].isin(selected_failure_classes)
                ]

            if not filtered_df.empty:
                ordered_tuples = sorted(
                    filtered_df.itertuples(index=False, name=None),
                    key=lambda row: (
                        str(row[1] or ""),
                        str(row[4] or ""),
                        str(row[0] or ""),
                    ),
                )
                filtered_df = pd.DataFrame(ordered_tuples, columns=filtered_df.columns)

            st.dataframe(filtered_df, width='stretch')

    if selected_view == "JSON Output":
        st.subheader("JSON Output")
        report_path = summary_data.get("report_path")
        if report_path:
            try:
                with open(report_path, "r", encoding="utf-8") as handle:
                    report_data = handle.read()
                st.download_button(
                    "Download Report JSON",
                    data=report_data,
                    file_name=report_path.split("/")[-1],
                    mime="application/json",
                    width='stretch',
                )
            except OSError:
                st.warning("Report file could not be opened for download.")

        st.json(payload)

