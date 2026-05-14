import streamlit as st
import pandas as pd

def render_catalog_summary(catalog_df):
    if not catalog_df.empty:
        # Ensure family column exists
        if "family" not in catalog_df.columns:
            catalog_df["family"] = catalog_df["control_id"].apply(lambda cid: cid.split(".")[0] if isinstance(cid, str) else "")
        aiuc_df = catalog_df[catalog_df["control_id"].str.match(r"^[A-Z]\d{3}(?:\.\d+)?$", na=False)]
        owasp_df = catalog_df[catalog_df["control_id"].str.match(r"^LLM\d{2}(?:\.\d+)?$", na=False)]
        nist_df = catalog_df[catalog_df["control_id"].str.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", na=False)]
        st.subheader("Catalog Summary")
        st.caption(
            f"AIUC: {len(aiuc_df)} | OWASP LLM: {len(owasp_df)} | NIST AI RMF: {len(nist_df)}"
        )
        total_controls = len(catalog_df)
        family_count = catalog_df["family"].nunique()
        mandatory_count = (catalog_df["mandatory_optional"].str.lower() == "mandatory").sum()
        optional_count = (catalog_df["mandatory_optional"].str.lower() == "optional").sum()
        from dashboard.components.metric_row import metric_row
        metric_row([
            ("Total Controls", total_controls),
            ("Control Families", family_count),
            ("Mandatory", mandatory_count),
            ("Optional", optional_count),
        ])
