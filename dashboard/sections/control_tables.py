import streamlit as st
import pandas as pd

def render_control_tables(catalog_df):
    if not catalog_df.empty:
        aiuc_df = catalog_df[catalog_df["control_id"].str.match(r"^[A-Z]\d{3}(?:\.\d+)?$", na=False)]
        owasp_df = catalog_df[catalog_df["control_id"].str.match(r"^LLM\d{2}(?:\.\d+)?$", na=False)]
        nist_df = catalog_df[catalog_df["control_id"].str.match(r"^(GOVERN|MANAGE|MAP|MEASURE)\d+(?:\.\d+)?$", na=False)]
        preview_cols = ["control_id", "title", "evidence_title", "category", "mandatory_optional"]
        st.subheader("All AIUC-1 Controls")
        with st.expander("Show Full AIUC-1 Control Catalog"):
            st.dataframe(
                aiuc_df[preview_cols].rename(
                    columns={
                        "control_id": "Control",
                        "title": "Requirement",
                        "evidence_title": "Evidence",
                        "category": "Category",
                        "mandatory_optional": "Priority",
                    }
                ),
                width='stretch',
            )
        st.subheader("All OWASP LLM Controls")
        with st.expander("Show Full OWASP LLM Control Catalog"):
            st.dataframe(
                owasp_df[preview_cols].rename(
                    columns={
                        "control_id": "Control",
                        "title": "Requirement",
                        "evidence_title": "Evidence",
                        "category": "Category",
                        "mandatory_optional": "Priority",
                    }
                ),
                width='stretch',
            )
        st.subheader("All NIST AI RMF Controls")
        with st.expander("Show Full NIST AI RMF Control Catalog"):
            st.dataframe(
                nist_df[preview_cols].rename(
                    columns={
                        "control_id": "Control",
                        "title": "Requirement",
                        "evidence_title": "Evidence",
                        "category": "Category",
                        "mandatory_optional": "Priority",
                    }
                ),
                width='stretch',
            )
