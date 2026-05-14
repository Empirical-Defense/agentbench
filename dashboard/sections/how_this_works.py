import streamlit as st

def render_how_this_works():
    st.subheader("How This Works")
    st.markdown(
        "1. Select an API URL and agent endpoint.\n"
        "2. Choose AIUC-1 families (for example, A001) or specific sub-controls (for example, A001.1).\n"
        "3. Run the assessment and review red/green/gray outcomes.\n"
        "4. Use Findings for prompt-level detail and Controls for full control status."
    )
