import streamlit as st
import altair as alt
import pandas as pd
from typing import Optional, Dict, Any

def altair_chart_block(
    chart: alt.Chart,
    title: Optional[str] = None,
    expander: Optional[Dict[str, Any]] = None,
    width: str = 'stretch',
    height: Optional[int] = None,
):
    """
    Render an Altair chart in Streamlit, optionally inside an expander and with a title.
    Args:
        chart: Altair chart object.
        title: Optional subheader above the chart.
        expander: Dict with keys 'label' (str) and 'expanded' (bool) for expander, or None for no expander.
        width: Width argument for st.altair_chart.
        height: Optional height override for chart (if not set in chart itself).
    """
    if title:
        st.subheader(title)
    if height:
        chart = chart.properties(height=height)
    if expander:
        with st.expander(expander.get('label', 'Show Chart'), expanded=expander.get('expanded', False)):
            st.altair_chart(chart, width=width)
    else:
        st.altair_chart(chart, width=width)
