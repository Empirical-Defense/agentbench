import streamlit as st
from typing import List, Tuple, Optional

def metric_row(metrics: List[Tuple[str, str]], widths: Optional[List[float]] = None):
    """
    Render a row of Streamlit metric cards.
    Args:
        metrics: List of (label, value) pairs.
        widths: Optional list of column width ratios (must sum to 1.0).
    """
    if widths and len(widths) == len(metrics):
        cols = st.columns(widths)
    else:
        cols = st.columns(len(metrics))
    for col, (label, value) in zip(cols, metrics):
        col.metric(label, value)
