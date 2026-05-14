import streamlit as st
import pandas as pd
from typing import Optional, Dict

def table_block(df: pd.DataFrame, title: Optional[str] = None, expander: Optional[Dict] = None, width: str = 'stretch'):
    """
    Render a Streamlit dataframe or table, optionally inside an expander.
    Args:
        df: DataFrame to display.
        title: Optional subheader above the table.
        expander: Dict with keys 'label' (str) and 'expanded' (bool) for expander, or None for no expander.
        width: Width argument for st.dataframe/st.table.
    """
    if title:
        st.subheader(title)
    if expander:
        with st.expander(expander.get('label', 'Show Table'), expanded=expander.get('expanded', False)):
            st.dataframe(df, width=width)
    else:
        st.dataframe(df, width=width)
