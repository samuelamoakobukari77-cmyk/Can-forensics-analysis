"""
shap_ui.py

Streamlit UI for SHAP-based detection explainability.

HOW TO INTEGRATE INTO YOUR EXISTING APP
----------------------------------------
1. Copy train_demo_model.py, shap_explain.py, and this file into your
   project folder. (pip install shap joblib if not already installed)

2. TODAY (no real model yet): just run this file standalone —
   it trains a demo model on synthetic data automatically the first
   time it's needed, so you can see and demo the whole feature now.

3. WHEN YOU HAVE YOUR REAL TRAINED MODEL:
   a. Replace `build_feature_row()` in train_demo_model.py with
      however YOUR pipeline turns a raw packet into a feature vector
      (or just import your own feature-engineering function instead).
   b. Save your real model with joblib.dump(your_model, "model.joblib")
      and your real feature list to feature_names.json.
   c. In your main app, wherever you show a detected/flagged packet,
      add a "why?" button that calls:

          from shap_explain import DetectionExplainer
          from shap_ui import render_shap_tab

          explainer = DetectionExplainer.from_files()
          render_shap_tab(explainer, all_classified_packets_df, selected_row_dict)

Nothing else changes — the UI and explanation logic are model-agnostic
as long as your model has .predict_proba().
"""

import os

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from shap_explain import DetectionExplainer
from train_demo_model import FEATURE_NAMES, generate_synthetic_training_data, train_and_save


def _ensure_demo_model_exists():
    if not (os.path.exists("model.joblib") and os.path.exists("feature_names.json")):
        with st.spinner("First run: training demo model..."):
            train_and_save()


def build_waterfall_figure(explanation) -> go.Figure:
    top = explanation.top_n(8)
    top_sorted = sorted(top, key=lambda c: c.shap_value)

    colors = ["#d62728" if c.shap_value > 0 else "#2ca02c" for c in top_sorted]
    fig = go.Figure(go.Bar(
        x=[c.shap_value for c in top_sorted],
        y=[f"{c.feature} = {c.value:g}" for c in top_sorted],
        orientation="h",
        marker_color=colors,
    ))
    fig.update_layout(
        title=f"Why the model predicted: {explanation.predicted_label} ({explanation.predicted_confidence:.1%} confidence)",
        xaxis_title="SHAP value (→ toward attack, ← toward normal)",
        height=350,
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig


def build_global_importance_figure(importance_df: pd.DataFrame) -> go.Figure:
    top = importance_df.head(10).sort_values("mean_abs_shap")
    fig = go.Figure(go.Bar(
        x=top["mean_abs_shap"],
        y=top["feature"],
        orientation="h",
        marker_color="#1f77b4",
    ))
    fig.update_layout(
        title="Overall feature importance (mean |SHAP value| across sample)",
        xaxis_title="Mean |SHAP value|",
        height=350,
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig


def render_shap_tab(explainer: DetectionExplainer, packets_df: pd.DataFrame, selected_row: dict = None) -> None:
    st.subheader("🔍 Why did the model flag this?")
    st.caption(
        "SHAP explains individual detections in terms of the features that drove them, "
        "and shows which features matter most to the model overall."
    )

    tab1, tab2 = st.tabs(["Explain a specific packet", "Global feature importance"])

    with tab1:
        if selected_row is None:
            st.markdown("Pick a packet from the log to explain:")
            idx = st.number_input("Row index", min_value=0, max_value=len(packets_df) - 1, value=0, step=1)
            selected_row = packets_df.iloc[idx][FEATURE_NAMES].to_dict()
            true_label = packets_df.iloc[idx].get("label", None)
            if true_label is not None:
                st.caption(f"(Ground-truth label for this row: {true_label})")

        explanation = explainer.explain_instance(selected_row)
        st.plotly_chart(build_waterfall_figure(explanation), use_container_width=True)
        st.markdown(f"**Summary:** {explanation.to_summary_text()}")

        with st.expander("Full feature values for this packet"):
            st.json(selected_row)

    with tab2:
        if st.button("Compute global feature importance (samples the log)"):
            with st.spinner("Computing SHAP values across a sample..."):
                importance = explainer.global_feature_importance(packets_df)
            st.plotly_chart(build_global_importance_figure(importance), use_container_width=True)
            st.dataframe(importance, use_container_width=True)
        else:
            st.info("Click the button above — this samples up to 300 packets and can take a few seconds.")


# --------------------------------------------------------------------------
# Standalone demo
# --------------------------------------------------------------------------

if __name__ == "__main__":
    st.set_page_config(page_title="CAN Forensics — SHAP Explainability", layout="wide")
    st.title("CAN Bus Forensics — SHAP Explainability Demo")
    st.caption(
        "Running on a DEMO model trained on synthetic data (see train_demo_model.py docstring "
        "for how to swap in your real trained model)."
    )

    _ensure_demo_model_exists()

    if "shap_demo_df" not in st.session_state:
        st.session_state.shap_demo_df = generate_synthetic_training_data(n_rows=500, seed=99)
    if "shap_explainer" not in st.session_state:
        st.session_state.shap_explainer = DetectionExplainer.from_files()

    render_shap_tab(st.session_state.shap_explainer, st.session_state.shap_demo_df)
