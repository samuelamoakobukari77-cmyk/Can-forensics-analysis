"""
timeline_ui.py

Streamlit UI: attack timeline chart + incident log + play/pause replay
dashboard for the CAN Bus Forensic Analysis capstone project.

HOW TO INTEGRATE INTO YOUR EXISTING APP
----------------------------------------
1. Copy timeline_replay.py and this file into your project folder.
   (pip install plotly if you don't already have it)

2. Wherever your model finishes classifying a batch of packets, you
   should have a DataFrame with columns: timestamp, can_id, label,
   confidence (and optionally dlc, data). That's the only integration
   point — feed YOUR real dataframe in instead of the sample one:

       from timeline_ui import render_timeline_tab
       render_timeline_tab(your_classified_df)

3. Add it as a new tab/page, e.g. "Attack Timeline", alongside your
   existing detection results tab and the chain-of-custody tab from
   the ledger module.

Run `streamlit run timeline_ui.py` on its own to see a standalone demo
with synthetic data.
"""

import time

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from timeline_replay import (
    ReplayEngine,
    compute_live_stats,
    extract_incidents,
    generate_sample_can_log,
)

LABEL_COLORS = {
    "Normal": "#2ca02c",
    "DoS": "#d62728",
    "Fuzzy": "#ff7f0e",
    "Spoofing": "#9467bd",
}


def _color_for(label: str) -> str:
    return LABEL_COLORS.get(label, "#7f7f7f")


def build_timeline_figure(df: pd.DataFrame, played_up_to: float | None = None) -> go.Figure:
    """
    Scatter timeline: x = time, y = CAN ID (categorical), colour = label.
    If played_up_to is given, packets after that time are dimmed, so the
    chart doubles as a "what's been revealed so far" replay view.
    """
    fig = go.Figure()

    for label, color in LABEL_COLORS.items():
        sub = df[df["label"] == label]
        if sub.empty:
            continue

        if played_up_to is not None:
            opacity = [1.0 if t <= played_up_to else 0.12 for t in sub["timestamp"]]
        else:
            opacity = 1.0

        fig.add_trace(go.Scatter(
            x=sub["timestamp"],
            y=sub["can_id"],
            mode="markers",
            name=label,
            marker=dict(color=color, size=7, opacity=opacity),
            hovertemplate="t=%{x:.3f}s<br>CAN ID=%{y}<br>label=" + label + "<extra></extra>",
        ))

    if played_up_to is not None:
        fig.add_vline(x=played_up_to, line_width=2, line_dash="dash", line_color="white")

    fig.update_layout(
        height=380,
        xaxis_title="Time (s)",
        yaxis_title="CAN ID",
        legend_title="Label",
        margin=dict(l=10, r=10, t=30, b=10),
    )
    return fig


def render_incident_log(df: pd.DataFrame) -> None:
    incidents = extract_incidents(df)
    st.markdown("#### 🚨 Incident log")
    if not incidents:
        st.info("No attack incidents detected in this log.")
        return
    inc_df = pd.DataFrame([i.to_dict() for i in incidents])
    st.dataframe(inc_df, use_container_width=True)


def render_live_dashboard(stats: dict) -> None:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Packets in window", stats["packets_in_window"])
    col2.metric("Rate (pkt/s, est.)", stats["packets_per_sec_est"])
    col3.metric("% attack traffic", f"{stats['pct_attack']}%")
    col4.metric("Unique CAN IDs", stats["unique_can_ids"])

    if stats["active_alert"]:
        st.error(f"⚠️ Active alert — dominant label right now: **{stats['dominant_label']}**")
    else:
        st.success(f"Nominal — dominant label right now: **{stats['dominant_label']}**")


def render_timeline_tab(df: pd.DataFrame) -> None:
    st.subheader("📈 Attack Timeline & Replay")
    st.caption(
        "Full timeline of classified traffic below. Use the replay controls to step through "
        "the incident the way you'd narrate it live during your defense."
    )

    # --- static full timeline ---
    st.plotly_chart(build_timeline_figure(df), use_container_width=True, key="static_timeline")

    render_incident_log(df)

    st.markdown("---")
    st.markdown("#### ▶️ Replay")

    if "replay_engine" not in st.session_state or st.session_state.get("replay_df_id") != id(df):
        st.session_state.replay_engine = ReplayEngine(df, dashboard_window_seconds=2.0)
        st.session_state.replay_df_id = id(df)
        st.session_state.playing = False

    engine: ReplayEngine = st.session_state.replay_engine

    c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
    if c1.button("⏮️ Reset"):
        engine.reset()
        st.session_state.playing = False
    if c2.button("⏸️ Pause" if st.session_state.playing else "▶️ Play"):
        st.session_state.playing = not st.session_state.playing
    step_size = c3.selectbox("Step size (packets)", [1, 5, 10, 25], index=1)
    speed = c4.slider("Playback speed (packets per refresh)", 1, 50, 10)

    st.slider(
        "Scrub to time (s)",
        min_value=float(df["timestamp"].min()),
        max_value=float(df["timestamp"].max()),
        value=float(engine.current_time),
        key="scrub_slider",
        on_change=lambda: engine.jump_to_time(st.session_state.scrub_slider),
    )

    st.plotly_chart(
        build_timeline_figure(df, played_up_to=engine.current_time),
        use_container_width=True,
        key="replay_timeline",
    )

    render_live_dashboard(compute_live_stats(engine.get_dashboard_window()))

    st.caption(f"Playhead: t = {engine.current_time:.3f}s  |  packet {engine.current_index + 1}/{engine.total_packets}")

    if st.session_state.playing and not engine.is_finished():
        engine.step(speed)
        time.sleep(0.15)
        st.rerun()
    elif st.session_state.playing and engine.is_finished():
        st.session_state.playing = False
        st.info("Replay finished.")


# --------------------------------------------------------------------------
# Standalone demo
# --------------------------------------------------------------------------

if __name__ == "__main__":
    st.set_page_config(page_title="CAN Forensics — Attack Timeline", layout="wide")
    st.title("CAN Bus Forensics — Attack Timeline & Replay Demo")

    if "demo_df" not in st.session_state:
        st.session_state.demo_df = generate_sample_can_log(duration_seconds=45, n_incidents=3, seed=42)

    render_timeline_tab(st.session_state.demo_df)
