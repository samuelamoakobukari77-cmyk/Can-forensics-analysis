"""
theme.py

Visual theme for the CAN Bus Forensic Analysis app.

IMPORTANT: this version uses ONLY native Streamlit components (st.metric,
st.dataframe with pandas Styler, st.columns, st.plotly_chart, emoji) plus
the app's .streamlit/config.toml for color theming. It deliberately does
NOT inject raw <style>/<link> HTML via st.markdown(unsafe_allow_html=True)
— that approach was tried and, in this deployment environment, the tags
were being stripped and their text content rendered as literal visible
text on the page. Native components can't have that failure mode: there's
no HTML string for anything to mis-parse.

Pure presentation layer — none of this touches detection, the ledger,
SHAP, or PDF generation.
"""

import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go

# --------------------------------------------------------------------------
# Palette — also mirrored in .streamlit/config.toml for the app-wide theme
# --------------------------------------------------------------------------

BG = "#0A0C10"
PANEL = "#111318"
ACCENT = "#74f5ff"
DANGER = "#ffb4ab"
WARN = "#f59e0b"
OK = "#22c55e"
TEXT_MUTED = "#b9cacb"

LABEL_COLORS = {
    "Normal": "#4ade80",
    "DoS": "#ffb4ab",
    "Fuzzy": "#fb923c",
    "Spoofing": "#c084fc",
}

LABEL_EMOJI = {
    "Normal": "🟢",
    "DoS": "🔴",
    "Fuzzy": "🟠",
    "Spoofing": "🟣",
}


def inject_theme() -> None:
    """
    No-op kept for backwards compatibility with app.py's call site.
    All theming now comes from .streamlit/config.toml, which Streamlit
    applies natively — nothing to inject here.
    """
    pass


def severity_line(label: str, count: int, total: int) -> str:
    """Plain-markdown (no raw HTML) colored indicator line for a label count."""
    emoji = LABEL_EMOJI.get(label, "⚪")
    pct = count / total if total else 0
    return f"{emoji} **{label}** — {count} packets ({pct:.1%} of total)"


def animated_metric_row(items: list[tuple[str, str, float, str]]) -> None:
    """
    Renders a row of count-up animated metric cards using a sandboxed
    HTML component (components.html — a real iframe, not markdown-parsed
    text, so it isn't subject to the tag-stripping issue above).

    items: list of (label, icon, target_number, suffix) tuples.
    """
    cards_html = ""
    for i, (label, icon, target, suffix) in enumerate(items):
        cards_html += (
            f'<div class="am-card" style="animation-delay:{i * 0.08}s;">'
            f'<div class="am-icon">{icon}</div>'
            f'<div class="am-value" data-target="{target}" data-suffix="{suffix}">0{suffix}</div>'
            f'<div class="am-label">{label}</div>'
            f'</div>'
        )

    html = (
        '<div class="am-row">' + cards_html + '</div>'
        '<style>'
        'body{margin:0;background:transparent;}'
        '.am-row{display:flex;gap:14px;flex-wrap:wrap;font-family:system-ui,sans-serif;}'
        '.am-card{flex:1;min-width:140px;background:#111318;border:1px solid #2a2f3a;'
        'border-radius:10px;padding:16px 18px;opacity:0;animation:amFadeIn 0.5s ease forwards;}'
        '.am-icon{font-size:1.3rem;margin-bottom:4px;}'
        '.am-value{font-size:1.9rem;font-weight:700;color:#e2e2e8;font-family:monospace;}'
        '.am-label{color:#b9cacb;font-size:0.68rem;margin-top:4px;font-family:monospace;'
        'letter-spacing:0.1em;text-transform:uppercase;}'
        '@keyframes amFadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}'
        '</style>'
        '<script>'
        "const vals=document.querySelectorAll('.am-value');"
        'vals.forEach(el=>{'
        "const target=parseFloat(el.getAttribute('data-target'));"
        "const suffix=el.getAttribute('data-suffix');"
        'const isInt=Number.isInteger(target);'
        'let start=null;const duration=800;'
        'function step(ts){if(!start)start=ts;'
        'const progress=Math.min((ts-start)/duration,1);'
        'const eased=1-Math.pow(1-progress,3);'
        'const current=target*eased;'
        "el.textContent=(isInt?Math.round(current):current.toFixed(1))+suffix;"
        'if(progress<1)requestAnimationFrame(step);}'
        'requestAnimationFrame(step);});'
        '</script>'
    )
    components.html(html, height=120 + (14 if len(items) > 4 else 0))


def threat_gauge(attack_pct: float, dominant_label: str) -> go.Figure:
    """A gauge showing overall threat severity based on % attack traffic."""
    color = LABEL_COLORS.get(dominant_label, ACCENT) if attack_pct > 0 else OK

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_pct,
        number={"suffix": "%", "font": {"color": "#e2e2e8", "size": 40}},
        title={"text": f"Threat level — dominant: {dominant_label}", "font": {"color": TEXT_MUTED, "size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_MUTED},
            "bar": {"color": color},
            "bgcolor": PANEL,
            "borderwidth": 1,
            "bordercolor": "#2a2f3a",
            "steps": [
                {"range": [0, 15], "color": "#14532d"},
                {"range": [15, 45], "color": "#78350f"},
                {"range": [45, 100], "color": "#7f1d1d"},
            ],
        },
    ))
    fig.update_layout(
        height=260,
        margin=dict(l=20, r=20, t=50, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e2e2e8"},
    )
    return fig


def pursuit_vehicle_banner(case_id: str = "", packet_count: int = 0) -> None:
    """
    Hero banner using only native Streamlit elements (container, columns,
    markdown text with no raw tags, metric). Real case_id/packet_count
    values only — nothing fabricated.
    """
    with st.container(border=True):
        c1, c2 = st.columns([3, 1])
        with c1:
            st.markdown("🛰️ **ACTIVE SCAN**")
            st.markdown("##### Digital Forensics Division — In-Vehicle Network Capture")
        with c2:
            st.metric("Case ID", case_id or "—")
            st.metric("Packets", f"{packet_count:,}")


def styled_recent_traffic(df, n: int = 6):
    """
    Returns a pandas Styler for the most recent N classified packets,
    color-coded by label — rendered via st.dataframe(), which is a
    native Streamlit component and handles the styling reliably (no
    raw HTML string involved on our side).
    """
    recent = df.tail(n).iloc[::-1][["timestamp", "can_id", "dlc", "data", "label", "confidence"]].copy()

    def highlight_label(row):
        color = LABEL_COLORS.get(row["label"], TEXT_MUTED)
        return [f"color: {color}; font-weight: 700" if col == "label" else "" for col in row.index]

    return recent.style.apply(highlight_label, axis=1)


def animated_pipeline_progress(steps: list[str]) -> None:
    """Kept for compatibility — native st.status is used directly in app.py."""
    return st.status("Running forensic pipeline...", expanded=True)
