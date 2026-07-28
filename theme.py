"""
theme.py

Visual theme for the CAN Bus Forensic Analysis app: dark
"digital forensics lab" aesthetic, animated metric cards, a
severity gauge, and a multi-step animated loading sequence.

Pure presentation layer — none of this touches detection, the
ledger, SHAP, or PDF generation. Safe to tweak colors/copy here
without risk to the underlying pipeline.
"""

import time

import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

# --------------------------------------------------------------------------
# Palette (kept consistent with timeline_ui.LABEL_COLORS)
# --------------------------------------------------------------------------

BG = "#0a0e17"
PANEL = "#111826"
BORDER = "#1f2937"
ACCENT = "#38bdf8"
DANGER = "#ef4444"
WARN = "#f59e0b"
OK = "#22c55e"
TEXT_MUTED = "#94a3b8"

LABEL_COLORS = {
    "Normal": "#22c55e",
    "DoS": "#ef4444",
    "Fuzzy": "#f59e0b",
    "Spoofing": "#a855f7",
}


def inject_theme() -> None:
    """Injects the dark forensics theme. Call once near the top of main()."""
    st.markdown(
        f"""
        <style>
        .stApp {{
            background: radial-gradient(circle at 20% 0%, #0d1420 0%, {BG} 55%);
        }}

        [data-testid="stSidebar"] {{
            background: {PANEL};
            border-right: 1px solid {BORDER};
        }}

        h1, h2, h3 {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            letter-spacing: 0.3px;
        }}

        h1 {{
            background: linear-gradient(90deg, #e2e8f0 0%, {ACCENT} 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        code, .mono {{
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
        }}

        [data-testid="stMetric"] {{
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 10px;
            padding: 14px 16px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        [data-testid="stMetric"]:hover {{
            transform: translateY(-2px);
            border-color: {ACCENT};
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 4px;
        }}
        .stTabs [data-baseweb="tab"] {{
            background: {PANEL};
            border-radius: 8px 8px 0 0;
            border: 1px solid {BORDER};
        }}
        .stTabs [aria-selected="true"] {{
            background: linear-gradient(180deg, {ACCENT}22 0%, {PANEL} 100%);
            border-bottom: 2px solid {ACCENT};
        }}

        .badge {{
            display: inline-block;
            padding: 3px 12px;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.4px;
            border: 1px solid currentColor;
        }}

        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(8px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
        .fade-in {{ animation: fadeInUp 0.45s ease both; }}

        div[data-testid="stDataFrame"] {{
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def severity_badge(label: str) -> str:
    color = LABEL_COLORS.get(label, "#7f7f7f")
    return f'<span class="badge" style="color:{color};">{label}</span>'


def animated_metric_row(items: list[tuple[str, str, float, str]]) -> None:
    """
    Renders a row of count-up animated metric cards.

    items: list of (label, icon, target_number, suffix) tuples.
    Numbers count up from 0 to target over ~800ms when the component
    first renders. Non-numeric displays should just use st.metric instead.
    """
    cards_html = ""
    for i, (label, icon, target, suffix) in enumerate(items):
        cards_html += f"""
        <div class="am-card" style="animation-delay:{i * 0.08}s;">
            <div class="am-icon">{icon}</div>
            <div class="am-value" data-target="{target}" data-suffix="{suffix}">0{suffix}</div>
            <div class="am-label">{label}</div>
        </div>
        """

    html = f"""
    <div class="am-row">{cards_html}</div>
    <style>
        .am-row {{
            display: flex;
            gap: 14px;
            flex-wrap: wrap;
            font-family: 'Segoe UI', system-ui, sans-serif;
        }}
        .am-card {{
            flex: 1;
            min-width: 140px;
            background: linear-gradient(180deg, #131b2c 0%, #0e1420 100%);
            border: 1px solid {BORDER};
            border-radius: 12px;
            padding: 16px 18px;
            opacity: 0;
            animation: amFadeIn 0.5s ease forwards;
            box-shadow: 0 0 0 rgba(56,189,248,0);
            transition: box-shadow 0.2s ease;
        }}
        .am-card:hover {{ box-shadow: 0 0 16px rgba(56,189,248,0.15); }}
        .am-icon {{ font-size: 1.4rem; margin-bottom: 4px; }}
        .am-value {{
            font-size: 2rem;
            font-weight: 700;
            color: #e2e8f0;
            font-family: 'JetBrains Mono', monospace;
        }}
        .am-label {{ color: {TEXT_MUTED}; font-size: 0.85rem; margin-top: 2px; }}
        @keyframes amFadeIn {{
            from {{ opacity: 0; transform: translateY(10px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
    <script>
        const vals = document.querySelectorAll('.am-value');
        vals.forEach(el => {{
            const target = parseFloat(el.getAttribute('data-target'));
            const suffix = el.getAttribute('data-suffix');
            const isInt = Number.isInteger(target);
            let start = null;
            const duration = 800;
            function step(ts) {{
                if (!start) start = ts;
                const progress = Math.min((ts - start) / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                const current = target * eased;
                el.textContent = (isInt ? Math.round(current) : current.toFixed(1)) + suffix;
                if (progress < 1) requestAnimationFrame(step);
            }}
            requestAnimationFrame(step);
        }});
    </script>
    """
    components.html(html, height=120 + (14 if len(items) > 4 else 0))


def threat_gauge(attack_pct: float, dominant_label: str) -> go.Figure:
    """A gauge showing overall threat severity based on % attack traffic."""
    color = LABEL_COLORS.get(dominant_label, ACCENT) if attack_pct > 0 else OK

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=attack_pct,
        number={"suffix": "%", "font": {"color": "#e2e8f0", "size": 40}},
        title={"text": f"Threat level — dominant: {dominant_label}", "font": {"color": TEXT_MUTED, "size": 14}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_MUTED},
            "bar": {"color": color},
            "bgcolor": PANEL,
            "borderwidth": 1,
            "bordercolor": BORDER,
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
        font={"color": "#e2e8f0"},
    )
    return fig


def animated_pipeline_progress(steps: list[str]) -> None:
    """
    Runs a short animated multi-step progress sequence using st.status,
    used while the real detection pipeline runs underneath. Call this
    as a context manager replacement: it just cosmetically narrates the
    stages while the caller does the real work between the yields.
    """
    return st.status("Running forensic pipeline...", expanded=True)


def pursuit_vehicle_banner() -> None:
    """
    Original SVG illustration of an unmarked high-performance pursuit
    vehicle in the app's cyber/forensics color scheme — not a photo or
    trademarked design, safe to bundle with the app. Purely decorative,
    sits at the top of the Executive Summary tab.
    """
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, {PANEL} 0%, #0c1220 100%);
            border: 1px solid {BORDER};
            border-radius: 14px;
            padding: 18px 24px;
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 18px;
        " class="fade-in">
            <svg width="140" height="60" viewBox="0 0 140 60" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="bodyGrad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stop-color="#1e293b"/>
                        <stop offset="100%" stop-color="#0f172a"/>
                    </linearGradient>
                </defs>
                <path d="M8 42 L20 24 Q30 16 50 16 L95 16 Q110 16 118 30 L128 42
                         Q130 46 126 46 L12 46 Q6 46 8 42 Z"
                      fill="url(#bodyGrad)" stroke="{ACCENT}" stroke-width="1.2"/>
                <path d="M40 22 L52 22 L48 34 L36 34 Z" fill="{ACCENT}" opacity="0.35"/>
                <path d="M56 22 L86 22 L88 34 L54 34 Z" fill="{ACCENT}" opacity="0.35"/>
                <circle cx="30" cy="46" r="8" fill="#0a0e17" stroke="{TEXT_MUTED}" stroke-width="1.5"/>
                <circle cx="106" cy="46" r="8" fill="#0a0e17" stroke="{TEXT_MUTED}" stroke-width="1.5"/>
                <rect x="10" y="27" width="6" height="3" fill="{DANGER}"><animate attributeName="opacity" values="1;0.15;1" dur="0.9s" repeatCount="indefinite"/></rect>
                <rect x="122" y="27" width="6" height="3" fill="{ACCENT}"><animate attributeName="opacity" values="0.15;1;0.15" dur="0.9s" repeatCount="indefinite"/></rect>
            </svg>
            <div>
                <div style="color:#e2e8f0; font-size:1.15rem; font-weight:700;">Unmarked Interceptor Unit — Digital Forensics Division</div>
                <div style="color:{TEXT_MUTED}; font-size:0.88rem;">In-vehicle network capture &amp; post-incident analysis platform</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
