"""
theme.py

Visual theme for the CAN Bus Forensic Analysis app: dark
"digital forensics lab" aesthetic, animated metric cards, a
severity gauge, and a multi-step animated loading sequence.

Pure presentation layer — none of this touches detection, the
ledger, SHAP, or PDF generation. Safe to tweak colors/copy here
without risk to the underlying pipeline.
"""

import textwrap
import time

import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components

# --------------------------------------------------------------------------
# Palette (kept consistent with timeline_ui.LABEL_COLORS)
# --------------------------------------------------------------------------

BG = "#0A0C10"
PANEL = "rgba(255,255,255,0.03)"
BORDER = "rgba(255,255,255,0.10)"
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


def inject_theme() -> None:
    """Injects the CAN FORENSICS glassmorphism theme. Call once near the top of main()."""
    st.markdown(
        textwrap.dedent(f"""
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
        .stApp {{
            background-color: {BG};
            background-image: radial-gradient(circle at 15% 0%, rgba(116,245,255,0.05) 0%, transparent 45%);
        }}

        [data-testid="stSidebar"] {{
            background: rgba(17,19,24,0.9);
            backdrop-filter: blur(20px);
            border-right: 1px solid {BORDER};
        }}

        h1, h2, h3, h4 {{
            font-family: 'Inter', system-ui, sans-serif;
            letter-spacing: -0.01em;
        }}

        h1 {{
            color: {ACCENT} !important;
            text-shadow: 0 0 12px rgba(116,245,255,0.4);
            letter-spacing: -0.02em;
        }}

        code, .mono {{
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
        }}

        [data-testid="stMetric"] {{
            background: {PANEL};
            backdrop-filter: blur(20px);
            border: 1px solid {BORDER};
            border-radius: 10px;
            padding: 14px 16px;
            transition: box-shadow 0.2s ease, border-color 0.2s ease;
        }}
        [data-testid="stMetric"]:hover {{
            border-color: rgba(116,245,255,0.3);
            box-shadow: 0 0 15px rgba(116,245,255,0.1);
        }}
        [data-testid="stMetricLabel"] {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem !important;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: {TEXT_MUTED} !important;
        }}
        [data-testid="stMetricValue"] {{
            font-family: 'JetBrains Mono', monospace;
            color: #e2e2e8 !important;
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 4px;
        }}
        .stTabs [data-baseweb="tab"] {{
            background: {PANEL};
            backdrop-filter: blur(10px);
            border-radius: 8px 8px 0 0;
            border: 1px solid {BORDER};
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        .stTabs [aria-selected="true"] {{
            background: rgba(116,245,255,0.08);
            border-bottom: 2px solid {ACCENT};
            color: {ACCENT} !important;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 12px;
            border-radius: 999px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            border: 1px solid currentColor;
        }}

        @keyframes fadeInUp {{
            from {{ opacity: 0; transform: translateY(8px); }}
            to   {{ opacity: 1; transform: translateY(0); }}
        }}
        .fade-in {{ animation: fadeInUp 0.45s ease both; }}

        @keyframes statusPulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.5; transform: scale(1.15); }}
        }}
        .status-pulse {{ animation: statusPulse 2s ease-in-out infinite; }}

        div[data-testid="stDataFrame"] {{
            border: 1px solid {BORDER};
            border-radius: 8px;
        }}
        </style>
        """),
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
            background: {PANEL};
            backdrop-filter: blur(20px);
            border: 1px solid {BORDER};
            border-radius: 10px;
            padding: 16px 18px;
            opacity: 0;
            animation: amFadeIn 0.5s ease forwards;
            box-shadow: 0 0 0 rgba(116,245,255,0);
            transition: box-shadow 0.2s ease, border-color 0.2s ease;
        }}
        .am-card:hover {{ box-shadow: 0 0 16px rgba(116,245,255,0.12); border-color: rgba(116,245,255,0.3); }}
        .am-icon {{ font-size: 1.3rem; margin-bottom: 4px; }}
        .am-value {{
            font-size: 1.9rem;
            font-weight: 700;
            color: #e2e2e8;
            font-family: 'JetBrains Mono', monospace;
        }}
        .am-label {{
            color: {TEXT_MUTED};
            font-size: 0.68rem;
            margin-top: 4px;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }}
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


def pursuit_vehicle_banner(case_id: str = "", packet_count: int = 0) -> None:
    """
    Hero banner in the CAN FORENSICS glassmorphism style — an animated
    'ACTIVE SCAN' status pill, scan-line sweep, and case metadata.
    Purely decorative except the case ID / packet count, which are the
    real values passed in by the caller. No fabricated data, no
    real-world imagery — an original SVG interceptor silhouette only.
    """
    st.markdown(
        textwrap.dedent(f"""
        <div style="
            position: relative;
            background: linear-gradient(135deg, rgba(116,245,255,0.06) 0%, rgba(255,255,255,0.02) 100%);
            border: 1px solid rgba(116,245,255,0.25);
            border-radius: 14px;
            padding: 20px 24px;
            overflow: hidden;
            margin-bottom: 18px;
        " class="fade-in">
            <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:14px;">
                <div style="display:flex; align-items:center; gap:18px;">
                    <svg width="120" height="52" viewBox="0 0 140 60" xmlns="http://www.w3.org/2000/svg">
                        <defs>
                            <linearGradient id="bodyGrad2" x1="0" y1="0" x2="1" y2="1">
                                <stop offset="0%" stop-color="#1e293b"/>
                                <stop offset="100%" stop-color="#0a0e17"/>
                            </linearGradient>
                        </defs>
                        <path d="M8 42 L20 24 Q30 16 50 16 L95 16 Q110 16 118 30 L128 42
                                 Q130 46 126 46 L12 46 Q6 46 8 42 Z"
                              fill="url(#bodyGrad2)" stroke="{ACCENT}" stroke-width="1.2"/>
                        <path d="M40 22 L52 22 L48 34 L36 34 Z" fill="{ACCENT}" opacity="0.35"/>
                        <path d="M56 22 L86 22 L88 34 L54 34 Z" fill="{ACCENT}" opacity="0.35"/>
                        <circle cx="30" cy="46" r="8" fill="#0a0e17" stroke="{TEXT_MUTED}" stroke-width="1.5"/>
                        <circle cx="106" cy="46" r="8" fill="#0a0e17" stroke="{TEXT_MUTED}" stroke-width="1.5"/>
                        <rect x="10" y="27" width="6" height="3" fill="{DANGER}"><animate attributeName="opacity" values="1;0.15;1" dur="0.9s" repeatCount="indefinite"/></rect>
                        <rect x="122" y="27" width="6" height="3" fill="{ACCENT}"><animate attributeName="opacity" values="0.15;1;0.15" dur="0.9s" repeatCount="indefinite"/></rect>
                    </svg>
                    <div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                            <span style="width:8px; height:8px; border-radius:50%; background:{ACCENT}; display:inline-block;" class="status-pulse"></span>
                            <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; letter-spacing:0.15em; color:{ACCENT}; text-transform:uppercase;">Active Scan</span>
                        </div>
                        <div style="color:#e2e2e8; font-size:1.1rem; font-weight:700; font-family:'Inter',sans-serif;">Digital Forensics Division — In-Vehicle Network Capture</div>
                    </div>
                </div>
                <div style="text-align:right; font-family:'JetBrains Mono',monospace;">
                    <div style="color:{TEXT_MUTED}; font-size:0.65rem; letter-spacing:0.1em; text-transform:uppercase;">Case ID</div>
                    <div style="color:{ACCENT}; font-size:0.95rem;">{case_id or "—"}</div>
                    <div style="color:{TEXT_MUTED}; font-size:0.65rem; letter-spacing:0.1em; text-transform:uppercase; margin-top:6px;">Packets</div>
                    <div style="color:#e2e2e8; font-size:0.95rem;">{packet_count:,}</div>
                </div>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


def recent_traffic_table(df, n: int = 6) -> None:
    """
    Renders the most recent N classified packets as a glass-card table
    styled like a live CAN traffic feed. Uses whatever real
    classified DataFrame the caller passes in — no placeholder rows.
    """
    rows = df.tail(n).iloc[::-1]
    row_html = ""
    for _, r in rows.iterrows():
        is_attack = r["label"] != "Normal"
        color = LABEL_COLORS.get(r["label"], TEXT_MUTED)
        status_text = r["label"].upper() if is_attack else "NOMINAL"
        row_bg = "background: rgba(255,180,171,0.05);" if is_attack else ""
        row_html += f"""
        <tr style="{row_bg} border-bottom: 1px solid rgba(255,255,255,0.05);">
            <td style="padding:10px 12px; color:{TEXT_MUTED};">{r['timestamp']:.3f}s</td>
            <td style="padding:10px 12px; color:#e2e2e8;">{r['can_id']}</td>
            <td style="padding:10px 12px; color:#e2e2e8; letter-spacing:0.05em;">{r['data']}</td>
            <td style="padding:10px 12px; text-align:right; color:{color}; font-weight:700;">{status_text}</td>
        </tr>
        """

    st.markdown(
        textwrap.dedent(f"""
        <div style="background:{PANEL}; backdrop-filter: blur(20px); border:1px solid {BORDER}; border-radius: 10px; overflow:hidden;" class="fade-in">
            <div style="padding: 12px 16px; border-bottom: 1px solid {BORDER}; display:flex; justify-content:space-between; align-items:center;">
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; letter-spacing:0.1em; color:#e2e2e8; text-transform:uppercase;">Recent CAN Traffic</span>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.65rem; color:{ACCENT};">LOGGING</span>
            </div>
            <table style="width:100%; border-collapse:collapse; font-family:'JetBrains Mono',monospace; font-size:0.75rem;">
                <thead style="background: rgba(255,255,255,0.03);">
                    <tr style="color:{TEXT_MUTED}; text-align:left; font-size:0.65rem; text-transform:uppercase; letter-spacing:0.08em;">
                        <th style="padding:8px 12px; font-weight:400;">Timestamp</th>
                        <th style="padding:8px 12px; font-weight:400;">ID (hex)</th>
                        <th style="padding:8px 12px; font-weight:400;">Data (bytes)</th>
                        <th style="padding:8px 12px; font-weight:400; text-align:right;">Status</th>
                    </tr>
                </thead>
                <tbody>{row_html}</tbody>
            </table>
        </div>
        """),
        unsafe_allow_html=True,
    )
