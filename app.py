"""
app.py

CAN Bus Post-Incident Forensic Analysis — main application.

This is the full app: it ties together detection, the chain-of-custody
ledger, the attack timeline/replay, SHAP explainability, and a
downloadable PDF forensic report, all in one Streamlit tool.

RUNNING IT
----------
    pip install streamlit pandas plotly shap scikit-learn joblib reportlab --break-system-packages
    streamlit run app.py

WHAT'S REAL VS. DEMO RIGHT NOW
-------------------------------
- The DETECTION MODEL is a demo RandomForest trained on synthetic data
  shaped like the HCRL Car-Hacking dataset (see train_demo_model.py).
  It is NOT trained on the real HCRL dataset, because that dataset
  isn't available in this environment. Swap it for your real model by
  replacing model.joblib / feature_names.json and, if your feature
  engineering differs, the `engineer_features()` function below.
- The CAN LOG INPUT accepts either an uploaded CSV (see format below)
  or synthetic demo data generated on the fly.
- Everything else (ledger, timeline, SHAP, PDF report) works against
  whatever DataFrame comes out of detection — real or demo — unchanged.

CSV UPLOAD FORMAT
------------------
Columns required: timestamp (seconds, float), can_id (hex string like
"0x0316"), dlc (int), data (8 space-separated hex byte pairs, e.g.
"00 FF 00 00 00 00 00 52"). No label column needed — the model predicts it.
"""

import hashlib
import io
from datetime import datetime

import pandas as pd
import streamlit as st

from evidence_ledger import EvidenceLedger
from ledger_ui import render_ledger_tab
from timeline_ui import render_timeline_tab
from train_demo_model import FEATURE_NAMES, build_feature_row, generate_synthetic_raw_can_log
from shap_explain import DetectionExplainer
from shap_ui import render_shap_tab
from theme import inject_theme, animated_metric_row, threat_gauge, severity_badge, pursuit_vehicle_banner
from report_styles import REPORT_STYLES, get_style_keys_and_labels

st.set_page_config(page_title="CAN Bus Forensic Analysis", layout="wide", page_icon="🚗")


# --------------------------------------------------------------------------
# Detection pipeline: raw packets -> engineered features -> model predictions
# --------------------------------------------------------------------------

def engineer_features(raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    Turns a raw packet log (timestamp, can_id, dlc, data) into the
    feature columns the model expects, computing inter-arrival time and
    per-second ID frequency per row. Replace this if your real pipeline
    engineers features differently — see build_feature_row() docstring
    in train_demo_model.py.

    NOTE: id_frequency_1s counts packets in the trailing 1-second window,
    so during the first ~1 second of ANY log that window is still filling
    up and the frequency feature reads artificially low — this can cause
    a few low-confidence misclassifications right at the very start of a
    log. This is a normal characteristic of windowed streaming features
    (not specific to this demo model) and settles out after ~1 second.
    """
    df = raw_df.sort_values("timestamp").reset_index(drop=True)
    last_seen = {}
    rows = []

    for _, r in df.iterrows():
        data_bytes = [int(b, 16) for b in str(r["data"]).split()]
        t = float(r["timestamp"])
        can_id = r["can_id"]

        # For a CAN ID's very first appearance in the log there's no real
        # prior packet to measure from; assume a typical ~15ms gap rather
        # than defaulting to 0, which would look like flooding/fuzzing.
        inter_arrival_ms = (t - last_seen.get(can_id, t - 0.015)) * 1000.0
        last_seen[can_id] = t

        window = df[(df["can_id"] == can_id) & (df["timestamp"] > t - 1.0) & (df["timestamp"] <= t)]
        id_freq = len(window)

        feat = build_feature_row(can_id, int(r["dlc"]), data_bytes, inter_arrival_ms, id_freq)
        feat["timestamp"] = t
        feat["can_id"] = can_id
        feat["dlc"] = int(r["dlc"])
        feat["data"] = r["data"]
        rows.append(feat)

    return pd.DataFrame(rows)


@st.cache_resource
def load_model_and_explainer():
    return DetectionExplainer.from_files()


def classify(engineered_df: pd.DataFrame, explainer: DetectionExplainer) -> pd.DataFrame:
    X = engineered_df[FEATURE_NAMES]
    preds = explainer.model.predict(X)
    probas = explainer.model.predict_proba(X)
    confidences = probas.max(axis=1)

    out = engineered_df.copy()
    out["label"] = preds
    out["confidence"] = confidences
    return out


# --------------------------------------------------------------------------
# PDF forensic report
# --------------------------------------------------------------------------

def generate_pdf_report(
    case_id: str,
    classified_df: pd.DataFrame,
    ledger: EvidenceLedger,
    style_key: str = "academic",
    org: str = "",
    analyst: str = "",
    requirements: str = "",
) -> bytes:
    """
    Builds the PDF forensic report. style_key picks which reporting
    standard's section structure and wording to use (see
    report_styles.py) — the underlying data is identical regardless
    of style; only headings, framing language, and an optional
    org/analyst/requirements block change.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    from timeline_replay import extract_incidents

    style = REPORT_STYLES.get(style_key, REPORT_STYLES["academic"])
    sections = style["sections"]

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    total = len(classified_df)
    attack = int((classified_df["label"] != "Normal").sum())

    story.append(Paragraph("CAN Bus Post-Incident Forensic Report", styles["Title"]))
    story.append(Spacer(1, 10))
    if org:
        story.append(Paragraph(f"Prepared by: {org}", styles["Normal"]))
    if analyst:
        story.append(Paragraph(f"Analyst: {analyst}", styles["Normal"]))
    story.append(Paragraph(f"Case ID: {case_id}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}Z", styles["Normal"]))
    story.append(Spacer(1, 14))

    intro = style["intro"].format(case_id=case_id, org=org or "the examining organisation")
    story.append(Paragraph(intro, styles["Normal"]))
    story.append(Spacer(1, 14))

    # Section 1: summary stats
    story.append(Paragraph(sections[0], styles["Heading2"]))
    story.append(Paragraph(f"Total packets analysed: {total}", styles["Normal"]))
    story.append(Paragraph(f"Packets flagged as attack traffic: {attack} ({attack/total:.1%})", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Section 2: methodology
    story.append(Paragraph(sections[1], styles["Heading2"]))
    story.append(Paragraph(style["methodology"], styles["Normal"]))
    story.append(Spacer(1, 12))

    # Section 3: incidents table
    story.append(Paragraph(sections[2], styles["Heading2"]))
    incidents = extract_incidents(classified_df)
    if incidents:
        data = [["#", "Type", "Start (s)", "End (s)", "Duration (s)", "Packets", "CAN IDs"]]
        for inc in incidents:
            d = inc.to_dict()
            data.append([
                d["Incident #"], d["Attack type"], d["Start (s)"], d["End (s)"],
                d["Duration (s)"], d["Packets"], d["CAN IDs involved"],
            ])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No attack incidents detected.", styles["Normal"]))
    story.append(Spacer(1, 16))

    # Chain of custody (find its heading wherever the style places it)
    custody_heading = next((s for s in sections if "Custody" in s), "Chain of Custody")
    story.append(Paragraph(custody_heading, styles["Heading2"]))
    ok, problem = ledger.verify_chain()
    status = "INTACT — all hashes verified" if ok else f"BROKEN — {problem}"
    story.append(Paragraph(f"Evidence ledger status: {status}", styles["Normal"]))
    story.append(Paragraph(f"Total ledger records: {len(ledger.records)}", styles["Normal"]))
    if ledger.records:
        story.append(Paragraph(f"Final record hash: {ledger.records[-1].record_hash}", styles["Normal"]))
    story.append(Spacer(1, 14))

    # Optional: special requirements note
    if requirements.strip():
        story.append(Paragraph("Special Requirements / Additional Notes", styles["Heading2"]))
        story.append(Paragraph(requirements.strip(), styles["Normal"]))
        story.append(Spacer(1, 14))

    # Closing section (last heading not already used above, e.g. Conclusion/
    # Certification/Recommendations)
    used = {sections[0], sections[1], sections[2], custody_heading}
    remaining = [s for s in sections if s not in used]
    if remaining:
        story.append(Paragraph(remaining[-1], styles["Heading2"]))
        if style_key == "law_enforcement":
            story.append(Paragraph(
                f"I certify that the above findings and evidence log are accurate to the "
                f"best of my knowledge, based on the automated analysis and chain-of-custody "
                f"records generated for {case_id}.",
                styles["Normal"],
            ))
            if analyst:
                story.append(Spacer(1, 20))
                story.append(Paragraph(f"Signed: _____________________  ({analyst})", styles["Normal"]))
        elif style_key == "corporate_soc":
            story.append(Paragraph(
                "Recommend reviewing affected CAN IDs for firmware/ECU hardening, and "
                "monitoring for recurrence of the traffic patterns flagged above.",
                styles["Normal"],
            ))
        else:
            story.append(Paragraph(
                f"Based on the analysis above, {attack} of {total} packets ({attack/total:.1%}) "
                f"were flagged as attack traffic, with chain-of-custody integrity {status.split(' —')[0].lower()}.",
                styles["Normal"],
            ))

    doc.build(story)
    pdf_bytes = buf.getvalue()

    report_hash = hashlib.sha256(pdf_bytes).hexdigest()
    ledger.add_record("export", {
        "report_generated_at": datetime.utcnow().isoformat(),
        "report_sha256": report_hash,
        "report_style": style_key,
    })

    return pdf_bytes


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

def main():
    inject_theme()
    st.title("🚗 CAN Bus Post-Incident Forensic Analysis")

    if "case_id" not in st.session_state:
        st.session_state.case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    if "ledger" not in st.session_state:
        st.session_state.ledger = EvidenceLedger(case_id=st.session_state.case_id)
    if "classified_df" not in st.session_state:
        st.session_state.classified_df = None

    with st.sidebar:
        st.header("Case setup")
        st.session_state.case_id = st.text_input("Case ID", value=st.session_state.case_id)
        st.session_state.ledger.case_id = st.session_state.case_id

        st.markdown("---")
        st.subheader("Load CAN log")
        uploaded = st.file_uploader("Upload CSV (timestamp, can_id, dlc, data)", type=["csv"])
        use_demo = st.button("🧪 Or generate demo data instead")

        run_analysis = False
        raw_df = None

        if uploaded is not None:
            raw_df = pd.read_csv(uploaded)
            run_analysis = st.button("▶️ Run detection on uploaded log")
        elif use_demo:
            raw_df = generate_synthetic_raw_can_log(duration_seconds=45, n_incidents=3, seed=42)
            run_analysis = True

        if run_analysis and raw_df is not None:
            explainer = load_model_and_explainer()
            with st.status("Running forensic pipeline...", expanded=True) as status:
                st.write("🔧 Engineering features from raw CAN frames...")
                engineered = engineer_features(raw_df)
                st.write("🧠 Classifying traffic with trained model...")
                classified = classify(engineered, explainer)
                st.write("🔗 Logging detections to evidence ledger...")
                status.update(label="Pipeline complete", state="complete", expanded=False)
            st.session_state.classified_df = classified

            st.session_state.ledger.add_record("capture", {
                "packet_count": len(classified),
                "source": "uploaded_csv" if uploaded is not None else "demo_data",
            })
            attack_rows = classified[classified["label"] != "Normal"]
            for _, r in attack_rows.iterrows():
                st.session_state.ledger.add_record("detection", {
                    "timestamp": float(r["timestamp"]),
                    "can_id": r["can_id"],
                    "label": r["label"],
                    "confidence": float(r["confidence"]),
                })
            st.success(f"Classified {len(classified)} packets, logged {len(attack_rows)} detections to the ledger.")

        st.markdown("---")
        st.subheader("Report style")
        style_keys, style_labels = zip(*get_style_keys_and_labels())
        style_choice_label = st.selectbox("Reporting standard", style_labels, index=0)
        st.session_state.report_style_key = style_keys[style_labels.index(style_choice_label)]
        st.session_state.report_org = st.text_input("Agency / organisation name", value=st.session_state.get("report_org", ""))
        st.session_state.report_analyst = st.text_input("Analyst / officer name", value=st.session_state.get("report_analyst", ""))
        st.session_state.report_requirements = st.text_area(
            "Special requirements / notes (optional)",
            value=st.session_state.get("report_requirements", ""),
            help="Anything specific your agency wants included — inserted as its own section in the report.",
        )

    if st.session_state.classified_df is None:
        st.info("👈 Upload a CAN log or generate demo data from the sidebar to begin.")
        return

    df = st.session_state.classified_df
    explainer = load_model_and_explainer()

    tabs = st.tabs([
        "🛰️ Executive Summary", "📋 Detection Results", "📈 Attack Timeline",
        "🔗 Chain of Custody", "🔍 SHAP Explainability", "📄 Forensic Report",
    ])

    with tabs[0]:
        pursuit_vehicle_banner()

        total = len(df)
        attack = int((df["label"] != "Normal").sum())
        pct = round(100 * attack / total, 1) if total else 0.0
        dominant = df[df["label"] != "Normal"]["label"].mode().iat[0] if attack else "Normal"

        animated_metric_row([
            ("Packets analysed", "📦", total, ""),
            ("Attack packets", "🚨", attack, ""),
            ("Attack traffic", "📊", pct, "%"),
            ("Unique CAN IDs", "🆔", int(df["can_id"].nunique()), ""),
        ])

        st.write("")
        gcol, bcol = st.columns([1, 1])
        with gcol:
            st.plotly_chart(threat_gauge(pct, dominant), use_container_width=True)
        with bcol:
            st.markdown("##### Attack type breakdown")
            counts = df[df["label"] != "Normal"]["label"].value_counts()
            if counts.empty:
                st.success("No attack traffic detected in this capture.")
            else:
                for label, n in counts.items():
                    st.markdown(
                        f'{severity_badge(label)} &nbsp; **{n}** packets ({n/total:.1%} of total)',
                        unsafe_allow_html=True,
                    )
            ok, _ = st.session_state.ledger.verify_chain()
            st.markdown("##### Chain of custody")
            if ok:
                st.success("✅ Evidence ledger intact — all hashes verified")
            else:
                st.error("⚠️ Evidence ledger integrity check FAILED")

        st.markdown("---")
        incidents_df_export = None
        from timeline_replay import extract_incidents
        incidents = extract_incidents(df)
        if incidents:
            incidents_df_export = pd.DataFrame([i.to_dict() for i in incidents])
            st.download_button(
                "⬇️ Export incident log (CSV)",
                data=incidents_df_export.to_csv(index=False).encode("utf-8"),
                file_name=f"{st.session_state.case_id}_incidents.csv",
                mime="text/csv",
            )

    with tabs[1]:
        st.subheader("Detection results")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total packets", len(df))
        col2.metric("Attack packets", int((df["label"] != "Normal").sum()))
        col3.metric("Unique CAN IDs", df["can_id"].nunique())
        st.dataframe(
            df[["timestamp", "can_id", "dlc", "data", "label", "confidence"]],
            use_container_width=True,
        )
        st.download_button(
            "⬇️ Export full classified log (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"{st.session_state.case_id}_classified_log.csv",
            mime="text/csv",
        )

    with tabs[2]:
        render_timeline_tab(df)

    with tabs[3]:
        render_ledger_tab(st.session_state.ledger)

    with tabs[4]:
        render_shap_tab(explainer, df)

    with tabs[5]:
        st.subheader("Generate forensic report")
        st.caption("Bundles the detection summary, incident log, and chain-of-custody status into a signed PDF, formatted to the reporting standard selected in the sidebar.")
        st.info(f"Current style: **{REPORT_STYLES[st.session_state.report_style_key]['label']}**")
        if st.button("📄 Generate PDF report"):
            pdf_bytes = generate_pdf_report(
                st.session_state.case_id, df, st.session_state.ledger,
                style_key=st.session_state.report_style_key,
                org=st.session_state.report_org,
                analyst=st.session_state.report_analyst,
                requirements=st.session_state.report_requirements,
            )
            st.session_state.pdf_bytes = pdf_bytes
            st.success("Report generated and logged to the evidence ledger.")
        if "pdf_bytes" in st.session_state:
            st.download_button(
                "⬇️ Download PDF report",
                data=st.session_state.pdf_bytes,
                file_name=f"{st.session_state.case_id}_forensic_report.pdf",
                mime="application/pdf",
            )


if __name__ == "__main__":
    main()
