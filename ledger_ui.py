"""
ledger_ui.py

Streamlit UI for the chain-of-custody evidence ledger.

HOW TO INTEGRATE INTO YOUR EXISTING APP
----------------------------------------
1. Copy evidence_ledger.py and this file into your project folder.

2. In your main app, wherever you currently create/store detection
   results (e.g. after your model flags a packet as an attack), add:

       from evidence_ledger import EvidenceLedger

       if "ledger" not in st.session_state:
           st.session_state.ledger = EvidenceLedger(case_id="INC-2026-XXXX")

       # every time you log a detection or export a report:
       st.session_state.ledger.add_record("detection", {
           "can_id": row["can_id"],
           "label": row["predicted_label"],
           "confidence": float(row["confidence"]),
           "timestamp": row["timestamp"],
       })

3. Add a new tab/page called "Chain of Custody" and call:

       from ledger_ui import render_ledger_tab
       render_ledger_tab(st.session_state.ledger)

That's it -- the ledger already tracks everything you feed it and this
file just renders it.

Run `streamlit run ledger_ui.py` on its own to see a standalone demo
with sample data (useful for showing your supervisor the concept before
it's wired into the full pipeline).
"""

import streamlit as st
import pandas as pd

from evidence_ledger import EvidenceLedger, MerkleTree


def render_ledger_tab(ledger: EvidenceLedger) -> None:
    st.subheader("🔗 Chain of Custody — Evidence Ledger")
    st.caption(
        "Every capture, detection, and export event is hash-chained. "
        "If any evidence record is altered after the fact, verification below will catch it."
    )

    records = ledger.records

    if not records:
        st.info("No evidence events logged yet for this case.")
        return

    # --- Summary metrics ---
    col1, col2, col3 = st.columns(3)
    ok, problem = ledger.verify_chain()
    col1.metric("Records in chain", len(records))
    col2.metric("Case ID", ledger.case_id)
    col3.metric("Chain status", "✅ Intact" if ok else "⚠️ BROKEN")

    if not ok:
        st.error(f"Integrity check failed: {problem}")
    else:
        st.success("All records verified — no tampering detected.")

    # --- Verify button (explicit re-check, good for a live demo) ---
    if st.button("🔍 Re-verify chain now"):
        ok, problem = ledger.verify_chain()
        if ok:
            st.success("Verified: every hash matches. Evidence is intact.")
        else:
            st.error(f"Tampering detected: {problem}")

    # --- Table view ---
    st.markdown("#### Ledger records")
    df = pd.DataFrame([
        {
            "Index": r.index,
            "Event": r.event_type,
            "Timestamp": r.timestamp,
            "Data hash (short)": r.data_hash[:12] + "...",
            "Prev hash (short)": r.prev_hash[:12] + "...",
            "Record hash (short)": r.record_hash[:12] + "...",
        }
        for r in records
    ])
    st.dataframe(df, use_container_width=True)

    with st.expander("View a record's full detail"):
        idx = st.number_input("Record index", min_value=0, max_value=len(records) - 1, value=0, step=1)
        st.json(records[idx].to_dict())

    # --- Export ---
    st.download_button(
        "⬇️ Download full ledger (JSON, for the forensic report appendix)",
        data=ledger.to_json(),
        file_name=f"{ledger.case_id}_evidence_ledger.json",
        mime="application/json",
    )

    # --- Merkle batch demo section ---
    st.markdown("---")
    st.markdown("#### Merkle proof for an attack-window batch")
    st.caption(
        "Groups all detections into a batch and produces one root hash that "
        "fingerprints the whole batch — plus a proof that any single detection belongs to it."
    )
    detection_records = [r for r in records if r.event_type == "detection"]
    if len(detection_records) >= 1:
        tree = MerkleTree([r.data for r in detection_records])
        st.code(f"Merkle root: {tree.root}", language="text")

        proof_idx = st.number_input(
            "Prove that detection # belongs to this batch",
            min_value=0, max_value=len(detection_records) - 1, value=0, step=1,
        )
        proof = tree.get_proof(proof_idx)
        is_valid = MerkleTree.verify_proof(detection_records[proof_idx].data, proof, tree.root)
        st.write("Proof steps:", proof)
        st.write("Proof valid:", "✅ Yes" if is_valid else "❌ No")
    else:
        st.info("Log at least one detection event to see the Merkle batch demo.")


# --------------------------------------------------------------------------
# Standalone demo (so you can show this before it's wired into the full app)
# --------------------------------------------------------------------------

def _seed_demo_ledger() -> EvidenceLedger:
    ledger = EvidenceLedger(case_id="DEMO-CASE-001")
    ledger.add_record("capture", {"can_id": "0x0316", "dlc": 8, "data": "00 FF 00 00 00 00 00 52"})
    ledger.add_record("detection", {"can_id": "0x0316", "label": "DoS", "confidence": 0.982})
    ledger.add_record("detection", {"can_id": "0x0430", "label": "Fuzzy", "confidence": 0.911})
    ledger.add_record("detection", {"can_id": "0x0320", "label": "Spoofing", "confidence": 0.877})
    ledger.add_record("export", {"report_file": "incident_report_2026-07-24.pdf"})
    return ledger


if __name__ == "__main__":
    st.set_page_config(page_title="CAN Forensics — Chain of Custody", layout="wide")

    if "demo_ledger" not in st.session_state:
        st.session_state.demo_ledger = _seed_demo_ledger()

    st.title("CAN Bus Forensics — Chain of Custody Demo")

    if st.button("💥 Simulate tampering (for live defense demo)"):
        st.session_state.demo_ledger.tamper_demo(1, {"can_id": "0x0316", "label": "Normal", "confidence": 0.982})
        st.warning("Record 1 was tampered with behind the scenes. Re-verify below to catch it.")

    render_ledger_tab(st.session_state.demo_ledger)
