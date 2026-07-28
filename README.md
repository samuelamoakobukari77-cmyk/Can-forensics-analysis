# CAN Bus Post-Incident Forensic Analysis — Setup

## Files
- `app.py` — **run this one.** The full application: upload/generate a CAN log,
  classify it, and view results across 5 tabs.
- `train_demo_model.py` — trains the demo detection model + synthetic data generators
- `evidence_ledger.py` / `ledger_ui.py` — chain-of-custody hash chain + Merkle tree
- `timeline_replay.py` / `timeline_ui.py` — attack timeline, incident extraction, replay
- `shap_explain.py` / `shap_ui.py` — SHAP explainability for detections
- `model.joblib` / `feature_names.json` — the pre-trained demo model (RandomForest)

## Install
```
pip install streamlit pandas plotly shap scikit-learn joblib reportlab --break-system-packages
```
(drop `--break-system-packages` if you're using a virtualenv)

## Run
```
streamlit run app.py
```

## Using it
1. In the sidebar, either:
   - Upload a CSV with columns `timestamp, can_id, dlc, data` (data = 8 space-separated hex bytes), or
   - Click "generate demo data" to try it immediately with synthetic traffic
2. Click "Run detection" — this classifies every packet and logs detections
   to the evidence ledger automatically.
3. Explore the 5 tabs:
   - **Detection Results** — raw classified packet table
   - **Attack Timeline** — visual timeline + incident log + replay scrubber
   - **Chain of Custody** — hash-chain verification, tamper detection, JSON export
   - **SHAP Explainability** — why the model flagged a specific packet, and global feature importance
   - **Forensic Report** — generates a downloadable PDF summary, and logs the report's own hash back into the ledger

## Important: this uses a DEMO model, not your real trained model
There's no real training dataset available in this environment, so
`model.joblib` was trained on **synthetic data shaped like the HCRL
Car-Hacking dataset** (see `train_demo_model.py`). The demo model
correctly separates Normal / DoS / Fuzzy / Spoofing traffic *on synthetic
data with the same structure it was trained on* — this proves the whole
pipeline works, but it is not validated against real CAN bus captures.

### To swap in your real model later
1. Train your real model however you like (on the real HCRL dataset, your
   own captures, etc.) and get it to a fitted sklearn-compatible classifier
   with `.predict_proba()`.
2. `joblib.dump(your_model, "model.joblib")`
3. Save your real feature name list to `feature_names.json` (must match
   the columns your model was trained on).
4. If your feature engineering differs from `build_feature_row()` /
   `engineer_features()` in this project, update those functions to match
   how YOU turn a raw packet into a feature vector — everything downstream
   (ledger, timeline, SHAP, PDF report) works unchanged either way.

## Known limitation (documented, not a bug)
The `id_frequency_1s` feature counts packets in the trailing 1-second
window. For the first ~1 second of any log, that window hasn't filled up
yet, so a few packets right at the very start may get a low-confidence
misclassification. This is a normal property of windowed streaming
features and settles out immediately after the first second — real
captures are typically much longer than 1 second so this has negligible
impact in practice.
