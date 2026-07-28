"""
train_demo_model.py

Trains a demo attack-detection model with the SAME feature shape you'd
get from the HCRL Car-Hacking dataset, so the SHAP explainability layer
(shap_explain.py / shap_ui.py) has something real to explain today.

WHEN YOU HAVE YOUR OWN TRAINED MODEL
-------------------------------------
Replace this file's output with yours: shap_explain.py only needs
    - a fitted sklearn-compatible classifier (anything with .predict_proba)
    - the list of feature column names it was trained on
    - a DataFrame of rows to explain, with those same feature columns

So the integration point is just: swap `model.joblib` and `feature_names.json`
for the equivalent from YOUR training pipeline, and change
`build_feature_row()` below to match however YOU turn a raw CAN packet
into a feature vector. Nothing else in the SHAP layer needs to change.

Features engineered per packet (typical for CAN intrusion detection —
this mirrors common approaches used with the HCRL Car-Hacking dataset):
    - can_id_numeric      : CAN ID as an integer
    - dlc                 : data length code
    - byte_0 .. byte_7    : individual payload byte values (0-255)
    - inter_arrival_ms    : time since the previous packet on this CAN ID
    - id_frequency_1s     : how many times this CAN ID appeared in the last 1s
"""

from __future__ import annotations

import json
import random

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

FEATURE_NAMES = [
    "can_id_numeric", "dlc",
    "byte_0", "byte_1", "byte_2", "byte_3", "byte_4", "byte_5", "byte_6", "byte_7",
    "inter_arrival_ms", "id_frequency_1s",
]

LABELS = ["Normal", "DoS", "Fuzzy", "Spoofing"]


def _hex_to_int(can_id: str) -> int:
    return int(can_id, 16)


def build_feature_row(can_id: str, dlc: int, data_bytes: list, inter_arrival_ms: float, id_frequency_1s: int) -> dict:
    """
    Turns one raw CAN packet into the flat feature dict the model expects.
    THIS is the function to rewrite if your real pipeline engineers
    features differently.
    """
    row = {
        "can_id_numeric": _hex_to_int(can_id),
        "dlc": dlc,
        "inter_arrival_ms": inter_arrival_ms,
        "id_frequency_1s": id_frequency_1s,
    }
    padded = (data_bytes + [0] * 8)[:8]
    for i, b in enumerate(padded):
        row[f"byte_{i}"] = b
    return row


def generate_synthetic_training_data(n_rows: int = 8000, seed: int = 42) -> pd.DataFrame:
    """
    Synthetic training set shaped like the HCRL Car-Hacking dataset's
    four classes. Attack classes are given deliberately distinctive
    (but realistic) feature signatures so the demo model — and the
    SHAP explanations it produces — actually makes sense:
        - DoS       : CAN ID 0x0000, very high frequency, near-zero inter-arrival
        - Fuzzy     : random/unusual CAN IDs, random payload bytes
        - Spoofing  : normal-looking CAN ID but abnormal payload pattern
        - Normal    : realistic mixed traffic
    """
    rng = random.Random(seed)
    normal_ids = ["0x0316", "0x0320", "0x018F", "0x0260", "0x0043"]
    rows = []

    for _ in range(n_rows):
        label = rng.choices(LABELS, weights=[0.7, 0.1, 0.1, 0.1])[0]

        if label == "Normal":
            can_id = rng.choice(normal_ids)
            dlc = 8
            data_bytes = [rng.randint(0, 255) for _ in range(8)]
            inter_arrival_ms = rng.uniform(8, 25)
            id_freq = rng.randint(40, 60)

        elif label == "DoS":
            can_id = "0x0000"
            dlc = 8
            data_bytes = [0] * 8
            inter_arrival_ms = rng.uniform(0.05, 0.5)
            id_freq = rng.randint(800, 2000)

        elif label == "Fuzzy":
            can_id = f"0x{rng.randint(0, 0x7FF):04X}"
            dlc = rng.randint(2, 8)
            data_bytes = [rng.randint(0, 255) for _ in range(8)]
            inter_arrival_ms = rng.uniform(1, 15)
            id_freq = rng.randint(1, 10)

        else:  # Spoofing
            can_id = rng.choice(normal_ids)
            dlc = 8
            data_bytes = [rng.randint(200, 255) for _ in range(8)]  # abnormal payload skew
            inter_arrival_ms = rng.uniform(5, 20)
            id_freq = rng.randint(30, 70)

        row = build_feature_row(can_id, dlc, data_bytes, inter_arrival_ms, id_freq)
        row["label"] = label
        rows.append(row)

    return pd.DataFrame(rows)


def generate_synthetic_raw_can_log(duration_seconds: float = 45.0, n_incidents: int = 3, seed: int = 42) -> pd.DataFrame:
    """
    Generates a RAW packet stream (timestamp, can_id, dlc, data) — not
    pre-computed features — where the actual inter-arrival times and
    per-ID frequencies naturally match the signatures the demo model
    was trained on (see generate_synthetic_training_data). This is what
    app.py's engineer_features() should be run against, so the features
    it computes from real timestamps line up with what the model expects.

    Use this (not timeline_replay.generate_sample_can_log, which is only
    illustrative timing for the timeline UI demo) whenever you need a
    raw log that this specific demo model will classify sensibly.
    """
    rng = random.Random(seed)
    normal_ids = ["0x0316", "0x0320", "0x018F", "0x0260", "0x0043"]
    rows = []

    # Non-overlapping incident windows, evenly spread with gaps, so the
    # demo's incident log reads cleanly instead of interleaving attack types.
    usable = duration_seconds - 10
    slot_width = usable / max(n_incidents, 1)
    incident_plan = []
    for i in range(n_incidents):
        slot_start = 5 + i * slot_width
        start = slot_start + rng.uniform(0, slot_width * 0.3)
        end = start + min(rng.uniform(2.0, 4.0), slot_width * 0.6)
        incident_plan.append((start, end, rng.choice(["DoS", "Fuzzy", "Spoofing"])))

    def spoofing_window_at(t: float):
        return next(((s, e) for (s, e, lbl) in incident_plan if lbl == "Spoofing" and s <= t <= e), None)

    # Each real CAN ID broadcasts periodically on its own — this matches the
    # per-ID inter-arrival/frequency the model was trained to expect for
    # "Normal" traffic (~8-25ms between messages on any given ID).
    for can_id in normal_ids:
        t = rng.uniform(0, 0.02)
        while t < duration_seconds:
            if spoofing_window_at(t):
                data_bytes = [rng.randint(200, 255) for _ in range(8)]  # abnormal payload skew
            else:
                data_bytes = [rng.randint(0, 255) for _ in range(8)]
            rows.append({"timestamp": round(t, 4), "can_id": can_id, "dlc": 8,
                         "data": " ".join(f"{b:02X}" for b in data_bytes)})
            t += rng.uniform(0.008, 0.025)

    # DoS: a flood of 0x0000 packets layered on top, only during its window(s)
    for (s, e, label) in incident_plan:
        if label == "DoS":
            t = s
            while t < e:
                rows.append({"timestamp": round(t, 4), "can_id": "0x0000", "dlc": 8, "data": "00 00 00 00 00 00 00 00"})
                t += rng.uniform(0.0005, 0.002)
        elif label == "Fuzzy":
            t = s
            while t < e:
                can_id = f"0x{rng.randint(0, 0x7FF):04X}"
                data_bytes = [rng.randint(0, 255) for _ in range(8)]
                rows.append({"timestamp": round(t, 4), "can_id": can_id, "dlc": rng.randint(2, 8),
                             "data": " ".join(f"{b:02X}" for b in data_bytes)})
                t += rng.uniform(0.02, 0.08)
        # Spoofing is handled inline above (same normal IDs, corrupted payload, same timing)

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def train_and_save(output_dir: str = ".") -> None:
    df = generate_synthetic_training_data()
    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150, max_depth=10, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test)))

    joblib.dump(model, f"{output_dir}/model.joblib")
    with open(f"{output_dir}/feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f)

    print(f"\nSaved model.joblib and feature_names.json to {output_dir}/")


if __name__ == "__main__":
    train_and_save()
