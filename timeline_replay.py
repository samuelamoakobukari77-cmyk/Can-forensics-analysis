"""
timeline_replay.py

Attack timeline / dashboard replay engine for the CAN Bus Forensic
Analysis capstone project.

Purpose
-------
Turns a flat log of classified CAN packets (timestamp, can_id, data,
predicted label, confidence) into:

1. A TIMELINE VIEW  — every packet plotted over time, colour-coded by
   label, so an investigator can see at a glance *when* an attack
   started, *how long* it lasted, and *which CAN IDs* were involved.

2. An INCIDENT LOG  — consecutive non-"Normal" packets are grouped
   into discrete incidents (start time, end time, duration, CAN IDs
   involved, packet count, average confidence) instead of forcing the
   investigator to scroll through raw rows.

3. A REPLAY ENGINE  — steps through the log packet-by-packet (like a
   video scrubber) so you can "play back" an incident during your
   defense/demo instead of just showing a static chart, and a live
   dashboard of stats for whatever time window is currently visible.

Expects a pandas DataFrame with (at minimum) these columns:
    timestamp : float, seconds
    can_id    : str, e.g. "0x0316"
    label     : str, "Normal" or an attack type e.g. "DoS", "Fuzzy", "Spoofing"

Optional columns used if present:
    confidence : float 0-1
    dlc        : int
    data       : str (hex payload)

No dependency beyond pandas for the core logic; timeline_ui.py adds
plotly + streamlit for rendering.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd


# --------------------------------------------------------------------------
# Sample data generator (so this can be demoed/tested before being wired to
# your real model's output — matches the shape of the HCRL Car-Hacking set)
# --------------------------------------------------------------------------

def generate_sample_can_log(
    duration_seconds: float = 60.0,
    normal_rate_hz: float = 50.0,
    n_incidents: int = 3,
    seed: int = 7,
) -> pd.DataFrame:
    """
    Builds a synthetic log: mostly Normal traffic with a handful of
    injected attack windows, for testing/demoing the timeline before
    it's connected to your real detection pipeline's output.
    """
    rng = random.Random(seed)
    normal_ids = ["0x0316", "0x0320", "0x018F", "0x0260", "0x0043"]
    attack_labels = ["DoS", "Fuzzy", "Spoofing"]

    rows = []
    t = 0.0
    dt = 1.0 / normal_rate_hz

    incident_starts = sorted(rng.uniform(5, duration_seconds - 10) for _ in range(n_incidents))
    incident_windows = [(s, s + rng.uniform(1.5, 4.0), rng.choice(attack_labels)) for s in incident_starts]

    while t < duration_seconds:
        label = "Normal"
        can_id = rng.choice(normal_ids)
        conf = rng.uniform(0.9, 0.999)

        for (start, end, atype) in incident_windows:
            if start <= t <= end:
                label = atype
                can_id = "0x0000" if atype == "DoS" else rng.choice(normal_ids + ["0x07FF"])
                conf = rng.uniform(0.85, 0.995)
                break

        rows.append({
            "timestamp": round(t, 4),
            "can_id": can_id,
            "dlc": 8,
            "data": " ".join(f"{rng.randint(0,255):02X}" for _ in range(8)),
            "label": label,
            "confidence": round(conf, 4),
        })
        t += dt

    return pd.DataFrame(rows)


# --------------------------------------------------------------------------
# Incident extraction
# --------------------------------------------------------------------------

@dataclass
class Incident:
    incident_id: int
    label: str
    start_time: float
    end_time: float
    packet_count: int
    can_ids: list
    avg_confidence: float

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 4)

    def to_dict(self) -> dict:
        return {
            "Incident #": self.incident_id,
            "Attack type": self.label,
            "Start (s)": self.start_time,
            "End (s)": self.end_time,
            "Duration (s)": self.duration,
            "Packets": self.packet_count,
            "CAN IDs involved": ", ".join(self.can_ids),
            "Avg confidence": self.avg_confidence,
        }


def extract_incidents(df: pd.DataFrame, gap_tolerance_seconds: float = 0.5) -> list[Incident]:
    """
    Groups consecutive attack-labelled rows into discrete incidents.
    A new incident starts whenever the label changes, or whenever the
    gap between consecutive attack packets exceeds gap_tolerance_seconds
    (so a brief detection dropout doesn't split one real incident into two).
    """
    df = df.sort_values("timestamp").reset_index(drop=True)
    attack_rows = df[df["label"] != "Normal"]

    if attack_rows.empty:
        return []

    incidents: list[Incident] = []
    current_rows = []
    current_label = None
    last_ts = None
    incident_counter = 0

    def flush():
        nonlocal incident_counter
        if not current_rows:
            return
        sub = pd.DataFrame(current_rows)
        incident_counter += 1
        incidents.append(Incident(
            incident_id=incident_counter,
            label=current_label,
            start_time=float(sub["timestamp"].min()),
            end_time=float(sub["timestamp"].max()),
            packet_count=len(sub),
            can_ids=sorted(sub["can_id"].unique().tolist()),
            avg_confidence=round(float(sub["confidence"].mean()), 4) if "confidence" in sub else None,
        ))

    for _, row in attack_rows.iterrows():
        if (
            current_label is None
            or row["label"] != current_label
            or (last_ts is not None and row["timestamp"] - last_ts > gap_tolerance_seconds)
        ):
            flush()
            current_rows = []
            current_label = row["label"]

        current_rows.append(row)
        last_ts = row["timestamp"]

    flush()
    return incidents


# --------------------------------------------------------------------------
# Replay engine
# --------------------------------------------------------------------------

class ReplayEngine:
    """
    Lets you "scrub" through a CAN log like a video: advance by packet
    count or jump to a timestamp, and pull whatever window of recent
    history should currently be visible on a live dashboard.
    """

    def __init__(self, df: pd.DataFrame, dashboard_window_seconds: float = 2.0):
        self.df = df.sort_values("timestamp").reset_index(drop=True)
        self.dashboard_window_seconds = dashboard_window_seconds
        self.current_index = 0

    @property
    def total_packets(self) -> int:
        return len(self.df)

    @property
    def current_time(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return float(self.df.iloc[min(self.current_index, self.total_packets - 1)]["timestamp"])

    def step(self, n_packets: int = 1) -> None:
        self.current_index = min(self.current_index + n_packets, self.total_packets - 1)

    def jump_to_time(self, t: float) -> None:
        idx = (self.df["timestamp"] - t).abs().idxmin()
        self.current_index = int(idx)

    def reset(self) -> None:
        self.current_index = 0

    def is_finished(self) -> bool:
        return self.current_index >= self.total_packets - 1

    def get_dashboard_window(self) -> pd.DataFrame:
        """Rows within `dashboard_window_seconds` before the current playhead."""
        now = self.current_time
        window_start = now - self.dashboard_window_seconds
        mask = (self.df["timestamp"] > window_start) & (self.df["timestamp"] <= now)
        return self.df.loc[mask]

    def get_played_so_far(self) -> pd.DataFrame:
        return self.df.iloc[: self.current_index + 1]


# --------------------------------------------------------------------------
# Live dashboard stats
# --------------------------------------------------------------------------

def compute_live_stats(window_df: pd.DataFrame) -> dict:
    if window_df.empty:
        return {
            "packets_in_window": 0,
            "packets_per_sec_est": 0.0,
            "pct_attack": 0.0,
            "unique_can_ids": 0,
            "dominant_label": "—",
            "active_alert": False,
        }

    n = len(window_df)
    attack_mask = window_df["label"] != "Normal"
    pct_attack = round(100 * attack_mask.sum() / n, 1)
    dominant_label = window_df["label"].value_counts().idxmax()
    span = max(window_df["timestamp"].max() - window_df["timestamp"].min(), 1e-6)

    return {
        "packets_in_window": n,
        "packets_per_sec_est": round(n / span, 1),
        "pct_attack": pct_attack,
        "unique_can_ids": window_df["can_id"].nunique(),
        "dominant_label": dominant_label,
        "active_alert": bool(attack_mask.any()),
    }


# --------------------------------------------------------------------------
# Self-test when run directly
# --------------------------------------------------------------------------

if __name__ == "__main__":
    df = generate_sample_can_log(duration_seconds=30, n_incidents=2)
    print(f"Generated {len(df)} packets over 30s with {(df['label'] != 'Normal').sum()} attack packets.")

    incidents = extract_incidents(df)
    print(f"\nExtracted {len(incidents)} incident(s):")
    for inc in incidents:
        print(" ", inc.to_dict())

    engine = ReplayEngine(df, dashboard_window_seconds=1.5)
    # jump into the middle of the first incident and check live stats
    if incidents:
        engine.jump_to_time(incidents[0].start_time + 0.5)
        stats = compute_live_stats(engine.get_dashboard_window())
        print(f"\nLive stats at t={engine.current_time:.2f}s (inside incident #1):")
        print(" ", stats)
