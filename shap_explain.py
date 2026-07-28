"""
shap_explain.py

SHAP explainability layer for the CAN Bus Forensic Analysis capstone
project. Wraps any sklearn-compatible classifier (with .predict_proba)
so you can answer, for any flagged packet: "WHY did the model call
this an attack, and which features drove that decision?"

This is exactly the kind of thing that turns "we detected an attack"
into "we detected an attack AND can defend why the model believes it,"
which is what makes a forensics tool defensible/prize-worthy rather
than a black box.

INTEGRATION POINT
------------------
    explainer = DetectionExplainer(model, feature_names, class_names)
    explanation = explainer.explain_instance(feature_row_dict)

Swap in YOUR trained model + feature_names list (see train_demo_model.py
docstring) and everything below works unchanged, as long as your model
exposes .predict_proba() (true for RandomForest, XGBoost, LightGBM,
sklearn's MLPClassifier, etc). If your model is a different kind
(e.g. a Keras/PyTorch neural net), tell me and I'll swap the explainer
type (KernelExplainer/DeepExplainer instead of TreeExplainer) — the
rest of this file and the UI stay the same either way.
"""

from __future__ import annotations

from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
import shap


@dataclass
class FeatureContribution:
    feature: str
    value: float
    shap_value: float

    @property
    def direction(self) -> str:
        return "pushes toward attack" if self.shap_value > 0 else "pushes toward normal"


@dataclass
class Explanation:
    predicted_label: str
    predicted_confidence: float
    base_value: float
    contributions: list  # list[FeatureContribution], sorted by |shap_value| descending

    def top_n(self, n: int = 5) -> list:
        return sorted(self.contributions, key=lambda c: abs(c.shap_value), reverse=True)[:n]

    def to_summary_text(self, n: int = 3) -> str:
        top = self.top_n(n)
        parts = [
            f"{c.feature}={c.value:g} ({c.direction}, impact {c.shap_value:+.3f})"
            for c in top
        ]
        return f"Predicted **{self.predicted_label}** ({self.predicted_confidence:.1%} confidence). Top drivers: " + "; ".join(parts)


class DetectionExplainer:
    """
    Wraps a fitted tree-based classifier (RandomForest, XGBoost, etc.)
    with SHAP's TreeExplainer for fast, exact explanations.
    """

    def __init__(self, model, feature_names: list, class_names: list | None = None):
        self.model = model
        self.feature_names = feature_names
        self.class_names = class_names or list(getattr(model, "classes_", []))
        self._explainer = shap.TreeExplainer(model)

    @classmethod
    def from_files(cls, model_path: str = "model.joblib", feature_names_path: str = "feature_names.json") -> "DetectionExplainer":
        import json
        model = joblib.load(model_path)
        with open(feature_names_path) as f:
            feature_names = json.load(f)
        return cls(model, feature_names)

    def explain_instance(self, feature_row: dict) -> Explanation:
        """
        feature_row: dict mapping feature_name -> value for ONE packet.
        Returns an Explanation for whichever class the model predicted.
        """
        X = pd.DataFrame([feature_row])[self.feature_names]
        pred_label = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]
        class_idx = list(self.model.classes_).index(pred_label)
        confidence = float(proba[class_idx])

        shap_values = self._explainer.shap_values(X)

        # shap_values shape handling: newer SHAP returns array (n_samples, n_features, n_classes)
        # for multiclass tree models; older returns a list of per-class arrays.
        if isinstance(shap_values, list):
            sv_for_class = shap_values[class_idx][0]
            base_value = self._explainer.expected_value[class_idx]
        elif shap_values.ndim == 3:
            sv_for_class = shap_values[0, :, class_idx]
            base_value = self._explainer.expected_value[class_idx]
        else:
            sv_for_class = shap_values[0]
            base_value = self._explainer.expected_value

        contributions = [
            FeatureContribution(feature=f, value=float(X.iloc[0][f]), shap_value=float(sv))
            for f, sv in zip(self.feature_names, sv_for_class)
        ]

        return Explanation(
            predicted_label=str(pred_label),
            predicted_confidence=confidence,
            base_value=float(base_value),
            contributions=contributions,
        )

    def global_feature_importance(self, background_df: pd.DataFrame, sample_size: int = 300) -> pd.DataFrame:
        """
        Mean |SHAP value| per feature across a sample of packets —
        answers "which features matter most to the model overall?"
        (as opposed to explain_instance, which answers "why THIS packet?").
        """
        sample = background_df[self.feature_names]
        if len(sample) > sample_size:
            sample = sample.sample(sample_size, random_state=42)

        shap_values = self._explainer.shap_values(sample)

        if isinstance(shap_values, list):
            stacked = np.abs(np.array(shap_values))  # (n_classes, n_samples, n_features)
            mean_abs = stacked.mean(axis=(0, 1))
        elif shap_values.ndim == 3:
            mean_abs = np.abs(shap_values).mean(axis=(0, 2))
        else:
            mean_abs = np.abs(shap_values).mean(axis=0)

        return pd.DataFrame({
            "feature": self.feature_names,
            "mean_abs_shap": mean_abs,
        }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)


# --------------------------------------------------------------------------
# Self-test when run directly
# --------------------------------------------------------------------------

if __name__ == "__main__":
    from train_demo_model import generate_synthetic_training_data, FEATURE_NAMES

    explainer = DetectionExplainer.from_files()

    df = generate_synthetic_training_data(n_rows=500, seed=99)

    print("=== Explaining a DoS packet ===")
    dos_row = df[df["label"] == "DoS"].iloc[0][FEATURE_NAMES].to_dict()
    exp = explainer.explain_instance(dos_row)
    print(exp.to_summary_text())

    print("\n=== Explaining a Spoofing packet ===")
    spoof_row = df[df["label"] == "Spoofing"].iloc[0][FEATURE_NAMES].to_dict()
    exp2 = explainer.explain_instance(spoof_row)
    print(exp2.to_summary_text())

    print("\n=== Global feature importance ===")
    importance = explainer.global_feature_importance(df)
    print(importance)
