"""Phishing prediction engine with probability calibration and occlusion attribution."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.ml.features import FEATURE_NAMES, extract_features

logger = logging.getLogger(__name__)

_shared_predictor: PhishingPredictor | None = None


def get_shared_predictor() -> PhishingPredictor | None:
    return _shared_predictor


def set_shared_predictor(predictor: PhishingPredictor | None) -> None:
    global _shared_predictor
    _shared_predictor = predictor


class PhishingPredictor:
    """Loads trained model once and computes calibrated predictions and feature attributions."""

    def __init__(
        self,
        model_path: str = "app/ml/model/phishing_model.joblib",
        metadata_path: str = "app/ml/model/metadata.json",
    ) -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.model = None
        self.metadata: dict[str, Any] = {}
        self.version = "unknown"
        self.medians: dict[str, float] = {}
        self.is_loaded = False

        self._load()

    def _load(self) -> None:
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
                logger.info("Loaded ML model artifact from %s", self.model_path)
            except Exception as e:
                logger.error("Failed to load model from %s: %s", self.model_path, e)
                self.model = None
                self.is_loaded = False

        if self.metadata_path.exists():
            try:
                with self.metadata_path.open("r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.version = self.metadata.get("version", "1.0.0")
                self.medians = self.metadata.get("per_feature_training_medians", {})
            except Exception as e:
                logger.error("Failed to load model metadata from %s: %s", self.metadata_path, e)

        # Fallback default medians if metadata missing
        if not self.medians:
            self.medians = {feat: 0.0 for feat in FEATURE_NAMES}

    def predict_sync(self, url: str) -> dict[str, Any]:
        """Synchronous prediction and occlusion calculation."""
        if not self.is_loaded or self.model is None:
            raise RuntimeError("Phishing model is not loaded")

        raw_features = extract_features(url)
        proc_features = {k: (int(v) if isinstance(v, bool) else v) for k, v in raw_features.items()}

        # Original input row
        X_orig = pd.DataFrame([proc_features])[list(FEATURE_NAMES)]
        p_orig = float(self.model.predict_proba(X_orig)[0, 1])

        # Feature explanation by occlusion:
        # Create a batch of 34 variants, each with one feature replaced with its training median
        occluded_rows: list[dict[str, Any]] = []
        for feat in FEATURE_NAMES:
            row_copy = dict(proc_features)
            row_copy[feat] = self.medians.get(feat, 0.0)
            occluded_rows.append(row_copy)

        X_occluded = pd.DataFrame(occluded_rows)[list(FEATURE_NAMES)]
        p_occluded = self.model.predict_proba(X_occluded)[:, 1]

        # Calculate impact = p_original - p_replaced
        # Positive impact raises risk (original value made probability higher than median)
        raw_impacts: dict[str, float] = {}
        for idx, feat in enumerate(FEATURE_NAMES):
            raw_impacts[feat] = float(p_orig - p_occluded[idx])

        max_abs_impact = max((abs(imp) for imp in raw_impacts.values()), default=0.0)

        # Normalize impacts to range -1..1
        normalized_features: list[dict[str, Any]] = []
        for feat in FEATURE_NAMES:
            if max_abs_impact > 1e-6:
                norm_imp = round(raw_impacts[feat] / max_abs_impact, 4)
            else:
                norm_imp = 0.0
            norm_imp = max(-1.0, min(1.0, norm_imp))

            normalized_features.append({
                "name": feat,
                "value": raw_features[feat],  # Real value preserving original type
                "impact": norm_imp,
            })

        # Return top 8 features by absolute impact
        normalized_features.sort(key=lambda item: abs(item["impact"]), reverse=True)
        top_8 = normalized_features[:8]

        return {
            "phishing_probability": round(p_orig, 4),
            "model_version": self.version,
            "top_features": top_8,
        }

    async def predict_async(self, url: str) -> dict[str, Any]:
        """Asynchronously executes prediction in thread pool."""
        return await asyncio.to_thread(self.predict_sync, url)
