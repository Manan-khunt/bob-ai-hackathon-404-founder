"""Stable telemetry feature extraction and IsolationForest persistence."""

from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from common.schemas import TelemetryEvent

FEATURE_NAMES = (
    "cpu_percent", "memory_percent", "network_connections", "connection_rate",
    "bytes_sent", "bytes_received", "file_activity", "entropy",
)


def telemetry_vector(event: TelemetryEvent | dict) -> list[float]:
    values = event if isinstance(event, dict) else event.model_dump()
    return [float(values.get(name, 0.0)) for name in FEATURE_NAMES]


def fit_baseline(events: Iterable[TelemetryEvent], model_path: str | Path, contamination: float = 0.02) -> dict:
    rows = [telemetry_vector(event) for event in events]
    if not rows:
        raise ValueError("at least one telemetry event is required to fit a baseline")
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(np.asarray(rows))
    path = Path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, path)
    return {"samples": len(rows), "model_path": str(path), "feature_names": FEATURE_NAMES}


def load_model(model_path: str | Path):
    return joblib.load(model_path)


def confidence(anomaly_score: float, duration_factor: float, classifier_agreement: float = 1.0) -> float:
    return min(1.0, max(0.0, 0.6 * anomaly_score + 0.25 * duration_factor + 0.15 * classifier_agreement))
