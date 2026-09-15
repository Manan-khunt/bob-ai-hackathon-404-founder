"""Cheap local fast-path detector for obvious telemetry spikes."""

from collections import deque
from statistics import mean, pstdev


class LocalDetector:
    def __init__(self, window: int = 20, z_threshold: float = 3.0):
        self.window = window
        self.z_threshold = z_threshold
        self.values: deque[float] = deque(maxlen=window)

    def score(self, value: float) -> float:
        if len(self.values) < 2:
            self.values.append(value)
            return 0.0
        baseline = mean(self.values)
        spread = pstdev(self.values) or 1.0
        self.values.append(value)
        return abs(value - baseline) / spread

    def is_anomaly(self, value: float) -> bool:
        return self.score(value) >= self.z_threshold
