from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "immune_memory.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

WATSONX_API_KEY = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
WATSONX_MODEL = os.getenv("WATSONX_MODEL", "ibm/granite-13b-chat-v2")
WATSONX_PROMPT_MODEL = os.getenv("WATSONX_PROMPT_MODEL", "ibm/granite-8b-japanese")

WS_BROADCAST_INTERVAL = float(os.getenv("WS_BROADCAST_INTERVAL", "0.1"))

TRIAGE_THRESHOLDS = {
    "min_correlation_score_for_threat": 0.70,
    "honeypot_bonus": 0.20,
    "multi_source_bonus_per_source": 0.05,
    "multi_source_cap": 0.15,
    "needs_review_upper": 0.69,
}

PRIORITY_WEIGHTS = {
    "correlation_score": 30,
    "severity_value": 25,
    "confidence": 20,
    "multi_source_diversity": 15,
    "asset_criticality": 10,
}

SOURCE_TYPES = [
    "SIEM",
    "CYBER_SENSOR",
    "SATELLITE",
    "INTELLIGENCE",
    "ENDPOINT",
    "NETWORK_SENSOR",
    "HONEYPOT",
    "OSINT",
]
