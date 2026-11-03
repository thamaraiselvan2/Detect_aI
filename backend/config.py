import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "fakedetector.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")


def load_environment():
    """Load backend settings from the .env next to this module."""
    return load_dotenv(dotenv_path=ENV_PATH, override=False)


ENV_LOADED = load_environment()

# Risk Level Classification Thresholds
RISK_LEVELS = {
    "LOW": (0, 29),
    "MEDIUM": (30, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100)
}

# Impersonation Alert Threshold: Minimum score to raise an automated alert
MONITORING_ALERT_THRESHOLD = 50

# Similarity metric thresholds
USERNAME_SIMILARITY_HIGH = 0.85
USERNAME_SIMILARITY_MODERATE = 0.70
DISPLAY_NAME_SIMILARITY_HIGH = 0.88

# Email simulation settings
EMAIL_CONFIG = {
    "ENABLED": True,
    "SENDER": "security-alerts@fakedetector.system",
    "SIMULATE_ONLY": True
}
