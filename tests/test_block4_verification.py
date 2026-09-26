import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.detection.runner import run_all_detections
from src.correlation.correlate import correlate_detections
from src.scoring.score import load_scoring_config, score_case, severity_for

def test_correlation_and_scoring():
    config = load_scoring_config()
    all_det = run_all_detections()
    groups = correlate_detections(all_det, sensitive_assets=config.get("sensitive_assets"))

    print("=== Correlation & Scoring Results ===")
    for g in groups:
        score = score_case(
            g["detections"],
            g["touched_sensitive_asset"],
            config["weights"],
            config["weights"].get("sensitive_asset", 3)
        )
        sev = severity_for(score, config["severity_bands"])
        print(f"Account: {g['account']}, IP: {g['source_ip']}, Detections: {g['detections']}, Sensitive: {g['touched_sensitive_asset']}, Score: {score}, Severity: {sev}")

if __name__ == "__main__":
    test_correlation_and_scoring()
