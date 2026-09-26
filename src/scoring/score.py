import yaml
import os

DETECTION_TO_WEIGHT_KEY = {
    "BRUTE_FORCE": "failed_auth",
    "SUCCESS_AFTER_FAILURE": "successful_auth",
    "SUSPICIOUS_SOURCE_IP": "suspicious_ip",
    "SUSPICIOUS_RDP": "rdp",
    "PRIVILEGE_ESCALATION": "privilege_escalation",
}

def load_scoring_config(config_path=None):
    path = config_path or os.path.join("config", "scoring.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def score_case(detection_types, touched_sensitive_asset, weights, sensitive_bonus=3):
    total = 0
    for d in detection_types:
        weight_key = DETECTION_TO_WEIGHT_KEY.get(d, d)
        if weight_key in weights:
            total += weights[weight_key]
    if touched_sensitive_asset:
        total += sensitive_bonus
    return total

def severity_for(score, bands):
    for label, (lo, hi) in bands.items():
        if lo <= score <= hi:
            return label
    return "UNKNOWN"
