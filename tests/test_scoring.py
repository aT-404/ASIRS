import pytest
from src.scoring.score import score_case, severity_for, load_scoring_config

@pytest.fixture
def scoring_config():
    return load_scoring_config()

def test_score_case_single_detection(scoring_config):
    weights = scoring_config["weights"]
    bands = scoring_config["severity_bands"]

    score = score_case(["BRUTE_FORCE"], touched_sensitive_asset=False, weights=weights)
    assert score == 2
    assert severity_for(score, bands) == "LOW"

def test_score_case_full_attack_chain(scoring_config):
    weights = scoring_config["weights"]
    bands = scoring_config["severity_bands"]

    detections = ["BRUTE_FORCE", "SUCCESS_AFTER_FAILURE", "SUSPICIOUS_RDP", "PRIVILEGE_ESCALATION", "SUSPICIOUS_SOURCE_IP"]
    score = score_case(detections, touched_sensitive_asset=True, weights=weights)
    
    # 2 + 3 + 2 + 4 + 2 + 3 (sensitive bonus) = 16
    assert score == 16
    assert severity_for(score, bands) == "CRITICAL"

def test_severity_bands_boundary(scoring_config):
    bands = scoring_config["severity_bands"]
    assert severity_for(3, bands) == "LOW"
    assert severity_for(4, bands) == "MODERATE"
    assert severity_for(7, bands) == "HIGH"
    assert severity_for(11, bands) == "CRITICAL"
