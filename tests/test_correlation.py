import pytest
from src.correlation.correlate import correlate_detections

def test_correlate_detections_grouping():
    fake_detections = {
        "BRUTE_FORCE": [
            {"account": "testuser", "source_ip": "198.51.100.1", "fail_count": 5}
        ],
        "SUSPICIOUS_RDP": [
            {"account": "testuser", "source_ip": "198.51.100.1", "computer": "DC-01", "activity": "RDP logon"}
        ]
    }

    groups = correlate_detections(fake_detections, sensitive_assets=["DC-01"])
    assert len(groups) == 1
    g = groups[0]
    assert g["account"] == "testuser"
    assert g["source_ip"] == "198.51.100.1"
    assert set(g["detections"]) == {"BRUTE_FORCE", "SUSPICIOUS_RDP"}
    assert g["touched_sensitive_asset"] is True
    assert "DC-01" in g["hosts"]
