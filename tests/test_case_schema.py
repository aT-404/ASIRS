import pytest
from src.investigation.case_builder import build_full_case

def test_case_schema_structure():
    fake_group = {
        "account": "testuser",
        "source_ip": "198.51.100.1",
        "detections": ["BRUTE_FORCE", "PRIVILEGE_ESCALATION"],
        "touched_sensitive_asset": True,
        "hosts": ["DC-01"],
        "raw_hits": [
            ("BRUTE_FORCE", {"fail_count": 8, "first_seen": "2026-09-21T14:00:00Z", "computer": "FILE-01"}),
            ("PRIVILEGE_ESCALATION", {"target_account": "Administrators", "time_generated": "2026-09-21T14:14:00Z", "computer": "DC-01"})
        ]
    }

    case = build_full_case("CASE-999", fake_group)

    expected_keys = {
        "case_id", "account", "source_ip", "detections", "mitre",
        "risk_score", "severity", "verdict", "timeline", "iocs", "servicenow_sys_id"
    }

    assert expected_keys.issubset(set(case.keys()))
    assert isinstance(case["case_id"], str)
    assert isinstance(case["risk_score"], int)
    assert isinstance(case["timeline"], list)
    assert isinstance(case["iocs"], dict)
    assert "accounts" in case["iocs"]
    assert "ips" in case["iocs"]
    assert "hosts" in case["iocs"]
