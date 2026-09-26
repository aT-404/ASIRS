DETECTION_TO_MITRE = {
    "BRUTE_FORCE": ["T1110"],
    "SUCCESS_AFTER_FAILURE": ["T1078"],
    "SUSPICIOUS_RDP": ["T1021.001"],
    "PRIVILEGE_ESCALATION": ["T1098"],
    "SUSPICIOUS_SOURCE_IP": ["T1090"],
}

def get_mitre_techniques(detections):
    techniques = set()
    for d in detections:
        for t in DETECTION_TO_MITRE.get(d, []):
            techniques.add(t)
    return sorted(list(techniques))
