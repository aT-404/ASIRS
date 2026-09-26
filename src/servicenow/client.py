import requests
import json

SEVERITY_MAPPING = {
    "CRITICAL": ("1", "1"),
    "HIGH": ("1", "2"),
    "MODERATE": ("2", "2"),
    "LOW": ("3", "3"),
}

def map_case_to_servicenow_payload(case):
    urgency, impact = SEVERITY_MAPPING.get(case.get("severity", "LOW"), ("3", "3"))
    
    desc_lines = [
        f"Detections Triggered: {', '.join(case.get('detections', []))}",
        f"MITRE ATT&CK Techniques: {', '.join(case.get('mitre', []))}",
        f"Risk Score: {case.get('risk_score')} (Severity: {case.get('severity')})",
        "",
        "--- Event Timeline ---"
    ]
    for item in case.get("timeline", []):
        desc_lines.append(f"[{item.get('time')}] Host: {item.get('host')} - {item.get('event')}")
    
    desc_lines.extend([
        "",
        "--- IOC Summary ---",
        f"Accounts: {', '.join(case.get('iocs', {}).get('accounts', []))}",
        f"IPs: {', '.join(case.get('iocs', {}).get('ips', []))}",
        f"Hosts: {', '.join(case.get('iocs', {}).get('hosts', []))}",
    ])

    return {
        "short_description": f"Security Alert: Suspicious activity from {case['source_ip']} on account {case['account']}",
        "description": "\n".join(desc_lines),
        "category": "Security",
        "subcategory": "Unauthorized Access",
        "urgency": urgency,
        "impact": impact,
        "correlation_id": case["case_id"],
    }

def find_existing(instance_url, auth, case_id):
    url = f"{instance_url.rstrip('/')}/api/now/table/incident"
    r = requests.get(
        url,
        auth=auth,
        params={"sysparm_query": f"correlation_id={case_id}"},
        headers={"Accept": "application/json"},
    )
    r.raise_for_status()
    results = r.json().get("result", [])
    return results[0]["sys_id"] if results else None

def update_incident_work_note(instance_url, auth, sys_id, note_text):
    url = f"{instance_url.rstrip('/')}/api/now/table/incident/{sys_id}"
    r = requests.patch(
        url,
        auth=auth,
        json={"work_notes": note_text},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    r.raise_for_status()
    return r.json()["result"]["sys_id"]

def create_or_update_incident(instance_url, auth, case):
    existing_sys_id = find_existing(instance_url, auth, case["case_id"])
    if existing_sys_id:
        update_incident_work_note(
            instance_url,
            auth,
            existing_sys_id,
            f"Pipeline re-run for {case['case_id']}: Re-verified detection chain. No changes."
        )
        return existing_sys_id, False  # (sys_id, created_new)

    payload = map_case_to_servicenow_payload(case)
    url = f"{instance_url.rstrip('/')}/api/now/table/incident"
    r = requests.post(
        url,
        auth=auth,
        json=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    r.raise_for_status()
    sys_id = r.json()["result"]["sys_id"]
    return sys_id, True  # (sys_id, created_new)
