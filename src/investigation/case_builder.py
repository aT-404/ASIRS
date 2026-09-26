import json
import os
import glob
import pandas as pd
from src.mitre.mapping import get_mitre_techniques
from src.scoring.score import score_case, severity_for, load_scoring_config

def build_timeline(raw_hits):
    time_host_events = {}
    brute_force_windows = []

    # Step 1: Identify all Brute Force attack windows
    for det_type, hit in raw_hits:
        if det_type == "BRUTE_FORCE":
            t_first = pd.to_datetime(hit.get("first_seen")) if hit.get("first_seen") else None
            t_last = pd.to_datetime(hit.get("last_seen")) if hit.get("last_seen") else t_first
            if t_first:
                brute_force_windows.append((t_first, t_last))

    # Step 2: Build candidate timeline events
    for det_type, hit in raw_hits:
        time_val = hit.get("time_generated") or hit.get("first_seen") or hit.get("success_at") or ""
        if not time_val:
            continue

        host_val = hit.get("computer")
        if not host_val and hit.get("hosts"):
            host_val = ", ".join(hit.get("hosts"))
        if not host_val:
            host_val = "UNKNOWN"

        if det_type == "BRUTE_FORCE":
            desc = f"Brute force attempt ({hit.get('fail_count')} failures)"
        elif det_type == "PRIVILEGE_ESCALATION":
            desc = f"User added to group {hit.get('target_account')}"
        else:
            desc = hit.get("activity") or det_type

        # Suppress individual raw failed-logon events that fall inside a Brute Force summary window
        if det_type != "BRUTE_FORCE" and any(w in desc.lower() for w in ["failed rdp logon", "failed network logon", "failed logon", "failed auth"]):
            t_event = pd.to_datetime(time_val)
            inside_bf_window = False
            for w_start, w_end in brute_force_windows:
                if w_start - pd.Timedelta(minutes=1) <= t_event <= w_end + pd.Timedelta(minutes=1):
                    inside_bf_window = True
                    break
            if inside_bf_window:
                continue

        key = (time_val, host_val)
        if key not in time_host_events:
            time_host_events[key] = desc
        else:
            existing_desc = time_host_events[key]
            # Prefer specific event descriptions over general/generic ones
            if "group" in desc.lower() and "group" not in existing_desc.lower():
                time_host_events[key] = desc
            elif "brute force" in desc.lower() and "brute force" not in existing_desc.lower():
                time_host_events[key] = desc
            elif len(desc) > len(existing_desc) and "external ip" not in desc.lower():
                time_host_events[key] = desc

    events = []
    for (time_val, host_val), desc in time_host_events.items():
        events.append({
            "time": time_val,
            "event": desc,
            "host": host_val
        })

    events.sort(key=lambda x: x["time"])
    return events

def build_full_case(case_id, correlated_group, config=None):
    config = config or load_scoring_config()
    detections = correlated_group["detections"]
    account = correlated_group["account"]
    source_ip = correlated_group["source_ip"]
    hosts = correlated_group["hosts"]
    raw_hits = correlated_group.get("raw_hits", [])

    score = score_case(
        detections,
        correlated_group["touched_sensitive_asset"],
        config["weights"],
        config["weights"].get("sensitive_asset", 3)
    )
    severity = severity_for(score, config["severity_bands"])
    mitre = get_mitre_techniques(detections)
    timeline = build_timeline(raw_hits)

    verdict = "TRUE_POSITIVE" if severity in ["HIGH", "CRITICAL"] else "UNDER_REVIEW"

    return {
        "case_id": case_id,
        "account": account,
        "source_ip": source_ip,
        "detections": detections,
        "mitre": mitre,
        "risk_score": score,
        "severity": severity,
        "verdict": verdict,
        "timeline": timeline,
        "iocs": {
            "accounts": [account],
            "ips": [source_ip],
            "hosts": hosts
        },
        "servicenow_sys_id": None
    }

def clear_cases_dir(cases_dir="cases"):
    """Purge stale CASE-*.json files from previous runs."""
    if os.path.exists(cases_dir):
        for f in glob.glob(os.path.join(cases_dir, "CASE-*.json")):
            try:
                os.remove(f)
            except Exception:
                pass

def save_case(case, cases_dir="cases"):
    os.makedirs(cases_dir, exist_ok=True)
    file_path = os.path.join(cases_dir, f"{case['case_id']}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2)
    return file_path
