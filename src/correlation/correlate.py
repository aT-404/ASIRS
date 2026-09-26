import ipaddress
from datetime import datetime, timedelta
import pandas as pd

def is_private_ip(ip):
    if not ip or pd.isna(ip) or str(ip).strip() == "":
        return True
    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
        return (
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj in ipaddress.ip_network("10.0.0.0/8") or
            ip_obj in ipaddress.ip_network("172.16.0.0/12") or
            ip_obj in ipaddress.ip_network("192.168.0.0/16")
        )
    except ValueError:
        return True

def parse_time(t_str):
    if not t_str or pd.isna(t_str):
        return None
    try:
        dt = pd.to_datetime(t_str)
        if hasattr(dt, "to_pydatetime"):
            return dt.to_pydatetime()
        return dt
    except Exception:
        return None

def extract_hit_times(det_type, hit):
    if det_type == "BRUTE_FORCE":
        t_start = parse_time(hit.get("first_seen"))
        t_end = parse_time(hit.get("last_seen")) or t_start
    elif det_type == "SUCCESS_AFTER_FAILURE":
        t_start = parse_time(hit.get("first_fail"))
        t_end = parse_time(hit.get("success_at")) or t_start
    elif det_type in ["SUSPICIOUS_RDP", "PRIVILEGE_ESCALATION", "SUSPICIOUS_SOURCE_IP"]:
        t_start = parse_time(hit.get("time_generated"))
        t_end = t_start
    else:
        t_start = None
        t_end = None
    return t_start, t_end

def correlate_detections(all_detection_results, sensitive_assets=None, window_minutes=60):
    """
    Groups raw detection hits by (account, source_ip) within rolling window_minutes.
    Events for the same account+IP separated by more than window_minutes form separate cases.
    Each case only includes hits that fall inside its own time window.
    """
    sensitive_assets = sensitive_assets or ["DC-01"]
    raw_by_account_ip = {}

    # Step 1: Collect hits per (account, source_ip)
    for det_type, hits in all_detection_results.items():
        for hit in hits:
            account = hit.get("account")
            ip = hit.get("source_ip")
            if not account or not ip:
                continue

            # Filter internal routine low-scoring mistyped password control noise
            if is_private_ip(ip) and det_type == "SUCCESS_AFTER_FAILURE":
                continue

            key = (account, ip)
            if key not in raw_by_account_ip:
                raw_by_account_ip[key] = []
            
            t_start, t_end = extract_hit_times(det_type, hit)
            raw_by_account_ip[key].append((det_type, hit, t_start, t_end))

    result_groups = []

    # Step 2: For each account+IP pair, cluster timestamped hits using rolling correlation window
    for (account, ip), hit_tuples in raw_by_account_ip.items():
        timestamped_hits = [item for item in hit_tuples if item[2] is not None]
        static_hits = [item for item in hit_tuples if item[2] is None]

        # Sort chronologically by start time
        timestamped_hits.sort(key=lambda x: x[2])

        sessions = []
        current_session = []
        session_end_time = None

        for item in timestamped_hits:
            det_type, hit, t_start, t_end = item
            if not current_session:
                current_session.append(item)
                session_end_time = t_end or t_start
            else:
                # Calculate time gap between current hit start and running session end
                time_gap = (t_start - session_end_time).total_seconds() / 60.0
                if time_gap <= window_minutes:
                    current_session.append(item)
                    if t_end and t_end > session_end_time:
                        session_end_time = t_end
                else:
                    # Gap exceeds rolling window: finalize current session, start new session
                    sessions.append(current_session)
                    current_session = [item]
                    session_end_time = t_end or t_start

        if current_session:
            sessions.append(current_session)

        # Handle case where only static hits exist (fallback)
        if not sessions and static_hits:
            sessions.append(static_hits)
            static_hits = []

        # Step 3: Convert each session into a correlated group
        for session_hits in sessions:
            full_session_hits = list(session_hits)
            # Attach static detection hits (without timestamps)
            for item in static_hits:
                full_session_hits.append(item)

            detections = set()
            hosts = set()
            touched_sensitive = False
            raw_hits_for_case = []

            for item in full_session_hits:
                det_type, hit = item[0], item[1]
                raw_hits_for_case.append((det_type, hit))
                detections.add(det_type)
                computer = hit.get("computer")
                if computer:
                    hosts.add(computer)
                    if computer in sensitive_assets:
                        touched_sensitive = True
                if hit.get("hosts"):
                    for h in hit.get("hosts"):
                        hosts.add(h)
                        if h in sensitive_assets:
                            touched_sensitive = True

            result_groups.append({
                "account": account,
                "source_ip": ip,
                "detections": sorted(list(detections)),
                "touched_sensitive_asset": touched_sensitive,
                "hosts": sorted(list(hosts)),
                "raw_hits": raw_hits_for_case
            })

    return result_groups
