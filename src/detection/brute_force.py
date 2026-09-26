import os
import pandas as pd

def run_brute_force_query(kusto_client=None, database="soc", csv_path=None):
    """
    Executes brute force detection using a true 15-minute sliding window.
    If kusto_client is provided, queries ADX.
    Otherwise, if csv_path is provided (or defaults to local sample dataset), evaluates locally.
    Returns list of dicts: [{account, source_ip, fail_count, first_seen, last_seen, computer, hosts}]
    """
    if kusto_client and os.getenv("ADX_CLUSTER_URL") and "<cluster>" not in os.getenv("ADX_CLUSTER_URL", ""):
        query = """
        let window = 15m;
        let fails = SecurityEvents
            | where EventID == "4625"
            | project Time1 = TimeGenerated, Account, IPAddress, Computer;
        let fails2 = SecurityEvents
            | where EventID == "4625"
            | project Time2 = TimeGenerated, Account, IPAddress;
        fails
        | join kind=inner fails2 on Account, IPAddress
        | where Time1 >= Time2 and Time1 - Time2 <= window
        | summarize FailCount = count(), FirstFail = min(Time2), LastFail = max(Time1), Hosts = make_set(Computer)
            by Account, IPAddress, Time1
        | where FailCount >= 5
        | summarize FailCount = max(FailCount), FirstFail = min(FirstFail), LastFail = max(LastFail), Hosts = make_set_pv(Hosts)
            by Account, IPAddress
        """
        response = kusto_client.execute(database, query)
        results = []
        for row in response.primary_results[0]:
            hosts = list(row["Hosts"]) if row["Hosts"] else []
            computer = ", ".join(hosts) if hosts else "UNKNOWN"
            results.append({
                "account": str(row["Account"]),
                "source_ip": str(row["IPAddress"]),
                "fail_count": int(row["FailCount"]),
                "first_seen": str(row["FirstFail"]),
                "last_seen": str(row["LastFail"]),
                "computer": computer,
                "hosts": hosts
            })
        return results

    # Local fallback with true 15-minute sliding window evaluation
    path = csv_path or os.path.join("data", "sample", "securitylab_windows_events_v2.csv")
    df = pd.read_csv(path)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df["EventID"] = df["EventID"].astype(str)

    fails = df[df["EventID"] == "4625"].copy().sort_values("TimeGenerated")

    results = []

    for (account, ip), group in fails.groupby(["Account", "IPAddress"]):
        group_rows = group.to_dict("records")
        detected_windows = []

        for curr in group_rows:
            curr_time = curr["TimeGenerated"]
            win_start = curr_time - pd.Timedelta(minutes=15)
            window_events = [r for r in group_rows if win_start <= r["TimeGenerated"] <= curr_time]

            if len(window_events) >= 5:
                first_seen = min(r["TimeGenerated"] for r in window_events)
                last_seen = max(r["TimeGenerated"] for r in window_events)
                fail_count = len(window_events)
                hosts = list(set(r["Computer"] for r in window_events if pd.notna(r["Computer"])))
                detected_windows.append({
                    "account": account,
                    "source_ip": ip,
                    "fail_count": fail_count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "hosts": hosts
                })

        if detected_windows:
            max_fail_count = max(w["fail_count"] for w in detected_windows)
            first_seen_overall = min(w["first_seen"] for w in detected_windows)
            last_seen_overall = max(w["last_seen"] for w in detected_windows)
            all_hosts = list(set(h for w in detected_windows for h in w["hosts"]))
            computer = ", ".join(all_hosts) if all_hosts else "UNKNOWN"

            results.append({
                "account": str(account),
                "source_ip": str(ip),
                "fail_count": max_fail_count,
                "first_seen": first_seen_overall.isoformat(),
                "last_seen": last_seen_overall.isoformat(),
                "computer": computer,
                "hosts": all_hosts
            })

    return results
