import os
import pandas as pd

def run_success_after_failure_query(kusto_client=None, database="soc", csv_path=None):
    if kusto_client and os.getenv("ADX_CLUSTER_URL") and "<cluster>" not in os.getenv("ADX_CLUSTER_URL", ""):
        query = """
        let window = 30m;
        let fails = SecurityEvents
            | where EventID == "4625"
            | project FailTime = TimeGenerated, Account, IPAddress;
        let successes = SecurityEvents
            | where EventID == "4624"
            | project SuccessTime = TimeGenerated, Account, IPAddress, Computer, Activity;
        fails
        | join kind=inner successes on Account, IPAddress
        | where SuccessTime > FailTime and SuccessTime - FailTime <= window
        | summarize FailsBefore = count(), FirstFail = min(FailTime), SuccessAt = max(SuccessTime), Hosts = make_set(Computer), Activities = make_set(Activity)
            by Account, IPAddress
        """
        response = kusto_client.execute(database, query)
        results = []
        for row in response.primary_results[0]:
            hosts = list(row["Hosts"]) if row["Hosts"] else []
            activities = list(row["Activities"]) if row["Activities"] else []
            computer = ", ".join(hosts) if hosts else "UNKNOWN"
            activity = ", ".join(activities) if activities else "Successful logon after repeated failures"
            results.append({
                "account": str(row["Account"]),
                "source_ip": str(row["IPAddress"]),
                "fails_before": int(row["FailsBefore"]),
                "first_fail": str(row["FirstFail"]),
                "success_at": str(row["SuccessAt"]),
                "computer": computer,
                "hosts": hosts,
                "activity": activity
            })
        return results

    # Local fallback
    path = csv_path or os.path.join("data", "sample", "securitylab_windows_events_v2.csv")
    df = pd.read_csv(path)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df["EventID"] = df["EventID"].astype(str)

    fails = df[df["EventID"] == "4625"][["TimeGenerated", "Account", "IPAddress"]].rename(columns={"TimeGenerated": "FailTime"})
    successes = df[df["EventID"] == "4624"][["TimeGenerated", "Account", "IPAddress", "Computer", "Activity"]].rename(columns={"TimeGenerated": "SuccessTime"})

    merged = pd.merge(fails, successes, on=["Account", "IPAddress"])
    merged["TimeDiff"] = merged["SuccessTime"] - merged["FailTime"]
    
    matched = merged[(merged["SuccessTime"] > merged["FailTime"]) & (merged["TimeDiff"] <= pd.Timedelta(minutes=30))].copy()

    # Group per unique successful logon event
    grouped = matched.groupby(["Account", "IPAddress", "SuccessTime", "Computer", "Activity"]).agg(
        FailsBefore=("FailTime", "count"),
        FirstFail=("FailTime", "min")
    ).reset_index()

    results = []
    for _, row in grouped.iterrows():
        results.append({
            "account": str(row["Account"]),
            "source_ip": str(row["IPAddress"]),
            "fails_before": int(row["FailsBefore"]),
            "first_fail": row["FirstFail"].isoformat(),
            "success_at": row["SuccessTime"].isoformat(),
            "computer": str(row["Computer"]),
            "hosts": [str(row["Computer"])],
            "activity": str(row["Activity"]) if pd.notna(row["Activity"]) else "Successful logon after repeated failures"
        })
    return results
