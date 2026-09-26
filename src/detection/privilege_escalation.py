import os
import pandas as pd

def run_privilege_escalation_query(kusto_client=None, database="soc", csv_path=None):
    if kusto_client and os.getenv("ADX_CLUSTER_URL") and "<cluster>" not in os.getenv("ADX_CLUSTER_URL", ""):
        query = """
        SecurityEvents
        | where EventID == "4728"
        | project TimeGenerated, Account, TargetAccount, MemberName, IPAddress, Computer
        """
        response = kusto_client.execute(database, query)
        results = []
        for row in response.primary_results[0]:
            results.append({
                "time_generated": str(row["TimeGenerated"]),
                "account": str(row["Account"]),
                "target_account": str(row["TargetAccount"]),
                "member_name": str(row["MemberName"]),
                "source_ip": str(row["IPAddress"]),
                "computer": str(row["Computer"]),
            })
        return results

    # Local fallback
    path = csv_path or os.path.join("data", "sample", "securitylab_windows_events_v2.csv")
    df = pd.read_csv(path)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df["EventID"] = df["EventID"].astype(str)

    priv_events = df[df["EventID"] == "4728"].copy()

    results = []
    for _, row in priv_events.iterrows():
        results.append({
            "time_generated": row["TimeGenerated"].isoformat(),
            "account": str(row["Account"]),
            "target_account": str(row["TargetAccount"]),
            "member_name": str(row["MemberName"]),
            "source_ip": str(row["IPAddress"]) if pd.notna(row["IPAddress"]) else "",
            "computer": str(row["Computer"]),
        })
    return results
