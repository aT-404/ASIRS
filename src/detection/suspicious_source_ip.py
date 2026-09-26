import os
import ipaddress
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

def run_suspicious_source_ip_query(kusto_client=None, database="soc", csv_path=None):
    if kusto_client and os.getenv("ADX_CLUSTER_URL") and "<cluster>" not in os.getenv("ADX_CLUSTER_URL", ""):
        query = """
        SecurityEvents
        | where isnotempty(IPAddress) and not(ipv4_is_private(IPAddress))
        | project TimeGenerated, Account, IPAddress, Computer, Activity
        """
        response = kusto_client.execute(database, query)
        results = []
        for row in response.primary_results[0]:
            results.append({
                "time_generated": str(row["TimeGenerated"]),
                "account": str(row["Account"]),
                "source_ip": str(row["IPAddress"]),
                "computer": str(row["Computer"]),
                "activity": str(row["Activity"]),
            })
        return results

    # Local fallback
    path = csv_path or os.path.join("data", "sample", "securitylab_windows_events_v2.csv")
    df = pd.read_csv(path)
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"])
    df["EventID"] = df["EventID"].astype(str)

    external_events = df[~df["IPAddress"].apply(is_private_ip)].copy()

    results = []
    for _, row in external_events.iterrows():
        results.append({
            "time_generated": row["TimeGenerated"].isoformat(),
            "account": str(row["Account"]),
            "source_ip": str(row["IPAddress"]),
            "computer": str(row["Computer"]),
            "activity": str(row["Activity"]) if pd.notna(row["Activity"]) else "External IP Activity",
        })
    return results
