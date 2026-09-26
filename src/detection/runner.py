import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.detection.brute_force import run_brute_force_query
from src.detection.success_after_failure import run_success_after_failure_query
from src.detection.suspicious_rdp import run_suspicious_rdp_query
from src.detection.privilege_escalation import run_privilege_escalation_query
from src.detection.suspicious_source_ip import run_suspicious_source_ip_query

def run_all_detections(kusto_client=None, database="soc", csv_path=None):
    results = {
        "BRUTE_FORCE": run_brute_force_query(kusto_client, database, csv_path),
        "SUCCESS_AFTER_FAILURE": run_success_after_failure_query(kusto_client, database, csv_path),
        "SUSPICIOUS_RDP": run_suspicious_rdp_query(kusto_client, database, csv_path),
        "PRIVILEGE_ESCALATION": run_privilege_escalation_query(kusto_client, database, csv_path),
        "SUSPICIOUS_SOURCE_IP": run_suspicious_source_ip_query(kusto_client, database, csv_path),
    }
    return results

if __name__ == "__main__":
    all_res = run_all_detections()
    for det_type, hits in all_res.items():
        print(f"=== {det_type} ({len(hits)} hits) ===")
        for h in hits:
            print(" ", h)
