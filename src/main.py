import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
from src.detection.runner import run_all_detections
from src.correlation.correlate import correlate_detections
from src.scoring.score import load_scoring_config
from src.investigation.case_builder import build_full_case, save_case, clear_cases_dir
from src.servicenow.client import create_or_update_incident

load_dotenv()

def run_pipeline():
    print("==================================================")
    print(" SOC Investigation Platform - Main Pipeline Run ")
    print("==================================================")

    # 1. Load config & run detections
    config = load_scoring_config()
    print("[+] Step 1: Running all 5 KQL detections...")
    all_detections = run_all_detections()

    # 2. Correlate detections
    print("[+] Step 2: Correlating detections into security cases...")
    groups = correlate_detections(all_detections, sensitive_assets=config.get("sensitive_assets"))
    print(f"    -> Correlated {len(groups)} distinct security incident groups.")

    # 3. Build & score case objects
    cases = []
    print("[+] Step 3: Scoring cases & generating investigation case objects...")
    for idx, g in enumerate(groups, start=1):
        case_id = f"CASE-{idx:03d}"
        case = build_full_case(case_id, g, config=config)
        cases.append(case)
        print(f"    -> {case['case_id']}: Account={case['account']}, IP={case['source_ip']}, "
              f"Score={case['risk_score']} ({case['severity']}), Detections={case['detections']}")

    # 4. Save case files (purge stale cases from previous runs first)
    print("[+] Step 4: Purging stale cases & saving new case objects to cases/...")
    clear_cases_dir("cases")
    for case in cases:
        saved_path = save_case(case)
        print(f"    -> Saved {saved_path}")

    # 5. Integrate with ServiceNow
    instance_url = os.getenv("SERVICENOW_INSTANCE_URL")
    user = os.getenv("SERVICENOW_USER")
    password = os.getenv("SERVICENOW_PASSWORD")

    if instance_url and "<your-instance>" not in instance_url and password != "changeme":
        print("[+] Step 5: Syncing cases to ServiceNow...")
        auth = (user, password)
        for case in cases:
            try:
                sys_id, created_new = create_or_update_incident(instance_url, auth, case)
                action_str = "Created NEW Incident" if created_new else "Updated EXISTING Incident (Work Note Added)"
                print(f"    -> [{case['case_id']}] {action_str} - sys_id: {sys_id}")
                case["servicenow_sys_id"] = sys_id
                save_case(case)
            except Exception as e:
                print(f"    [!] Error syncing {case['case_id']} to ServiceNow: {e}")
    else:
        print("[!] ServiceNow credentials not set in .env; skipping ServiceNow sync.")

    print("\n[OK] Pipeline execution finished successfully.")
    return cases

if __name__ == "__main__":
    run_pipeline()
