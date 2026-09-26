# SOC Investigation Platform — Detailed Implementation Plan

This is the full, block-by-block build plan. Each block lists exact files, exact KQL/config where possible, and a clear "done when" test. Use this alongside `PROJECT_PLAN.md` for the high-level picture.

Dataset used: `securitylab_windows_events_v2.csv` (1230 rows — see the note at the end of this file for what changed from v1).

---

## Block 0 — Environment Setup

**Goal:** a working ADX cluster with your data in it, and a ServiceNow instance you can hit from Python.

Steps:
1. Go to the ADX free-cluster page, sign in with a Microsoft account, create a cluster (`MyFreeCluster` or similar) and one database (e.g. `soc`).
2. Ingest `securitylab_windows_events_v2.csv` using the web UI's "Ingest new data" wizard into a table called `SecurityEvents`. Let the wizard infer the schema, then check the types:
   - `TimeGenerated` → `datetime`
   - `EventID` → `string` (keep as string, not int — you'll filter by exact values like `"4624"`)
   - Everything else → `string`
3. Sign up for a ServiceNow Personal Developer Instance (PDI). Note the instance URL, and create a basic-auth user for API access (Settings → your PDI login is fine to start with).
4. Repo skeleton:
   ```
   soc-investigation-platform/
   ├── README.md
   ├── LICENSE
   ├── requirements.txt
   ├── .env.example
   ├── config/
   │   └── scoring.yaml
   ├── data/sample/securitylab_windows_events_v2.csv
   ├── kql/{exploration,detections,hunting}/
   ├── src/{detection,correlation,scoring,investigation,mitre,servicenow}/
   ├── dashboard/
   ├── cases/
   ├── evidence/
   ├── reports/
   ├── docs/
   └── tests/
   ```
5. `.env.example`:
   ```
   ADX_CLUSTER_URL=https://<cluster>.<region>.kusto.windows.net
   ADX_DATABASE=soc
   SERVICENOW_INSTANCE_URL=https://<your-instance>.service-now.com
   SERVICENOW_USER=admin
   SERVICENOW_PASSWORD=changeme
   ```
6. `requirements.txt`: `azure-kusto-data`, `requests`, `pyyaml`, `pandas`, `streamlit`, `pytest`.

**Done when:** `SecurityEvents | take 10` in the ADX web UI returns rows, and you can log into your PDI in a browser.

---

## Block 1 — Exploration

**Goal:** confirm the data shape in KQL before writing detections against it.

Files in `kql/exploration/`:

- `counts_by_account.kql`
  ```kql
  SecurityEvents
  | summarize Events = count() by Account
  | order by Events desc
  ```
- `counts_by_eventid.kql`
  ```kql
  SecurityEvents
  | summarize Events = count() by EventID, Activity
  | order by Events desc
  ```
- `external_ip_activity.kql`
  ```kql
  SecurityEvents
  | where isnotempty(IPAddress) and not(ipv4_is_private(IPAddress))
  | summarize Events = count(), Accounts = make_set(Account) by IPAddress
  ```

**Done when:** `external_ip_activity.kql` returns 4 external IPs (`203.0.113.45`, `198.51.100.77`, `45.145.66.12`, `91.198.174.192`), each tied to the account you'd expect.

---

## Block 2 — MVP Slice (the one that matters most)

**Goal:** one detection, one case, one real incident in ServiceNow. Do this before anything else.

`kql/detections/brute_force.kql`:
```kql
SecurityEvents
| where EventID == "4625"
| summarize FailCount = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated)
    by Account, IPAddress, bin(TimeGenerated, 15m)
| where FailCount >= 5
```

`src/detection/brute_force.py` — pulls the query result via `azure-kusto-data`, returns a list of dicts: `{account, source_ip, fail_count, first_seen, last_seen}`.

`src/investigation/case_builder.py` — turns one detection hit into a minimal case:
```python
def build_case(case_id, account, source_ip, detections, risk_score, severity):
    return {
        "case_id": case_id,
        "account": account,
        "source_ip": source_ip,
        "detections": detections,
        "risk_score": risk_score,
        "severity": severity,
        "verdict": "UNDER_REVIEW",
        "servicenow_sys_id": None,
    }
```
Save it as `cases/CASE-001.json`.

`src/servicenow/client.py` — minimal incident creation:
```python
import requests

def create_incident(instance_url, auth, case):
    payload = {
        "short_description": f"Brute force from {case['source_ip']} against {case['account']}",
        "description": str(case["detections"]),
        "category": "Security",
        "urgency": "2",
        "impact": "2",
        "correlation_id": case["case_id"],
    }
    r = requests.post(
        f"{instance_url}/api/now/table/incident",
        auth=auth, json=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    r.raise_for_status()
    return r.json()["result"]["sys_id"]
```

Wire it up in `src/main.py` (a temporary script, gets replaced properly in Block 6): run the brute-force query → build one case from `bob`'s data → create the incident → write the returned `sys_id` back into `cases/CASE-001.json`.

**Done when:** you open your ServiceNow PDI and see a real incident with `bob` and `203.0.113.45` in the short description, and `cases/CASE-001.json` has a non-null `servicenow_sys_id`.

---

## Block 3 — Remaining Detections

Each one is its own `.kql` file in `kql/detections/`, plus a matching `.py` wrapper in `src/detection/`.

`success_after_failure.kql`:
```kql
let window = 30m;
let fails = SecurityEvents
    | where EventID == "4625"
    | project FailTime = TimeGenerated, Account, IPAddress;
let successes = SecurityEvents
    | where EventID == "4624"
    | project SuccessTime = TimeGenerated, Account, IPAddress;
fails
| join kind=inner successes on Account, IPAddress
| where SuccessTime > FailTime and SuccessTime - FailTime <= window
| summarize FailsBefore = count(), FirstFail = min(FailTime), SuccessAt = max(SuccessTime)
    by Account, IPAddress
```

`suspicious_rdp.kql`:
```kql
SecurityEvents
| where EventID == "4624" and LogonType == "10"
| where isnotempty(IPAddress) and not(ipv4_is_private(IPAddress))
| project TimeGenerated, Account, IPAddress, Computer, Activity
```
This is the one that catches `charlie` from `45.145.66.12` — no failed logons at all, so `brute_force.kql` would miss it completely. This is why it needs to be its own detection, not a variant of Detection 1.

`privilege_escalation.kql`:
```kql
SecurityEvents
| where EventID == "4728"
| project TimeGenerated, Account, TargetAccount, MemberName, IPAddress, Computer
```
`TargetAccount` here is the group name (`Administrators`, `Backup Operators`), `MemberName` is who got added. With the updated dataset this now returns 2 rows on 2 different accounts/groups, so your detection logic can't just hardcode "bob" — test that it doesn't.

`suspicious_source_ip.kql`:
```kql
SecurityEvents
| where isnotempty(IPAddress) and not(ipv4_is_private(IPAddress))
| summarize Events = count(), Activities = make_set(Activity) by Account, IPAddress
```

**Done when:** running all 5 against the full dataset gives you:
- `bob` / `203.0.113.45` → 4 detections fire (brute force, success-after-failure, suspicious RDP, privilege escalation)
- `eve` / `91.198.174.192` → same 4 detections fire, different group
- `diana` / `198.51.100.77` → only suspicious source IP fires (no success, no escalation)
- `charlie` / `45.145.66.12` → only suspicious RDP fires (no brute force at all — proves Detection 3 earns its place)
- `alice`'s two failed logons on 2026-09-25 → nothing fires (below every threshold)

---

## Block 4 — Correlation + Scoring

`config/scoring.yaml`:
```yaml
correlation_window_minutes: 60

weights:
  failed_auth: 2
  successful_auth: 3
  suspicious_ip: 2
  rdp: 2
  privilege_escalation: 4
  sensitive_asset: 3

sensitive_assets:
  - DC-01

severity_bands:
  LOW: [0, 3]
  MODERATE: [4, 6]
  HIGH: [7, 10]
  CRITICAL: [11, 999]
```

`src/correlation/correlate.py` — group raw detection hits by `(account, source_ip)` where the events fall inside `correlation_window_minutes` of each other. Output: one group per account+IP combination, with the list of detection types that fired for it.

`src/scoring/score.py` — pure function, no I/O, easy to unit test:
```python
def score_case(detection_types, touched_sensitive_asset, weights, sensitive_bonus):
    total = sum(weights[d] for d in detection_types)
    if touched_sensitive_asset:
        total += sensitive_bonus
    return total

def severity_for(score, bands):
    for label, (lo, hi) in bands.items():
        if lo <= score <= hi:
            return label
    return "UNKNOWN"
```

**Done when:** `bob` and `eve` both land in HIGH or CRITICAL, `diana` lands in LOW or MODERATE, `charlie` lands in LOW (RDP + external IP only, no escalation), and `alice` produces no case at all.

---

## Block 5 — Investigation Case Object

Full case schema (`cases/CASE-XXX.json`):
```json
{
  "case_id": "CASE-002",
  "account": "eve",
  "source_ip": "91.198.174.192",
  "detections": ["BRUTE_FORCE", "SUCCESS_AFTER_FAILURE", "SUSPICIOUS_RDP", "PRIVILEGE_ESCALATION"],
  "mitre": ["T1110", "T1078", "T1021.001", "T1098"],
  "risk_score": 11,
  "severity": "CRITICAL",
  "verdict": "TRUE_POSITIVE",
  "timeline": [
    {"time": "2026-09-25T16:00:00Z", "event": "Failed RDP logon", "host": "FILE-01"},
    {"time": "2026-09-25T16:04:00Z", "event": "Successful RDP logon after repeated failures", "host": "FILE-01"},
    {"time": "2026-09-25T16:09:00Z", "event": "User added to Backup Operators", "host": "DC-01"},
    {"time": "2026-09-25T16:11:00Z", "event": "Successful privileged logon", "host": "DC-01"}
  ],
  "iocs": {
    "accounts": ["eve"],
    "ips": ["91.198.174.192"],
    "hosts": ["FILE-01", "DC-01"]
  },
  "servicenow_sys_id": null
}
```
Start with plain JSON files in `cases/`. Only move to SQLite once you have more than a handful of cases and start wanting to query across them — don't build the database layer before you need it.

---

## Block 6 — ServiceNow Full Integration

Field mapping (`src/servicenow/client.py`, extended from Block 2):

| Case field | ServiceNow incident field |
|---|---|
| `case_id` | `correlation_id` (used for the idempotency check) |
| `account` + `source_ip` | `short_description` |
| `timeline` + `detections` | `description` |
| `severity` | `urgency` / `impact` (map HIGH/CRITICAL → 1, MODERATE → 2, LOW → 3) |
| fixed value | `category = "Security"`, `subcategory = "Unauthorized Access"` |
| `mitre` list | appended to `description`, or a custom field `u_mitre_techniques` if you add one |

Idempotency check — before creating, query for an existing incident with the same `correlation_id`:
```python
def find_existing(instance_url, auth, case_id):
    r = requests.get(
        f"{instance_url}/api/now/table/incident",
        auth=auth, params={"sysparm_query": f"correlation_id={case_id}"},
        headers={"Accept": "application/json"},
    )
    r.raise_for_status()
    results = r.json()["result"]
    return results[0]["sys_id"] if results else None
```
If found, add a work note instead of creating a new incident (`PATCH` to `/api/now/table/incident/{sys_id}` with `{"work_notes": "Re-checked, no change"}` or updated findings).

**Done when:** running your pipeline twice on the same dataset produces exactly one incident per case, not two.

---

## Block 7 — Dashboard

`dashboard/app.py` (Streamlit), rough layout:
- Top row: 4 metric boxes — Active Cases, High Risk, Critical, True Positives (`st.metric`)
- Below: a table of cases (`st.dataframe`) — case_id, account, source_ip, risk_score, severity
- Click a row (or a `st.selectbox` of case_ids) → detail view:
  - Timeline as a simple ordered list
  - IOCs as three small tables (accounts, IPs, hosts)
  - MITRE technique IDs as tags
  - A link/button to the ServiceNow incident, built as `f"{instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"`

Build this last. It's a read-only view over `cases/*.json` — there's no new integration risk here, so it doesn't need to be built early.

---

## Block 8 — Tests, Docs, Polish

Tests (`tests/`):
- `test_scoring.py` — feed `score_case()` known detection lists, assert exact scores and severity bands
- `test_correlation.py` — feed a small fake list of timestamped events, assert they group correctly inside/outside the window
- `test_case_schema.py` — assert every field in Block 5's schema is present and correctly typed for a sample case

Docs (`docs/`):
- `architecture.md` — the diagram from `PROJECT_PLAN.md`, plus a one-paragraph explanation of each stage
- `detection-methodology.md` — the 5 detections, their KQL, and the MITRE table
- `investigation-methodology.md` — correlation window, scoring weights, severity bands, and the explicit line: *this is a project-specific analytical scoring model, not an industry-standard severity calculation*
- `setup.md` — ADX free cluster setup, ServiceNow PDI setup (and the note that PDIs hibernate — log in every few days), `.env` setup

README: problem statement → architecture diagram → one real case walkthrough (use `eve`'s case, it's the cleanest full chain) → screenshot of the dashboard → screenshot of the ServiceNow incident it created → how to run it locally.

Extra: a GitHub Actions workflow (`.github/workflows/tests.yml`) that runs `pytest` on every push. Small addition, decent signal that you think about CI. - do this after the completion of the entire work and everything is tested and deployed properly

---

## What changed in the dataset (v1 → v2)

Kept everything from the original file and added 12 rows:
- `charlie` / `45.145.66.12` — clean RDP access from a new external IP, no failed logons at all. Exists so Detection 3 (suspicious RDP) has its own standalone test case, separate from the brute-force chains.
- `eve` / `91.198.174.192` — a second full brute-force → success → privilege escalation chain, into `Backup Operators` instead of `Administrators`. Exists so the privilege-escalation detection isn't only ever tested against one row.
- `alice` — two ordinary mistyped-password failures followed by a normal successful login, same day, same internal IP. Exists as a control case: your scoring model should produce nothing for this, and that's the point — it proves the model isn't just flagging every failed login it sees.
