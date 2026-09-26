# Platform Architecture

```mermaid
flowchart TD
    A["Windows Event Logs (CSV / Event Stream)"] --> B["Azure Data Explorer (ADX) - SecurityEvents"]
    B --> C["KQL Detection Queries (kql/detections/*.kql)"]
    C --> D["Python Detection Runner (src/detection/runner.py)"]
    D --> E["Correlation Engine (src/correlation/correlate.py)"]
    E --> F["Risk Scoring & MITRE Engine (src/scoring/ & src/mitre/)"]
    F --> G["Case Object Generator (src/investigation/case_builder.py)"]
    G --> H["JSON Case Repository (cases/CASE-XXX.json)"]
    H --> I["ServiceNow REST API Client (src/servicenow/client.py)"]
    H --> J["Streamlit Incident Dashboard (dashboard/app.py)"]
    I --> K["ServiceNow Security Incident Tickets"]
```

## Stage Descriptions

1. **Log Storage & Querying:** Logs are ingested into Azure Data Explorer (ADX) database table `SecurityEvents` and queried using high-performance Kusto Query Language (KQL).
2. **Detection Layer:** Modular KQL detection queries target specific indicators (Brute Force, RDP logon, privilege escalation, success-after-failure).
3. **Correlation Engine:** Raw hits are grouped by account and external source IP across a rolling correlation time window.
4. **Analytical Risk Scoring & MITRE Mapping:** Calculates risk scores based on detection weights, sensitive asset touches (e.g. Domain Controller `DC-01`), assigns severity bands, and tags corresponding MITRE ATT&CK techniques.
5. **Investigation Case Objects:** Standardized JSON objects created for each correlated incident with timeline details and IOCs.
6. **ServiceNow Incident Integration:** Automatic creation and idempotent updating of ServiceNow security incident tickets.
7. **Streamlit Dashboard:** Interactive visual dashboard for SOC analysts to review active metrics, case details, timelines, and ServiceNow links.
