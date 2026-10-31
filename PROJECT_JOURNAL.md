# Project Journal — SOC Investigation Platform

A running log of how this project actually happened. Kept mostly for myself, and to ensure every design trade-off, architectural revision, and bug hunt is documented with a clear paper trail rather than appearing out of nowhere.

---

### Entry 1 — The idea
Doing my ERM internship at Axis Max Life has put me next to a lot of "risk" conversations, and I keep thinking the technical, hands-on side of risk (actual attacker behavior, actual detection logic) is more interesting to me than the paperwork side of it. I've wanted to explore the practical intersection of enterprise risk, detection engineering, and incident response with hands-on tooling. The best way to understand how real-world detections behave is to build an end-to-end system from scratch.

So: a mini SOC investigation platform. Logs in, detections out, a real ticket at the end of it. Something with an actual pipeline, not just a Jupyter notebook that prints "ALERT!!" in red text.

### Entry 2 — Research
Spent the evening reading about how real SOC teams structure investigations: detection → correlation → triage → case → incident. Also looked at KQL for the first time properly — turns out it's basically SQL that went to detective school. Landed on this stack:

- Azure Data Explorer for the log storage + KQL querying
- Python for everything that isn't a query
- ServiceNow for the actual incident ticket (because a real investigation workflow needs to integrate with an enterprise ITSM platform rather than stopping at mock console alerts)
- Streamlit for a dashboard, at the very end, once there's something worth looking at

Also decided early: I'm not claiming my risk-scoring formula is an industry standard. It's mine, it's transparent, and I'll say so in the README instead of pretending Gartner blessed it.

### Entry 3 — Building the sample dataset
Since enterprise production logs are confidential, I built a dedicated dataset: Windows security events (4624 successful logon, 4625 failed logon, 4728 group membership change) across 5 fake employees and 6 fake machines, spread over about 5 days. Buried a proper attack story in there on purpose — a brute-force RDP attempt that eventually succeeds and ends with the attacker adding themselves to Administrators. If I can't detect the attack I planted myself, there's no point going further.

### Entry 4 — First base plan
Wrote up v1 of the system plan: architecture diagram, five detection ideas, a risk-scoring table, a repo structure, and a 33-step roadmap that built every detection first and only touched ServiceNow at step 17. Felt very complete. Felt very organized. Was, in hindsight, backwards.

### Entry 5 — Seeking a second opinion (Using AI for Planning)
Before sinking real hours into this, I used Claude / AI to assist in developing and pressure-testing the system plan and architecture. I handed over my initial architecture draft and sample CSV structure and asked the AI to poke holes in the workflow, challenge assumptions, and catch architectural blind spots before writing code.

Turns out there were holes:
- I was planning to build all 5 detections *before* ever proving the ServiceNow connection worked. Backwards — the integration is the riskiest part, so it should go first, not last.
- I assumed Azure Data Explorer needed a paid subscription. It doesn't — there's a free cluster, no card required.
- ServiceNow's free dev instance hibernates if you leave it alone too long. Would've been a fun surprise to discover mid-build.
- My "correlation" step wasn't actually defined as a rule anywhere, just a box in a diagram.
- No MITRE ATT&CK technique IDs anywhere, just tactic names. Not specific enough.
- A `tests/` folder existed in the repo draft with nothing planned to put in it.

### Entry 6 — Corrections
Rewrote the build order around one idea: prove the hardest connection first. New order is one detection → one case → one real ServiceNow incident, *then* build out the rest. Added the MITRE technique table, defined the correlation window properly (same account + same IP, inside a rolling window), moved my scoring weights into a config file instead of hardcoding them, and added an actual test plan.

Also went back to the dataset with fresh eyes and noticed two gaps: my privilege-escalation detection only had one example to test against (bad — means I can't tell if the logic generalizes or if I just memorized one row), and my "suspicious RDP" detection had no case where it was the *only* thing that should fire. Added:
- A second escalation chain on a different account, into a different privileged group, from a different IP.
- A clean RDP-from-a-new-IP case with zero failed logons, so the RDP detection can't just piggyback on the brute-force one.
- A boring control case — a user mistyping their password twice and then logging in fine — specifically so I can prove the scoring model doesn't flag ordinary human error as an incident.

### Entry 7 — Where things stand
The roadmap was structured into clear development milestones, each with a concrete verification test instead of a vague step in a list. Dataset was finalized at 1230 rows across 5 accounts, 6 hosts, and 4 external IPs, with enough deliberate variety (2 full attack chains, 1 RDP-only case, 1 IP-only case, 1 clean control case) that I can actually demonstrate every detection independently instead of hoping one big scenario covers everything.

### Entry 8 — Phase 0: Repo Skeleton and Environment Setup
Set up the full codebase directory structure (`config/`, `data/sample/`, `kql/`, `src/`, `dashboard/`, `cases/`, `docs/`, `tests/`), copied `securitylab_windows_events_v2.csv` into `data/sample/`, and created `requirements.txt`, `.env.example`, `config/scoring.yaml`, `README.md`, and `LICENSE`.

With the local repo skeleton in place, the next phase requires verifying the external cloud infrastructure: ingesting the dataset into an Azure Data Explorer (ADX) free cluster database (`SecurityEvents` table) and acquiring a ServiceNow Personal Developer Instance (PDI) for API connectivity.

### Entry 9 — Phase 1: Data Exploration KQL Queries Prepared
Authored the three exploration queries in `kql/exploration/`: `counts_by_account.kql`, `counts_by_eventid.kql`, and `external_ip_activity.kql`. These queries allow baseline aggregation by account, event type/activity, and non-private external IP filtering to verify dataset shape and confirm the 4 external IPs (`203.0.113.45`, `198.51.100.77`, `45.145.66.12`, `91.198.174.192`) upon ADX ingestion.

### Entry 10 — Phase 2: MVP Slice Execution
Built the end-to-end MVP slice: `kql/detections/brute_force.kql`, `src/detection/brute_force.py` (with ADX client execution and local fallback), `src/investigation/case_builder.py`, `src/servicenow/client.py`, and `src/main.py`. Verified detection logic against the dataset, successfully extracting brute-force attempts for `bob` (8 failures from `203.0.113.45`) and `diana` (5 failures from `198.51.100.77`), generating `cases/CASE-001.json`. ServiceNow incident creation logic and idempotency lookup (`find_existing`) were integrated into the client script and tested. Tested with live ServiceNow credentials, successfully creating incident `sys_id: 079bf37dc3270310022c770d050131d9` and verifying idempotency on repeated execution.

### Entry 11 — Phase 3: All 5 Detections Constructed and Verified
Authored all remaining KQL detection queries in `kql/detections/` (`success_after_failure.kql`, `suspicious_rdp.kql`, `privilege_escalation.kql`, `suspicious_source_ip.kql`) alongside their matching Python execution wrappers in `src/detection/` and unified `src/detection/runner.py`. Resolved IP range evaluation for RFC 5737 documentation ranges to align Python local private IP filtering with ADX `ipv4_is_private()`. Verification against the 1230-row dataset confirmed expected behavior:
- `bob` (`203.0.113.45`): 5 detections fired (`BRUTE_FORCE`, `SUCCESS_AFTER_FAILURE`, `SUSPICIOUS_RDP`, `PRIVILEGE_ESCALATION` into Administrators, `SUSPICIOUS_SOURCE_IP`).
- `eve` (`91.198.174.192`): 4 detections fired (`SUCCESS_AFTER_FAILURE`, `SUSPICIOUS_RDP`, `PRIVILEGE_ESCALATION` into Backup Operators, `SUSPICIOUS_SOURCE_IP`) — brute force did *not* trigger here, since eve's chain only has 3 failed logons before the successful one, one short of the 5-fail threshold. Small relief, actually: it means the threshold is doing its job instead of rubber-stamping every case with every label.
- `diana` (`198.51.100.77`): `BRUTE_FORCE` & `SUSPICIOUS_SOURCE_IP` fired (no success, no privilege escalation).
- `charlie` (`45.145.66.12`): `SUSPICIOUS_RDP` & `SUSPICIOUS_SOURCE_IP` fired (clean RDP logon, zero failed attempts).
- `alice` (internal control case): no attack detections triggered.

### Entry 12 — Core Pipeline & Platform Completion
Completed all core architecture components:
- **Correlation & Scoring Engine**: Built `src/correlation/correlate.py` (60-minute window, Account + Source IP grouping, noise filtering) and `src/scoring/score.py` (weight mapping from `config/scoring.yaml`, sensitive asset bonus for `DC-01`, severity band assignment). Verified scores: `bob` (Score 16, CRITICAL), `eve` (Score 14, CRITICAL), `diana` (Score 4, MODERATE), `charlie` (Score 4, MODERATE), `alice` (filtered/0 cases).
- **Investigation Case Object**: Enhanced `src/investigation/case_builder.py` with MITRE ATT&CK mapping (`T1110`, `T1078`, `T1021.001`, `T1098`, `T1090`), chronological timeline ordering, IOC aggregation, and JSON file generation (`cases/CASE-001.json` through `CASE-004.json`).
- **ServiceNow Full Integration**: Updated `src/servicenow/client.py` with full payload mapping, severity translation (`urgency`/`impact`), and work note patching (`update_incident_work_note`) for idempotency. Executed against live ServiceNow instance: created tickets for `CASE-001` through `CASE-004` and confirmed idempotency on re-run.
- **Interactive Dashboard**: Created `dashboard/app.py` (Streamlit) featuring active case metrics, incident dataframes, case selector, chronological timeline, IOC breakdown, and ServiceNow direct links.
- **Tests & Documentation**: Implemented full pytest suite (`tests/test_scoring.py`, `tests/test_correlation.py`, `tests/test_case_schema.py`, `tests/test_integration.py` — 6/6 passed), complete documentation suite (`docs/architecture.md`, `docs/detection-methodology.md`, `docs/investigation-methodology.md`, `docs/setup.md`), and finalized `README.md`.

### Entry 13 — Testing Verification, CI Pipeline & Deployment Readiness
Finalized testing and deployment preparation across the platform:
- **Automated CI/CD Workflow**: Authored `.github/workflows/tests.yml` to automatically execute unit tests via `pytest` on Python 3.11 for all repository pushes and pull requests.
- **Security & Secret Sanitization**: Verified `.gitignore` configuration to exclude `.env` environment files, virtual environments (`.venv/`), and cached bytecode (`__pycache__/`). Ensured no live API tokens, passwords, or private environment variables are committed or exposed in the repository or journal log.
- **Verification**: All 6 pytest test cases executed cleanly, verifying scoring weights, correlation grouping, and case schema validity. The platform is fully verified and prepared for production review and repository deployment.

### Entry 14 — Refactoring for Usability: Interactive SOC Workspace & Executive PDF Reporting
After stepping back to review the complete platform, something about the workflow bugged me. We had a functional backend pipeline and a read-only Streamlit viewer, but in a real-world SOC setting, asking an analyst to context-switch into a terminal prompt or manually swap log file paths on disk whenever a new event batch arrives felt clunky and incomplete. A true investigation platform shouldn't feel like a disconnected set of CLI scripts wrapped in a passive viewer — it should be an interactive operational workspace.

Decided to go back and elevate the dashboard into a full SOC Workspace:
1. **On-Demand Pipeline Execution**: Added a direct "Run Investigation Pipeline" trigger in the UI sidebar, allowing analysts to execute detections, correlation, risk scoring, and ServiceNow ticket sync directly from the browser.
2. **Dynamic Drag-and-Drop Log Ingestion**: Integrated a file uploader enabling analysts to drag and drop raw Windows Event Log CSV files directly into the web UI, analyze new datasets instantly, and inspect updated triage results on the fly.
3. **Executive PDF Report Export**: Built a dedicated ReportLab-powered PDF engine (`src/reports/pdf_generator.py`) and added a one-click "Download PDF Executive Report" button in the dashboard. Analysts can now export formal, publication-ready incident reports — complete with executive metric summaries, triage overview tables, timelines, MITRE ATT&CK tags, and ServiceNow incident references — ready for management or compliance sharing.

### Entry 15 — Timeline Cleanup and Report Polish
Sent the generated PDF back for another look, and it was worth it — three real bugs and two things worth double-checking turned up.

Bug 1 and Bug 2 turned out to be the same root problem wearing two different hats: `build_timeline()` was looping over detection *names* as if they were dated events. `SUSPICIOUS_SOURCE_IP` isn't tied to a single moment — it's a property of the whole case — so it was showing up as a standalone row with no timestamp at all. `SUCCESS_AFTER_FAILURE` had a worse version of the same bug: it grabbed whatever timestamp happened to be sitting in scope at that point in the loop, so it showed up as a duplicate row with the *wrong* time attached. Fixed by making `build_timeline()` pull only from real, timestamped log rows (`4624`, `4625`, `4728`) and nothing else. Detection names now stay exactly where they belong — the `detections` list and the MITRE tags — instead of pretending to be diary entries.

Bug 3 was smaller: the brute-force summary query grouped by account, IP, and time bin, but never asked for `Computer` in the process, so the host silently disappeared into `UNKNOWN`. Added `Hosts = make_set(Computer)` and wired it through.

Also cleaned up two smaller things while I was in there: an emoji in the PDF title that ReportLab's default font couldn't render (showed up as two black boxes — stripped it), and tightened the HIGH vs CRITICAL split so "High Severity" actually means the 7–10 band, not "HIGH or CRITICAL, who's counting."

Re-ran the pipeline on the same dataset and diffed every timeline row against the raw CSV by hand afterward. Everything lines up now — no `UNKNOWN`s, no duplicates, no vanished hosts — and the risk scores themselves didn't move (`bob` 16 CRITICAL, `eve` 14 CRITICAL, `diana` 4 MODERATE, `charlie` 4 MODERATE), which is exactly what should happen when a formatting bug gets fixed without anyone touching the actual scoring logic.

### Entry 16 — The Testing Marathon (v2, v3, v4)
Decided the platform wasn't "done" just because it ran without errors — it needed to survive datasets built specifically to break it. So I generated three more purpose-built test datasets and worked through the reports one bug at a time instead of trusting the first clean-looking output.

What actually turned up, in the order it turned up:
- **State leakage between runs.** Re-running the pipeline on a smaller dataset didn't clear out cases from a previous, larger run — old cases from one dataset were bleeding into the report for a completely different one. Fixed by making sure each run only reports on cases that belong to it.
- **A detection that outlived its own time window.** After I got proper rolling-window correlation working (splitting one account's activity into separate cases when the gap between events was too large), `SUSPICIOUS_RDP` kept showing up on a case that had zero RDP events in it — it was still being computed at the whole-account level instead of per case. Fixed so every detection is scoped to only the events inside its own case.
- **A vanishing timeline row**, caused by an off-by-one in whatever was splitting a account's events into separate case groups — one case was quietly missing its last real event. Found by comparing the raw dataset against the report line by line until the missing row stood out.
- **The big one: a tumbling-bin blind spot.** My brute-force detection binned failed logons into fixed 15-minute clock buckets. Built a test account with 6 failed logons in under 9 minutes, split 3-and-3 across exactly one of those bucket boundaries on purpose — and the whole attack went completely undetected, because neither half crossed the 5-fail threshold alone. That's not a display bug, that's a real gap an attacker could walk through just by pacing their attempts. Rewrote it as a true sliding window instead of a fixed bin, re-ran the same split-burst scenario, and it fired correctly this time.

Also picked up a smaller, genuinely nice discovery along the way: `SUSPICIOUS_RDP` only fires on a *successful* RDP logon, not a failed one — meaning a pure RDP brute-force attempt that never gets in correctly stays out of that specific detection. Wasn't something I'd deliberately designed, but it turned out to be exactly the right behavior once I thought about what the detection is actually supposed to mean.

Every fix got re-verified against the exact scenario that caught it, not just glanced at. Four real bugs found this way beats zero bugs found by not looking.

---

*Testing turned out to be less of an afterthought and more of its own project. Deployment write-up — the actual "here's how you stand this up yourself" walkthrough — is still mine to add once it's live somewhere.*
