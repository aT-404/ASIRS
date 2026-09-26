# Detection Methodology

This platform implements 5 distinct KQL detections designed to identify malicious behaviors across Windows Security Events.

| Detection Name | Target Event ID | Target Behavior | MITRE ATT&CK Technique |
|---|---|---|---|
| **Brute Force** | 4625 | 5 or more failed logon attempts within a 15-minute window | T1110 (Brute Force) |
| **Success After Failure** | 4625 -> 4624 | Successful logon within 30 minutes following failed logon attempts | T1078 (Valid Accounts) |
| **Suspicious RDP** | 4624 (LogonType 10) | Interactive RDP session initiated from non-private external IP | T1021.001 (Remote Services: RDP) |
| **Privilege Escalation** | 4728 | Member addition to privileged domain groups (Administrators, Backup Operators) | T1098 (Account Manipulation) |
| **Suspicious Source IP** | Any | Aggregated activity from non-private external IP addresses | T1090 (Proxy / Infrastructure) |

## KQL Queries Overview

- **`brute_force.kql`**: Filters EventID `4625`, bins `TimeGenerated` into 15m intervals, and aggregates failure counts per Account and IP.
- **`success_after_failure.kql`**: Joins failed logons with subsequent successful logons for the same account and IP within a 30-minute window.
- **`suspicious_rdp.kql`**: Filters Remote Desktop interactive logons (`LogonType 10`) originating from non-private IP ranges.
- **`privilege_escalation.kql`**: Captures security group membership changes (`4728`) to track unauthorized administrative additions.
- **`suspicious_source_ip.kql`**: Aggregates all external non-private IP activities per user account.
