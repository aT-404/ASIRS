# Investigation & Scoring Methodology

> [!IMPORTANT]
> *Note: This is a project-specific analytical scoring model, not an industry-standard severity calculation.*

## Correlation Window
Raw detection alerts are correlated by matching `(account, source_ip)` events that occur within a rolling `60-minute` window.

## Risk Scoring Weights
Each detection type carries a specific risk weight defined in `config/scoring.yaml`:

- **Failed Auth (`BRUTE_FORCE`)**: 2 points
- **Successful Auth (`SUCCESS_AFTER_FAILURE`)**: 3 points
- **Suspicious Source IP (`SUSPICIOUS_SOURCE_IP`)**: 2 points
- **RDP Access (`SUSPICIOUS_RDP`)**: 2 points
- **Privilege Escalation (`PRIVILEGE_ESCALATION`)**: 4 points
- **Sensitive Asset Bonus (`DC-01`)**: 3 points

## Severity Bands
- **LOW:** 0 to 3 points
- **MODERATE:** 4 to 6 points
- **HIGH:** 7 to 10 points
- **CRITICAL:** 11+ points
