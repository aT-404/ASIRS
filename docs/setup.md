# Setup & Operations Guide

## 1. Environment Requirements
- Python 3.10+
- Azure Data Explorer (ADX) Free Cluster
- ServiceNow Personal Developer Instance (PDI)

## 2. Installation
```bash
git clone <repo-url>
cd soc-investigation-platform
pip install -r requirements.txt
```

## 3. Configuration (.env)
Copy `.env.example` to `.env`:
```env
ADX_CLUSTER_URL=https://<your-cluster>.<region>.kusto.windows.net
ADX_DATABASE=soc
SERVICENOW_INSTANCE_URL=https://devXXXXX.service-now.com
SERVICENOW_USER=admin
SERVICENOW_PASSWORD=your_password
```

> [!NOTE]
> *ServiceNow PDIs hibernate if left inactive for several days. If API calls fail with HTTP 401/403, log into the ServiceNow Developer Console to wake up your instance.*

## 4. Running the Pipeline
```bash
python src/main.py
```

## 5. Launching the Dashboard
```bash
streamlit run dashboard/app.py
```

> [!NOTE]
> *On Windows, Streamlit may display a non-critical notice regarding symlink permissions (`Symlinks not supported on this system... Falling back to global installation`). This is standard OS behavior for Streamlit skills on Windows and does not affect application functionality.*
