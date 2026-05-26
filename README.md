# Azure Security Data Collector

A Python-based security data collection tool that authenticates to Azure 
using a Service Principal, pulls security-relevant data via REST API,
normalizes it into a consistent structure, and outputs audit-ready JSON reports. 
The normalization can be seen to standardize data that is pulled from various
data sources, rather than looking through each data set, which can have different 
ways outputs are displayed. 

Built to demonstrate the core pattern used in enterprise security data 
pipelines — authenticate, collect, normalize, deliver.

---

## What This Does

- Authenticates to Azure programmatically using a Service Principal 
  with Reader-only permissions (least privilege)
- Pulls role assignments — who has access to what across the subscription
- Pulls Azure activity logs — every operation performed in the last 24 hours
- Normalizes raw API responses into clean, consistent JSON
- Outputs a structured security report ready for ingestion into a 
  SIEM, data lake, or security dashboard

---

## Why This Matters in a Security Context

Banks and regulated enterprises run dozens of security tools — Azure, 
Zscaler, Palo Alto, SIEMs — each generating data in different formats. 
This project demonstrates the foundational pattern for collecting and 
normalizing that data into one consistent structure so security analysts 
can query across all sources without caring where the data came from.

Key security principles applied:
- **Least Privilege** — Service Principal assigned Reader role only. 
  A data collection script has no business modifying infrastructure
- **No Hardcoded Credentials** — all secrets stored in `.env` and 
  excluded from version control via `.gitignore`
- **Bearer Token Authentication** — standard OAuth2 pattern used 
  across enterprise API integrations
- **Audit Trail** — activity logs capture every operation performed 
  in the Azure environment, supporting compliance requirements

---

## Tech Stack

- **Python 3.12**
- **Azure Identity** — Service Principal authentication 
  via `ClientSecretCredential`
- **Azure Management Authorization SDK** — role assignment collection
- **Azure REST API** — activity log collection via HTTP requests
- **python-dotenv** — secure environment variable management

---

## Project Structure

azure-security-collector/
├── main.py                 # Main data collection script
├── .env                    # Credentials (excluded from Git)
├── .gitignore              # Protects credentials and venv
├── requirements.txt        # Python dependencies
└── security_report.json    # Normalized output (auto-generated)

---

## How It Works

### 1. Authentication
The script authenticates to Azure using a Service Principal — 
An application identity with scoped read-only permissions. 
This follows the principle of least privilege and mirrors how 
Production data collection pipelines authenticate in regulated environments.

```python
credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)
```

### 2. Data Collection
Two REST API calls pull security-relevant data:

**Role Assignments** — who has access to what:
```python
auth_client = AuthorizationManagementClient(credential, SUBSCRIPTION_ID)
assignments = auth_client.role_assignments.list_for_subscription()
```

**Activity Logs** — what happened in the last 24 hours:
```python
token = credential.get_token("https://management.azure.com/.default").token
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(url, headers=headers)
```

### 3. Normalization
Raw API responses are stripped down to only the fields that matter — 
timestamp, operation, status, caller, resource, correlation ID. 
This consistent structure allows downstream tools like Splunk, 
Grafana, or a data lake to query across multiple sources 
without needing to understand each source's raw format.

### 4. Output
Results are saved to `security_report.json` with a summary block 
showing total records collected — simulating delivery to a 
centralized security platform.

---

## Enterprise Connection

This project was inspired by real-world work supporting a 
J.P. Morgan infrastructure migration involving 49,000 enterprise 
endpoints. The need to programmatically validate endpoint security 
configurations at scale using PowerShell to call banking APIs, 
pull cipher suite data, and surface anomalies through Grafana-
revealed the same pattern this project demonstrates in Python and Azure.

---

## Security Notes

- `.env` is excluded from version control via `.gitignore`
- Service Principal uses Reader-only access. There is no write permissions for Service Principles
- Credentials are loaded via environment variables, never hardcoded
- Bearer tokens are obtained at runtime and never stored

---

## Future Enhancements

- [ ] Add Microsoft Defender for Cloud security score collection
- [ ] Integrate Zscaler API for web proxy log collection
- [ ] Add multi-subscription support
- [ ] Normalize output to OCSF (Open Cybersecurity Schema Framework)
- [ ] Schedule collection via Azure Functions or GitHub Actions
