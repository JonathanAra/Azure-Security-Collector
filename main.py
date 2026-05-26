import os
import json
from datetime import datetime, timedelta,timezone
from azure .identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
import requests

#This is meant to load credentials from Environment

TENANT_ID       = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID       = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET   = os.environ.get("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID")

#This is used to authenticate to Azure by using environment objects. Best approach for security first. 

credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)

print("✓ Authenticated to Azure successfully")

#Pulling role Assignments


def get_role_assignments():
    print("\n── Role Assignments (Who Has Access To What) ──")
    
    auth_client = AuthorizationManagementClient(credential, SUBSCRIPTION_ID)
    assignments = auth_client.role_assignments.list_for_subscription()
    
    results = []
    for assignment in assignments:
        entry = {
            "principal_id": assignment.principal_id,
            "role_definition_id": assignment.role_definition_id,
            "scope": assignment.scope,
        }
        results.append(entry)
        print(f"  Principal: {assignment.principal_id} | Scope: {assignment.scope}")
    
    return results

# PULL AZURE ACTIVITY LOGS 


def get_activity_logs():
    print("\n── Azure Activity Logs (Last 24 Hours) ──")

    # Get access token for API call
    token = credential.get_token("https://management.azure.com/.default").token

    # Set time range — last 24 hours
    end_time   = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    # Format timestamps for Azure API
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str   = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build the API request
    url = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/providers/microsoft.insights/eventtypes/management/values"
        f"?api-version=2015-04-01"
        f"&$filter=eventTimestamp ge '{start_str}' and eventTimestamp le '{end_str}'"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        logs = response.json().get("value", [])
        print(f"  Retrieved {len(logs)} activity log entries")
        for log in logs[:5]:  # Show first 5 only
            print(f"  [{log.get('eventTimestamp', 'N/A')}] "
                  f"{log.get('operationName', {}).get('localizedValue', 'N/A')} "
                  f"— {log.get('status', {}).get('localizedValue', 'N/A')}")
        return logs
    else:
        print(f"  Error pulling logs: {response.status_code} — {response.text}")
        return []
    

# ── 5. NORMALIZE DATA ─────────────────────────────────────────────────────────
def normalize_activity_logs(raw_logs):
    normalized = []
    for log in raw_logs:
        entry = {
            "timestamp": log.get("eventTimestamp", "N/A"),
            "operation": log.get("operationName", {}).get("localizedValue", "N/A"),
            "status": log.get("status", {}).get("localizedValue", "N/A"),
            "caller": log.get("caller", "N/A"),
            "resource": log.get("resourceId", "N/A"),
            "correlation_id": log.get("correlationId", "N/A")
        }
        normalized.append(entry)
    return normalized

def normalize_role_assignments(raw_assignments):
    normalized = []
    for assignment in raw_assignments:
        entry = {
            "principal_id": assignment.get("principal_id", "N/A"),
            "scope": assignment.get("scope", "N/A"),
            "role_id": assignment.get("role_definition_id", "N/A"),
            "collected_at": datetime.now(timezone.utc).isoformat()
        }
        normalized.append(entry)
    return normalized

# ── 5. SAVES RESULTS TO JSON
def save_results(role_assignments, activity_logs):
    normalized_roles = normalize_role_assignments(role_assignments)
    normalized_logs  = normalize_activity_logs(activity_logs)

    output = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "subscription_id": SUBSCRIPTION_ID,
        "summary": {
            "total_role_assignments": len(normalized_roles),
            "total_activity_logs": len(normalized_logs)
        },
        "role_assignments": normalized_roles,
        "activity_logs_last_24h": normalized_logs
    }

    with open("security_report.json", "w") as f:
        json.dump(output, f, indent=2, default=str)

    print("\n✓ Results normalized and saved to security_report.json")

# RUN EVERYTHING 
if __name__ == "__main__":
    print("Azure Security Data Collector")
    print("=" * 40)
    
    role_assignments = get_role_assignments()
    activity_logs    = get_activity_logs()
    save_results(role_assignments, activity_logs)
    
    print("\n✓ Collection complete")