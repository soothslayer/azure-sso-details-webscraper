import os
import csv
import requests
from azure.identity import ClientSecretCredential

# ----------------------------
# CONFIG - fill these in
# ----------------------------
TENANT_ID = os.getenv("AZURE_TENANT_ID", "<your-tenant-id>")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "<your-client-id>")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "<your-client-secret>")

# The attribute set and attribute name in Entra Custom Security Attributes
# Example: customSecurityAttributes/Engineering/uniqueUserIdentifier
CSA_SET = os.getenv("CSA_SET", "Engineering")  # <-- change to your attribute set
CSA_ATTR = os.getenv("CSA_ATTR", "uniqueUserIdentifier")  # <-- change if different

OUTPUT_CSV = "service_principals_missing_unique_user_identifier.csv"

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

# Fields to pull. We include customSecurityAttributes.
SELECT_FIELDS = "id,appId,displayName,servicePrincipalType,accountEnabled,customSecurityAttributes"


def get_access_token():
    cred = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )
    token = cred.get_token(GRAPH_SCOPE)
    return token.token


def graph_get_all_service_principals(token: str):
    """
    Generator yielding service principals with paging.
    """
    url = f"{GRAPH_ROOT}/servicePrincipals?$select={SELECT_FIELDS}&$top=999&$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp') and tags/any(t:t eq 'SSO')"

    headers = {
        "Authorization": f"Bearer {token}",
        # Even if we don't filter server-side, keeping these headers
        # helps for consistency in tenants that require advanced queries for CSAs.
        "ConsistencyLevel": "eventual"
    }

    while url:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        for sp in data.get("value", []):
            yield sp

        url = data.get("@odata.nextLink")


def csa_value_is_empty(sp: dict) -> bool:
    """
    Returns True if the CSA is missing, None, empty string, or empty list.
    Handles different CSA shapes safely.
    """
    csa = sp.get("customSecurityAttributes") or {}
    set_block = csa.get(CSA_SET) or {}

    # Attribute could be absent or present with null/""/[].
    val = set_block.get(CSA_ATTR, None)

    if val is None:
        return True
    if isinstance(val, str) and val.strip() == "":
        return True
    if isinstance(val, list) and len(val) == 0:
        return True

    return False


def main():
    token = get_access_token()

    rows = []
    for sp in graph_get_all_service_principals(token):
        if csa_value_is_empty(sp):
            rows.append({
                "id": sp.get("id"),
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName"),
                "servicePrincipalType": sp.get("servicePrincipalType"),
                "accountEnabled": sp.get("accountEnabled"),
                "csa_set": CSA_SET,
                "csa_attr": CSA_ATTR
            })

    # Write CSV
    fieldnames = [
        "id", "appId", "displayName",
        "servicePrincipalType", "accountEnabled",
        "csa_set", "csa_attr"
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} service principals to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

