import os
import time
import pyotp
import csv
import requests
from azure.identity import ClientSecretCredential
import datetime

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# ----------------------------
# CONFIG - fill these in
# ----------------------------
TENANT_ID = os.getenv("AZURE_TENANT_ID", "<your-tenant-id>")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "<your-client-id>")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "<your-client-secret>")

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

import time

def get_graph_token():
    tenant_id = TENANT_ID
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }

    resp = requests.post(token_url, data=data)
    resp.raise_for_status()

    j = resp.json()
    access_token = j["access_token"]

    # expires_in is usually 3600 seconds
    expires_in = j.get("expires_in", 3600)
    expires_at = time.time() + expires_in - 60  
    # ^ subtract 60s so you refresh slightly early instead of failing

    return access_token, expires_at

def ensure_graph_token():
    global graph_token, graph_token_expires_at

    # if no token yet, or the current one is expired → refresh
    if graph_token is None or time.time() >= graph_token_expires_at:
        graph_token, graph_token_expires_at = get_graph_token()
        print("[Token] Refreshed Graph access token.")

    return graph_token

def update_sso_attributes_for_sp(sp_id: str, name_id: str, token: str):
    # UTC now, rounded to nearest minute (±1 minute)
    now = datetime.datetime.utcnow()
    if now.second >= 30:
        now = now + datetime.timedelta(minutes=1)
    utc_now = now.replace(second=0, microsecond=0).isoformat()  # e.g. 2025-11-27T22:41

    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}"

    body = {
        "customSecurityAttributes": {
            "SSO": {
                "@odata.type": "#Microsoft.DirectoryServices.CustomSecurityAttributeValue",
                "UniqueUserIdentifier": name_id,
                "UniqueUserIdentifierLastUpdated": utc_now,
            }
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    token = ensure_graph_token()

    resp = requests.patch(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=body
    )
    if resp.status_code not in (200, 204):
        print(f"Failed to update CSA for {sp_id}: {resp.status_code} {resp.text}")
    else:
        print(
            f"Updated SSO attributes for {sp_id} "
            f"-> UniqueUserIdentifier='{name_id}', LastUpdated='{rounded}'"
        )

def parse_iso(dt_str):
    """Best-effort ISO parser; returns aware UTC datetime."""
    if not dt_str:
        return None
    # handle possible trailing Z
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(dt_str)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)

def get_sso_attributes_for_sp(sp_id: str, token: str):
    """
    Returns (existing_name_id, existing_last_updated_str)
    for the SSO custom security attributes on a service principal.
    """
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}?$select=customSecurityAttributes"
    headers = {"Authorization": f"Bearer {token}"}

    token = ensure_graph_token()

    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    )
    if resp.status_code != 200:
        print(f"Failed to read CSA for {sp_id}: {resp.status_code} {resp.text}")
        return None, None

    data = resp.json()
    csa = (data.get("customSecurityAttributes") or {}).get("SSO") or {}

    existing_name_id = csa.get("UniqueUserIdentifier")
    existing_last_updated_str = csa.get("UniqueUserIdentifierLastUpdated")

    return existing_name_id, existing_last_updated_str

def get_app_last_updated_from_audit(sp_id: str, token: str):
    """
    Returns the last time the application/service principal was updated,
    based on directory audit logs (UTC datetime or None).
    """
    url = (
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        f"?$filter=targetResources/any(tr: tr/id eq '{sp_id}')"
        "&$orderby=activityDateTime desc&$top=1"
    )
    headers = {"Authorization": f"Bearer {token}"}

    token = ensure_graph_token()

    resp = requests.patch(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    )
    if resp.status_code != 200:
        print(f"Failed to read audit logs for {sp_id}: {resp.status_code} {resp.text}")
        return None

    value = resp.json().get("value", [])
    if not value:
        return None

    last = value[0]
    activity_dt_str = last.get("activityDateTime")
    return parse_iso(activity_dt_str)

graph_token = None
graph_token_expires_at = 0
graph_token = get_graph_token()

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.get("https://portal.azure.com")

wait = WebDriverWait(driver, 20)

# Username
wait.until(EC.visibility_of_element_located((By.ID, "i0116"))).send_keys(
    "SECADM_EHanlon.Miller@nationalgridplc.onmicrosoft.com"
)
driver.find_element(By.ID, "idSIButton9").click()

# Password
password = os.getenv("AZURE_PASSWORD")
wait.until(EC.visibility_of_element_located((By.ID, "i0118"))).send_keys(password)
driver.find_element(By.ID, "idSIButton9").click()

time.sleep(2)
# TOTP code (MFA "Enter code" screen)
try:
    totp_secret = os.getenv("AZURE_TOTP_SECRET")
    totp = pyotp.TOTP(totp_secret, interval=60).now()

    code_box = wait.until(
        EC.visibility_of_element_located((By.ID, "idTxtBx_SAOTCC_OTC"))
    )
    code_box.send_keys(totp)

    driver.find_element(By.ID, "idSubmit_SAOTCC_Continue").click()
except Exception as e:
    print("No TOTP screen or failed to enter code:", e)

# Stay signed in? -> Yes
try:
    stay_signed_in_btn = wait.until(
        EC.element_to_be_clickable((By.ID, "idSIButton9"))
    )
    stay_signed_in_btn.click()
except Exception:
    pass
# ---- After login + "Stay signed in?" handling ----

csv_path = "service_principals_missing_unique_user_identifier.csv"

# Read all rows once so we know how many there are
with open(csv_path, newline="") as f:
    rows = list(csv.DictReader(f))

    total = len(rows)
    print(f"Found {total} service principals to process.")

    for index, row in enumerate(rows, start=1):
        obj_id = row["id"]
        app_id = row["appId"]

        # Simple progress counter + optional % bar
        percent = index / total * 100
        bar_len = 30
        filled = int(bar_len * index / total)
        bar = "#" * filled + "-" * (bar_len - filled)

        print(f"\n[{bar}] {percent:5.1f}%  ({index}/{total})  id={obj_id}")
        name_id = "Unkown"
        found_oidc = False

        url = (
            "https://portal.azure.com/"
            "#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn"
            f"/objectId/{obj_id}"
            f"/appId/{app_id}"
            "/preferredSingleSignOnMode/saml"
            "/servicePrincipalType/Application/fromNav/"
        )
        time.sleep(2)
        print(f"Opening: {url}")
        driver.get(url)
        # wait a bit for the blade to load
        time.sleep(7)
        # Print all visible text on the page
        
        page_text = driver.find_element(By.TAG_NAME, "body").text
        print("\n----- PAGE TEXT START -----\n")
        print(page_text)
        print("\n----- PAGE TEXT END -----\n")
        if "SAML" in page_text:
            lines = page_text.splitlines()

            for i, line in enumerate(lines):
                if line.strip() == "Unique User Identifier":
                    # look for the next non-empty line
                    for j in range(i+1, len(lines)):
                        next_line = lines[j].strip()
                        if next_line:
                            name_id = next_line
                            break
                    break

            print("Extracted Unique User Identifier →", name_id)
        elif "Single sign-on is not configured for " in page_text:
            name_id = "SSO not configured"
        elif "You do not have access" in page_text:
            name_id = "Access issue"
        elif "You don't have access" in page_text:
            name_id = "Access issue"


        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")

        for i, frame in enumerate(iframes):
            driver.switch_to.frame(frame)
            try:
                body_text = driver.find_element(By.TAG_NAME, "body").text
                print(f"\n----- IFRAME {i} TEXT (first 500 chars) -----\n")
                print(body_text[:500])
                if "This is a multi-tenant application" in body_text:
                    name_id = "multi-tenant application"
                elif "This application uses OpenID Connect and OAuth" in body_text:
                    found_oidc = True
                    print("Detected OpenID Connect/OAuth app on this blade.")
                    # leave iframe loop; we’ll navigate to token config
                    driver.switch_to.default_content()
                    break
#            except NoSuchElementException:
#                pass
            finally:
                driver.switch_to.default_content()

        if found_oidc:
            token_url = (
                "https://portal.azure.com/"
                "#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/TokenConfiguration"
                f"/appId/{app_id}"
            )
            print(f"Navigating to Token Configuration: {token_url}")
            driver.get(token_url)

            time.sleep(2)
            # Print all visible text on the page
            
            page_text = driver.find_element(By.TAG_NAME, "body").text
            print("\n----- PAGE TEXT START -----\n")
            print(page_text)
            print("\n----- PAGE TEXT END -----\n")
            if "No results." in page_text:
                name_id = "user.userprincipalname"
            elif "email" in page_text:
                name_id = "user.mail"
            else:
                print("No results not found")
                name_id = "user.userprincipalname"
        print("Extracted Unique User Identifier →", name_id)
        # Only act when name_id is set and not "Unknown"/"Unkown"
        if name_id and name_id.strip().lower() not in ["unknown", "unkown"]:
            existing_name_id, existing_last_updated_str = get_sso_attributes_for_sp(obj_id, graph_token)
            print(f"Existing CSA UniqueUserIdentifier={existing_name_id}, "
                f"UniqueUserIdentifierLastUpdated={existing_last_updated_str}")

            existing_last_updated_dt = parse_iso(existing_last_updated_str) if existing_last_updated_str else None

            # 1) If CSA is null or different → update immediately
            if not existing_name_id or existing_name_id != name_id:
                print("CSA UniqueUserIdentifier is null or different → updating CSA.")
                update_sso_attributes_for_sp(obj_id, name_id, graph_token)
                # auto-continue to next SP
                continue

            # 2) CSA matches name_id → check audit logs
            print("CSA UniqueUserIdentifier already matches name_id; checking audit logs...")
            app_last_updated_dt = get_app_last_updated_from_audit(obj_id, graph_token)

            print(f"App last updated (audit): {app_last_updated_dt}")
            print(f"CSA UniqueUserIdentifierLastUpdated parsed: {existing_last_updated_dt}")

            # If the app has been updated more recently than the CSA timestamp → update CSA
            if app_last_updated_dt and existing_last_updated_dt and app_last_updated_dt > existing_last_updated_dt:
                print("App was updated after CSA LastUpdated → updating CSA.")
                update_sso_attributes_for_sp(obj_id, name_id, graph_token)
                continue
            else:
                print("CSA is up to date relative to app updates; no CSA update needed.")
                # fall through to loop end (no pause here)
        else:
            print("name_id is missing or Unknown; not attempting CSA update.")

        # Only pause if name_id is missing/Unknown (your previous rule)
        if not name_id or name_id.strip().lower() in ["unknown", "unkown"]:
            input("Press Enter to go to the next service principal...")
        else:
            print(f"Processed {obj_id} automatically (name_id='{name_id}').")
            # continue implicitly via loop

# When done
input("All rows done. Press Enter to close the browser...")
driver.quit()
