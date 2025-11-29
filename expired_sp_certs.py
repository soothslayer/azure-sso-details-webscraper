import os
import time
import datetime
import requests

# Selenium imports
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import pyotp


# =========================
#  Auth helpers (Graph)
# =========================

def get_graph_token():
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_CLIENT_ID"]
    client_secret = os.environ["AZURE_CLIENT_SECRET"]

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
    expires_in = j.get("expires_in", 3600)
    expires_at = time.time() + expires_in - 60  # refresh 1 min early

    return access_token, expires_at


graph_token = None
graph_token_expires_at = 0


def ensure_graph_token():
    global graph_token, graph_token_expires_at
    if graph_token is None or time.time() >= graph_token_expires_at:
        graph_token, graph_token_expires_at = get_graph_token()
        print("[Token] Refreshed Graph access token.")
    return graph_token


# =========================
#  Date helper
# =========================

def parse_iso_utc(dt_str):
    if not dt_str:
        return None
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(dt_str)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


# =========================
#  Selenium login helpers
# =========================

def login_to_azure_portal(driver, wait):
    # Update username if needed
    username = os.getenv("AZURE_USERNAME")
    password = os.getenv("AZURE_PASSWORD")
    totp_secret = os.getenv("AZURE_TOTP_SECRET")

    driver.get("https://portal.azure.com")

    # Username
    wait.until(EC.visibility_of_element_located((By.ID, "i0116"))).send_keys(username)
    driver.find_element(By.ID, "idSIButton9").click()

    # Password
    wait.until(EC.visibility_of_element_located((By.ID, "i0118"))).send_keys(password)
    driver.find_element(By.ID, "idSIButton9").click()

    # TOTP MFA (if prompted)
    if totp_secret:
        try:
            totp = pyotp.TOTP(totp_secret, interval=60).now()
            code_box = WebDriverWait(driver, 20).until(
                EC.visibility_of_element_located((By.ID, "idTxtBx_SAOTCC_OTC"))
            )
            code_box.send_keys(totp)
            driver.find_element(By.ID, "idSubmit_SAOTCC_Continue").click()
        except Exception as e:
            print(f"[MFA] No TOTP prompt or failed to enter code: {e}")

    # Stay signed in? Yes
    try:
        stay_btn = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.ID, "idSIButton9"))
        )
        stay_btn.click()
    except Exception:
        pass

    print("[Selenium] Logged into Azure Portal.")


def open_saml_sso_blade(driver, sp_id, app_id):
    url = (
        "https://portal.azure.com/"
        "#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/SignOn"
        f"/objectId/{sp_id}"
        f"/appId/{app_id}"
        "/preferredSingleSignOnMode/saml"
        "/servicePrincipalType/Application/fromNav/"
    )
    print(f"[Selenium] Opening SAML SSO blade: {url}")
    driver.get(url)


# =========================
#  Main logic
# =========================

def main():
    now_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

    # Selenium setup
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    wait = WebDriverWait(driver, 20)

    login_to_azure_portal(driver, wait)

    # Filter to IAM-tagged service principals
    url = (
        "https://graph.microsoft.com/v1.0/servicePrincipals"
        "?$filter=tags/any(t:t eq 'IAM')"
        "&$select=id,appId,displayName,keyCredentials,tags"
    )

    sp_index = 0
    while url:
        token = ensure_graph_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        sps = data.get("value", [])
        for sp in sps:
            sp_index += 1
            sp_id = sp.get("id")
            app_id = sp.get("appId")
            name = sp.get("displayName")
            key_creds = sp.get("keyCredentials", []) or []

            print(f"\n[{sp_index}] Service principal: {name} (appId={app_id}, id={sp_id})")

            if not key_creds:
                print("  -> No keyCredentials; skipping.")
                continue

            for cred in key_creds:
                cred_type = cred.get("type")
                if cred_type and "AsymmetricX509Cert" not in cred_type:
                    continue

                end_raw = cred.get("endDateTime")
                start_raw = cred.get("startDateTime")
                end_dt = parse_iso_utc(end_raw)
                start_dt = parse_iso_utc(start_raw) if start_raw else None

                if not end_dt:
                    continue

                if end_dt >= now_utc:
                    # not expired
                    continue

                # This credential is expired
                cred_display_name = cred.get("displayName")
                cred_key_id = cred.get("keyId")
                days_ago = (now_utc - end_dt).days

                print("  -> EXPIRED CERTIFICATE FOUND")
                print(f"     displayName : {cred_display_name}")
                print(f"     keyId       : {cred_key_id}")
                print(f"     endDateTime : {end_raw} (≈{days_ago} days ago)")

                # Check if there is another newer active cert
                newer_active_exists = False
                for other in key_creds:
                    if other is cred:
                        continue
                    other_type = other.get("type")
                    if other_type and "AsymmetricX509Cert" not in other_type:
                        continue

                    o_end_raw = other.get("endDateTime")
                    o_start_raw = other.get("startDateTime")
                    o_end_dt = parse_iso_utc(o_end_raw)
                    o_start_dt = parse_iso_utc(o_start_raw) if o_start_raw else None

                    if not o_end_dt:
                        continue

                    # Active now?
                    if o_start_dt and o_start_dt > now_utc:
                        continue  # not yet active
                    if o_end_dt <= now_utc:
                        continue  # already expired

                    # Newer than the expired one?
                    if o_end_dt > end_dt:
                        newer_active_exists = True
                        break

                if not newer_active_exists:
                    print("  !! No newer active certificate found. Will NOT prompt for manual deletion.")
                    continue

                # There IS a newer active cert → open SAML SSO blade and wait for you
                open_saml_sso_blade(driver, sp_id, app_id)
                input("  Delete the expired certificate in the portal, then press Enter to continue...")

            # end for cred

        url = data.get("@odata.nextLink")

    print("\nDone. All IAM-tagged service principals processed.")
    input("Press Enter to close the browser...")
    driver.quit()


if __name__ == "__main__":
    main()