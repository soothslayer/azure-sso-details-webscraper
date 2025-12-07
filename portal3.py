#!/usr/bin/env python3
"""
portal3.py

End-to-end script:

1. Uses Microsoft Graph to find IAM-tagged service principals whose
   SSO.UniqueUserIdentifier CSA is missing or "Unknown".
2. Logs into Azure Portal with Selenium.
3. For each target SP:
   - Opens the SAML SSO blade.
   - Scrapes the "Unique User Identifier" from the page.
   - Updates the CSA (and LastUpdated) based on audit log rules.
"""

import datetime
import time
from dotenv import load_dotenv
load_dotenv(override=True)

from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException

from common.graph_utils import graph_get, graph_patch
from common.time_utils import parse_iso_utc, utc_now_rounded_minute
from common.selenium_utils import create_driver, login_to_azure_portal, open_saml_sso_blade


# -----------------------------
# Helper functions
# -----------------------------

def build_progress_bar(index: int, total: int, bar_len: int = 30) -> str:
    if total <= 0:
        return "[------------------------------] 100.0%"
    percent = index / total * 100
    filled = int(bar_len * index / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    return f"[{bar}] {percent:5.1f}%  ({index}/{total})"


def get_target_service_principals():
    """
    Returns a list of service principals tagged 'IAM'
    where SSO.UniqueUserIdentifier is missing or 'Unknown'.
    """
    targets = []
    url = (
        "https://graph.microsoft.com/v1.0/servicePrincipals"
        "?$filter=tags/any(t:t eq 'IAM')"
        "&$select=id,appId,displayName,customSecurityAttributes,tags"
    )

    print("[Graph] Discovering IAM-tagged service principals needing CSA update...")

    batch_index = 0
    while url:
        resp = graph_get(url)
        resp.raise_for_status()
        data = resp.json()
        batch_index += 1

        for sp in data.get("value", []):
            sp_id = sp.get("id")
            app_id = sp.get("appId")
            name = sp.get("displayName")

            csa = (sp.get("customSecurityAttributes") or {}).get("SSO") or {}
            uui = csa.get("UniqueUserIdentifier")

            if not uui or str(uui).strip().lower() in ["unknown", "unkown"]:
                targets.append(
                    {
                        "id": sp_id,
                        "appId": app_id,
                        "displayName": name,
                        "existing_uui": uui,
                    }
                )

        url = data.get("@odata.nextLink")

    print(f"[Graph] Found {len(targets)} service principals needing CSA review.")
    return targets


def get_page_text_for_sp(driver, sp_id: str, app_id: str) -> str:
    """Open SAML SSO blade and return concatenated visible text from its iframes."""
    open_saml_sso_blade(driver, sp_id, app_id)

    # Give the blade a moment to render
    time.sleep(5)

    page_text_parts = []
    iframes = driver.find_elements(By.TAG_NAME, "iframe")
    print(f"  Found {len(iframes)} iframes on SSO blade.")

    for i, frame in enumerate(iframes):
        try:
            driver.switch_to.frame(frame)
            try:
                body = driver.find_element(By.TAG_NAME, "body")
                txt = body.text or ""
                if txt.strip():
                    page_text_parts.append(txt)
            except NoSuchElementException:
                pass
        finally:
            driver.switch_to.default_content()

    return "\n".join(page_text_parts)


def extract_name_id(page_text: str) -> str:
    """
    From the page text, find the line 'Unique User Identifier'
    and return the next non-empty line as name_id.
    """
    name_id = None
    lines = page_text.splitlines()

    for i, line in enumerate(lines):
        if line.strip() == "Unique User Identifier":
            for j in range(i + 1, len(lines)):
                next_line = lines[j].strip()
                if next_line:
                    name_id = next_line
                    break
            break

    return name_id or ""


def get_sso_attributes_for_sp(sp_id: str):
    """
    Read existing SSO custom security attributes from the service principal:
    Returns (existing_name_id, existing_last_updated_str)
    """
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}?$select=customSecurityAttributes"
    resp = graph_get(url)
    if resp.status_code != 200:
        print(f"  !! Failed to read CSA for {sp_id}: {resp.status_code} {resp.text}")
        return None, None

    data = resp.json()
    csa = (data.get("customSecurityAttributes") or {}).get("SSO") or {}
    existing_name_id = csa.get("UniqueUserIdentifier")
    existing_last_updated_str = csa.get("UniqueUserIdentifierLastUpdated")
    return existing_name_id, existing_last_updated_str


def get_app_last_updated_from_audit(sp_id: str):
    """
    Returns the last time the service principal was updated based on
    directory audit logs (UTC datetime or None).
    """
    url = (
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        f"?$filter=targetResources/any(tr: tr/id eq '{sp_id}')"
        "&$orderby=activityDateTime desc&$top=1"
    )
    resp = graph_get(url)
    if resp.status_code != 200:
        print(f"  !! Failed to read audit logs for {sp_id}: {resp.status_code} {resp.text}")
        return None

    value = resp.json().get("value", [])
    if not value:
        return None

    last = value[0]
    activity_dt_str = last.get("activityDateTime")
    return parse_iso_utc(activity_dt_str)


def update_sso_attributes_for_sp(sp_id: str, name_id: str):
    """
    Update the SSO custom security attributes on the service principal:
      - SSO.UniqueUserIdentifier = name_id
      - SSO.UniqueUserIdentifierLastUpdated = utc_now_rounded_minute() (no seconds, no Z)
    """
    rounded = utc_now_rounded_minute().isoformat()  # e.g. 2025-11-27T22:41

    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}"
    body = {
        "customSecurityAttributes": {
            "SSO": {
                "@odata.type": "#Microsoft.DirectoryServices.CustomSecurityAttributeValue",
                "UniqueUserIdentifier": name_id,
                "UniqueUserIdentifierLastUpdated": rounded,
            }
        }
    }

    resp = graph_patch(url, json=body)
    if resp.status_code not in (200, 204):
        print(f"  !! Failed to update CSA for {sp_id}: {resp.status_code} {resp.text}")
    else:
        print(
            f"  -> Updated SSO CSA for {sp_id}: "
            f"UniqueUserIdentifier='{name_id}', LastUpdated='{rounded}'"
        )


# -----------------------------
# Main
# -----------------------------

def main():
    # Step 1: find targets via Graph (no CSV)
    targets = get_target_service_principals()
    total = len(targets)
    if total == 0:
        print("No service principals need CSA updates. Exiting.")
        return

    # Step 2: Selenium setup & login
    driver, wait = create_driver()
    login_to_azure_portal(driver, wait)

    for index, sp in enumerate(targets, start=1):
        obj_id = sp["id"]
        app_id = sp["appId"]
        name = sp["displayName"]

        progress = build_progress_bar(index, total)
        print(f"\n{progress}  {name}  (id={obj_id}, appId={app_id})")

        # Get page text from SAML SSO blade
        page_text = get_page_text_for_sp(driver, obj_id, app_id)
        if not page_text.strip():
            print("  !! No page text found on SSO blade (maybe layout changed or no iframe text).")
            input("  Press Enter to go to the next service principal...")
            continue

        # Extract Unique User Identifier
        name_id = extract_name_id(page_text)
        print(f"  Extracted Unique User Identifier → '{name_id}'")

        # Only act when name_id is set and not "Unknown"/"Unkown"
        if name_id and name_id.strip().lower() not in ["unknown", "unkown"]:
            existing_name_id, existing_last_updated_str = get_sso_attributes_for_sp(obj_id)
            print(
                f"  Existing CSA UniqueUserIdentifier={existing_name_id}, "
                f"UniqueUserIdentifierLastUpdated={existing_last_updated_str}"
            )

            existing_last_updated_dt = (
                parse_iso_utc(existing_last_updated_str) if existing_last_updated_str else None
            )

            # 1) If CSA is null or different → update immediately
            if not existing_name_id or existing_name_id != name_id:
                print("  CSA UniqueUserIdentifier is null or different → updating CSA.")
                update_sso_attributes_for_sp(obj_id, name_id)
                print(f"  Processed {obj_id} automatically (name_id='{name_id}').")
                continue

            # 2) CSA matches name_id → check audit logs
            print("  CSA UniqueUserIdentifier already matches name_id; checking audit logs...")
            app_last_updated_dt = get_app_last_updated_from_audit(obj_id)

            print(f"  App last updated (audit): {app_last_updated_dt}")
            print(f"  CSA UniqueUserIdentifierLastUpdated parsed: {existing_last_updated_dt}")

            # If the app has been updated more recently than the CSA timestamp → update CSA
            if app_last_updated_dt and existing_last_updated_dt and app_last_updated_dt > existing_last_updated_dt:
                print("  App was updated after CSA LastUpdated → updating CSA.")
                update_sso_attributes_for_sp(obj_id, name_id)
                print(f"  Processed {obj_id} automatically (name_id='{name_id}').")
                continue
            else:
                print("  CSA appears up to date relative to app updates; no CSA update needed.")
                print(f"  Processed {obj_id} automatically (name_id='{name_id}').")
                continue
        else:
            print("  name_id is missing or 'Unknown'; not attempting CSA update.")
            input("  Press Enter to go to the next service principal...")

    print("\nDone. All IAM-tagged service principals needing CSA updates have been processed.")
    input("Press Enter to close the browser...")
    driver.quit()


if __name__ == "__main__":
    main()