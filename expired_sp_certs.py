import datetime

from common.graph_utils import graph_get
from common.time_utils import parse_iso_utc
from common.selenium_utils import create_driver, login_to_azure_portal, open_saml_sso_blade

def main():
    now_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

    driver, wait = create_driver()
    login_to_azure_portal(driver, wait)

    url = (
        "https://graph.microsoft.com/v1.0/servicePrincipals"
        "?$filter=tags/any(t:t eq 'IAM')"
        "&$select=id,appId,displayName,keyCredentials,tags"
    )

    sp_index = 0
    while url:
        resp = graph_get(url)
        resp.raise_for_status()
        data = resp.json()

        for sp in data.get("value", []):
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