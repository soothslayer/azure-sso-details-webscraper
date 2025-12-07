#!/usr/bin/env python3
"""
expired_password_creds.py

Finds IAM-tagged applications with passwordCredentials that expired more than
30 days ago. For each expired secret, prompts for confirmation and, if 'y',
appends a note to the application's notes field.

A delete_password_credential() helper is provided, but the call is commented
out so no secrets are deleted until you're ready to go live.
"""

import datetime
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

from common.graph_utils import graph_get, graph_patch, graph_post
from common.time_utils import parse_iso_utc

load_dotenv(override=True)

# -----------------------------
# Helpers
# -----------------------------

def append_app_notes(app_obj_id: str, current_notes: Optional[str], extra_line: str) -> str:
    """
    Append extra_line to the application's notes field.
    Uses current_notes as the base (may be empty string).
    Returns the new notes string (or old on failure).
    """
    url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}"

    if current_notes:
        new_notes = current_notes.rstrip() + "\n" + extra_line
    else:
        new_notes = extra_line

    body = {"notes": new_notes}
    resp = graph_patch(url, json=body)

    if resp.status_code not in (200, 204):
        print(f"  !! Failed to update notes: {resp.status_code} {resp.text}")
        return current_notes or ""
    else:
        print("  -> Application notes updated.")
        return new_notes


def delete_password_credential(app_obj_id: str, key_id: str) -> None:
    """
    Deletes a passwordCredential from an application using
    the Microsoft Graph removePassword API.

    NOTE: This function is not called by default. The call site is commented out
    so you can safely test the script without deleting anything.
    """
    url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}/removePassword"
    body = {"keyId": key_id}

    resp = graph_post(url, json=body)
    if resp.status_code not in (200, 204):
        print(f"  !! Failed to delete secret: {resp.status_code} {resp.text}")
    else:
        print("  -> Expired secret deleted successfully.")


# -----------------------------
# Main
# -----------------------------

def main():
    now_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    cutoff = now_utc - datetime.timedelta(days=30)
    today_str = now_utc.date().isoformat()  # YYYY-MM-DD for notes

    # Filter: applications with tag "IAM"
    url = (
        "https://graph.microsoft.com/v1.0/applications"
        "?$filter=tags/any(t:t eq 'IAM')"
        "&$select=id,appId,displayName,notes,passwordCredentials"
    )

    app_index = 0
    while url:
        resp = graph_get(url)
        resp.raise_for_status()
        data = resp.json()

        apps = data.get("value", [])
        for app in apps:
            app_index += 1
            app_id = app.get("appId")
            obj_id = app.get("id")
            name = app.get("displayName")
            current_notes = app.get("notes") or ""

            print(f"\n[{app_index}] Checking app: {name} (appId={app_id}, id={obj_id})")

            creds = app.get("passwordCredentials", []) or []
            expired_found = False

            for cred in creds:
                cred_display_name = cred.get("displayName")
                cred_key_id = cred.get("keyId")
                end_dt_raw = cred.get("endDateTime")
                end_dt = parse_iso_utc(end_dt_raw)

                if end_dt is None:
                    continue

                if end_dt < cutoff:
                    expired_found = True
                    days_ago = (now_utc - end_dt).days

                    # secretHint: from hint (if present), otherwise blank
                    hint_full = cred.get("hint") or ""
                    secret_hint = hint_full[:4] if hint_full else ""

                    print("  -> EXPIRED PASSWORD CREDENTIAL FOUND")
                    print(f"     displayName : {cred_display_name}")
                    print(f"     keyId       : {cred_key_id}")
                    print(f"     endDateTime : {end_dt_raw} (≈{days_ago} days ago)")
                    print(f"     secretHint  : {secret_hint}")

                    note_line = (
                        f"Expired secret starting with {secret_hint} and "
                        f"description {cred_display_name} with expiration date "
                        f"{end_dt_raw} was deleted on {today_str}."
                    )

                    answer = input(
                        "  Append this info to application notes? (y/n): "
                    ).strip().lower()

                    if answer == "y":
                        print("  Appending to notes:")
                        print(f"    {note_line}")
                        current_notes = append_app_notes(obj_id, current_notes, note_line)

                        # When you're ready to actually delete:
                        # delete_password_credential(obj_id, cred_key_id)
                    else:
                        print("  Skipping notes update for this credential.")

                    # proceed to next expired passwordCredential (no break)

            if not expired_found:
                print("  -> No password credentials expired > 30 days ago.")

        url = data.get("@odata.nextLink")  # pagination

    print("\nDone. All IAM-tagged applications processed.")


if __name__ == "__main__":
    main()