import os
import time
import datetime
import requests


# ---------- Auth helpers ----------

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


# ---------- Date helper ----------

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


# ---------- Notes helper ----------

def append_app_notes(app_obj_id, current_notes, extra_line):
    """
    Append extra_line to the application's notes field.
    Uses current_notes as the base (may be empty string).
    """
    token = ensure_graph_token()
    url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}"

    if current_notes:
        new_notes = current_notes.rstrip() + "\n" + extra_line
    else:
        new_notes = extra_line

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {"notes": new_notes}

    resp = requests.patch(url, headers=headers, json=body)
    if resp.status_code not in (200, 204):
        print(f"  !! Failed to update notes: {resp.status_code} {resp.text}")
        return current_notes  # return old notes on failure

    print("  -> Application notes updated.")
    return new_notes  # return updated notes so caller can keep appending in memory

#delete secret helper
def delete_password_credential(app_obj_id, key_id):
    """Deletes a passwordCredential from an application (Graph removePassword API)."""
    token = ensure_graph_token()
    url = f"https://graph.microsoft.com/v1.0/applications/{app_obj_id}/removePassword"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {"keyId": key_id}

    resp = requests.post(url, headers=headers, json=body)
    if resp.status_code not in (200, 204):
        print(f"  !! Failed to delete secret: {resp.status_code} {resp.text}")
    else:
        print("  -> Expired secret deleted successfully.")

# ---------- Main logic ----------

def main():
    # cutoff: more than 30 days ago
    now_utc = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
    cutoff = now_utc - datetime.timedelta(days=30)
    today_str = now_utc.date().isoformat()  # YYYY-MM-DD for notes

    # Filter: applications with tag "IAM", include notes
    url = (
        "https://graph.microsoft.com/v1.0/applications"
        "?$filter=tags/any(t:t eq 'IAM')"
        "&$select=id,appId,displayName,notes,passwordCredentials"
    )

    app_index = 0
    while url:
        token = ensure_graph_token()
        headers = {"Authorization": f"Bearer {token}"}

        resp = requests.get(url, headers=headers)
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

                    # Prompt user
                    answer = input(
                        "  Append this info to application notes? (y/n): "
                    ).strip().lower()

                    if answer == "y":
                        print("  Appending to notes:")
                        print(f"    {note_line}")
                        # Uncomment the line below when ready to go live:
                        # delete_password_credential(obj_id, cred_key_id)
                        current_notes = append_app_notes(obj_id, current_notes, note_line)
                    else:
                        print("  Skipping notes update for this credential.")

                    # IMPORTANT: we do NOT delete the secret.
                    # Then proceed to the next expired passwordCredential (no break)

            if not expired_found:
                print("  -> No password credentials expired > 30 days ago.")

        url = data.get("@odata.nextLink")  # pagination

    print("\nDone. All IAM-tagged applications processed.")


if __name__ == "__main__":
    main()