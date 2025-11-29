# common/graph_utils.py
import os
import time
import datetime
from typing import Optional, Tuple
import requests


_graph_token: Optional[str] = None
_graph_token_expires_at: float = 0.0


def get_graph_token() -> Tuple[str, float]:
    tenant_id = os.environ["AZ_TENANT_ID"]
    client_id = os.environ["AZ_CLIENT_ID"]
    client_secret = os.environ["AZ_CLIENT_SECRET"]

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


def ensure_graph_token() -> str:
    global _graph_token, _graph_token_expires_at
    if _graph_token is None or time.time() >= _graph_token_expires_at:
        _graph_token, _graph_token_expires_at = get_graph_token()
        print("[Token] Refreshed Graph access token.")
    return _graph_token


def graph_get(url: str, **kwargs) -> requests.Response:
    token = ensure_graph_token()
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {token}")
    return requests.get(url, headers=headers, **kwargs)


def graph_post(url: str, json=None, **kwargs) -> requests.Response:
    token = ensure_graph_token()
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {token}")
    headers.setdefault("Content-Type", "application/json")
    return requests.post(url, headers=headers, json=json, **kwargs)


def graph_patch(url: str, json=None, **kwargs) -> requests.Response:
    token = ensure_graph_token()
    headers = kwargs.pop("headers", {})
    headers.setdefault("Authorization", f"Bearer {token}")
    headers.setdefault("Content-Type", "application/json")
    return requests.patch(url, headers=headers, json=json, **kwargs)