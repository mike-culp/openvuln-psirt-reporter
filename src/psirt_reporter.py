import os
from datetime import datetime, timedelta

import requests

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BASE_URL = "https://apix.cisco.com/security/advisories/v2"
ADVISORY_URL = f"{BASE_URL}/all/lastpublished"

CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")

if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError("Missing OPENVULN_CLIENT_ID or OPENVULN_CLIENT_SECRET")


def get_access_token():
    response = requests.post(
        TOKEN_URL,
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"},
        timeout=30,
    )

    print("Token status:", response.status_code)
    if response.status_code != 200:
        print("Token response:", response.text)

    response.raise_for_status()
    return response.json()["access_token"]


def fetch_all_advisories():
    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=365)

    params = {
        "startDate": start_date.isoformat(),
        "endDate": today.isoformat(),
        "pageIndex": 1,
        "pageSize": 100,
        "productNames": "true",
        "summaryDetails": "false",
    }

    all_advisories = []
    page_index = 1

    while True:
        params["pageIndex"] = page_index

        response = requests.get(
            ADVISORY_URL,
            headers=headers,
            params=params,
            timeout=30,
        )

        print(f"Advisory status for page {page_index}:", response.status_code)
        if response.status_code != 200:
            print("Advisory response:", response.text)

        response.raise_for_status()

        data = response.json()
        paging = data.get("paging", {})
        advisories = data.get("advisories", [])

        all_advisories.extend(advisories)

        print(f"Paging for page {page_index}:", paging)
        print(f"Advisories returned on page {page_index}:", len(advisories))

        if paging.get("next") == "NA":
            break

        page_index += 1

    print("Total advisories returned:", len(all_advisories))

    if all_advisories:
        first = all_advisories[0]
        print("First advisory ID:", first.get("advisoryId"))
        print("First advisory title:", first.get("advisoryTitle"))
        print("First advisory keys:", list(first.keys()))

if __name__ == "__main__":
    fetch_all_advisories()
