import os
import requests
from datetime import datetime, timedelta

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
ADVISORY_URL = "https://apix.cisco.com/security/advisories/v2/all/lastpublished"

CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")


def get_access_token():
    """Retrieve OAuth token from Cisco"""
    response = requests.post(
        TOKEN_URL,
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        timeout=30,
    )

    response.raise_for_status()
    return response.json()["access_token"]


def test_api_connection():
    """Test OpenVuln API connectivity"""
    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=180)

    params = {
        "startDate": start_date.isoformat(),
        "endDate": today.isoformat(),
        "pageIndex": 1,
        "pageSize": 5,
        "productNames": "true",
    }

    response = requests.get(
        ADVISORY_URL,
        headers=headers,
        params=params,
        timeout=30,
    )

    response.raise_for_status()

    data = response.json()

    print("\nAPI connection successful")
    print(f"HTTP Status: {response.status_code}")

    advisories = data.get("advisories", [])
    print(f"Advisories returned: {len(advisories)}")

    if advisories:
        first = advisories[0]

        print("\nFirst advisory preview:")
        print("Advisory ID:", first.get("advisoryId"))
        print("Title:", first.get("advisoryTitle"))

        print("\nAvailable fields:")
        for key in first.keys():
            print("-", key)


if __name__ == "__main__":
    test_api_connection()
