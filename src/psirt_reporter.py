import os
from datetime import datetime, timedelta

import requests


TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BASE_URL = "https://apix.cisco.com/security/advisories/v2"
ADVISORIES_URL = f"{BASE_URL}/all/lastpublished"

CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")


if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError("Missing OPENVULN_CLIENT_ID or OPENVULN_CLIENT_SECRET")


def get_access_token():
    """Authenticate to the Cisco OpenVuln API and return a bearer token."""
    response = requests.post(
        TOKEN_URL,
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"},
        timeout=30,
    )

    print(f"Token status: {response.status_code}")

    if response.status_code != 200:
        print("Token response:")
        print(response.text)

    response.raise_for_status()
    return response.json()["access_token"]


def fetch_all_advisories(days_back=365):
    """
    Fetch all advisories updated within the past `days_back` days.

    Returns:
        list[dict]: A list of advisory records returned by the API.
    """
    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    today = datetime.utcnow().date()
    start_date = today - timedelta(days=days_back)

    query_params = {
        "startDate": start_date.isoformat(),
        "endDate": today.isoformat(),
        "pageIndex": 1,
        "pageSize": 100,
        "productNames": "true",
        "summaryDetails": "false",
    }

    all_advisories = []
    current_page = 1

    while True:
        query_params["pageIndex"] = current_page

        response = requests.get(
            ADVISORIES_URL,
            headers=headers,
            params=query_params,
            timeout=30,
        )

        print(f"Advisory status for page {current_page}: {response.status_code}")

        if response.status_code != 200:
            print("Advisory response:")
            print(response.text)

        response.raise_for_status()

        response_data = response.json()
        paging_info = response_data.get("paging", {})
        advisories = response_data.get("advisories", [])

        all_advisories.extend(advisories)

        print(f"Paging for page {current_page}: {paging_info}")
        print(f"Advisories returned on page {current_page}: {len(advisories)}")

        if paging_info.get("next") == "NA":
            break

        current_page += 1

    return all_advisories


def extract_unique_product_names(advisories):
    """
    Extract a sorted list of unique product names from advisory data.

    The API returns productNames as a comma-separated string, so this
    function splits the string and normalizes whitespace.
    """
    unique_product_names = set()

    for advisory in advisories:
        product_names = advisory.get("productNames", "")

        if not product_names:
            continue

        for product_name in product_names.split(","):
            cleaned_name = product_name.strip()

            if cleaned_name:
                unique_product_names.add(cleaned_name)

    return sorted(unique_product_names)


def print_advisory_summary(advisories):
    """Print a small summary of the advisory pull."""
    print()
    print(f"Total advisories returned: {len(advisories)}")

    if not advisories:
        return

    first_advisory = advisories[0]

    print(f"First advisory ID: {first_advisory.get('advisoryId')}")
    print(f"First advisory title: {first_advisory.get('advisoryTitle')}")
    print(f"First advisory keys: {list(first_advisory.keys())}")


def print_unique_product_names(product_names):
    """Print the discovered unique product names."""
    print()
    print(f"Unique product names discovered: {len(product_names)}")
    print()

    for product_name in product_names:
        print(product_name)


def main():
    advisories = fetch_all_advisories(days_back=365)
    print_advisory_summary(advisories)

    unique_product_names = extract_unique_product_names(advisories)
    print_unique_product_names(unique_product_names)


if __name__ == "__main__":
    main()
