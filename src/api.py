import requests

from src.config import (
    ADVISORIES_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    KEV_CATALOG_URL,
    TOKEN_URL,
)

from src.logging_utils import verbose_print


def validate_credentials():
    if not CLIENT_ID or not CLIENT_SECRET:
        raise ValueError(
            "Please set OPENVULN_CLIENT_ID and OPENVULN_CLIENT_SECRET "
            "environment variables."
        )


def get_access_token():
    """Authenticate to the Cisco OpenVuln API and return a bearer token."""
    validate_credentials()

    response = requests.post(
        TOKEN_URL,
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"},
        timeout=30,
    )

    verbose_print(f"OpenVuln token status: {response.status_code}")

    if response.status_code != 200:
        verbose_print("OpenVuln token response:")
        verbose_print(response.text)

    response.raise_for_status()
    return response.json()["access_token"]


def fetch_all_advisories(start_date, end_date):
    """
    Fetch all advisories updated within the requested date range.
    """
    print("Getting OpenVuln OAuth token...")
    token = get_access_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    query_params = {
        "startDate": start_date.isoformat(),
        "endDate": end_date.isoformat(),
        "pageIndex": 1,
        "pageSize": 100,
        "productNames": "true",
        "summaryDetails": "false",
    }

    all_advisories = []
    current_page = 1

    print("Getting advisories from OpenVuln...")
    while True:
        query_params["pageIndex"] = current_page

        response = requests.get(
            ADVISORIES_URL,
            headers=headers,
            params=query_params,
            timeout=30,
        )

        verbose_print(
            f"OpenVuln advisory status for page {current_page}: {response.status_code}"
        )

        if response.status_code != 200:
            verbose_print("Advisory response:")
            verbose_print(response.text)

        response.raise_for_status()

        response_data = response.json()
        paging_info = response_data.get("paging", {})
        advisories = response_data.get("advisories", [])

        all_advisories.extend(advisories)

        verbose_print(f"Paging for page {current_page}: {paging_info}")
        verbose_print(f"Advisories returned on page {current_page}: {len(advisories)}")

        if paging_info.get("next") == "NA":
            break

        current_page += 1

    return all_advisories


def fetch_kev_catalog():
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    try:
        response = requests.get(KEV_CATALOG_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as error:
        print(f"Warning: Could not fetch KEV catalog: {error}")
        return {"vulnerabilities": []}


def extract_kev_cves(kev_catalog):
    """Extract CVE IDs from the KEV catalog into a set."""
    vulnerabilities = kev_catalog.get("vulnerabilities", [])
    kev_cves = set()

    for vulnerability in vulnerabilities:
        cve_id = vulnerability.get("cveID")
        if cve_id:
            kev_cves.add(cve_id)

    return kev_cves


def normalize_cves(cves):
    """Normalize advisory CVE data into a clean list of CVE strings."""
    if not cves:
        return []

    if isinstance(cves, list):
        return [str(cve).strip() for cve in cves if str(cve).strip()]

    if isinstance(cves, str):
        cleaned = cves.strip()
        return [cleaned] if cleaned else []

    return [str(cves).strip()] if str(cves).strip() else []


def is_kev_advisory(advisory, kev_cves):
    """Return True if any CVE in the advisory is present in the KEV catalog."""
    advisory_cves = normalize_cves(advisory.get("cves"))

    if not advisory_cves:
        return False

    return any(cve in kev_cves for cve in advisory_cves)