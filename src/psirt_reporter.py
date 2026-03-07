import os
from datetime import datetime, timedelta
from pathlib import Path
import requests
import yaml
import argparse


TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BASE_URL = "https://apix.cisco.com/security/advisories/v2"
ADVISORIES_URL = f"{BASE_URL}/all/lastpublished"

ROOT_DIR = Path(__file__).resolve().parents[1]
PRODUCT_GROUPS_FILE = ROOT_DIR / "config" / "product_groups.yaml"

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


def load_product_groups():
    """Load product group definitions from the YAML config file."""
    with open(PRODUCT_GROUPS_FILE, "r", encoding="utf-8") as file_handle:
        config_data = yaml.safe_load(file_handle)

    return config_data["groups"]


def parse_arguments(product_groups):
    """Parse command line arguments."""

    group_names = list(product_groups.keys())

    group_help_text = (
        "Product groups to include.\n\n"
        "Available groups:\n"
        + "\n".join(f"  {g}" for g in group_names)
        + "\n\nUse 'all' to include everything (default)."
    )

    parser = argparse.ArgumentParser(
        description="Cisco PSIRT advisory reporter"
    )

    parser.add_argument(
        "--group",
        nargs="+",
        default=["all"],
        help=group_help_text,
    )

    parser.add_argument(
        "--days",
        type=int,
        default=60,
        help="Number of days back to pull advisories (default: 60)",
    )
    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date in YYYY-MM-DD format",
    )

    parser.add_argument(
        "--end-date",
        type=str,
        help="End date in YYYY-MM-DD format",
    )
    return parser.parse_args()


def classify_advisory_products(product_names, product_groups):
    """
    Match an advisory's product names against the configured product groups.

    Args:
        product_names: A list of product names from one advisory.
        product_groups: The groups loaded from product_groups.yaml.

    Returns:
        A list of matching group keys.
    """
    matched_groups = []

    if not product_names:
        return matched_groups

    for group_key, group_config in product_groups.items():
        match_terms = group_config.get("match", [])
        exclude_terms = group_config.get("exclude", [])

        group_matched = False

        for product_name in product_names:
            product_name_lower = product_name.lower()

            matches_group = any(
                match_term.lower() in product_name_lower
                for match_term in match_terms
            )

            excluded_from_group = any(
                exclude_term.lower() in product_name_lower
                for exclude_term in exclude_terms
            )

            if matches_group and not excluded_from_group:
                group_matched = True
                break

        if group_matched:
            matched_groups.append(group_key)

    return matched_groups


def classify_all_advisories(advisories, product_groups):
    """
    Classify every advisory using the configured product groups.

    Returns:
        A new list of dictionaries. Each dictionary contains the original
        advisory plus a new key called 'matched_groups'.
    """
    classified_advisories = []

    for advisory in advisories:
        product_names = advisory.get("productNames", [])
        matched_groups = classify_advisory_products(product_names, product_groups)

        advisory_with_groups = advisory.copy()
        advisory_with_groups["matched_groups"] = matched_groups

        classified_advisories.append(advisory_with_groups)

    return classified_advisories


def filter_advisories_by_group(classified_advisories, selected_groups):
    """
    Filter advisories by selected product groups.

    Args:
        classified_advisories: list of advisories with matched_groups
        selected_groups: list of groups from CLI

    Returns:
        list of advisories that match the selected groups
    """

    if "all" in selected_groups:
        return classified_advisories

    filtered = []

    for advisory in classified_advisories:
        matched_groups = advisory.get("matched_groups", [])

        if any(group in matched_groups for group in selected_groups):
            filtered.append(advisory)

    return filtered


def fetch_all_advisories(start_date, end_date):
    """
    Fetch all advisories updated within the requested date range.

    Returns:
        list[dict]: A list of advisory records returned by the API.
    """
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
    Handles both string and list formats returned by the API.
    """
    unique_product_names = set()

    for advisory in advisories:
        product_names = advisory.get("productNames")

        if not product_names:
            continue

        if isinstance(product_names, list):
            for product_name in product_names:
                cleaned_name = product_name.strip()
                if cleaned_name:
                    unique_product_names.add(cleaned_name)

        elif isinstance(product_names, str):
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
    """Print a list of product names."""
    print()
    print(f"Product names shown: {len(product_names)}")
    print()

    for product_name in product_names:
        print(product_name)


def write_unique_product_names(product_names):
    """Write unique product names to a text file for review."""
    output_file = "unique_product_names.txt"

    with open(output_file, "w", encoding="utf-8") as file_handle:
        for product_name in product_names:
            file_handle.write(f"{product_name}\n")

    print()
    print(f"Unique product names written to: {output_file}")


def resolve_date_range(args):
    """
    Determine the date range to use for the advisory query.

    Rules:
    - If start_date and end_date are provided, use them
    - If only one is provided, raise an error
    - Otherwise use args.days
    """

    today = datetime.utcnow().date()

    if args.start_date and args.end_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d").date()
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()
        return start_date, end_date

    if args.start_date or args.end_date:
        raise ValueError("Both --start-date and --end-date must be provided together")

    start_date = today - timedelta(days=args.days)
    end_date = today

    return start_date, end_date


def main():
    product_groups = load_product_groups()
    args = parse_arguments(product_groups)
    start_date, end_date = resolve_date_range(args)
    print()
    print("PSIRT Reporter")
    print("--------------")
    print(f"Groups: {args.group}")

    if args.start_date and args.end_date:
        print(f"Start date: {start_date}")
        print(f"End date: {end_date}")
    else:
        print(f"Days: {args.days}")
        print(f"Start date: {start_date}")
        print(f"End date: {end_date}")
        print()

    print()
    advisories = fetch_all_advisories(start_date, end_date)
    print_advisory_summary(advisories)
    print("Loaded product groups:")
    print(list(product_groups.keys()))

    if advisories:
        print()
        print("First advisory product names:")
        for product_name in advisories[0].get("productNames", []):
            print(product_name)

        sample_matches = classify_advisory_products(
            advisories[0].get("productNames", []),
            product_groups,
        )

        print()
        print("Sample advisory group matches:")
        print(sample_matches)

    classified_advisories = classify_all_advisories(advisories, product_groups)

    filtered_advisories = filter_advisories_by_group(
    classified_advisories,
    args.group,
)

    print()
    print(f"Filtered advisories: {len(filtered_advisories)}")

    if filtered_advisories:
        print("Matched groups for first filtered advisory:")
        print(filtered_advisories[0].get("matched_groups", []))
        unique_product_names = extract_unique_product_names(filtered_advisories)
    print()
    print(f"Total unique product names discovered: {len(unique_product_names)}")
    print("Showing the first 50 unique product names alphabetically:")

    print_unique_product_names(unique_product_names[:50])
    write_unique_product_names(unique_product_names)

if __name__ == "__main__":
    main()
