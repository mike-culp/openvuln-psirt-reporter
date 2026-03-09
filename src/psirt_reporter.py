import argparse
import csv
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import requests
import yaml
import html
import sys


# ============================================================
# CONFIGURATION
# ============================================================


TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BASE_URL = "https://apix.cisco.com/security/advisories/v2"
ADVISORIES_URL = f"{BASE_URL}/all/lastpublished"

ROOT_DIR = Path(__file__).resolve().parents[1]
PRODUCT_GROUPS_FILE = ROOT_DIR / "config" / "product_groups.yaml"
OUTPUT_DIR = ROOT_DIR / "output"

CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ============================================================
# API FUNCTIONS
# ============================================================


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


# ============================================================
# CLI / INPUT HANDLING
# ============================================================


def positive_int(value):
    """Argparse type that only accepts integers >= 1."""
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(
            f"invalid positive integer value: {value}"
        )
    return ivalue


def parse_arguments(product_groups):
    """Parse command line arguments."""
    group_names = list(product_groups.keys())

    group_help_text = (
        "Product groups to include.\n\n"
        "Available groups:\n"
        + "\n".join(f"  {group_name}" for group_name in group_names)
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
        type=positive_int,
        default=60,
        help="Number of days to look back. Ignored if start/end date are provided.",
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

    parser.add_argument(
        "--sir",
        nargs="+",
        choices=["critical", "high", "medium", "low"],
        help=(
            "Filter advisories by Cisco severity rating. "
            "Allowed values: critical, high, medium, low"
        ),
    )

    parser.add_argument(
        "--min-cvss",
        type=float,
        help="Minimum CVSS base score to include (example: 8.0)",
    )

    parser.add_argument(
        "--kev-only",
        action="store_true",
        help="Include only advisories with CVEs present in the CISA KEV catalog",
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report in addition to the CSV report",
    )

    return parser.parse_args()


def resolve_date_range(args):
    """Resolve start and end dates from CLI arguments."""
    if args.days < 1:
        raise ValueError("--days must be greater than or equal to 1")

    if (args.start_date and not args.end_date) or (
        args.end_date and not args.start_date
    ):
        raise ValueError(
            "Both --start-date and --end-date must be provided together."
        )

    if args.start_date and args.end_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d").date()
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()
    else:
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=args.days)

    if start_date > end_date:
        raise ValueError("--start-date must be on or before --end-date")

    return start_date, end_date


# ============================================================
# CLASSIFICATION
# ============================================================


def classify_advisory_products(product_names, product_groups):
    """
    Match an advisory's product names against the configured product groups.

    Args:
        product_names: A list of product names from one advisory.
        product_groups: The groups loaded from product_groups.yaml.

    Returns:
        A dictionary with:
            - matched_groups: list of matching group keys
            - friendly_products: list of matching friendly product names
    """
    matched_groups = set()
    friendly_products = set()

    if not product_names:
        return {
            "matched_groups": [],
            "friendly_products": [],
        }

    for group_key, group_config in product_groups.items():
        products = group_config.get("products", {})

        for friendly_name, product_config in products.items():
            match_terms = product_config.get("match", [])
            exclude_terms = product_config.get("exclude", [])

            product_matched = False

            for product_name in product_names:
                product_name_lower = product_name.lower()

                matches_product = any(
                    match_term.lower() in product_name_lower
                    for match_term in match_terms
                )

                excluded_from_product = any(
                    exclude_term.lower() in product_name_lower
                    for exclude_term in exclude_terms
                )

                if matches_product and not excluded_from_product:
                    product_matched = True
                    break

            if product_matched:
                matched_groups.add(group_key)
                friendly_products.add(friendly_name)

    return {
        "matched_groups": sorted(matched_groups),
        "friendly_products": sorted(friendly_products),
    }


def classify_all_advisories(advisories, product_groups):
    """
    Classify every advisory using the configured product groups.

    Returns:
        A new list of dictionaries. Each dictionary contains the original
        advisory plus:
            - matched_groups
            - friendly_products
    """
    classified_advisories = []

    for advisory in advisories:
        product_names = advisory.get("productNames", [])

        if isinstance(product_names, str):
            product_names = [product_names]
        elif not isinstance(product_names, list):
            product_names = [str(product_names)]

        classification = classify_advisory_products(product_names, product_groups)

        advisory_with_classification = advisory.copy()
        advisory_with_classification["matched_groups"] = classification["matched_groups"]
        advisory_with_classification["friendly_products"] = classification["friendly_products"]

        classified_advisories.append(advisory_with_classification)

    return classified_advisories


# ============================================================
# FILTERS
# ============================================================


def filter_advisories_by_group(classified_advisories, selected_groups):
    """
    Filter advisories by selected product groups.

    Args:
        classified_advisories: list of advisories with matched_groups
        selected_groups: list of groups from CLI

    Returns:
        list of advisories that match the selected groups
    """
    selected_group_set = {group.lower() for group in selected_groups}

    if "all" in selected_group_set:
        return classified_advisories

    filtered_advisories = []

    for advisory in classified_advisories:
        matched_groups = advisory.get("matched_groups", [])
        matched_group_set = {group.lower() for group in matched_groups}

        if matched_group_set.intersection(selected_group_set):
            filtered_advisories.append(advisory)

    return filtered_advisories

def filter_advisories_by_sir(advisories, selected_sirs):
    """
    Filter advisories by Cisco severity rating (sir).
    """
    if not selected_sirs:
        return advisories

    selected_sir_set = {sir.lower() for sir in selected_sirs}
    filtered_advisories = []

    for advisory in advisories:
        advisory_sir = str(advisory.get("sir", "")).strip().lower()

        if advisory_sir in selected_sir_set:
            filtered_advisories.append(advisory)

    return filtered_advisories

def filter_advisories_by_cvss(advisories, threshold):
    """Filter advisories by minimum CVSS base score."""
    if threshold is None:
        return advisories

    filtered_advisories = []

    for advisory in advisories:
        score = advisory.get("cvssBaseScore")

        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            continue

        if numeric_score >= threshold:
            filtered_advisories.append(advisory)

    return filtered_advisories

def filter_advisories_by_kev(advisories, kev_cves):
    """
    Filter advisories to only those with at least one CVE in the KEV catalog.
    """
    filtered_advisories = []

    for advisory in advisories:
        if is_kev_advisory(advisory, kev_cves):
            filtered_advisories.append(advisory)

    return filtered_advisories

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


def fetch_kev_catalog():
    """Fetch the CISA Known Exploited Vulnerabilities catalog."""
    try:
        response = requests.get(KEV_CATALOG_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Warning: Could not fetch KEV catalog: {e}")
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


def extract_unique_raw_product_names(advisories):
    """
    Extract a sorted list of unique raw product names from advisory data.
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


# ============================================================
# REPORTING / OUTPUT
# ============================================================


def print_runtime_settings(args, start_date, end_date):
    """Print the current runtime settings."""
    print()
    print("PSIRT Reporter")
    print("--------------")
    print(f"Groups: {args.group}")
    print(f"SIR filter: {args.sir if args.sir else 'all'}")

    cvss_display = args.min_cvss if args.min_cvss is not None else "all"
    print(f"Minimum CVSS: {cvss_display}")

    print(f"KEV only: {args.kev_only}")

    if args.start_date and args.end_date:
        print(f"Start date: {start_date}")
        print(f"End date: {end_date}")
    else:
        print(f"Days: {args.days}")
        print(f"Start date: {start_date}")
        print(f"End date: {end_date}")

    print()


def print_advisory_summary(advisories):
    """Print a small summary of the advisory pull."""
    print(f"Total advisories returned: {len(advisories)}")

    if not advisories:
        return

    first_advisory = advisories[0]

    print(f"First advisory ID: {first_advisory.get('advisoryId')}")
    print(f"First advisory title: {first_advisory.get('advisoryTitle')}")
    print(f"First advisory keys: {list(first_advisory.keys())}")


def print_loaded_product_groups(product_groups):
    """Print loaded product group names."""
    print("Loaded product groups:")
    print(list(product_groups.keys()))


def print_sample_classification(advisories, product_groups):
    """Print sample classification details for the first advisory."""
    if not advisories:
        return

    product_names = advisories[0].get("productNames", [])

    if isinstance(product_names, str):
        product_names = [product_names]
    elif not isinstance(product_names, list):
        product_names = [str(product_names)]

    print()
    print("First advisory product names:")
    for product_name in product_names:
        print(product_name)

    sample_classification = classify_advisory_products(
        product_names,
        product_groups,
    )

    print()
    print("Sample advisory group matches:")
    print(sample_classification["matched_groups"])

    print("Sample friendly product matches:")
    print(sample_classification["friendly_products"])


def print_filtered_summary(filtered_advisories):
    """Print summary information for filtered advisories."""
    print()
    print(f"Filtered advisories: {len(filtered_advisories)}")

    if not filtered_advisories:
        return

    print("Matched groups for first filtered advisory:")
    print(filtered_advisories[0].get("matched_groups", []))

    print("Friendly products for first filtered advisory:")
    print(filtered_advisories[0].get("friendly_products", []))


def print_unique_product_names(product_names):
    """Print a list of product names."""
    print()
    print(f"Product names shown: {len(product_names)}")
    print()

    for product_name in product_names:
        print(product_name)


def write_unique_product_names(product_names):
    """Write unique product names to a text file for review."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    output_file = OUTPUT_DIR / "unique_product_names.txt"

    with open(output_file, "w", encoding="utf-8") as file_handle:
        for product_name in product_names:
            file_handle.write(f"{product_name}\n")

    print()
    print(f"Unique product names written to: {output_file}")


def build_output_base_name(selected_groups, start_date, end_date):
    """Build the shared base filename for report outputs."""
    group_label = (
        "all"
        if selected_groups == ["all"]
        else "_".join(selected_groups)
    )
    return f"psirt_{group_label}_{start_date}_to_{end_date}"


def write_advisories_to_csv(advisories, selected_groups, start_date, end_date, kev_cves):
    """
    Write filtered advisories to a CSV file.

    Args:
        advisories: List of filtered advisory dictionaries
        selected_groups: List of selected groups from CLI
        start_date: Start date used for the query
        end_date: End date used for the query

    Returns:
        Path to the written CSV file
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    base_name = build_output_base_name(selected_groups, start_date, end_date)
    file_name = f"{base_name}.csv"
    output_file = OUTPUT_DIR / file_name

    advisories = sorted(
    advisories,
    key=lambda a: float(a.get("cvssBaseScore") or 0),
    reverse=True,
    )

    fieldnames = [
        "matched_groups",
        "friendly_products",
        "kev",
        "firstPublished",
        "lastUpdated",
        "status",
        "advisoryId",
        "sir",
        "cvssBaseScore",
        "cves",
        "advisoryTitle",
        "productNames",
        "publicationUrl",
        "cwe",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()

        for advisory in advisories:
            product_names = advisory.get("productNames", [])
            if isinstance(product_names, list):
                product_names_value = ", ".join(product_names)
            else:
                product_names_value = str(product_names)

            matched_groups = advisory.get("matched_groups", [])
            matched_groups_value = ", ".join(matched_groups)

            friendly_products = advisory.get("friendly_products", [])
            friendly_products_value = ", ".join(friendly_products)

            cves = advisory.get("cves", [])
            if isinstance(cves, list):
                cves_value = ", ".join(cves)
            else:
                cves_value = str(cves)

            cwe = advisory.get("cwe", [])
            if isinstance(cwe, list):
                cwe_value = ", ".join(cwe)
            else:
                cwe_value = str(cwe)

            kev_value = "Y" if is_kev_advisory(advisory, kev_cves) else "N"

            row = {
                "matched_groups": matched_groups_value,
                "friendly_products": friendly_products_value,
                "kev": kev_value,
                "firstPublished": advisory.get("firstPublished", ""),
                "lastUpdated": advisory.get("lastUpdated", ""),
                "status": advisory.get("status", ""),
                "advisoryId": advisory.get("advisoryId", ""),
                "sir": advisory.get("sir", ""),
                "cvssBaseScore": advisory.get("cvssBaseScore", ""),
                "cves": cves_value,
                "advisoryTitle": advisory.get("advisoryTitle", ""),
                "productNames": product_names_value,
                "publicationUrl": advisory.get("publicationUrl", ""),
                "cwe": cwe_value,
            }

            writer.writerow(row)

    return output_file


def write_advisories_to_html(advisories, selected_groups, start_date, end_date, kev_cves):
    """
    Write filtered advisories to an HTML file.

    Args:
        advisories: List of filtered advisory dictionaries
        selected_groups: List of selected groups from CLI
        start_date: Start date used for the query
        end_date: End date used for the query
        kev_cves: Set of CVE IDs present in the CISA KEV catalog

    Returns:
        Path to the written HTML file
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    base_name = build_output_base_name(selected_groups, start_date, end_date)
    file_name = f"{base_name}.html"
    output_file = OUTPUT_DIR / file_name

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    advisories = sorted(
    advisories,
    key=lambda a: float(a.get("cvssBaseScore") or 0),
    reverse=True,
)

    total_count = len(advisories)
    kev_count = 0
    sir_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    unique_cves = set()
    group_counts = {}
    product_counts = {}

    for advisory in advisories:
        cves = normalize_cves(advisory.get("cves"))

        if any(cve in kev_cves for cve in cves):
            kev_count += 1

        sir = (advisory.get("sir") or "").strip().title()
        if sir in sir_counts:
            sir_counts[sir] += 1

        for cve in cves:
            if cve:
                unique_cves.add(cve)

        matched_groups = advisory.get("matched_groups", []) or []
        if isinstance(matched_groups, str):
            matched_groups = [matched_groups]

        for group in matched_groups:
            if group:
                group_counts[group] = group_counts.get(group, 0) + 1

        friendly_products = advisory.get("friendly_products", []) or []
        if isinstance(friendly_products, str):
            friendly_products = [friendly_products]

        for product in friendly_products:
            if product:
                product_counts[product] = product_counts.get(product, 0) + 1

    summary_cards_html = f"""
    <div class="summary-grid">
        <div class="card"><h3>Total Advisories</h3><p>{total_count}</p></div>
        <div class="card"><h3>KEV Advisories</h3><p>{kev_count}</p></div>
        <div class="card"><h3>Critical</h3><p>{sir_counts["Critical"]}</p></div>
        <div class="card"><h3>High</h3><p>{sir_counts["High"]}</p></div>
        <div class="card"><h3>Medium</h3><p>{sir_counts["Medium"]}</p></div>
        <div class="card"><h3>Low</h3><p>{sir_counts["Low"]}</p></div>
        <div class="card"><h3>Unique CVEs</h3><p>{len(unique_cves)}</p></div>
    </div>
    """

    group_rows = ""
    for group, count in sorted(group_counts.items()):
        group_rows += (
            f"<tr><td>{html.escape(str(group))}</td><td>{count}</td></tr>"
        )

    if not group_rows:
        group_rows = "<tr><td colspan='2'>No group data</td></tr>"

    product_rows = ""
    for product, count in sorted(product_counts.items()):
        product_rows += (
            f"<tr><td>{html.escape(str(product))}</td><td>{count}</td></tr>"
        )

    if not product_rows:
        product_rows = "<tr><td colspan='2'>No product data</td></tr>"

    advisory_rows = ""
    for advisory in advisories:
        advisory_id = advisory.get("advisoryId", "")
        title = advisory.get("advisoryTitle", "")
        sir = advisory.get("sir", "")
        cvss = advisory.get("cvssBaseScore", "")
        status = advisory.get("status", "")
        first_published = advisory.get("firstPublished", "")
        last_updated = advisory.get("lastUpdated", "")
        publication_url = advisory.get("publicationUrl", "")

        cves = normalize_cves(advisory.get("cves"))
        cves_display = ", ".join(cves)

        matched_groups = advisory.get("matched_groups", []) or []
        if isinstance(matched_groups, list):
            matched_groups_display = ", ".join(matched_groups)
        else:
            matched_groups_display = str(matched_groups)

        friendly_products = advisory.get("friendly_products", []) or []
        if isinstance(friendly_products, list):
            friendly_products_display = ", ".join(friendly_products)
        else:
            friendly_products_display = str(friendly_products)

        kev_flag = "Yes" if is_kev_advisory(advisory, kev_cves) else "No"

        advisory_id_escaped = html.escape(str(advisory_id))
        if publication_url:
            advisory_link = (
                f'<a href="{html.escape(str(publication_url))}" '
                f'target="_blank" rel="noopener noreferrer">{advisory_id_escaped}</a>'
            )
        else:
            advisory_link = advisory_id_escaped

        advisory_rows += f"""
        <tr>
            <td>{advisory_link}</td>
            <td>{html.escape(str(title))}</td>
            <td>{html.escape(str(sir))}</td>
            <td>{html.escape(str(cvss))}</td>
            <td>{kev_flag}</td>
            <td>{html.escape(str(matched_groups_display))}</td>
            <td>{html.escape(str(friendly_products_display))}</td>
            <td>{html.escape(str(cves_display))}</td>
            <td>{html.escape(str(first_published))}</td>
            <td>{html.escape(str(last_updated))}</td>
            <td>{html.escape(str(status))}</td>
        </tr>
        """

    if not advisory_rows:
        advisory_rows = "<tr><td colspan='11'>No advisories found</td></tr>"

    selected_groups_display = ", ".join(selected_groups)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cisco PSIRT Advisory Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 24px;
            color: #222;
            background: #f7f7f7;
        }}
        h1, h2 {{
            margin-bottom: 8px;
        }}
        .meta {{
            margin-bottom: 24px;
            padding: 16px;
            background: #fff;
            border: 1px solid #ddd;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #fff;
            border: 1px solid #ddd;
            padding: 16px;
        }}
        .card h3 {{
            margin: 0 0 8px 0;
            font-size: 16px;
        }}
        .card p {{
            margin: 0;
            font-size: 28px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            background: #fff;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #efefef;
        }}
        a {{
            color: #0645ad;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <h1>Cisco PSIRT Advisory Report</h1>

    <div class="meta">
        <p><strong>Generated:</strong> {html.escape(generated_at)}</p>
        <p><strong>Selected Groups:</strong> {html.escape(selected_groups_display)}</p>
        <p><strong>Date Range:</strong> {html.escape(start_date.isoformat())} to {html.escape(end_date.isoformat())}</p>
    </div>

    {summary_cards_html}

    <h2>Group Breakdown</h2>
    <table>
        <thead>
            <tr>
                <th>Group</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            {group_rows}
        </tbody>
    </table>

    <h2>Product Breakdown</h2>
    <table>
        <thead>
            <tr>
                <th>Product</th>
                <th>Count</th>
            </tr>
        </thead>
        <tbody>
            {product_rows}
        </tbody>
    </table>

    <h2>Advisories</h2>
    <table>
        <thead>
            <tr>
                <th>Advisory ID</th>
                <th>Title</th>
                <th>SIR</th>
                <th>CVSS</th>
                <th>KEV</th>
                <th>Matched Groups</th>
                <th>Friendly Products</th>
                <th>CVEs</th>
                <th>First Published</th>
                <th>Last Updated</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {advisory_rows}
        </tbody>
    </table>
</body>
</html>
"""

    output_file.write_text(html_content, encoding="utf-8")
    return output_file


# ============================================================
# MAIN PROGRAM FLOW
# ============================================================


def main():

    product_groups = load_product_groups()
    args = parse_arguments(product_groups)

    # Validate requested groups
    available_groups = set(product_groups.keys())

    if "all" not in args.group:
        invalid_groups = [g for g in args.group if g not in available_groups]

        if invalid_groups:
            print(
                f"Error: Unknown group(s): {', '.join(invalid_groups)}. "
                f"Valid groups: {', '.join(sorted(available_groups))}"
            )
            sys.exit(1)

    start_date, end_date = resolve_date_range(args)

    # Validate CVSS threshold
    if args.min_cvss is not None:
        if not 0.0 <= args.min_cvss <= 10.0:
            raise ValueError(
                f"Invalid --min-cvss value: {args.min_cvss}. "
                "CVSS scores must be between 0.0 and 10.0."
            )

    print_runtime_settings(args, start_date, end_date)

    advisories = fetch_all_advisories(start_date, end_date)
    print("Fetching CISA KEV catalog...")
    kev_catalog = fetch_kev_catalog()
    kev_cves = extract_kev_cves(kev_catalog)
    print(f"Loaded KEV CVEs: {len(kev_cves)}")
    print_advisory_summary(advisories)
    print_loaded_product_groups(product_groups)
    print_sample_classification(advisories, product_groups)

    classified_advisories = classify_all_advisories(advisories, product_groups)

    filtered_advisories = filter_advisories_by_group(
        classified_advisories,
        args.group,
    )

    filtered_advisories = filter_advisories_by_sir(
        filtered_advisories,
        args.sir,
    )

    filtered_advisories = filter_advisories_by_cvss(
        filtered_advisories,
        args.min_cvss,
    )

    if args.kev_only:
        filtered_advisories = filter_advisories_by_kev(
            filtered_advisories,
            kev_cves,
        )

    print_filtered_summary(filtered_advisories)
    if not filtered_advisories:
        print("No advisories matched your filters. Exiting.")
    sys.exit(0)

    unique_product_names = extract_unique_raw_product_names(filtered_advisories)

    print()
    print(f"Total unique product names discovered: {len(unique_product_names)}")
    print("Showing the first 50 unique product names alphabetically:")

    print_unique_product_names(unique_product_names[:50])
    write_unique_product_names(unique_product_names)

    csv_file = write_advisories_to_csv(
        filtered_advisories,
        args.group,
        start_date,
        end_date,
        kev_cves,
    )

    print()
    print(f"CSV report written to: {csv_file}")

    if args.html:
        html_file = write_advisories_to_html(
            filtered_advisories,
            args.group,
            start_date,
            end_date,
            kev_cves,
        )
        print(f"HTML report written to: {html_file}")


# ============================================================
# ENTRY POINT
# ============================================================


if __name__ == "__main__":
    main()