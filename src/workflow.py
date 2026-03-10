import sys

from src.api import (
    extract_kev_cves,
    fetch_all_advisories,
    fetch_kev_catalog,
)
from src.classification import classify_all_advisories
from src.cli import parse_arguments, resolve_date_range
from src.config import load_product_groups
from src.filters import (
    filter_advisories_by_cvss,
    filter_advisories_by_group,
    filter_advisories_by_kev,
    filter_advisories_by_sir,
)
from src.reporting import (
    extract_unique_raw_product_names,
    print_advisory_summary,
    print_filtered_summary,
    print_loaded_product_groups,
    print_runtime_settings,
    print_sample_classification,
    print_unique_product_names,
    write_advisories_to_csv,
    write_advisories_to_html,
    write_unique_product_names,
)
from src.bug_enrichment import enrich_advisories_with_bug_details


def run():
    product_groups = load_product_groups()
    args = parse_arguments(product_groups)

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

    filtered_advisories = enrich_advisories_with_bug_details(filtered_advisories)

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