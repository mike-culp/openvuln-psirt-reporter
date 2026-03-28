import csv
import html
from datetime import datetime, timezone
from src.api import is_kev_advisory, normalize_cves
from src.classification import classify_advisory_products
from src.config import OUTPUT_DIR
from src.environment import is_version_affected, pick_first_fixed_version


def stringify_list(value):
    """
    Normalize strings/lists/None into a comma-separated string.
    """
    if value is None:
        return ""

    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if str(item).strip())

    cleaned = str(value).strip()
    return cleaned


def normalize_selected_groups(selected_groups):
    """
    Normalize selected groups for report display filtering.
    """
    if not selected_groups:
        return set()

    return {str(group).strip().lower() for group in selected_groups}


def filter_display_groups(matched_groups, selected_groups):
    """
    Limit displayed matched groups to the groups selected for this report.
    """
    if not matched_groups:
        return []

    normalized_selected = normalize_selected_groups(selected_groups)

    if "all" in normalized_selected:
        return matched_groups

    return [
        group for group in matched_groups
        if str(group).strip().lower() in normalized_selected
    ]


def filter_display_products(advisory, display_groups):
    """
    Limit displayed friendly products to those that belong to the
    groups selected for this report.
    """
    if not display_groups:
        return []

    friendly_products = advisory.get("friendly_products", []) or []
    if isinstance(friendly_products, str):
        friendly_products = [friendly_products]

    matched_groups = advisory.get("matched_groups", []) or []
    if isinstance(matched_groups, str):
        matched_groups = [matched_groups]

    if not friendly_products or not matched_groups:
        return []

    display_group_set = {str(group).strip().lower() for group in display_groups}
    matched_group_set = {str(group).strip().lower() for group in matched_groups}

    if not matched_group_set.intersection(display_group_set):
        return []

    product_to_group = {
        "ASA": "netsec",
        "FTD": "netsec",
        "FMC": "netsec",
        "FXOS": "netsec",
        "IOS": "enterprise",
        "IOS XE": "enterprise",
    }

    filtered = []
    for product in friendly_products:
        group = product_to_group.get(str(product).strip())
        if group in display_group_set:
            filtered.append(product)

    return filtered


def build_report_rows(advisories, kev_cves, selected_groups):
    """
    Normalize advisories into a stable reporting row model.

    Standard mode:
        one row per advisory

    Environment mode:
        one row per advisory + queried version context
        using _matched_product / _matched_version when present
    """
    rows = []

    for advisory in advisories:
        display_groups = filter_display_groups(
            advisory.get("matched_groups", []),
            selected_groups,
        )

        display_products = filter_display_products(
            advisory,
            display_groups,
)
        matched_product = advisory.get("_matched_product")
        matched_version = advisory.get("_matched_version")

        affected_versions = advisory.get("affected_versions", []) or []
        fixed_versions = advisory.get("fixed_versions", []) or []

        is_environment_row = bool(matched_product and matched_version)

        affected = ""
        first_fixed = ""

        if is_environment_row:
            affected_bool = is_version_affected(
                matched_product,
                matched_version,
                affected_versions,
            )
            affected = "Yes" if affected_bool else "No"

            if affected_bool:
                first_fixed_value = pick_first_fixed_version(
                    matched_product,
                    matched_version,
                    fixed_versions,
                )
                first_fixed = first_fixed_value or "n/a"
            else:
                first_fixed = "n/a"

        row = {
            "product": matched_product or "",
            "version": matched_version or "",
            "matched_groups": stringify_list(display_groups),
            "friendly_products": stringify_list(display_products),
            "kev": "Y" if is_kev_advisory(advisory, kev_cves) else "N",
            "affected": affected,
            "first_fixed": first_fixed,
            "firstPublished": advisory.get("firstPublished", ""),
            "lastUpdated": advisory.get("lastUpdated", ""),
            "status": advisory.get("status", ""),
            "advisoryId": advisory.get("advisoryId", ""),
            "sir": advisory.get("sir", ""),
            "cvssBaseScore": advisory.get("cvssBaseScore", ""),
            "cves": stringify_list(normalize_cves(advisory.get("cves"))),
            "cwe": stringify_list(advisory.get("cwe")),
            "bugIDs": stringify_list(advisory.get("bugIDs_normalized", [])),
            "bugStatuses": stringify_list(advisory.get("bug_statuses", [])),
            "bugSeverities": stringify_list(advisory.get("bug_severities", [])),
            "affectedVersions": stringify_list(affected_versions),
            "fixedVersions": stringify_list(fixed_versions),
            "advisoryTitle": advisory.get("advisoryTitle", ""),
            "productNames": stringify_list(display_products),
            "publicationUrl": advisory.get("publicationUrl", ""),
        }

        rows.append(row)

    return rows


def extract_unique_raw_product_names(advisories):
    """
    Extract all unique raw product names from advisories.
    """
    unique_names = set()

    for advisory in advisories:
        product_names = advisory.get("productNames", [])

        if isinstance(product_names, list):
            for product_name in product_names:
                if product_name:
                    unique_names.add(str(product_name).strip())
        elif product_names:
            unique_names.add(str(product_names).strip())

    return sorted(name for name in unique_names if name)


def print_runtime_settings(args, start_date, end_date):
    """
    Print the runtime settings selected for this execution.
    """
    print()
    print("PSIRT Reporter")
    print("--------------")
    print(f"Groups: {args.group}")
    print(f"SIR filter: {args.sir if args.sir else 'all'}")
    print(f"Minimum CVSS: {args.min_cvss if args.min_cvss is not None else 'all'}")
    print(f"KEV only: {args.kev_only}")
    print(f"Days: {args.days}")
    print(f"Start date: {start_date}")
    print(f"End date: {end_date}")
    print()


def print_advisory_summary(advisories):
    """
    Print a basic summary of the advisories returned by the API.
    """
    print()
    print(f"Total advisories retrieved: {len(advisories)}")


def print_loaded_product_groups(product_groups):
    """
    Print loaded product groups and product counts.
    """
    print()
    print("Loaded product groups:")

    for group_name, group_config in product_groups.items():
        products = group_config.get("products", {})
        print(f"  - {group_name}: {len(products)} product definitions")


def print_sample_classification(advisories, product_groups):
    """
    Print a small sample showing how advisory products classify.
    """
    if not advisories:
        return

    print()
    print("Sample product classification (first 3 advisories):")

    for advisory in advisories[:3]:
        advisory_id = advisory.get("advisoryId", "unknown")
        product_names = advisory.get("productNames", [])

        if isinstance(product_names, str):
            product_names = [product_names]
        elif not isinstance(product_names, list):
            product_names = [str(product_names)]

        classification = classify_advisory_products(product_names, product_groups)

        print()
        print(f"Advisory: {advisory_id}")
        print(f"Matched groups: {classification['matched_groups']}")
        print(f"Friendly products: {classification['friendly_products']}")


def print_filtered_summary(filtered_advisories):
    """
    Print a summary after filtering.
    """
    print()
    print(f"Filtered advisories count: {len(filtered_advisories)}")


def print_unique_product_names(product_names):
    """
    Print unique raw product names, one per line.
    """
    for product_name in product_names:
        print(f"  - {product_name}")


def write_unique_product_names(unique_product_names):
    """
    Write unique raw product names to a text file for discovery/review.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    output_file = OUTPUT_DIR / "unique_product_names.txt"

    with open(output_file, "w", encoding="utf-8") as file_handle:
        for product_name in unique_product_names:
            file_handle.write(f"{product_name}\n")

    print(f"Unique product names written to: {output_file}")
    return output_file


def build_output_base_name(selected_groups, start_date, end_date):
    """
    Build the base filename for output reports.
    """
    if "all" in selected_groups:
        group_part = "all"
    else:
        group_part = "_".join(sorted(selected_groups))

    return f"psirt_report_{group_part}_{start_date}_{end_date}"


def write_advisories_to_csv(advisories, selected_groups, start_date, end_date, kev_cves):
    """
    Write filtered advisories to a CSV file.
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

    rows = build_report_rows(advisories, kev_cves, selected_groups)

    fieldnames = [
        "product",
        "version",
        "matched_groups",
        "friendly_products",
        "kev",
        "affected",
        "first_fixed",
        "firstPublished",
        "lastUpdated",
        "status",
        "advisoryId",
        "sir",
        "cvssBaseScore",
        "cves",
        "cwe",
        "bugIDs",
        "bugStatuses",
        "bugSeverities",
        "affectedVersions",
        "fixedVersions",
        "advisoryTitle",
        "productNames",
        "publicationUrl",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            
            writer.writerow(row)

    return output_file


def write_advisories_to_html(advisories, selected_groups, start_date, end_date, kev_cves):
    """
    Write filtered advisories to an HTML file.
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

    rows = build_report_rows(advisories, kev_cves, selected_groups)

    total_count = len(rows)
    kev_count = 0
    sir_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    unique_cves = set()
    group_counts = {}
    product_counts = {}

    # Summary aggregation
    for row in rows:
        if row.get("kev") == "Y":
            kev_count += 1

        sir = str(row.get("sir", "")).strip().title()
        if sir in sir_counts:
            sir_counts[sir] += 1

        cves = [
            cve.strip()
            for cve in str(row.get("cves", "")).split(",")
            if cve.strip()
        ]
        for cve in cves:
            unique_cves.add(cve)

        matched_groups = [
            group.strip()
            for group in str(row.get("matched_groups", "")).split(",")
            if group.strip()
        ]
        for group in matched_groups:
            group_counts[group] = group_counts.get(group, 0) + 1

        friendly_products = [
            product.strip()
            for product in str(row.get("friendly_products", "")).split(",")
            if product.strip()
        ]
        for product in friendly_products:
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

    # Advisory table rendering
    advisory_rows = ""
    for row in rows:
        advisory_id = row.get("advisoryId", "")
        title = row.get("advisoryTitle", "")
        sir = row.get("sir", "")
        cvss = row.get("cvssBaseScore", "")
        status = row.get("status", "")
        first_published = row.get("firstPublished", "")
        last_updated = row.get("lastUpdated", "")
        publication_url = row.get("publicationUrl", "")
        cves_display = row.get("cves", "")
        matched_groups_display = row.get("matched_groups", "")
        friendly_products_display = row.get("friendly_products", "")
        kev_flag = "Yes" if row.get("kev") == "Y" else "No"

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