import csv
import html
from datetime import datetime, timezone
from src.api import is_kev_advisory, normalize_cves
from src.classification import classify_advisory_products
from src.config import OUTPUT_DIR


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
    "bugIDs",
    "bugStatuses",
    "bugSeverities",
    "affectedVersions",
    "fixedVersions",
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

            advisory_id = advisory.get("advisoryId", "")
            advisory_title = advisory.get("advisoryTitle", "")
            first_published = advisory.get("firstPublished", "")
            last_updated = advisory.get("lastUpdated", "")
            status = advisory.get("status", "")
            sir = advisory.get("sir", "")
            cvss_base_score = advisory.get("cvssBaseScore", "")
            publication_url = advisory.get("publicationUrl", "")

            bug_ids = advisory.get("bugIDs_normalized", [])
            if isinstance(bug_ids, list):
                bug_ids_value = ", ".join(bug_ids)
            else:
                bug_ids_value = str(bug_ids)

            bug_statuses = advisory.get("bug_statuses", [])
            if isinstance(bug_statuses, list):
                bug_statuses_value = ", ".join(bug_statuses)
            else:
                bug_statuses_value = str(bug_statuses)

            bug_severities = advisory.get("bug_severities", [])
            if isinstance(bug_severities, list):
                bug_severities_value = ", ".join(bug_severities)
            else:
                bug_severities_value = str(bug_severities)

            affected_versions = advisory.get("affected_versions", [])
            if isinstance(affected_versions, list):
                affected_versions_value = ", ".join(affected_versions)
            else:
                affected_versions_value = str(affected_versions)

            fixed_versions = advisory.get("fixed_versions", [])
            if isinstance(fixed_versions, list):
                fixed_versions_value = ", ".join(fixed_versions)
            else:
                fixed_versions_value = str(fixed_versions)

            # --- BUG ENRICHMENT VALUES (add here) ---
            bug_ids = advisory.get("bugIDs_normalized", [])
            if isinstance(bug_ids, list):
                bug_ids_value = ", ".join(bug_ids)
            else:
                bug_ids_value = str(bug_ids)

            bug_statuses = advisory.get("bug_statuses", [])
            if isinstance(bug_statuses, list):
                bug_statuses_value = ", ".join(bug_statuses)
            else:
                bug_statuses_value = str(bug_statuses)

            bug_severities = advisory.get("bug_severities", [])
            if isinstance(bug_severities, list):
                bug_severities_value = ", ".join(bug_severities)
            else:
                bug_severities_value = str(bug_severities)

            affected_versions = advisory.get("affected_versions", [])
            if isinstance(affected_versions, list):
                affected_versions_value = ", ".join(affected_versions)
            else:
                affected_versions_value = str(affected_versions)

            fixed_versions = advisory.get("fixed_versions", [])
            if isinstance(fixed_versions, list):
                fixed_versions_value = ", ".join(fixed_versions)
            else:
                fixed_versions_value = str(fixed_versions)
            # --- END BUG ENRICHMENT VALUES ---

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
                "bugIDs": bug_ids_value,
                "bugStatuses": bug_statuses_value,
                "bugSeverities": bug_severities_value,
                "affectedVersions": affected_versions_value,
                "fixedVersions": fixed_versions_value,
                "advisoryTitle": advisory_title,
                "productNames": product_names_value,
                "publicationUrl": publication_url,
                "cwe": cwe_value,
            }

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