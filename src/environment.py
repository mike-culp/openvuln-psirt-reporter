from src.api import fetch_advisories_for_os_version
from src.config import load_environment_products


def normalize_os_version_for_query(product, version):
    """
    Normalize user-supplied versions into API-friendly versions.
    """
    version = version.strip()

    if product == "ftd":
        parts = version.split(".")
        if len(parts) == 2:
            return f"{version}.0"

    return version


from src.api import fetch_advisories_for_os_version
from src.config import load_environment_products


def normalize_os_version_for_query(product, version):
    """
    Normalize user-supplied versions into API-friendly versions.
    """
    version = version.strip()

    if product == "ftd":
        parts = version.split(".")
        if len(parts) == 2:
            return f"{version}.0"

    return version


def run_environment_assessment(product_versions):
    """
    Run environment assessment mode.
    """
    print("Environment mode")

    env_products = load_environment_products()
    all_advisories = []
    seen_advisory_ids = set()
    version_summaries = []

    for product, versions in product_versions.items():
        product_config = env_products.get(product, {})
        api_type = product_config.get("api_type")
        display_name = product.upper()

        for version in versions:
            query_version = normalize_os_version_for_query(product, version)

            print(f"\nChecking product: {product}")
            print(f"  Querying version: {version} -> {query_version}")

            advisories = fetch_advisories_for_os_version(api_type, query_version)
            print(f"    Advisories returned: {len(advisories)}")

            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

            for advisory in advisories:
                sir = str(advisory.get("sir", "")).strip().lower()
                if sir in severity_counts:
                    severity_counts[sir] += 1

                advisory_id = advisory.get("advisoryId")
                if advisory_id and advisory_id not in seen_advisory_ids:
                    seen_advisory_ids.add(advisory_id)
                    advisory["_matched_product"] = product
                    advisory["_matched_version"] = query_version
                    all_advisories.append(advisory)

            version_summaries.append(
                {
                    "product": display_name,
                    "version": query_version,
                    "count": len(advisories),
                    "severity_counts": severity_counts,
                }
            )

    print("\nVersion summary:")
    for summary in version_summaries:
        print(f"\n{summary['product']} {summary['version']}")
        print(f"Advisories affecting this version: {summary['count']}")
        print(f"Critical: {summary['severity_counts']['critical']}")
        print(f"High: {summary['severity_counts']['high']}")
        print(f"Medium: {summary['severity_counts']['medium']}")
        print(f"Low: {summary['severity_counts']['low']}")

    print(f"\nUnique advisories retrieved across all queries: {len(all_advisories)}")

    if all_advisories:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
        sorted_advisories = sorted(
            all_advisories,
            key=lambda advisory: (
                severity_order.get(str(advisory.get("sir", "")).strip().lower(), 5),
                advisory.get("advisoryId", ""),
            ),
        )

        print("\nSample advisories:")
        for advisory in sorted_advisories[:10]:
            print(
                f"- {advisory.get('advisoryId', 'unknown')} | "
                f"{advisory.get('sir', '')} | "
                f"{advisory.get('advisoryTitle', '')}"
            )