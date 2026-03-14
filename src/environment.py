from src.api import fetch_advisories_for_os_version
from src.config import load_environment_products
from src.bug_enrichment import enrich_advisories_with_bug_details


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


def get_release_train(product, version):
    """
    Return the release train for a queried version.

    For FTD, 7.6.2 -> 7.6
    """
    parts = str(version).split(".")
    if product == "ftd" and len(parts) >= 2:
        return ".".join(parts[:2])
    return str(version)


def version_key(version):
    """
    Build a sortable key for dotted versions like 7.6.2 or 7.4.0.1.
    """
    key = []

    for part in str(version).split("."):
        part = part.strip()
        if part.isdigit():
            key.append(int(part))
        else:
            key.append(part)

    return tuple(key)


def pick_first_fixed_version(product, queried_version, fixed_versions):
    """
    Prefer the first fixed version in the same train as the queried version.
    If no same-train fix exists, return None.
    """
    if not fixed_versions:
        return None

    queried_train = get_release_train(product, queried_version)

    same_train = [
        version for version in fixed_versions
        if get_release_train(product, version) == queried_train
    ]

    if not same_train:
        return None

    candidates = sorted(set(same_train), key=version_key)
    return candidates[0] if candidates else None



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

        # Enrich advisories with Bug API data
        all_advisories = enrich_advisories_with_bug_details(all_advisories)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

        sorted_advisories = sorted(
            all_advisories,
            key=lambda advisory: (
                severity_order.get(str(advisory.get("sir", "")).strip().lower(), 5),
                advisory.get("advisoryId", ""),
            ),
    )

        print("\nExample advisories (first 10):")
        for advisory in sorted_advisories[:10]:
            first_fixed = pick_first_fixed_version(
                advisory.get("_matched_product", ""),
                advisory.get("_matched_version", ""),
                advisory.get("fixed_versions", []),
            )

            print(
                f"- {advisory.get('advisoryId', 'unknown')} | "
                f"{advisory.get('sir', '')} | "
                f"First fixed: {first_fixed or 'unknown'} | "
                f"{advisory.get('advisoryTitle', '')}"
            )
