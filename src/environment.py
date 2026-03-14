from src.api import fetch_advisories_for_os_version
from src.config import load_environment_products


def run_environment_assessment(product_versions):
    """
    Run environment assessment mode.
    """
    print("Environment mode")

    env_products = load_environment_products()
    all_advisories = []
    seen_advisory_ids = set()

    for product, versions in product_versions.items():
        product_config = env_products.get(product, {})
        api_type = product_config.get("api_type")

        print(f"\nChecking product: {product}")

        for version in versions:
            print(f"  Querying version: {version}")

            advisories = fetch_advisories_for_os_version(api_type, version)
            print(f"    Advisories returned: {len(advisories)}")

            for advisory in advisories:
                advisory_id = advisory.get("advisoryId")
                if advisory_id and advisory_id not in seen_advisory_ids:
                    seen_advisory_ids.add(advisory_id)
                    advisory["_matched_product"] = product
                    advisory["_matched_version"] = version
                    all_advisories.append(advisory)

    print(f"\nUnique advisories retrieved: {len(all_advisories)}")

    if all_advisories:
        print("\nSample advisories:")
        for advisory in all_advisories[:10]:
            print(
                f"- {advisory.get('advisoryId', 'unknown')} | "
                f"{advisory.get('sir', '')} | "
                f"{advisory.get('advisoryTitle', '')}"
            )