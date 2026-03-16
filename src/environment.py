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

    Current generic behavior:
    - dotted numeric versions use major.minor as the train
    - if the version cannot be parsed numerically, fall back to the raw string
    """
    parts = normalize_version_parts(version)

    if parts and len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"

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


def normalize_version_parts(version):
    """
    Convert a dotted version string into a tuple of integers.

    Examples:
        7.6.2 -> (7, 6, 2)
        7.6.2.1 -> (7, 6, 2, 1)
        7.4 -> (7, 4)
    """
    parts = []

    for part in str(version).split("."):
        part = part.strip()

        if not part:
            continue

        if not part.isdigit():
            return None

        parts.append(int(part))

    return tuple(parts) if parts else None


def compare_versions(left, right):
    """
    Compare dotted versions numerically.

    Returns:
        -1 if left < right
         0 if left == right
         1 if left > right
        None if either version is not purely numeric
    """
    left_parts = normalize_version_parts(left)
    right_parts = normalize_version_parts(right)

    if left_parts is None or right_parts is None:
        return None

    max_len = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (max_len - len(left_parts))
    right_parts = right_parts + (0,) * (max_len - len(right_parts))

    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def is_version_affected(product, queried_version, affected_versions):
    """
    Return True if the queried version exactly matches one of the
    advisory's affected versions.

    Initial behavior:
    - exact dotted-version match
    - missing trailing zeros are treated as equal
    """
    if not affected_versions:
        return False

    for affected_version in affected_versions:
        if compare_versions(queried_version, affected_version) == 0:
            return True

    return False


def pick_first_fixed_version(product, queried_version, fixed_versions):
    """
    Prefer the earliest fixed version in the same train that is
    greater than or equal to the queried version.
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

    candidates = []

    for version in same_train:
        comparison = compare_versions(version, queried_version)
        if comparison is not None and comparison >= 0:
            candidates.append(version)

    if not candidates:
        return None

    candidates = sorted(set(candidates), key=version_key)
    return candidates[0]


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

            advisories = enrich_advisories_with_bug_details(advisories)

            validated_advisories = []
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

            for advisory in advisories:
                advisory["_matched_product"] = product
                advisory["_matched_version"] = query_version

                if is_version_affected(
                    product,
                    query_version,
                    advisory.get("affected_versions", []),
                ):
                    validated_advisories.append(advisory)

                    sir = str(advisory.get("sir", "")).strip().lower()
                    if sir in severity_counts:
                        severity_counts[sir] += 1

                advisory_id = advisory.get("advisoryId")
                advisory_key = (advisory_id, query_version)

                if advisory_id and advisory_key not in seen_advisory_ids:
                    seen_advisory_ids.add(advisory_key)
                    all_advisories.append(advisory)

            version_summaries.append(
                {
                    "product": display_name,
                    "version": query_version,
                    "count": len(validated_advisories),
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

    print(f"\nTotal advisory matches across all queried versions: {len(all_advisories)}")

    if all_advisories:

        validated_advisories = []

        for advisory in all_advisories:
            matched_product = advisory.get("_matched_product", "")
            matched_version = advisory.get("_matched_version", "")

            if is_version_affected(
                matched_product,
                matched_version,
                advisory.get("affected_versions", []),
            ):
                validated_advisories.append(advisory)

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
            matched_product = advisory.get("_matched_product", "")
            matched_version = advisory.get("_matched_version", "")
            affected_versions = advisory.get("affected_versions", [])
            fixed_versions = advisory.get("fixed_versions", [])

            validated_affected = is_version_affected(
                matched_product,
                matched_version,
                affected_versions,
            )

            first_fixed = None
            if validated_affected:
                first_fixed = pick_first_fixed_version(
                    matched_product,
                    matched_version,
                    fixed_versions,
                )

            print(
                f"- {advisory.get('advisoryId', 'unknown')} | "
                f"{advisory.get('sir', '')} | "
                f"Affected: {'Yes' if validated_affected else 'No'} | "
                f"First fixed: {first_fixed or 'n/a'} | "
                f"{advisory.get('advisoryTitle', '')}"
            )
