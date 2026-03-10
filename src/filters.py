from src.api import is_kev_advisory


def filter_advisories_by_group(classified_advisories, selected_groups):
    """Filter advisories by selected product groups."""
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
    """Filter advisories by Cisco severity rating (sir)."""
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
    """Filter advisories to only those with at least one CVE in the KEV catalog."""
    filtered_advisories = []

    for advisory in advisories:
        if is_kev_advisory(advisory, kev_cves):
            filtered_advisories.append(advisory)

    return filtered_advisories