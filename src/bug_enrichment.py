# src/bug_enrichment.py

"""
Bug enrichment helpers.

Initial scope:
- Extract bug IDs from filtered advisories
- Normalize and de-duplicate them
- Query Cisco Bug API through src.bug_api
- Attach normalized bug details back onto advisories
- Fail gracefully if Bug API is unavailable
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from src.bug_api import BugApiError, fetch_bug_details_by_ids, verbose_print

from src.logging_utils import verbose_print


def normalize_bug_ids(value: Any) -> List[str]:
    """
    Normalize advisory bugIDs into a clean list of bug ID strings.

    OpenVuln may return bugIDs as:
    - a string: "CSCxx12345"
    - a comma-separated string: "CSCxx12345, CSCyy67890"
    - a list
    - missing / blank
    """
    if not value:
        return []

    if isinstance(value, list):
        raw_items = value
    elif isinstance(value, str):
        raw_items = value.split(",")
    else:
        raw_items = [value]

    normalized = []
    seen = set()

    for item in raw_items:
        cleaned = str(item).strip().upper()
        if cleaned and cleaned not in seen:
            normalized.append(cleaned)
            seen.add(cleaned)

    return normalized


def extract_unique_bug_ids(advisories: Iterable[Dict[str, Any]]) -> List[str]:
    """
    Extract, normalize, de-duplicate, and sort all bug IDs from advisories.
    """
    unique_bug_ids = set()

    for advisory in advisories:
        for bug_id in normalize_bug_ids(advisory.get("bugIDs")):
            unique_bug_ids.add(bug_id)

    return sorted(unique_bug_ids)


def flatten_bug_values(
    bug_records: Iterable[Dict[str, Any]],
    field_name: str,
) -> List[str]:
    """
    Collect unique string values from a given field across multiple bug records.
    """
    values = []
    seen = set()

    for record in bug_records:
        raw_value = record.get(field_name, [])

        if isinstance(raw_value, str):
            raw_items = [raw_value]
        elif isinstance(raw_value, list):
            raw_items = raw_value
        else:
            raw_items = []

        for item in raw_items:
            cleaned = str(item).strip()
            if cleaned and cleaned not in seen:
                values.append(cleaned)
                seen.add(cleaned)

    return values


def enrich_advisories_with_bug_details(
    advisories: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Enrich advisories with Bug API metadata.

    Adds these fields to each advisory:
    - bugIDs_normalized
    - bug_details
    - bug_statuses
    - bug_severities
    - affected_versions
    - fixed_versions

    If Bug API access is unavailable, advisories are returned with empty
    enrichment fields so the rest of the report still works.
    """
    unique_bug_ids = extract_unique_bug_ids(advisories)

    verbose_print()
    verbose_print(f"Unique bug IDs found in filtered advisories: {len(unique_bug_ids)}")

    if not unique_bug_ids:
        for advisory in advisories:
            advisory["bugIDs_normalized"] = normalize_bug_ids(advisory.get("bugIDs"))
            advisory["bug_details"] = []
            advisory["bug_statuses"] = []
            advisory["bug_severities"] = []
            advisory["affected_versions"] = []
            advisory["fixed_versions"] = []
        return advisories

    try:
        bug_lookup = fetch_bug_details_by_ids(unique_bug_ids)
        verbose_print(f"Bug API details retrieved for: {len(bug_lookup)} bug IDs")

        # DEBUG
        verbose_print("DEBUG bug_lookup sample:")
        sample_items = list(bug_lookup.items())[:5]
        for key, value in sample_items:
            verbose_print(key, value)

        for advisory in advisories:
            advisory_bug_ids = normalize_bug_ids(advisory.get("bugIDs"))

            bug_records = [
                bug_lookup[bug_id]
                for bug_id in advisory_bug_ids
                if bug_id in bug_lookup
            ]

            verbose_print("DEBUG advisory bug IDs:", advisory_bug_ids)
            verbose_print("DEBUG matched bug records:", bug_records)

            advisory["bugIDs_normalized"] = advisory_bug_ids
            advisory["bug_details"] = bug_records
            advisory["bug_statuses"] = flatten_bug_values(bug_records, "status")
            advisory["bug_severities"] = flatten_bug_values(bug_records, "severity")
            advisory["affected_versions"] = flatten_bug_values(
                bug_records,
                "affected_versions",
            )
            advisory["fixed_versions"] = flatten_bug_values(
                bug_records,
                "fixed_versions",
            )

    except BugApiError as e:
        print(f"Warning: Bug API enrichment skipped: {e}")

        for advisory in advisories:
            advisory["bugIDs_normalized"] = normalize_bug_ids(advisory.get("bugIDs"))
            advisory["bug_details"] = []
            advisory["bug_statuses"] = []
            advisory["bug_severities"] = []
            advisory["affected_versions"] = []
            advisory["fixed_versions"] = []

    return advisories