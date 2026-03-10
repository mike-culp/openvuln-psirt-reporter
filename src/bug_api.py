"""
Cisco Bug API client.

Initial scope:
- Authenticate with Cisco OAuth2 using client credentials
- Fetch bug details by bug ID, batched up to 5 per request
- Throttle requests to stay comfortably under API limits
- Return normalized data keyed by bug ID

Expected environment variables:
- BUG_API_CLIENT_ID
- BUG_API_CLIENT_SECRET

Notes:
- Bug API endpoint supports up to 5 bug IDs per request.
- We intentionally sleep between requests to remain under 2 calls/sec.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Iterable, List

import requests


BUG_API_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BUG_API_BASE_URL = "https://api.cisco.com/bug/v2.0/bugs"
BUG_API_CLIENT_ID = os.getenv("BUG_API_CLIENT_ID")
BUG_API_CLIENT_SECRET = os.getenv("BUG_API_CLIENT_SECRET")

# Keep this conservative. 0.6 sec ~= 1.67 calls/sec.
BUG_API_MIN_INTERVAL_SECONDS = 0.6
BUG_API_BATCH_SIZE = 5
BUG_API_TIMEOUT_SECONDS = 30


class BugApiError(Exception):
    """Raised when the Cisco Bug API request fails."""


def validate_bug_api_config() -> None:
    """Ensure required Bug API credentials are present."""
    missing = []

    if not BUG_API_CLIENT_ID:
        missing.append("BUG_API_CLIENT_ID")
    if not BUG_API_CLIENT_SECRET:
        missing.append("BUG_API_CLIENT_SECRET")

    if missing:
        joined = ", ".join(missing)
        raise BugApiError(
            f"Missing required Bug API environment variable(s): {joined}"
        )


def get_bug_api_token() -> str:
    """
    Obtain an OAuth access token for the Cisco Bug API.
    """
    validate_bug_api_config()

    response = requests.post(
        BUG_API_TOKEN_URL,
        data={"grant_type": "client_credentials"},
        auth=(BUG_API_CLIENT_ID, BUG_API_CLIENT_SECRET),
        timeout=BUG_API_TIMEOUT_SECONDS,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise BugApiError(
            f"Bug API token request failed: {response.status_code} {response.text}"
        ) from exc

    token = response.json().get("access_token")
    if not token:
        raise BugApiError("Bug API token response did not include access_token")

    return token


def chunked(items: Iterable[str], size: int) -> List[List[str]]:
    """
    Split an iterable into fixed-size chunks.
    """
    batch: List[str] = []

    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []

    if batch:
        yield batch


def normalize_bug_ids(bug_ids: Iterable[str]) -> List[str]:
    """
    Normalize, deduplicate, and sort bug IDs.
    """
    normalized = set()

    for bug_id in bug_ids:
        if not bug_id:
            continue

        cleaned = str(bug_id).strip().upper()
        if cleaned:
            normalized.add(cleaned)

    return sorted(normalized)


def extract_bug_rows(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract the list of bug records from the Bug API response.

    This is intentionally defensive because Cisco response wrappers
    sometimes vary slightly across APIs.
    """
    if not isinstance(payload, dict):
        return []

    common_keys = [
        "bugs",
        "bug",
        "items",
        "itemsData",
        "data",
    ]

    for key in common_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value

    # Sometimes the API may return a wrapper object with nested data.
    response_obj = payload.get("response") or payload.get("Response")
    if isinstance(response_obj, dict):
        for key in common_keys:
            value = response_obj.get(key)
            if isinstance(value, list):
                return value

    return []


def normalize_bug_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize one Bug API record into a stable internal shape.

    Keep this lightweight for v1. We can expand once we inspect
    real responses from your account.
    """
    bug_id = (
        record.get("bugId")
        or record.get("bug_id")
        or record.get("id")
        or record.get("identifier")
        or ""
    )

    status = record.get("status") or ""
    severity = record.get("severity") or ""
    headline = (
        record.get("headline")
        or record.get("title")
        or record.get("bugHeadline")
        or ""
    )

    affected_versions = (
        record.get("affectedVersions")
        or record.get("affected_versions")
        or record.get("knownAffectedReleases")
        or []
    )

    fixed_versions = (
        record.get("fixedVersions")
        or record.get("fixed_versions")
        or record.get("knownFixedReleases")
        or []
    )

    if isinstance(affected_versions, str):
        affected_versions = [affected_versions]
    if isinstance(fixed_versions, str):
        fixed_versions = [fixed_versions]

    return {
        "bug_id": str(bug_id).strip().upper(),
        "status": status,
        "severity": severity,
        "headline": headline,
        "affected_versions": [str(v).strip() for v in affected_versions if v],
        "fixed_versions": [str(v).strip() for v in fixed_versions if v],
        "raw": record,
    }


def fetch_bug_details_batch(
    bug_ids: List[str],
    token: str,
) -> Dict[str, Dict[str, Any]]:
    """
    Fetch bug details for a batch of up to 5 bug IDs.
    Returns a dict keyed by bug_id.
    """
    if not bug_ids:
        return {}

    if len(bug_ids) > BUG_API_BATCH_SIZE:
        raise BugApiError(
            f"Bug API batch too large: {len(bug_ids)} "
            f"(max {BUG_API_BATCH_SIZE})"
        )

    joined_bug_ids = ",".join(bug_ids)
    url = f"{BUG_API_BASE_URL}/bug_ids/{joined_bug_ids}"

    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=BUG_API_TIMEOUT_SECONDS,
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise BugApiError(
            f"Bug API batch request failed for [{joined_bug_ids}]: "
            f"{response.status_code} {response.text}"
        ) from exc

    payload = response.json()
    rows = extract_bug_rows(payload)

    if rows:
        print()
        print("DEBUG: First Bug API record:")
        print(rows[0])
        print()

    normalized: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        bug = normalize_bug_record(row)
        if bug["bug_id"]:
            normalized[bug["bug_id"]] = bug

    return normalized


def fetch_bug_details_by_ids(
    bug_ids: Iterable[str],
    sleep_seconds: float = BUG_API_MIN_INTERVAL_SECONDS,
) -> Dict[str, Dict[str, Any]]:
    """
    Fetch bug details for all unique bug IDs.

    Batching and throttling are built in to respect the Bug API limit.
    """
    normalized_bug_ids = normalize_bug_ids(bug_ids)

    if not normalized_bug_ids:
        return {}

    token = get_bug_api_token()
    results: Dict[str, Dict[str, Any]] = {}

    for index, batch in enumerate(chunked(normalized_bug_ids, BUG_API_BATCH_SIZE)):
        batch_results = fetch_bug_details_batch(batch, token)
        results.update(batch_results)

        # Sleep after each batch except the last.
        if index < (len(normalized_bug_ids) - 1) // BUG_API_BATCH_SIZE:
            time.sleep(sleep_seconds)

    return results