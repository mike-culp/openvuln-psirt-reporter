import argparse
from datetime import datetime, timedelta, timezone


def positive_int(value):
    """Argparse type that only accepts integers >= 1."""
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(
            f"invalid positive integer value: {value}"
        )
    return ivalue


def parse_arguments(product_groups):
    """Parse command line arguments."""
    group_names = list(product_groups.keys())

    group_help_text = (
        "Product groups to include.\n\n"
        "Available groups:\n"
        + "\n".join(f"  {group_name}" for group_name in group_names)
        + "\n\nUse 'all' to include everything (default)."
    )

    parser = argparse.ArgumentParser(
        description="Cisco PSIRT advisory reporter"
    )

    parser.add_argument(
        "--group",
        nargs="+",
        default=["all"],
        help=group_help_text,
    )
    
    parser.add_argument(
        "--product",
        nargs="+",
        action="append",
        metavar=("PRODUCT", "VERSION"),
        help="Specify product and version(s) for environment assessment mode"
    )

    parser.add_argument(
        "--sir",
        nargs="+",
        choices=["critical", "high", "medium", "low"],
        help=(
            "Filter advisories by Cisco severity rating. "
            "Allowed values: critical, high, medium, low"
        ),
    )

    parser.add_argument(
        "--min-cvss",
        type=float,
        help="Minimum CVSS base score to include (example: 8.0)",
    )

    parser.add_argument(
        "--kev-only",
        action="store_true",
        help="Include only advisories with CVEs present in the CISA KEV catalog",
    )

    parser.add_argument(
        "--days",
        type=positive_int,
        default=60,
        help="Number of days to look back. Ignored if start/end date are provided.",
    )

    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date in YYYY-MM-DD format",
    )

    parser.add_argument(
        "--end-date",
        type=str,
        help="End date in YYYY-MM-DD format",
    )
    
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report in addition to the CSV report",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging for API requests and debugging output",
    )

    return parser.parse_args()


def resolve_date_range(args):
    """Resolve start and end dates from CLI arguments."""
    if args.days < 1:
        raise ValueError("--days must be greater than or equal to 1")

    if (args.start_date and not args.end_date) or (
        args.end_date and not args.start_date
    ):
        raise ValueError(
            "Both --start-date and --end-date must be provided together."
        )

    if args.start_date and args.end_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d").date()
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()
    else:
        end_date = datetime.now(timezone.utc).date()
        start_date = end_date - timedelta(days=args.days)

    if start_date > end_date:
        raise ValueError("--start-date must be on or before --end-date")

    return start_date, end_date