import argparse
from datetime import datetime, timedelta, timezone
from src.config import load_environment_products


def positive_int(value):
    """
    Ensure CLI integer arguments are positive.
    """
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} must be a positive integer")
    return ivalue


def parse_product_version_args(product_args):
    """
    Validate and normalize --product arguments.

    Input from argparse looks like:
        [["ftd", "7.2.2.1"]]

    Output:
        {"ftd": ["7.2.2.1"]}
    """
    supported_products = load_environment_products()
    parsed = {}

    for entry in product_args or []:
        product = entry[0].strip().lower()
        versions = [v.strip() for v in entry[1:] if str(v).strip()]

        if not versions:
            raise ValueError(
                f"--product {product} requires at least one version"
            )

        if product not in supported_products:
            valid = ", ".join(sorted(supported_products.keys()))
            raise ValueError(
                f"Unsupported product '{product}'. Supported products: {valid}"
            )

        if product in parsed:
            parsed[product].extend(versions)
        else:
            parsed[product] = versions

    return parsed


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

    args = parser.parse_args()
    args.environment_mode = bool(args.product)
    args.product_versions = parse_product_version_args(args.product)
    return args


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