VERSION = "1.3.0"
import os
from pathlib import Path
import yaml


TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
BASE_URL = "https://apix.cisco.com/security/advisories/v2"
ADVISORIES_URL = f"{BASE_URL}/all/lastpublished"
ROOT_DIR = Path(__file__).resolve().parents[1]
PRODUCT_GROUPS_FILE = ROOT_DIR / "config" / "product_groups.yaml"
ENVIRONMENT_PRODUCTS_FILE = ROOT_DIR / "config" / "environment_products.yaml"
OUTPUT_DIR = ROOT_DIR / "output"

CLIENT_ID = os.getenv("OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.getenv("OPENVULN_CLIENT_SECRET")

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_product_groups():
    """Load product group definitions from the YAML config file."""
    with open(PRODUCT_GROUPS_FILE, "r", encoding="utf-8") as file_handle:
        config_data = yaml.safe_load(file_handle)

    return config_data["groups"]


def load_environment_products():
    """
    Load environment-assessable products configuration.
    """
    with open(ENVIRONMENT_PRODUCTS_FILE, "r") as f:
        data = yaml.safe_load(f)

    return data.get("products", {})