# Cisco PSIRT Reporter

A Python tool for querying Cisco PSIRT advisories using the Cisco OpenVuln API and generating structured CSV reports filtered by configurable product groups.

The tool retrieves Cisco security advisories, classifies them by product family, and produces an operationally useful CSV report containing CVEs, severity, affected products, and advisory metadata.

This tool is intended for security engineers, vulnerability management teams, and operations teams who need quick visibility into Cisco security advisories affecting their environment.

---

# Overview

Cisco publishes security advisories through the OpenVuln API. These advisories often include many products and versions, making it difficult to quickly determine relevance.

This tool automates the process by:

1. Querying Cisco PSIRT advisories
2. Filtering to products of interest
3. Classifying advisories by product group
4. Producing a structured CSV report
5. Discovering new product name patterns to improve classification

---

# Features

## Cisco OpenVuln API Integration
Uses Cisco’s OAuth2 client credentials flow to authenticate and query advisories from the OpenVuln API.

## Product Group Classification
Uses a YAML configuration file to classify advisories into logical product groups with friendly names.

Example supported products:

- Adaptive Security Appliance (ASA)
- Secure Firewall Threat Defense (FTD)
- Firepower Management Center (FMC)
- Firepower Extensible Operating System (FXOS)

## Flexible Date Filtering

Supports:

- last **N days**
- explicit **start and end dates**

## CSV Reporting

Generates structured CSV output including:

- advisory metadata
- severity
- CVEs
- affected products
- friendly product names

## Product Discovery Mode

Extracts all raw product names returned by Cisco to help improve product matching rules.

---

# Script Flow (High Level)

1. Load product classification rules from YAML
2. Parse command line arguments
3. Resolve query date range
4. Authenticate with Cisco API
5. Retrieve advisories from OpenVuln API
6. Classify advisories by product group
7. Filter advisories based on selected groups
8. Extract unique product names for analysis
9. Export results to CSV

---

# Prerequisites

## Cisco API Access

Before using this script you must have access to the Cisco OpenVuln API.

You need:

- A registered Cisco developer application
- A valid **Client ID**
- A valid **Client Secret**

If you do not yet have API credentials, register an application on the Cisco Developer Platform and request access to the OpenVuln API.

---

## Python Requirements

Python 3.10+ recommended.

Required Python packages:

requests  
pyyaml  

Install them with:

pip install -r requirements.txt

---

# Secure Setup (Environment Variables)

API credentials should never be stored in source code.

Set them as environment variables instead.

## macOS / Linux

Add to your shell profile (~/.zshrc, ~/.bashrc, etc.):

export OPENVULN_CLIENT_ID="your_client_id"  
export OPENVULN_CLIENT_SECRET="your_client_secret"

Reload your shell:

source ~/.zshrc

or

source ~/.bashrc

---

## Windows PowerShell (temporary)

$env:OPENVULN_CLIENT_ID="your_client_id"  
$env:OPENVULN_CLIENT_SECRET="your_client_secret"

---

## Windows PowerShell (persistent)

[System.Environment]::SetEnvironmentVariable("OPENVULN_CLIENT_ID","your_client_id","User")  
[System.Environment]::SetEnvironmentVariable("OPENVULN_CLIENT_SECRET","your_client_secret","User")

Restart PowerShell after setting persistent variables.

---

# Configuration

Product matching rules are defined in:

config/product_groups.yaml

Example structure:

groups:
  netsec:
    description: Network Security Products
    products:
      FTD:
        match:
          - "Firewall Threat Defense"
        exclude: []

      ASA:
        match:
          - "Adaptive Security Appliance"
        exclude: []

This allows the tool to convert raw Cisco product names into cleaner friendly names used in reports.

---

# Usage

Run the reporter:

python src/psirt_reporter.py

Default behavior:

- pulls advisories from the last **60 days**
- includes **all configured product groups**

---

# Command Line Options

## Filter by Product Group

python src/psirt_reporter.py --group netsec

Multiple groups:

python src/psirt_reporter.py --group netsec switching

Include all groups:

python src/psirt_reporter.py --group all

---

## Query Last N Days

python src/psirt_reporter.py --days 30

---

## Query Specific Date Range

python src/psirt_reporter.py --start-date 2026-01-01 --end-date 2026-03-01

---

# Output

All generated files are written to:

output/

Example CSV file:

output/psirt_netsec_2026-01-01_to_2026-03-01.csv

---

# CSV Output Fields

| Column | Description |
|------|-------------|
| matched_groups | Product groups matched from configuration |
| friendly_products | Friendly product names |
| kev | Placeholder for Known Exploited Vulnerabilities flag |
| firstPublished | Advisory publication date |
| lastUpdated | Advisory last update date |
| status | Cisco advisory status |
| advisoryId | Cisco advisory identifier |
| sir | Cisco severity rating |
| cvssBaseScore | CVSS base score |
| cves | Associated CVE identifiers |
| advisoryTitle | Advisory title |
| productNames | Raw Cisco product names |
| publicationUrl | Cisco advisory link |
| cwe | Weakness classification |

---

# Product Name Discovery

The script also produces:

output/unique_product_names.txt

This file lists every unique product name returned by the Cisco API.

It helps improve product matching rules in `product_groups.yaml`.

---

# Project Structure

repo/
│
├── config/
│   └── product_groups.yaml
│
├── src/
│   └── psirt_reporter.py
│
├── output/
│   └── generated reports
│
├── README.md
└── LICENSE

---

# Troubleshooting

## Missing API Credentials

Ensure the following environment variables are set in the same shell where you run the script:

OPENVULN_CLIENT_ID  
OPENVULN_CLIENT_SECRET

---

## Authentication Errors (401 / 403)

Verify:

- your API key and secret are correct
- your Cisco developer app has OpenVuln API access

---

## No Advisories Returned

Possible reasons:

- No advisories were published in the selected date range
- Product filtering excluded all results

---

## Network / Proxy Issues

Ensure outbound access to:

id.cisco.com  
apix.cisco.com

---

# Roadmap

Planned improvements include:

- CISA Known Exploited Vulnerabilities (KEV) integration
- KEV filtering
- severity filtering
- HTML reporting
- scheduled reporting automation
- GitHub CI workflows

---

# License

This project is licensed under the MIT License.  
See the LICENSE file for details.