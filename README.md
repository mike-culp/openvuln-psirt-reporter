# Cisco PSIRT Reporter

A Python tool for querying Cisco PSIRT advisories using the Cisco OpenVuln API and generating structured CSV reports filtered by configurable product groups.

The tool retrieves Cisco security advisories, classifies them by product family, enriches them with CISA Known Exploited Vulnerabilities (KEV) intelligence, and produces an operationally useful CSV report containing CVEs, severity, affected products, and advisory metadata.

This tool is intended for security engineers, vulnerability management teams, and operations teams who need quick visibility into Cisco security advisories affecting their environment.

---

# Quick Start

Run the PSIRT reporter in just a few steps.

## 1. Clone the Repository

git clone https://github.com/<your-username>/psirt-reporter.git  
cd psirt-reporter

## 2. Install Dependencies

pip install -r requirements.txt

## 3. Set Cisco API Credentials

macOS / Linux

export OPENVULN_CLIENT_ID="your_client_id"  
export OPENVULN_CLIENT_SECRET="your_client_secret"

Windows PowerShell

$env:OPENVULN_CLIENT_ID="your_client_id"  
$env:OPENVULN_CLIENT_SECRET="your_client_secret"

## 4. Run the Reporter

python src/psirt_reporter.py

This pulls advisories from the last **60 days** and generates a CSV report in:

output/

## Example: NetSec Advisories From the Last 30 Days

python src/psirt_reporter.py --group netsec --days 30

## Example: Only Known Exploited Vulnerabilities

python src/psirt_reporter.py --kev-only

---

# Example Output

Example CSV output:

matched_groups,friendly_products,kev,advisoryId,cvssBaseScore,cves  
netsec,FTD,Y,cisco-sa-ftd-rce-2026,9.8,CVE-2026-XXXX

---

# Overview

Cisco publishes security advisories through the OpenVuln API. These advisories often include many products and versions, making it difficult to quickly determine relevance.

This tool automates the process by:

1. Querying Cisco PSIRT advisories
2. Filtering to products of interest
3. Classifying advisories by product group
4. Checking advisories against the CISA Known Exploited Vulnerabilities catalog
5. Producing a structured CSV report
6. Discovering new product name patterns to improve classification


---

# Architecture

The following diagram illustrates the high-level workflow of the PSIRT reporter.


            +----------------------+
            | Cisco OpenVuln API   |
            +----------+-----------+
                       |
                       v
               +---------------+
               | Advisory Pull |
               |  (Python API) |
               +-------+-------+
                       |
                       v
               +---------------+
               | Product       |
               | Classification|
               | YAML rules    |
               +-------+-------+
                       |
                       v
        +------------------------------+
        | KEV Intelligence Enrichment  |
        | CISA KEV Catalog             |
        +---------------+--------------+
                        |
                        v
               +---------------+
               | Advisory      |
               | Filtering     |
               +-------+-------+
                       |
                       v
               +---------------+
               | CSV Report    |
               | Output        |
               +---------------+

The tool retrieves Cisco advisories, classifies affected products using configurable YAML rules, enriches the results with CISA KEV intelligence, and produces structured CSV output for operational analysis.


---

# Security Use Cases

The PSIRT Reporter is designed to support common vulnerability management and security operations workflows.

## Vulnerability Intelligence Monitoring

Security teams can regularly pull Cisco PSIRT advisories and identify vulnerabilities affecting products deployed in their environment.

Example: python src/psirt_reporter.py --group netsec --days 30


This produces a report containing advisories affecting Cisco network security platforms such as:

- Secure Firewall Threat Defense (FTD)
- Adaptive Security Appliance (ASA)
- Firepower Management Center (FMC)
- Firepower Extensible Operating System (FXOS)

---

## Known Exploited Vulnerability Prioritization

Teams can filter advisories to include only vulnerabilities known to be actively exploited in the wild using the CISA KEV catalog.

Example:python src/psirt_reporter.py --group netsec --days 30 --kev-only

This allows engineers to quickly prioritize remediation for vulnerabilities with confirmed exploitation.

---

## Security Advisory Reporting

The generated CSV report can be used for:

- vulnerability tracking
- patch management workflows
- security reporting
- operational review meetings


---

# Features

## Cisco OpenVuln API Integration

Uses Cisco’s OAuth2 client credentials flow to authenticate and query advisories from the OpenVuln API.

---

## Product Group Classification

Uses a YAML configuration file to classify advisories into logical product groups with friendly names.

Example supported products:

- Adaptive Security Appliance (ASA)
- Secure Firewall Threat Defense (FTD)
- Firepower Management Center (FMC)
- Firepower Extensible Operating System (FXOS)

---

## Flexible Date Filtering

Supports:

- last **N days**
- explicit **start and end dates**

---

## CISA Known Exploited Vulnerabilities (KEV) Integration

The tool automatically downloads the CISA Known Exploited Vulnerabilities catalog and checks whether any CVEs associated with an advisory are present in the KEV list.

This allows engineers to quickly identify vulnerabilities that are known to be actively exploited in the wild.

---

## KEV Filtering

Use the `--kev-only` flag to return only advisories containing CVEs present in the CISA KEV catalog.

This allows teams to prioritize vulnerabilities with confirmed real-world exploitation.

Example:

python src/psirt_reporter.py --kev-only

---

## CSV Reporting

Generates structured CSV output including:

- advisory metadata
- severity
- CVEs
- affected products
- friendly product names
- KEV exploitation indicator

---

## Product Discovery Mode

Extracts all raw product names returned by Cisco to help improve product matching rules.

---

# Script Flow (High Level)

1. Load product classification rules from YAML  
2. Parse command line arguments  
3. Resolve query date range  
4. Authenticate with Cisco OpenVuln API  
5. Retrieve advisories from OpenVuln API  
6. Retrieve the CISA Known Exploited Vulnerabilities catalog  
7. Classify advisories by product group  
8. Filter advisories based on selected product groups  
9. Optionally filter to KEV advisories only  
10. Extract unique product names for analysis  
11. Export results to CSV  

---

# External Data Sources

The reporter pulls data from the following sources.

## Cisco OpenVuln API

https://apix.cisco.com/security/advisories

Used to retrieve Cisco PSIRT advisories.

---

## CISA Known Exploited Vulnerabilities Catalog

https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Used to determine whether advisory CVEs are known to be actively exploited.

---

# Prerequisites

## Cisco API Access

Before using this script you must have access to the Cisco OpenVuln API.

You need:

- A registered Cisco developer application
- A valid **Client ID**
- A valid **Client Secret**

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

macOS / Linux

export OPENVULN_CLIENT_ID="your_client_id"  
export OPENVULN_CLIENT_SECRET="your_client_secret"

Windows PowerShell

$env:OPENVULN_CLIENT_ID="your_client_id"  
$env:OPENVULN_CLIENT_SECRET="your_client_secret"

---

# Configuration

Product matching rules are defined in:

config/product_groups.yaml

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

python src/psirt_reporter.py --group netsec enterprise

Include all groups:

python src/psirt_reporter.py --group all

---

## Query Last N Days

python src/psirt_reporter.py --days 30

---

## Query Specific Date Range

python src/psirt_reporter.py --start-date 2026-01-01 --end-date 2026-03-01

---

## Show Only Known Exploited Vulnerabilities

Return only advisories containing CVEs listed in the CISA KEV catalog.

python src/psirt_reporter.py --kev-only

Example:

python src/psirt_reporter.py --group netsec --days 30 --kev-only

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
| kev | Indicates whether the advisory contains a CVE listed in the CISA KEV catalog (Y/N) |
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

config/  
└── product_groups.yaml  

src/  
└── psirt_reporter.py  

output/  
└── generated reports  

README.md  
LICENSE

---

# Troubleshooting

## Missing API Credentials

Ensure the following environment variables are set:

OPENVULN_CLIENT_ID  
OPENVULN_CLIENT_SECRET

---

## Authentication Errors (401 / 403)

Verify:

- your API key and secret are correct
- your Cisco developer app has OpenVuln API access

---

# Roadmap

Planned improvements include:

- severity filtering
- HTML reporting
- scheduled reporting automation
- GitHub CI workflows

---

# License

This project is licensed under the MIT License.