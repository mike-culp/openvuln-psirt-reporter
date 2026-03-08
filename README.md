# Cisco PSIRT Reporter

A Python tool for querying Cisco PSIRT advisories using the Cisco OpenVuln API and generating structured **CSV and optional HTML reports** filtered by configurable product groups.

The tool retrieves Cisco security advisories, classifies them by product family, supports severity filtering using Cisco’s Security Impact Rating (SIR), supports filtering by minimum CVSS score, enriches results with CISA Known Exploited Vulnerabilities (KEV) intelligence, and produces operationally useful reports containing CVEs, severity, affected products, and advisory metadata.

This tool is intended for security engineers, vulnerability management teams, and operations teams who need quick visibility into Cisco security advisories affecting their environment.

---

# Quick Start

Run the PSIRT reporter in just a few steps.

## 1. Clone the Repository

```
git clone https://github.com/<your-username>/psirt-reporter.git
cd psirt-reporter
```

## 2. Install Dependencies

```
pip install -r requirements.txt
```

## 3. Set Cisco API Credentials

macOS / Linux

```
export OPENVULN_CLIENT_ID="your_client_id"
export OPENVULN_CLIENT_SECRET="your_client_secret"
```

Windows PowerShell

```
$env:OPENVULN_CLIENT_ID="your_client_id"
$env:OPENVULN_CLIENT_SECRET="your_client_secret"
```

## 4. Run the Reporter

```
python src/psirt_reporter.py
```

This pulls advisories from the last **60 days** and generates a CSV report in:

```
output/
```

---

# CLI Help

To see all available options and filtering capabilities:

```
python src/psirt_reporter.py --help
```

This displays all supported command line options including product group filtering, date ranges, severity filtering, CVSS filtering, KEV prioritization, and optional HTML reporting.

---

# Example Commands

## NetSec Advisories From the Last 30 Days

```
python src/psirt_reporter.py --group netsec --days 30
```

## Generate HTML Report

```
python src/psirt_reporter.py --html
```

Generates both:

```
output/psirt_<groups>_<start>_to_<end>.csv
output/psirt_<groups>_<start>_to_<end>.html
```

## Only Known Exploited Vulnerabilities

```
python src/psirt_reporter.py --kev-only
```

## Only High or Critical Severity

```
python src/psirt_reporter.py --sir critical high
```

## Minimum CVSS Score

```
python src/psirt_reporter.py --min-cvss 8.0
```

## NetSec + High Severity + CVSS + KEV + HTML

```
python src/psirt_reporter.py --group netsec --sir critical high --min-cvss 8.0 --kev-only --html
```

---

# Example Output

## CSV Output

Example CSV output:

```
matched_groups,friendly_products,kev,advisoryId,cvssBaseScore,cves
netsec,FTD,Y,cisco-sa-ftd-rce-2026,9.8,CVE-2026-XXXX
```

## HTML Output

The optional HTML report provides:

* Advisory summary statistics
* Severity distribution
* KEV indicators
* Product group breakdown
* Friendly product breakdown
* Full advisory table with clickable links to Cisco advisories

The HTML report is designed to provide a quick operational dashboard view of Cisco PSIRT advisories.

---

# Overview

Cisco publishes security advisories through the OpenVuln API. These advisories often include many products and versions, making it difficult to quickly determine relevance.

This tool automates the process by:

1. Querying Cisco PSIRT advisories
2. Filtering to products of interest
3. Classifying advisories by product group
4. Filtering advisories by Cisco Security Impact Rating (SIR)
5. Filtering advisories by minimum CVSS score
6. Checking advisories against the CISA Known Exploited Vulnerabilities catalog
7. Producing structured CSV reports
8. Optionally generating an HTML report for operational visibility
9. Discovering new product names to improve classification rules

---

# Architecture

High-level workflow of the PSIRT reporter.

```
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
   +----------------------+
   | Severity Filtering   |
   | Cisco SIR            |
   +-----------+----------+
               |
               v
   +----------------------+
   | CVSS Filtering       |
   | Minimum Score        |
   +-----------+----------+
               |
               v
   +------------------------------+
   | KEV Intelligence Enrichment  |
   | CISA KEV Catalog             |
   +---------------+--------------+
                   |
                   v
           +----------------------+
           | Report Generation    |
           | CSV + Optional HTML  |
           +----------------------+
```

The tool retrieves Cisco advisories, classifies affected products using configurable YAML rules, filters by severity and CVSS score, enriches the results with CISA KEV intelligence, and produces structured output for operational analysis.

---

# Security Use Cases

## Vulnerability Intelligence Monitoring

Security teams can regularly pull Cisco PSIRT advisories and identify vulnerabilities affecting products deployed in their environment.

Example:

```
python src/psirt_reporter.py --group netsec --days 30
```

This produces a report containing advisories affecting Cisco network security platforms such as:

* Secure Firewall Threat Defense (FTD)
* Adaptive Security Appliance (ASA)
* Firepower Management Center (FMC)
* Firepower Extensible Operating System (FXOS)

---

## Known Exploited Vulnerability Prioritization

Teams can filter advisories to include only vulnerabilities known to be actively exploited in the wild using the CISA KEV catalog.

Example:

```
python src/psirt_reporter.py --group netsec --days 30 --kev-only
```

---

## Severity-Based Triage

Security teams can prioritize remediation by filtering advisories by Cisco Security Impact Rating (SIR).

Example:

```
python src/psirt_reporter.py --sir critical high
```

---

## CVSS-Based Risk Filtering

Security teams can filter advisories using a minimum CVSS score.

Example:

```
python src/psirt_reporter.py --min-cvss 8.0
```

---

# Features

## Cisco OpenVuln API Integration

Uses Cisco’s OAuth2 client credentials flow to authenticate and query advisories from the OpenVuln API.

---

## Product Group Classification

Uses a YAML configuration file to classify advisories into logical product groups with friendly names.

Product definitions are maintained in:

```
config/product_groups.yaml
```

Example product groups include NetSec, Enterprise Networking, Data Center, Wireless, Collaboration, Compute, and Cloud.

---

## Flexible Date Filtering

Supports:

* last **N days**
* explicit **start and end dates**

Examples:

```
python src/psirt_reporter.py --days 30
```

```
python src/psirt_reporter.py --start-date 2026-01-01 --end-date 2026-03-01
```

---

## Severity Filtering (Cisco SIR)

Advisories can be filtered using Cisco's **Security Impact Rating (SIR)**.

Supported values:

* critical
* high
* medium
* low

Example:

```
python src/psirt_reporter.py --sir critical high
```

---

## CVSS Score Filtering

Advisories can be filtered by **minimum CVSS base score**.

Example:

```
python src/psirt_reporter.py --min-cvss 8.0
```

---

## CISA Known Exploited Vulnerabilities (KEV) Integration

The tool automatically downloads the CISA Known Exploited Vulnerabilities catalog and checks whether any CVEs associated with an advisory are present in the KEV list.

---

## KEV Filtering

Use the `--kev-only` flag to return only advisories containing CVEs present in the CISA KEV catalog.

Example:

```
python src/psirt_reporter.py --kev-only
```

---

## HTML Reporting

Optional HTML reports can be generated using:

```
--html
```

The HTML report includes:

* advisory summary statistics
* severity distribution
* KEV indicators
* product group breakdown
* friendly product breakdown
* full advisory table with clickable advisory links

---

## CSV Reporting

Generates structured CSV output including:

* advisory metadata
* severity
* CVEs
* affected products
* friendly product names
* KEV exploitation indicator

---

## Product Discovery Mode

The script extracts all raw Cisco product names returned by the API and writes them to:

```
output/unique_product_names.txt
```

This helps identify new product names and improve classification rules.

---

# Script Flow (High Level)

1. Load product classification rules from YAML
2. Parse command line arguments
3. Resolve query date range
4. Authenticate with Cisco OpenVuln API
5. Retrieve advisories from OpenVuln API
6. Classify advisories by product group
7. Filter advisories by selected product groups
8. Filter advisories by Cisco severity (SIR)
9. Filter advisories by minimum CVSS score
10. Retrieve the CISA KEV catalog
11. Optionally filter to KEV advisories only
12. Extract unique product names
13. Export results to CSV
14. Optionally generate HTML report

---

# External Data Sources

## Cisco OpenVuln API

https://apix.cisco.com/security/advisories

## CISA Known Exploited Vulnerabilities Catalog

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
